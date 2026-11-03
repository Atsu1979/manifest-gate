"""Rules and the command-line entry point.

Rules (each can be tuned in the config file):
  R1  container images are pinned by digest (@sha256:)
  R2  no images from registries that only exist locally (node caches, ad-hoc registries)
  R3  workloads in selected namespaces have a readinessProbe and a memory limit
  R4  every namespace declared in the repo has a default-deny ingress NetworkPolicy
  R5  Secrets with data live only in encrypted files (e.g. *.sops.yaml)
  R6  Namespaces and PersistentVolumeClaims under the app paths opt out of GitOps pruning,
      so deleting a file cannot delete the data with it

Violations in workloads scaled to zero ("dormant") are reported as warnings: harmless today,
but the pods will be rejected the moment someone scales them back up.

Known exceptions live in the config with a reason and a review date. An exception without a
reason, an expired exception, and an exception that no longer matches anything all fail the gate,
so exceptions cannot be left behind silently.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import os
import re
import sys
from dataclasses import dataclass, field

import yaml

from . import __version__

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
PRUNE_ANNOTATION = "kustomize.toolkit.fluxcd.io/prune"
# libyaml's C loader is several times faster; both are "safe" loaders (no arbitrary object construction).
LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
SET_KEYS = ("digest_exempt_namespaces", "health_namespaces", "health_exempt_apps")
TUPLE_KEYS = ("local_image_prefixes", "app_paths", "skip_paths")
CONFIG_KEYS = set(SET_KEYS) | set(TUPLE_KEYS) | {"encrypted_suffix", "exceptions"}


class ConfigError(Exception):
    """The config file or the command line is unusable. The gate must not run with a guess."""


def _map(x) -> dict:
    """Treat anything that is not a mapping as empty, so malformed manifests cannot crash the gate."""
    return x if isinstance(x, dict) else {}


@dataclass
class Config:
    digest_exempt_namespaces: set[str] = field(default_factory=lambda: {
        "kube-system", "kube-public", "kube-node-lease", "flux-system", "default"})
    health_namespaces: set[str] = field(default_factory=set)
    health_exempt_apps: set[str] = field(default_factory=set)
    local_image_prefixes: tuple[str, ...] = ("docker.io/local/", "localhost:", "127.0.0.1:")
    encrypted_suffix: str = ".sops.yaml"
    app_paths: tuple[str, ...] = ("apps/",)
    skip_paths: tuple[str, ...] = ("/.git/", "/.github/", "/charts/")
    exceptions: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | None, required: bool = False) -> Config:
        """Load a config file.

        A missing file is an error when ``required`` (the user named it with -c): silently falling
        back to the defaults would switch rules off without anyone noticing. Unknown keys are errors
        for the same reason - a typo such as ``health_namespace`` must not disable R3.
        """
        c = cls()
        if not path or not os.path.exists(path):
            if required:
                raise ConfigError(f"config file not found: {path}")
            return c
        try:
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigError(f"{path}: cannot parse YAML: {str(e)[:200]}") from None
        raw = {} if raw is None else raw
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: top level must be a mapping")
        unknown = sorted(set(raw) - CONFIG_KEYS)
        if unknown:
            raise ConfigError(f"{path}: unknown key(s) {unknown}; allowed: {sorted(CONFIG_KEYS)}")
        for key in SET_KEYS + TUPLE_KEYS:
            if key not in raw:
                continue
            val = raw[key] or []
            if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
                raise ConfigError(f"{path}: {key} must be a list of strings")
            setattr(c, key, set(val) if key in SET_KEYS else tuple(val))
        if "encrypted_suffix" in raw:
            if not isinstance(raw["encrypted_suffix"], str) or not raw["encrypted_suffix"]:
                raise ConfigError(f"{path}: encrypted_suffix must be a non-empty string")
            c.encrypted_suffix = raw["encrypted_suffix"]
        exc = raw.get("exceptions") or []
        if not isinstance(exc, list) or not all(isinstance(x, dict) for x in exc):
            raise ConfigError(f"{path}: exceptions must be a list of mappings (match, reason, review_by)")
        c.exceptions = exc
        return c


def iter_docs(root: str, cfg: Config, stats: dict | None = None):
    stats = stats if stats is not None else {}
    stats.setdefault("files", 0)
    stats.setdefault("documents", 0)
    for path in sorted(glob.glob(os.path.join(root, "**/*.y*ml"), recursive=True)):
        if not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if any(s in "/" + rel for s in cfg.skip_paths) or os.path.basename(path).startswith("manifest-gate"):
            continue
        stats["files"] += 1
        try:
            with open(path, encoding="utf-8") as f:
                for d in yaml.load_all(f, Loader=LOADER):
                    if isinstance(d, dict) and isinstance(d.get("kind"), str) and "apiVersion" in d:
                        stats["documents"] += 1
                        yield rel, d
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            yield rel, {"kind": "__parse_error__", "error": str(e)[:200]}


def pod_template(d: dict) -> dict:
    """The object that carries the pod's metadata and spec, for every workload kind."""
    kind, spec = d["kind"], _map(d.get("spec"))
    if kind == "Pod":
        return d
    if kind == "CronJob":
        return _map(_map(_map(spec.get("jobTemplate")).get("spec")).get("template"))
    return _map(spec.get("template"))


def pod_spec(d: dict) -> dict:
    return _map(pod_template(d).get("spec"))


def is_default_deny_ingress(sp: dict) -> bool:
    """podSelector {} selecting every pod, Ingress in policyTypes, and no ingress rules.

    When policyTypes is omitted, Kubernetes treats the policy as Ingress (plus Egress only if
    an egress section exists), so ``spec: {podSelector: {}}`` alone is a default deny.
    """
    types = sp.get("policyTypes") or ["Ingress"]
    return sp.get("podSelector") in ({}, None) and "Ingress" in types and not sp.get("ingress")


def is_sops_encrypted(d: dict) -> bool:
    """A file named *.sops.yaml is not proof of encryption. SOPS adds a top-level ``sops`` block and
    replaces every value under data/stringData with ``ENC[...]``; anything else is plaintext."""
    if not isinstance(d.get("sops"), dict):
        return False
    values = [v for key in ("data", "stringData") for v in _map(d.get(key)).values()]
    return all(isinstance(v, str) and v.startswith("ENC[") for v in values)


def check(root: str, cfg: Config, today: dt.date | None = None,
          stats: dict | None = None) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). ``stats``, if given, receives the number of files and documents read."""
    today = today or dt.date.today()
    errs: list[str] = []
    warns: list[str] = []
    namespaces: set[str] = set()
    denied: set[str] = set()

    for path, d in iter_docs(root, cfg, stats):
        kind = d["kind"]
        if kind == "__parse_error__":
            errs.append(f"{path}: cannot parse YAML: {d['error']}")
            continue
        if not isinstance(d.get("metadata"), dict):
            errs.append(f"{path}: {kind} has no metadata mapping")
            continue
        md = d["metadata"]
        ns = md.get("namespace") or "default"
        if kind == "Namespace":
            namespaces.add(md.get("name"))
        if kind == "NetworkPolicy" and is_default_deny_ingress(_map(d.get("spec"))):
            denied.add(ns)
        if kind == "Secret" and (d.get("data") or d.get("stringData")):
            if not path.endswith(cfg.encrypted_suffix):
                errs.append(f"R5 {path}: Secret/{md.get('name')} holds data outside an encrypted file")
            elif not is_sops_encrypted(d):
                errs.append(f"R5 {path}: Secret/{md.get('name')} is in an encrypted-looking file "
                            f"but is not encrypted (no sops metadata, or a plaintext value)")
        if kind in ("Namespace", "PersistentVolumeClaim") and path.startswith(cfg.app_paths) and \
                _map(md.get("annotations")).get(PRUNE_ANNOTATION) != "disabled":
            errs.append(f"R6 {path}: {kind}/{md.get('name')} is not protected from pruning ({PRUNE_ANNOTATION}: disabled)")
        if kind not in WORKLOADS:
            continue

        ps = pod_spec(d)
        name = f"{path}: {kind}/{md.get('name')} (ns={ns})"
        dormant = _map(d.get("spec")).get("replicas") == 0
        before = len(errs)
        containers = [c for c in (ps.get("containers") or []) if isinstance(c, dict)]
        inits = [c for c in (ps.get("initContainers") or []) if isinstance(c, dict)]
        for c in containers + inits:
            img = str(c.get("image") or "")
            if ns not in cfg.digest_exempt_namespaces and "@sha256:" not in img:
                errs.append(f"R1 {name}: container {c.get('name')} image is not pinned by digest: {img}")
            if img.startswith(cfg.local_image_prefixes):
                errs.append(f"R2 {name}: container {c.get('name')} uses a local-only image: {img}")
        app = _map(_map(pod_template(d).get("metadata")).get("labels")).get("app")
        for c in containers:
            ok = "readinessProbe" in c and "memory" in _map(_map(c.get("resources")).get("limits"))
            if not ok and app not in cfg.health_exempt_apps:
                msg = f"R3 {name}: container {c.get('name')} lacks a readinessProbe or a memory limit"
                (errs if ns in cfg.health_namespaces else warns).append(
                    msg if ns in cfg.health_namespaces else msg + " (namespace not covered by the rule)")
        if dormant and len(errs) > before:
            warns.extend(e + " (dormant: replicas 0 - pods will be rejected when scaled up)" for e in errs[before:])
            del errs[before:]

    for ns in sorted(namespaces - denied - cfg.digest_exempt_namespaces):
        errs.append(f"R4 namespace {ns}: no default-deny ingress NetworkPolicy")

    used: set[str] = set()
    kept: list[str] = []
    for e in errs:
        hit = next((x for x in cfg.exceptions if isinstance(x.get("match"), str) and x["match"] and x["match"] in e), None)
        if hit:
            used.add(hit["match"])
            warns.append(e + f" (known exception: {hit.get('reason')}; review by {hit.get('review_by')})")
        else:
            kept.append(e)
    for x in cfg.exceptions:
        review_by = _parse_date(x.get("review_by"))
        if not x.get("match"):
            kept.append(f"EX exception without a match string: {x!r}")
        elif not x.get("reason") or not x.get("review_by"):
            kept.append(f"EX exception {x.get('match')!r} needs both reason and review_by")
        elif review_by is None:
            kept.append(f"EX exception {x.get('match')!r} has an invalid review_by (use YYYY-MM-DD): {x['review_by']!r}")
        elif review_by < today:
            kept.append(f"EX exception {x.get('match')!r} expired on {x['review_by']}: {x['reason']}")
        elif x.get("match") not in used:
            kept.append(f"EX exception {x.get('match')!r} no longer matches anything - remove it")
    return kept, warns


def _parse_date(v) -> dt.date | None:
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    # Only YYYY-MM-DD: fromisoformat also accepts "20261231" on 3.11+ but not on 3.10.
    if not isinstance(v, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return None
    try:
        return dt.date.fromisoformat(v)
    except ValueError:
        return None


def main(argv: list[str] | None = None) -> int:
    """Exit codes: 0 = pass, 1 = policy violations, 2 = the gate could not run (bad input or config)."""
    ap = argparse.ArgumentParser(prog="manifest-gate", description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    ap.add_argument("-c", "--config", default=None, help="config file (default: <root>/manifest-gate.yaml if present)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = ap.parse_args(argv)
    try:
        if not os.path.isdir(a.root):
            raise ConfigError(f"repository root is not a directory: {a.root}")
        cfg_path = a.config or os.path.join(a.root, "manifest-gate.yaml")
        cfg = Config.load(cfg_path, required=a.config is not None)
    except ConfigError as e:
        print(f"ERROR {e}", file=sys.stderr)
        return 2
    stats: dict = {}
    errs, warns = check(a.root, cfg, stats=stats)
    if stats["documents"] == 0 and not errs:
        # A wrong path or a skip_paths typo would otherwise make the gate pass on nothing.
        print(f"ERROR no Kubernetes manifests found under {a.root} ({stats['files']} YAML files read)", file=sys.stderr)
        return 2
    for w in warns:
        print("WARN", w)
    for e in errs:
        print("FAIL", e)
    print(f"checked: files={stats['files']} documents={stats['documents']} errors={len(errs)} warnings={len(warns)}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
