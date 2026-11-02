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
import sys
from dataclasses import dataclass, field

import yaml

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
PRUNE_ANNOTATION = "kustomize.toolkit.fluxcd.io/prune"


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
    def load(cls, path: str | None) -> "Config":
        c = cls()
        if not path or not os.path.exists(path):
            return c
        raw = yaml.safe_load(open(path, encoding="utf-8")) or {}
        for key in ("digest_exempt_namespaces", "health_namespaces", "health_exempt_apps"):
            if key in raw:
                setattr(c, key, set(raw[key] or []))
        for key in ("local_image_prefixes", "app_paths", "skip_paths"):
            if key in raw:
                setattr(c, key, tuple(raw[key] or []))
        c.encrypted_suffix = raw.get("encrypted_suffix", c.encrypted_suffix)
        c.exceptions = raw.get("exceptions") or []
        return c


def iter_docs(root: str, cfg: Config):
    for path in sorted(glob.glob(os.path.join(root, "**/*.y*ml"), recursive=True)):
        rel = os.path.relpath(path, root)
        if any(s in "/" + rel for s in cfg.skip_paths) or os.path.basename(path).startswith("manifest-gate"):
            continue
        try:
            for d in yaml.safe_load_all(open(path, encoding="utf-8")):
                if isinstance(d, dict) and "kind" in d and "apiVersion" in d:
                    yield rel, d
        except yaml.YAMLError as e:
            yield rel, {"kind": "__parse_error__", "error": str(e)[:200]}


def pod_spec(d: dict) -> dict:
    kind, spec = d["kind"], d.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def check(root: str, cfg: Config, today: dt.date | None = None) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    today = today or dt.date.today()
    errs: list[str] = []
    warns: list[str] = []
    namespaces: set[str] = set()
    denied: set[str] = set()

    for path, d in iter_docs(root, cfg):
        kind, md = d["kind"], d.get("metadata") or {}
        ns = md.get("namespace", "default")
        if kind == "__parse_error__":
            errs.append(f"{path}: cannot parse YAML: {d['error']}")
            continue
        if kind == "Namespace":
            namespaces.add(md.get("name"))
        if kind == "NetworkPolicy":
            sp = d.get("spec") or {}
            if sp.get("podSelector") in ({}, None) and "Ingress" in (sp.get("policyTypes") or []) and not sp.get("ingress"):
                denied.add(ns)
        if kind == "Secret" and not path.endswith(cfg.encrypted_suffix) and (d.get("data") or d.get("stringData")):
            errs.append(f"R5 {path}: Secret/{md.get('name')} holds data outside an encrypted file")
        if kind in ("Namespace", "PersistentVolumeClaim") and path.startswith(cfg.app_paths) and \
                (md.get("annotations") or {}).get(PRUNE_ANNOTATION) != "disabled":
            errs.append(f"R6 {path}: {kind}/{md.get('name')} is not protected from pruning ({PRUNE_ANNOTATION}: disabled)")
        if kind not in WORKLOADS:
            continue

        ps = pod_spec(d)
        name = f"{path}: {kind}/{md.get('name')} (ns={ns})"
        dormant = (d.get("spec") or {}).get("replicas") == 0
        before = len(errs)
        for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
            img = c.get("image", "")
            if ns not in cfg.digest_exempt_namespaces and "@sha256:" not in img:
                errs.append(f"R1 {name}: container {c.get('name')} image is not pinned by digest: {img}")
            if img.startswith(cfg.local_image_prefixes):
                errs.append(f"R2 {name}: container {c.get('name')} uses a local-only image: {img}")
        app = ((((d.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}).get("app")
        for c in ps.get("containers") or []:
            ok = "readinessProbe" in c and "memory" in ((c.get("resources") or {}).get("limits") or {})
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
        hit = next((x for x in cfg.exceptions if x.get("match") and x["match"] in e), None)
        if hit:
            used.add(hit["match"])
            warns.append(e + f" (known exception: {hit.get('reason')}; review by {hit.get('review_by')})")
        else:
            kept.append(e)
    for x in cfg.exceptions:
        if not x.get("reason") or not x.get("review_by"):
            kept.append(f"EX exception {x.get('match')!r} needs both reason and review_by")
        elif dt.date.fromisoformat(str(x["review_by"])) < today:
            kept.append(f"EX exception {x.get('match')!r} expired on {x['review_by']}: {x['reason']}")
        elif x.get("match") not in used:
            kept.append(f"EX exception {x.get('match')!r} no longer matches anything - remove it")
    return kept, warns


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="manifest-gate", description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    ap.add_argument("-c", "--config", default=None, help="config file (default: <root>/manifest-gate.yaml if present)")
    a = ap.parse_args(argv)
    cfg_path = a.config or os.path.join(a.root, "manifest-gate.yaml")
    errs, warns = check(a.root, Config.load(cfg_path))
    for w in warns:
        print("WARN", w)
    for e in errs:
        print("FAIL", e)
    print(f"checked: errors={len(errs)} warnings={len(warns)}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
