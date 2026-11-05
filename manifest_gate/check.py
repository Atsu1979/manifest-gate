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

Evasion hardening (audit FP-1380):
  - `kind: List` / `*List` wrappers are flattened so nested objects are inspected.
  - `.json` manifests are scanned too (kustomize/kubectl accept them).
  - skip paths match on path boundaries, not as a free substring.
  - the config file is skipped only by its exact name, not any `manifest-gate*` file.
  - R5 verifies the content is actually SOPS-encrypted, not just the filename.
  - exceptions must name a rule code and match the start of a violation; parse errors
    and an unset namespace are never silently exempted; a bad review_by date fails cleanly.
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

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
PRUNE_ANNOTATION = "kustomize.toolkit.fluxcd.io/prune"
CONFIG_NAMES = {"manifest-gate.yaml", "manifest-gate.yml"}
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}(?![0-9a-f])")  # 正しい digest のみ（未アンカー部分一致を塞ぐ）
RULE_CODE = re.compile(r"^(R[1-6]|EX)\b")  # 例外で抑制してよいのは規則由来の違反だけ（parse error 等は対象外）


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


def _expand(d):
    """kind: List / *List の items[] を再帰的に平らにする。
    包むだけで全規則を外せる回避(FP-1380 F-1)を塞ぐ。"""
    if isinstance(d, dict) and isinstance(d.get("kind"), str) and d["kind"].endswith("List") \
            and isinstance(d.get("items"), list):
        for it in d["items"]:
            yield from _expand(it)
    elif isinstance(d, dict) and "kind" in d:
        yield d


def _skipped(rel: str, cfg: Config) -> bool:
    """skip_paths をパス境界で判定する（自由部分一致だと任意階層 charts/ 等に隠せる）。"""
    rel = rel.replace(os.sep, "/")
    base = os.path.basename(rel)
    if base in CONFIG_NAMES:  # 設定ファイルは完全一致でのみ除外（manifest-gate* 前方一致にしない）
        return True
    for s in cfg.skip_paths:
        seg = s.strip("/")
        if seg and (rel == seg or rel.startswith(seg + "/")):
            return True
    return False


def iter_docs(root: str, cfg: Config):
    paths = glob.glob(os.path.join(root, "**/*.y*ml"), recursive=True) \
        + glob.glob(os.path.join(root, "**/*.json"), recursive=True)
    for path in sorted(set(paths)):
        rel = os.path.relpath(path, root)
        if _skipped(rel, cfg):
            continue
        try:
            for raw in yaml.safe_load_all(open(path, encoding="utf-8")):  # YAML は JSON の上位集合
                for d in _expand(raw):
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


def _is_encrypted(d: dict) -> bool:
    """中身が実際に SOPS で暗号化されているか（ファイル名だけでは判断しない）。"""
    sops = d.get("sops")
    if isinstance(sops, dict) and sops.get("mac"):
        return True
    for fld in ("data", "stringData"):
        vals = d.get(fld)
        if isinstance(vals, dict) and vals and all(isinstance(v, str) and v.startswith("ENC[") for v in vals.values()):
            return True
    return False


def check(root: str, cfg: Config, today: dt.date | None = None) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    today = today or dt.date.today()
    errs: list[str] = []
    warns: list[str] = []
    namespaces: set[str] = set()
    denied: set[str] = set()

    for path, d in iter_docs(root, cfg):
        kind, md = d["kind"], d.get("metadata") or {}
        ns_declared = md.get("namespace")  # 無記載を default と同一視しない（免除の連鎖を断つ）
        ns = ns_declared or "default"
        if kind == "__parse_error__":
            errs.append(f"{path}: cannot parse YAML: {d['error']}")
            continue
        if kind == "Namespace":
            namespaces.add(md.get("name"))
        if kind == "NetworkPolicy":
            sp = d.get("spec") or {}
            if sp.get("podSelector") in ({}, None) and "Ingress" in (sp.get("policyTypes") or []) and not sp.get("ingress"):
                denied.add(ns)
        if kind == "Secret":
            has_data = bool(d.get("data") or d.get("stringData"))
            if has_data and not _is_encrypted(d):
                errs.append(f"R5 {path}: Secret/{md.get('name')} holds plaintext data (not SOPS-encrypted)")
            elif path.endswith(cfg.encrypted_suffix) and not _is_encrypted(d):
                errs.append(f"R5 {path}: Secret/{md.get('name')} is named as encrypted but is not SOPS-encrypted")
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
            if ns_declared not in cfg.digest_exempt_namespaces and not DIGEST.search(img):
                errs.append(f"R1 {name}: container {c.get('name')} image is not pinned by digest: {img}")
            if img.startswith(cfg.local_image_prefixes):
                errs.append(f"R2 {name}: container {c.get('name')} uses a local-only image: {img}")
        # R3 の免除は運用側キー(ns/name)で持つ。マニフェスト自身の label.app を信じると自己申告で外せる。
        wl_name = md.get("name")
        exempt_health = wl_name in cfg.health_exempt_apps or f"{ns}/{wl_name}" in cfg.health_exempt_apps
        for c in ps.get("containers") or []:
            ok = "readinessProbe" in c and "memory" in ((c.get("resources") or {}).get("limits") or {})
            if not ok and not exempt_health:
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
        # 例外抑制は規則由来の違反に限る＆match は規則コードで始まり違反行の先頭に一致すること。
        # これで『container app』のような自由部分一致での一括降格と、parse error の握り潰しを防ぐ。
        hit = None
        if RULE_CODE.match(e):
            hit = next((x for x in cfg.exceptions
                        if x.get("match") and RULE_CODE.match(str(x["match"])) and e.startswith(str(x["match"]))), None)
        if hit:
            used.add(hit["match"])
            warns.append(e + f" (known exception: {hit.get('reason')}; review by {hit.get('review_by')})")
        else:
            kept.append(e)
    for x in cfg.exceptions:
        if not x.get("reason") or not x.get("review_by"):
            kept.append(f"EX exception {x.get('match')!r} needs both reason and review_by")
            continue
        try:
            review_by = dt.date.fromisoformat(str(x["review_by"]))
        except ValueError:
            kept.append(f"EX exception {x.get('match')!r} has an invalid review_by: {x['review_by']!r}")
            continue
        if review_by < today:
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
