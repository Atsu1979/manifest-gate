"""ゲート回避の回帰テスト（監査 FP-1380 / 2026-11-06）。

各テストは『素の違反は検知』『回避版も検知（＝穴が塞がった）』を対で確認する。
"""
import datetime as dt
import os

import pytest

from manifest_gate.check import Config, check

TODAY = dt.date(2026, 1, 1)

PLAIN_SECRET = """apiVersion: v1
kind: Secret
metadata: {name: db, namespace: web}
stringData: {password: hunter2}
"""
UNPINNED = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: web}
spec:
  template:
    spec:
      containers: [{name: app, image: myrepo/app:latest}]
"""


def run(tmp_path, files, cfg=None):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return check(str(tmp_path), cfg or Config(), today=TODAY)


def _r5(errs):
    return [e for e in errs if e.startswith("R5")]


# ---- F-1: kind: List 包みを flatten して内側を検査 ----
def test_f1_list_wrapper_flattened(tmp_path):
    assert _r5(run(tmp_path, {"apps/web/s.yaml": PLAIN_SECRET})[0])  # 素は検知（前提）


def test_f1_list_wrapped_secret_caught(tmp_path):
    wrapped = ("apiVersion: v1\nkind: List\nitems:\n"
               "- apiVersion: v1\n  kind: Secret\n  metadata: {name: db, namespace: web}\n"
               "  stringData: {password: hunter2}\n")
    assert _r5(run(tmp_path, {"apps/web/bundle.yaml": wrapped})[0]), "List 包みの平文Secretを取りこぼし"


def test_f1_secretlist_kind_flattened(tmp_path):
    sl = ("apiVersion: v1\nkind: SecretList\nitems:\n"
          "- apiVersion: v1\n  kind: Secret\n  metadata: {name: db, namespace: web}\n"
          "  data: {p: cGxhaW4=}\n")
    assert _r5(run(tmp_path, {"apps/web/sl.yaml": sl})[0]), "*List kind を flatten できていない"


# ---- F-2: 設定ファイルは完全一致でのみ除外（manifest-gate* で隠せない）----
def test_f2_manifest_gate_prefixed_file_still_scanned(tmp_path):
    assert _r5(run(tmp_path, {"apps/manifest-gate-secret.yaml": PLAIN_SECRET})[0]), \
        "manifest-gate* 命名でファイルごと隠蔽できる"


def test_f2_real_config_still_skipped(tmp_path):
    # ルート直下の設定ファイル名は従来どおり除外（自己走査しない）
    errs, _ = run(tmp_path, {"manifest-gate.yaml": "health_namespaces: [web]\n"})
    assert errs == []


# ---- F-3: skip はパス境界で判定（任意階層 charts/ に隠せない）----
def test_f3_nested_charts_not_skipped(tmp_path):
    assert _r5(run(tmp_path, {"apps/web/charts/s.yaml": PLAIN_SECRET})[0]), \
        "入れ子の charts/ 配下に隠蔽できる"


# ---- F-4: R5 は中身の暗号化を検証（偽 .sops.yaml 名で逃げられない）----
def test_f4_fake_sops_name_caught(tmp_path):
    assert _r5(run(tmp_path, {"apps/web/db.sops.yaml": PLAIN_SECRET})[0]), \
        "偽 .sops.yaml 名の平文Secretを取りこぼし"


def test_f4_real_sops_passes(tmp_path):
    enc = ("apiVersion: v1\nkind: Secret\nmetadata: {name: db, namespace: web}\n"
           "data: {password: 'ENC[AES256_GCM,data:abc,iv:x,tag:y,type:str]'}\n"
           "sops: {mac: 'ENC[AES256_GCM,data:zzz]'}\n")
    assert _r5(run(tmp_path, {"apps/web/db.sops.yaml": enc})[0]) == [], "本物の暗号化Secretを誤検知"


# ---- F-5: 例外は規則コード先頭一致に限定（自由部分一致で一括降格できない）----
def test_f5_broad_substring_exception_ignored(tmp_path):
    cfg = Config()
    cfg.exceptions = [{"match": "container app", "reason": "x", "review_by": "2099-01-01"}]
    errs, _ = run(tmp_path, {"apps/web/app.yaml": UNPINNED}, cfg)
    assert any(e.startswith("R1") for e in errs), "規則コードを含まない広い match で R1 を抑制できる"


def test_f5_specific_exception_still_works(tmp_path):
    cfg = Config()
    cfg.exceptions = [{"match": "R1 apps/web/app.yaml: Deployment/web",
                       "reason": "legacy", "review_by": "2099-01-01"}]
    errs, warns = run(tmp_path, {"apps/web/app.yaml": UNPINNED}, cfg)
    assert not any(e.startswith("R1") for e in errs)       # 具体的な例外は従来どおり降格
    assert any("known exception" in w for w in warns)


# ---- F-6: .json マニフェストも走査 ----
def test_f6_json_manifest_scanned(tmp_path):
    sj = '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"web"},"stringData":{"p":"hunter2"}}'
    assert _r5(run(tmp_path, {"apps/web/s.json": sj})[0]), ".json マニフェストが未走査"


# ---- F-7: namespace 無記載を免除扱いにしない ----
def test_f7_unset_namespace_not_exempt(tmp_path):
    nons = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n"
            "spec:\n  template:\n    spec:\n      containers: [{name: app, image: myrepo/app:latest}]\n")
    errs, _ = run(tmp_path, {"apps/web/app.yaml": nons})
    assert any(e.startswith("R1") for e in errs), "namespace 省略→default 免除で R1 回避"


# ---- F-8: parse error は例外で握り潰せない ----
def test_f8_parse_error_not_suppressible(tmp_path):
    cfg = Config()
    cfg.exceptions = [{"match": "cannot parse YAML", "reason": "x", "review_by": "2099-01-01"}]
    errs, _ = run(tmp_path, {"apps/x.yaml": "a: : : [\n"}, cfg)
    assert any("cannot parse YAML" in e for e in errs), "parse error を例外で握り潰せる"


# ---- F-9: R3 免除はラベル自己申告で外せない ----
def test_f9_r3_label_spoof_blocked(tmp_path):
    cfg = Config()
    cfg.health_namespaces = {"web"}
    cfg.health_exempt_apps = {"nightly-worker"}
    spoof = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: web}\n"
             "spec:\n  template:\n    metadata: {labels: {app: nightly-worker}}\n"
             "    spec:\n      containers: [{name: app, image: r@sha256:%s}]\n" % ("a" * 64))
    errs, _ = run(tmp_path, {"apps/web/app.yaml": spoof}, cfg)
    assert any(e.startswith("R3") for e in errs), "label.app の自己申告で R3 免除を奪える"


# ---- F-11: 不正 review_by で gate がクラッシュしない ----
def test_f11_invalid_review_by_no_crash(tmp_path):
    cfg = Config()
    cfg.exceptions = [{"match": "R5 x", "reason": "x", "review_by": "soon"}]
    errs, _ = run(tmp_path, {"apps/web/s.yaml": PLAIN_SECRET}, cfg)  # 例外送出せず
    assert any("invalid review_by" in e for e in errs)


# ---- F-12: @sha256 は正しい digest のみ pinned 扱い ----
def test_f12_malformed_digest_not_pinned(tmp_path):
    bad = ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: web}\n"
           "spec:\n  template:\n    spec:\n      containers: [{name: app, image: 'nginx:latest@sha256:deadbeef'}]\n")
    errs, _ = run(tmp_path, {"apps/web/app.yaml": bad})
    assert any(e.startswith("R1") for e in errs), "短い/不正な digest を pinned と誤認"
