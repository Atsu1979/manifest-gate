"""The gate is itself tested: deliberately bad changes must fail, good ones must pass."""
import datetime as dt
import textwrap

from manifest_gate.check import Config, check, main

DIGEST = "nginx@sha256:" + "a" * 64
GUARD = "annotations: {kustomize.toolkit.fluxcd.io/prune: disabled}"


def ns(name, guarded=True):
    meta = f"{{name: {name}, {GUARD}}}" if guarded else f"{{name: {name}}}"
    return textwrap.dedent(f"""\
        apiVersion: v1
        kind: Namespace
        metadata: {meta}
        ---
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata: {{name: default-deny-ingress, namespace: {name}}}
        spec: {{podSelector: {{}}, policyTypes: [Ingress]}}
        """)


def deploy(ns="web", image=DIGEST, probe=True, mem=True, replicas=1):
    body = textwrap.dedent(f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata: {{name: app, namespace: {ns}}}
        spec:
          replicas: {replicas}
          selector: {{matchLabels: {{app: app}}}}
          template:
            metadata: {{labels: {{app: app}}}}
            spec:
              containers:
              - name: app
                image: {image}
        """)
    if probe:
        body += "        readinessProbe: {httpGet: {path: /, port: 80}}\n"
    if mem:
        body += "        resources: {limits: {memory: 128Mi}}\n"
    return body


def run(tmp_path, files, cfg=None, today=None):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return check(str(tmp_path), cfg or Config(health_namespaces={"web"}), today)


def codes(errs):
    return {e.split()[0] for e in errs}


def test_good_repo_passes(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy()})
    assert errs == []


def test_tag_instead_of_digest_fails(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy(image="nginx:1.27")})
    assert codes(errs) == {"R1"}


def test_local_only_image_fails(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"),
                             "apps/web/d.yaml": deploy(image="docker.io/local/x@sha256:" + "b" * 64)})
    assert codes(errs) == {"R2"}


def test_missing_probe_fails_only_in_covered_namespace(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy(probe=False)})
    assert codes(errs) == {"R3"}
    errs, warns = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy(probe=False)},
                      cfg=Config(health_namespaces={"other"}))
    assert errs == [] and any("not covered" in w for w in warns)


def test_dormant_violation_is_a_warning(tmp_path):
    errs, warns = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy(probe=False, replicas=0)})
    assert errs == [] and any("dormant" in w for w in warns)


def test_namespace_without_default_deny_fails(tmp_path):
    errs, _ = run(tmp_path, {"apps/new/ns.yaml": f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: new, {GUARD}}}\n"})
    assert codes(errs) == {"R4"}


def test_plaintext_secret_fails_encrypted_file_passes(tmp_path):
    sec = "apiVersion: v1\nkind: Secret\nmetadata: {name: s, namespace: web}\nstringData: {K: v}\n"
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/s.yaml": sec})
    assert codes(errs) == {"R5"}
    (tmp_path / "apps/web/s.yaml").rename(tmp_path / "apps/web/s.sops.yaml")
    errs, _ = run(tmp_path, {})
    assert errs == []


def test_namespace_and_pvc_need_prune_guard(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web", guarded=False)})
    assert codes(errs) == {"R6"}
    pvc = "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: d, namespace: web}\nspec: {}\n"
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/pvc.yaml": pvc})
    assert codes(errs) == {"R6"}


def test_exceptions_need_reason_expire_and_go_stale(tmp_path):
    files = {"apps/new/ns.yaml": f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: new, {GUARD}}}\n"}
    ok = Config(exceptions=[{"match": "R4 namespace new:", "reason": "webhook needs ingress", "review_by": "2099-01-01"}])
    errs, warns = run(tmp_path, files, cfg=ok)
    assert errs == [] and any("known exception" in w for w in warns)

    expired = Config(exceptions=[{"match": "R4 namespace new:", "reason": "x", "review_by": "2020-01-01"}])
    errs, _ = run(tmp_path, {}, cfg=expired)
    assert any("expired" in e for e in errs)

    no_reason = Config(exceptions=[{"match": "R4 namespace new:", "review_by": "2099-01-01"}])
    errs, _ = run(tmp_path, {}, cfg=no_reason)
    assert any("needs both" in e for e in errs)

    stale = Config(exceptions=[{"match": "R4 namespace gone:", "reason": "x", "review_by": "2099-01-01"}])
    errs, _ = run(tmp_path, {}, cfg=stale)
    assert any("no longer matches" in e for e in errs)


def test_unparseable_yaml_fails(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/bad.yaml": "kind: [unclosed\n"})
    assert any("cannot parse" in e for e in errs)


def test_cli_exit_codes_and_config_file(tmp_path, capsys):
    (tmp_path / "apps/web").mkdir(parents=True)
    (tmp_path / "apps/web/ns.yaml").write_text(ns("web"))
    (tmp_path / "apps/web/d.yaml").write_text(deploy(probe=False))
    (tmp_path / "manifest-gate.yaml").write_text("health_namespaces: [web]\n")
    assert main([str(tmp_path)]) == 1
    (tmp_path / "manifest-gate.yaml").write_text("health_namespaces: []\n")
    assert main([str(tmp_path)]) == 0
    assert "checked:" in capsys.readouterr().out


def test_today_is_injectable(tmp_path):
    files = {"apps/new/ns.yaml": f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: new, {GUARD}}}\n"}
    cfg = Config(exceptions=[{"match": "R4 namespace new:", "reason": "x", "review_by": "2026-12-31"}])
    assert run(tmp_path, files, cfg=cfg, today=dt.date(2026, 12, 1))[0] == []
    assert run(tmp_path, {}, cfg=cfg, today=dt.date(2027, 1, 1))[0] != []
