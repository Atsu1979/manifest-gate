"""Regression tests for inputs that used to crash the gate or let it pass silently."""
import pytest

from manifest_gate import __version__
from manifest_gate.check import Config, ConfigError, check, main
from test_check import GUARD, codes, deploy, ns, run


def write(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


# --- the gate must not run on a guess -----------------------------------------------------------

def test_explicit_config_that_does_not_exist_is_an_error(tmp_path, capsys):
    write(tmp_path, {"apps/web/ns.yaml": ns("web")})
    assert main([str(tmp_path), "-c", str(tmp_path / "typo.yaml")]) == 2
    assert "config file not found" in capsys.readouterr().err


def test_implicit_config_may_be_absent(tmp_path):
    write(tmp_path, {"apps/web/ns.yaml": ns("web")})
    assert main([str(tmp_path)]) == 0


def test_unknown_config_key_is_an_error(tmp_path, capsys):
    write(tmp_path, {"apps/web/ns.yaml": ns("web"), "manifest-gate.yaml": "health_namespace: [web]\n"})
    assert main([str(tmp_path)]) == 2
    assert "unknown key" in capsys.readouterr().err


@pytest.mark.parametrize("text, msg", [
    ("- just a list\n", "top level must be a mapping"),
    ("health_namespaces: web\n", "list of strings"),
    ("exceptions: [R4]\n", "list of mappings"),
    ("encrypted_suffix: ''\n", "non-empty string"),
    ("health_namespaces: [web\n", "cannot parse YAML"),
])
def test_malformed_config_is_an_error(tmp_path, text, msg):
    (tmp_path / "c.yaml").write_text(text)
    with pytest.raises(ConfigError, match=msg):
        Config.load(str(tmp_path / "c.yaml"))


def test_nonexistent_root_is_an_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_root_without_manifests_is_an_error(tmp_path, capsys):
    write(tmp_path, {"docs/notes.yaml": "title: not a manifest\n"})
    assert main([str(tmp_path)]) == 2
    assert "no Kubernetes manifests" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and __version__ in capsys.readouterr().out


# --- malformed manifests are reported, not crashed on --------------------------------------------

@pytest.mark.parametrize("text", [
    "apiVersion: v1\nkind: ConfigMap\nmetadata: oops\n",
    "apiVersion: v1\nkind: ConfigMap\n",
])
def test_metadata_must_be_a_mapping(tmp_path, text):
    errs, _ = run(tmp_path, {"apps/web/cm.yaml": text})
    assert any("no metadata mapping" in e for e in errs)


@pytest.mark.parametrize("spec", ["spec: []", "spec: {template: x}", "spec: {template: {spec: {containers: [x]}}}"])
def test_malformed_workload_spec_does_not_crash(tmp_path, spec):
    text = f"apiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: a, namespace: web}}\n{spec}\n"
    run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": text})


def test_non_utf8_file_is_reported(tmp_path):
    (tmp_path / "apps").mkdir()
    (tmp_path / "apps/bad.yaml").write_bytes(b"kind: \xff\xfe\n")
    errs, _ = check(str(tmp_path), Config())
    assert any("cannot parse" in e for e in errs)


# --- exceptions ---------------------------------------------------------------------------------

R4_NEW = f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: new, {GUARD}}}\n"


@pytest.mark.parametrize("review_by", ["soon", "2026-13-40", 20261231])
def test_invalid_review_by_fails_instead_of_crashing(tmp_path, review_by):
    cfg = Config(exceptions=[{"match": "R4 namespace new:", "reason": "x", "review_by": review_by}])
    errs, _ = run(tmp_path, {"apps/new/ns.yaml": R4_NEW}, cfg=cfg)
    assert any("invalid review_by" in e for e in errs)


def test_exception_without_match_fails(tmp_path):
    cfg = Config(exceptions=[{"reason": "x", "review_by": "2099-01-01"}])
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web")}, cfg=cfg)
    assert any("without a match" in e for e in errs)


def test_config_file_dates_round_trip(tmp_path):
    """YAML turns 2099-12-31 into a date object; that path must work end to end."""
    write(tmp_path, {"apps/new/ns.yaml": R4_NEW, "manifest-gate.yaml":
                     'exceptions:\n  - {match: "R4 namespace new:", reason: webhook, review_by: 2099-12-31}\n'})
    assert main([str(tmp_path)]) == 0


# --- rule accuracy ------------------------------------------------------------------------------

def test_networkpolicy_without_policytypes_is_default_deny(tmp_path):
    """Kubernetes defaults policyTypes to [Ingress]; such a policy must satisfy R4."""
    text = (f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: x, {GUARD}}}\n---\n"
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {name: deny, namespace: x}\nspec: {podSelector: {}}\n")
    errs, _ = run(tmp_path, {"apps/x/ns.yaml": text})
    assert errs == []


def test_networkpolicy_that_allows_ingress_is_not_default_deny(tmp_path):
    text = (f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: x, {GUARD}}}\n---\n"
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {name: allow, namespace: x}\nspec: {podSelector: {}, policyTypes: [Ingress], ingress: [{}]}\n")
    errs, _ = run(tmp_path, {"apps/x/ns.yaml": text})
    assert codes(errs) == {"R4"}


def test_egress_only_policy_is_not_default_deny_ingress(tmp_path):
    text = (f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: x, {GUARD}}}\n---\n"
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            "metadata: {name: eg, namespace: x}\nspec: {podSelector: {}, policyTypes: [Egress]}\n")
    errs, _ = run(tmp_path, {"apps/x/ns.yaml": text})
    assert codes(errs) == {"R4"}


CRONJOB = """\
apiVersion: batch/v1
kind: CronJob
metadata: {{name: w, namespace: web}}
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        metadata: {{labels: {{app: {app}}}}}
        spec:
          containers: [{{name: c, image: "{image}"}}]
"""
DIG = "busybox@sha256:" + "c" * 64


def test_health_exempt_app_applies_to_cronjob(tmp_path):
    cfg = Config(health_namespaces={"web"}, health_exempt_apps={"nightly-worker"})
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"),
                             "apps/web/cj.yaml": CRONJOB.format(app="nightly-worker", image=DIG)}, cfg=cfg)
    assert errs == []
    errs, _ = run(tmp_path, {"apps/web/cj.yaml": CRONJOB.format(app="other", image=DIG)}, cfg=cfg)
    assert codes(errs) == {"R3"}


def test_cronjob_and_init_container_images_are_checked(tmp_path):
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"),
                             "apps/web/cj.yaml": CRONJOB.format(app="a", image="busybox:latest")},
                  cfg=Config(health_namespaces=set()))
    assert codes(errs) == {"R1"}
    init_line = "      initContainers: [{name: i, image: 'localhost:5000/x:1'}]\n      containers:"
    init = deploy().replace("      containers:", init_line)
    errs, _ = run(tmp_path, {"apps/web/cj.yaml": CRONJOB.format(app="a", image=DIG), "apps/web/d.yaml": init},
                  cfg=Config(health_namespaces=set()))
    assert codes(errs) == {"R1", "R2"}


def test_health_exempt_app_applies_to_bare_pod(tmp_path):
    pod = ("apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: web, labels: {app: nightly-worker}}\n"
           f"spec: {{containers: [{{name: c, image: '{DIG}'}}]}}\n")
    cfg = Config(health_namespaces={"web"}, health_exempt_apps={"nightly-worker"})
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/p.yaml": pod}, cfg=cfg)
    assert errs == []


def test_digest_exempt_namespace_skips_r1_but_not_r2(tmp_path):
    text = deploy(ns="kube-system", image="localhost:5000/x:1")
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "infra/d.yaml": text})
    assert codes(errs) == {"R2"}


def test_skip_paths_and_hidden_dirs_are_ignored(tmp_path):
    bad = deploy(image="nginx:latest")
    errs, _ = run(tmp_path, {"apps/web/ns.yaml": ns("web"), "charts/x/d.yaml": bad, ".github/d.yaml": bad})
    assert errs == []


def test_stats_count_files_and_documents(tmp_path):
    stats = {}
    run(tmp_path, {"apps/web/ns.yaml": ns("web"), "apps/web/d.yaml": deploy(), "notes.yaml": "a: 1\n"})
    check(str(tmp_path), Config(), stats=stats)
    assert stats == {"files": 3, "documents": 3}


def test_module_entry_point(tmp_path):
    import subprocess
    import sys
    write(tmp_path, {"apps/web/ns.yaml": ns("web")})
    r = subprocess.run([sys.executable, "-m", "manifest_gate", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0 and "checked:" in r.stdout
