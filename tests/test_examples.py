"""The shipped examples are the gate's acceptance tests: the good repo passes, the bad one trips every rule."""
import os

from manifest_gate.check import main

HERE = os.path.dirname(__file__)
EXAMPLES = os.path.join(HERE, "..", "examples")


def test_good_example_passes(capsys):
    assert main([os.path.join(EXAMPLES, "repo"), "-c", os.path.join(EXAMPLES, "manifest-gate.yaml")]) == 0
    assert "errors=0" in capsys.readouterr().out


def test_bad_example_trips_every_rule(capsys):
    assert main([os.path.join(EXAMPLES, "bad-repo")]) == 1
    fails = [line.split()[1] for line in capsys.readouterr().out.splitlines() if line.startswith("FAIL")]
    assert set(fails) == {"R1", "R2", "R3", "R4", "R5", "R6"}


def test_pure_python_loader_gives_the_same_result(monkeypatch, capsys):
    """LOADER falls back to yaml.SafeLoader without libyaml; the verdict must not depend on it."""
    import yaml

    import manifest_gate.check as mg

    bad = os.path.join(EXAMPLES, "bad-repo")
    main([bad])
    fast = capsys.readouterr().out
    monkeypatch.setattr(mg, "LOADER", yaml.SafeLoader)
    main([bad])
    assert capsys.readouterr().out == fast
