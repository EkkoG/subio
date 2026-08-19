import sys

# Import the module under test
from subio_v2 import main as main_mod
from subio_v2.conversion import ConversionIssue, IssueSeverity
from subio_v2.errors import ArtifactGenerationError


def test_find_default_config_priority(tmp_path, monkeypatch):
    # create files in priority order, ensure first match returned
    monkeypatch.chdir(tmp_path)
    # Create lower priority file first
    (tmp_path / "config.yaml").write_text("key: value")
    # Higher priority .toml should be selected when present
    (tmp_path / "config.toml").write_text("a = 1")
    assert main_mod.find_default_config() == "config.toml"


def test_main_no_config_logs_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # capture logger.error calls
    messages = []

    class DummyLogger:
        def error(self, msg):
            messages.append(msg)

    monkeypatch.setattr(main_mod, "logger", DummyLogger())

    # Simulate "subio convert" with no config args
    monkeypatch.setattr(sys, "argv", ["prog", "convert"])
    # Replace WorkflowEngine to ensure not constructed
    constructed = []

    class DummyEngine:
        def __init__(self, *a, **kw):
            constructed.append((a, kw))

        def run(self):
            pass

    # Ensure import path points to our dummy when referenced inside module
    monkeypatch.setattr(main_mod, "WorkflowEngine", DummyEngine)

    # Run main
    assert main_mod.main() == 1

    # Assert error logged and engine not constructed
    assert any("Config file not found" in m for m in messages)
    assert constructed == []


def test_main_creates_dist_and_runs_engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Prepare a valid config file
    cfg = tmp_path / "config.toml"
    cfg.write_text("a = 1")

    # Track engine instantiation and run call
    calls = {"init": None, "ran": False}

    class DummyEngine:
        def __init__(self, config_path, dry_run=False, clean_gist=False):
            calls["init"] = {
                "config_path": config_path,
                "dry_run": dry_run,
                "clean_gist": clean_gist,
            }

        def run(self):
            calls["ran"] = True

    monkeypatch.setattr(main_mod, "WorkflowEngine", DummyEngine)

    # Simulate args with flags
    monkeypatch.setattr(
        sys, "argv", ["prog", "convert", str(cfg), "--dry-run", "--clean-gist"]
    )

    # Ensure dist doesn't exist initially
    assert not (tmp_path / "dist").exists()

    # Run main
    assert main_mod.main() == 0

    # WorkflowEngine creates dist when it commits generated artifacts.
    assert not (tmp_path / "dist").exists()
    # Engine should be constructed with proper args and run
    assert calls["init"] == {
        "config_path": str(cfg),
        "dry_run": True,
        "clean_gist": True,
    }
    assert calls["ran"] is True


def test_main_uses_default_config_when_arg_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.json").write_text('{"a":1}')

    used = {"config": None}

    class DummyEngine:
        def __init__(self, config_path, **_):
            used["config"] = config_path

        def run(self):
            pass

    monkeypatch.setattr(
        sys, "argv", ["prog", "convert", "--dry-run"]
    )  # no positional config
    monkeypatch.setattr(main_mod, "WorkflowEngine", DummyEngine)

    main_mod.main()
    assert used["config"] == "config.json"


def test_main_returns_nonzero_for_structured_conversion_failure(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("a = 1")
    messages = []

    class DummyLogger:
        def error(self, message):
            messages.append(message)

    issue = ConversionIssue(
        severity=IssueSeverity.ERROR,
        node="bad-node",
        protocol="hysteria2",
        source="provider-a",
        target="v2rayn",
        field="type",
        message="unsupported",
    )

    class FailingEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self):
            raise ArtifactGenerationError("conversion failed", issues=[issue])

    monkeypatch.setattr(main_mod, "logger", DummyLogger())
    monkeypatch.setattr(main_mod, "WorkflowEngine", FailingEngine)
    monkeypatch.setattr(sys, "argv", ["prog", "convert", str(cfg)])

    assert main_mod.main() == 1
    assert messages == ["conversion failed"]
