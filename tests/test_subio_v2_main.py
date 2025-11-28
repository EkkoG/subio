import os
import sys
import types
import builtins
from pathlib import Path
import pytest

# Import the module under test
from subio_v2 import main as main_mod


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

    # Simulate no args and no config files
    monkeypatch.setattr(sys, "argv", ["prog"])  # no config provided
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
    main_mod.main()

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
    monkeypatch.setattr(sys, "argv", ["prog", str(cfg), "--dry-run", "--clean-gist"])

    # Ensure dist doesn't exist initially
    assert not (tmp_path / "dist").exists()

    # Run main
    main_mod.main()

    # dist should be created
    assert (tmp_path / "dist").is_dir()
    # Engine should be constructed with proper args and run
    assert calls["init"] == {
        "config_path": str(cfg),
        "dry_run": True,
        "clean_gist": True,
    }
    assert calls["ran"] is True


def test_main_uses_default_config_when_arg_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.json").write_text("{\"a\":1}")

    used = {"config": None}
    class DummyEngine:
        def __init__(self, config_path, **_):
            used["config"] = config_path
        def run(self):
            pass
    monkeypatch.setattr(sys, "argv", ["prog", "--dry-run"])  # no positional config
    monkeypatch.setattr(main_mod, "WorkflowEngine", DummyEngine)

    main_mod.main()
    assert used["config"] == "config.json"
