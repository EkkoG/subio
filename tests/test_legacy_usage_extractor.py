from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "extract_legacy_usage.py"
SCHEMA = REPO_ROOT / "schemas" / "subio-node-v2.schema.json"


def test_extractor_report_never_contains_source_values_or_custom_identifiers(tmp_path):
    source = tmp_path / "CANARY_PATH_NAME"
    source.mkdir()
    (source / "config.toml").write_text(
        """
[options]
personal_identifier = "CANARY_OPTION_VALUE"

[[provider]]
name = "CANARY_PROVIDER_NAME"
type = "mihomo"
url = "https://CANARY_HOST.example/CANARY_TOKEN"

[[artifact]]
name = "CANARY_ARTIFACT_NAME"
type = "mihomo"
providers = ["CANARY_PROVIDER_NAME"]
""".strip()
    )
    (source / "nodes.yaml").write_text(
        """
proxies:
  - name: CANARY_NODE_NAME
    type: ss
    server: CANARY_NODE_HOST.example
    port: 8388
    cipher: aes-256-gcm
    password: CANARY_PASSWORD
""".strip()
    )
    report = tmp_path / "report.json"

    extracted = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "extract",
            str(source),
            str(report),
            "--schema",
            str(SCHEMA),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    gated = subprocess.run(
        [sys.executable, str(SCRIPT), "gate", str(report)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert extracted.returncode == 0 and extracted.stdout.startswith("EXTRACT_OK")
    assert gated.returncode == 0 and gated.stdout.startswith("GATE_OK")
    serialized = json.dumps(json.loads(report.read_text()), sort_keys=True)
    for canary in (
        "CANARY_PATH_NAME",
        "CANARY_OPTION_VALUE",
        "personal_identifier",
        "CANARY_PROVIDER_NAME",
        "CANARY_HOST",
        "CANARY_TOKEN",
        "CANARY_ARTIFACT_NAME",
        "CANARY_NODE_NAME",
        "CANARY_NODE_HOST",
        "CANARY_PASSWORD",
    ):
        assert canary not in serialized
        assert canary not in extracted.stdout + extracted.stderr
        assert canary not in gated.stdout + gated.stderr

    tampered = json.loads(report.read_text())
    tampered["config_entries"][0]["fields"].append("personal_identifier:string")
    report.write_text(json.dumps(tampered))
    rejected = subprocess.run(
        [sys.executable, str(SCRIPT), "gate", str(report), "--show"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode == 3
    assert rejected.stdout == "GATE_FAIL\n"
    assert "personal_identifier" not in rejected.stdout + rejected.stderr


def test_extractor_refuses_symlink_output(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.toml").write_text(
        """
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"
""".strip()
    )
    victim = tmp_path / "victim.txt"
    victim.write_text("must-not-change")
    report = tmp_path / "report.json"
    report.symlink_to(victim)

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "extract",
            str(source),
            str(report),
            "--schema",
            str(SCHEMA),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == "EXTRACT_FAIL internal\n"
    assert victim.read_text() == "must-not-change"
    assert report.is_symlink()
