import json
import sys

from subio_v2.infrastructure.remote import RemoteFetchResult, RemoteMetadata
from subio_v2.main import main


def _write_config(tmp_path):
    (tmp_path / "nodes.yaml").write_text(
        "proxies:\n  - name: HK-1\n    type: ss\n    server: example.com\n"
        "    port: 8388\n    cipher: aes-256-gcm\n    password: secret\n"
    )
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["source"]
""".strip()
    )
    return config


def test_check_json_is_machine_readable_and_has_no_dist_side_effect(
    tmp_path, monkeypatch, capsys
):
    config = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "subio_v2.workflow.uploader.GistBatchUploader.begin",
        lambda _self: (_ for _ in ()).throw(AssertionError("check uploaded")),
    )
    monkeypatch.setattr(sys, "argv", ["subio", "check", str(config), "--format", "json"])

    assert main() == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "ok"
    assert report["summary"]["artifact_count"] == 1
    assert report["artifacts"][0]["supported_nodes"] == 1
    assert not (tmp_path / "dist").exists()
    assert "secret" not in captured.out + captured.err


def test_check_text_reports_dist_comparison(tmp_path, monkeypatch, capsys):
    config = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "out.yaml").write_text("old")
    monkeypatch.setattr(
        sys,
        "argv",
        ["subio", "check", str(config), "--compare-dist"],
    )

    assert main() == 0

    output = capsys.readouterr().out
    assert "artifact out.yaml:" in output
    assert "changed" in output


def test_check_json_missing_config_is_still_machine_readable(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["subio", "check", "missing.toml", "--format", "json"],
    )

    assert main() == 1

    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "error"
    assert report["error"] == "Config file not found"


def test_check_compare_dist_reports_manifest_orphans(tmp_path, monkeypatch, capsys):
    config = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / ".subio-manifest.json").write_text(
        json.dumps({"version": 1, "artifacts": {"old.yaml": {}}})
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "subio",
            "check",
            str(config),
            "--format",
            "json",
            "--compare-dist",
        ],
    )

    assert main() == 0

    report = json.loads(capsys.readouterr().out)
    assert report["orphan_files"] == ["old.yaml"]


def test_check_json_reports_stale_ruleset_from_real_prepare_path(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "nodes.yaml").write_text(
        "proxies:\n  - {name: direct, type: direct}\n"
    )
    (tmp_path / "template").mkdir()
    (tmp_path / "template" / "out.j2").write_text(
        '{{ remote_rules("DIRECT") }}'
    )
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"

[[ruleset]]
name = "rules"
url = "https://example.test/rules"

[[artifact]]
name = "out.yaml"
type = "mihomo"
providers = ["source"]
template = "out.j2"
""".strip()
    )

    def stale_fetch(loader, url, *, headers=None):
        loader.last_result = RemoteFetchResult(
            b"DOMAIN,example.com",
            RemoteMetadata(state="stale"),
        )
        return b"DOMAIN,example.com"

    monkeypatch.setattr("subio_v2.infrastructure.remote.RunRemoteLoader.fetch", stale_fetch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["subio", "check", str(config), "--format", "json"],
    )

    assert main() == 0

    report = json.loads(capsys.readouterr().out)
    assert report["rulesets"] == [
        {
            "name": "rules",
            "state": "stale",
            "etag": False,
            "last_modified": False,
            "content_length": None,
        }
    ]
    assert [issue["code"] for issue in report["issues"]] == [
        "remote.stale-cache"
    ]
