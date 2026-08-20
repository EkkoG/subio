from __future__ import annotations

import base64
import shutil
import stat
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "structure_simplification"


def _run_fixture(project: Path) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("subio")
    assert executable is not None, "the installed console script must be on PATH"
    return subprocess.run(
        [executable, "convert", "config.toml", "--dry-run"],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_structure_simplification_external_contract_fixture(tmp_path: Path):
    project = tmp_path / "fixture"
    shutil.copytree(FIXTURE, project)

    completed = _run_fixture(project)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "[Dry-run] Would upload 1 file(s) to Gist fixture-gist" in (
        completed.stdout + completed.stderr
    )
    assert "Protocol 'vless' is not supported by surge" in (
        completed.stdout + completed.stderr
    )
    assert "Legacy SubIO" not in (completed.stdout + completed.stderr)

    dist = project / "dist"
    assert {
        path.name
        for path in dist.iterdir()
        if path.is_file()
    } == {
        "mihomo.yaml",
        "stash.yaml",
        "surge.conf",
        "dae.txt",
        "v2rayn.txt",
        "user-alice.yaml",
        "user-bob.yaml",
    }
    assert not list(dist.glob(".*.tmp"))
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in dist.iterdir())

    mihomo = yaml.safe_load((dist / "mihomo.yaml").read_text())
    mihomo_by_name = {proxy["name"]: proxy for proxy in mihomo["proxies"]}
    assert set(mihomo_by_name) == {"ss-main", "vmess-main", "vless-main"}
    groups = {group["name"]: group for group in mihomo["proxy-groups"]}
    assert groups["All"]["proxies"] == ["ss-main", "vmess-main", "vless-main"]
    assert groups["Shadowsocks"]["proxies"] == ["ss-main"]
    assert mihomo["rules"] == [
        "DOMAIN-SUFFIX,example.test,DIRECT",
        "MATCH,All",
    ]

    stash = yaml.safe_load((dist / "stash.yaml").read_text())
    assert {proxy["name"] for proxy in stash["proxies"]} == set(mihomo_by_name)

    surge_text = (dist / "surge.conf").read_text()
    assert "ss-main =" in surge_text
    assert "vmess-main =" in surge_text
    assert "wg-main =" in surge_text
    assert "vless-main =" not in surge_text
    assert "[WireGuard fixture-wg]" in surge_text

    dae_lines = (dist / "dae.txt").read_text().splitlines()
    assert len(dae_lines) == 3
    assert {
        line.partition("': '")[2].partition("://")[0]
        for line in dae_lines
    } == {
        "ss",
        "vmess",
        "vless",
    }

    v2rayn_lines = base64.b64decode((dist / "v2rayn.txt").read_text()).decode().splitlines()
    assert len(v2rayn_lines) == 3
    assert {line.split(":", 1)[0] for line in v2rayn_lines} == {
        "ss",
        "vmess",
        "vless",
    }

    alice = yaml.safe_load((dist / "user-alice.yaml").read_text())
    bob = yaml.safe_load((dist / "user-bob.yaml").read_text())
    assert alice["proxies"][0]["password"] == "alice-example-password"
    assert bob["proxies"][0]["password"] == "bob-example-password"


def test_structure_simplification_fixture_rejects_subio_v1_without_fallback(
    tmp_path: Path,
):
    project = tmp_path / "fixture"
    shutil.copytree(FIXTURE, project)
    (project / "nodes.yaml").write_text(
        """
proxies:
  - name: old
    type: ss
    server: old.example.test
    port: 8388
    cipher: aes-256-gcm
    password: old-password
""".strip()
    )

    completed = _run_fixture(project)

    assert completed.returncode == 1
    output = completed.stdout + completed.stderr
    assert "Legacy SubIO 'proxies' syntax is no longer supported" in output
    assert not (project / "dist").exists()
