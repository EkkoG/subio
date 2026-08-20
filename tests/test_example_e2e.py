from __future__ import annotations

import base64
import shutil
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import toml
import yaml

from subio_v2.infrastructure import age
from subio_v2.parser.surge import SurgeParser

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "example"


def run_subio(
    project: Path,
    config: str = "config.toml",
    executable_name: str = "subio",
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(executable_name)
    assert executable is not None, "the installed console script must be on PATH"
    return subprocess.run(
        [executable, "convert", config, "--dry-run"],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_offline_example_cli_end_to_end(tmp_path):
    project = tmp_path / "example"
    shutil.copytree(EXAMPLE_DIR, project)

    completed = run_subio(project)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    dist = project / "dist"
    expected = {
        "dae-subscription.txt",
        "dae.conf",
        "mihomo.yaml",
        "raw-mihomo.yaml",
        "single-user.yaml",
        "stash.yaml",
        "surge.conf",
        "user-alice.yaml",
        "user-bob.yaml",
        "v2rayn.txt",
    }
    assert {path.name for path in dist.iterdir()} == expected
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in dist.iterdir())
    assert not list(dist.glob(".*.tmp"))

    mihomo = yaml.safe_load((dist / "mihomo.yaml").read_text())
    mihomo_by_name = {proxy["name"]: proxy for proxy in mihomo["proxies"]}
    assert len(mihomo_by_name) == 11
    assert mihomo_by_name["via-hop-ss"]["dialer-proxy"] == "portable-ss"
    assert not any(name.startswith("native-disabled-") for name in mihomo_by_name)
    assert {group["name"] for group in mihomo["proxy-groups"]} == {
        "Composed",
        "Example",
        "WithoutHTTP",
        "Work",
    }
    assert any(rule.startswith("AND,") for rule in mihomo["rules"])
    assert mihomo["rules"][-1] == "MATCH,Example"

    raw_mihomo = yaml.safe_load((dist / "raw-mihomo.yaml").read_text())
    assert {proxy["name"] for proxy in raw_mihomo["proxies"]} == {
        "modern-anytls",
        "modern-hysteria",
        "modern-ss-uot",
        "modern-tailscale",
        "modern-vless-grpc",
        "modern-vless-reality",
        "modern-vless-ws",
    }
    assert {proxy["type"] for proxy in raw_mihomo["proxies"]} == {
        "anytls",
        "hysteria",
        "ss",
        "tailscale",
        "vless",
    }
    raw_by_name = {proxy["name"]: proxy for proxy in raw_mihomo["proxies"]}
    assert raw_by_name["modern-ss-uot"]["udp-over-tcp-version"] == 2
    assert raw_by_name["modern-vless-ws"]["ws-opts"] == {
        "path": "/example",
        "headers": {"Host": "vless-ws.example.test"},
    }
    assert raw_by_name["modern-vless-grpc"]["grpc-opts"] == {
        "grpc-service-name": "example"
    }
    assert raw_by_name["modern-vless-reality"]["reality-opts"] == {
        "public-key": "example-public-key",
        "short-id": "abcd",
    }
    assert raw_by_name["modern-hysteria"]["auth-str"] == "example-auth"
    assert raw_by_name["modern-hysteria"]["up"] == "10 Mbps"
    assert raw_by_name["modern-tailscale"]["ephemeral"] is True

    stash = yaml.safe_load((dist / "stash.yaml").read_text())
    stash_by_name = {proxy["name"]: proxy for proxy in stash["proxies"]}
    assert set(stash_by_name) == {
        "portable-http",
        "portable-socks5",
        "portable-ss",
        "portable-trojan",
        "portable-vmess",
        "stash-anytls",
        "stash-direct",
        "stash-ss",
        "stash-vless",
    }
    assert stash_by_name["stash-ss"]["plugin"] == "shadow-tls"
    assert stash_by_name["stash-vless"]["network"] == "xhttp"

    surge_text = (dist / "surge.conf").read_text()
    surge_result = SurgeParser(source_kind="local").parse_result(surge_text)
    assert surge_result.issues == []
    assert {node.name for node in surge_result.nodes} == {
        "portable-http",
        "portable-socks5",
        "portable-ss",
        "portable-trojan",
        "portable-vmess",
        "surge-anytls",
        "surge-direct",
        "surge-http",
        "surge-socks",
        "surge-ss",
        "surge-ssh",
        "surge-trojan",
        "surge-vmess",
        "surge-wg",
    }
    assert "DEST-PORT,443,DIRECT" in surge_text
    assert "FINAL,PROXY" in surge_text
    assert "[Keystore]" in surge_text
    assert "[WireGuard ExampleWG]" in surge_text

    dae = (dist / "dae.conf").read_text()
    assert "via-hop-ss" in dae
    assert " -> " in dae
    assert "fallback: example" in dae
    dae_subscription = (dist / "dae-subscription.txt").read_text().splitlines()
    assert len(dae_subscription) == 6
    assert any(" -> " in line for line in dae_subscription)

    v2rayn_lines = (
        base64.b64decode((dist / "v2rayn.txt").read_text()).decode().splitlines()
    )
    assert len(v2rayn_lines) == 6
    assert {line.split(":", 1)[0] for line in v2rayn_lines} == {
        "socks5",
        "ss",
        "trojan",
        "vmess",
    }

    alice = yaml.safe_load((dist / "user-alice.yaml").read_text())
    bob = yaml.safe_load((dist / "user-bob.yaml").read_text())
    alice_by_name = {proxy["name"]: proxy for proxy in alice["proxies"]}
    bob_by_name = {proxy["name"]: proxy for proxy in bob["proxies"]}
    assert alice_by_name["user-hk"]["password"] == "alice-example-password"
    assert bob_by_name["user-hk"]["password"] == "bob-example-password"
    assert "user-jp" in alice_by_name and "user-jp" not in bob_by_name
    assert {group["name"] for group in bob["proxy-groups"]} == {"Example"}

    single_user = yaml.safe_load((dist / "single-user.yaml").read_text())
    assert [proxy["name"] for proxy in single_user["proxies"]] == [
        "user-hk",
        "user-jp",
        "shared-trojan",
    ]
    alias_project = tmp_path / "alias-example"
    shutil.copytree(EXAMPLE_DIR, alias_project)
    alias_run = run_subio(alias_project, executable_name="subio2")
    assert alias_run.returncode == 0, alias_run.stdout + alias_run.stderr
    assert {path.name for path in (alias_project / "dist").iterdir()} == expected


def test_cli_failure_preserves_existing_dist(tmp_path):
    (tmp_path / "nodes.yaml").write_text(
        """
proxies:
  - name: unsupported
    type: hysteria2
    server: failure.example.test
    port: 443
    password: example-password
""".strip()
    )
    (tmp_path / "config.toml").write_text(
        """
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"

[[artifact]]
name = "existing.txt"
type = "v2rayn"
providers = ["source"]
""".strip()
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    existing = dist / "existing.txt"
    existing.write_text("previous-content")
    stable = dist / "stable.txt"
    stable.write_text("stable-content")

    completed = run_subio(tmp_path)

    assert completed.returncode == 1
    assert existing.read_text() == "previous-content"
    assert stable.read_text() == "stable-content"
    assert {path.name for path in dist.iterdir()} == {"existing.txt", "stable.txt"}
    assert not list(dist.glob(".*.tmp"))


def test_remote_ruleset_and_age_round_trip_end_to_end(tmp_path):
    secret_key, public_key = age.generate_x25519_keypair()
    provider_plaintext = b"""proxies:
  - name: remote-ss
    type: ss
    server: remote.example.test
    port: 8388
    cipher: aes-256-gcm
    password: example-password
"""
    payloads = {
        "/provider.age": age.encrypt_bytes(provider_plaintext, public_key),
        "/surge.conf": b"""[Proxy]
surge-ss = ss, remote-surge.example.test, 8388, encrypt-method=aes-256-gcm, password=example-password
""",
        "/rules.list": b"DOMAIN-SUFFIX,remote.example.test\nDST-PORT,443\nMATCH\n",
        "/surge-rules.list": (
            b"DOMAIN-SUFFIX,remote-surge.example.test\nDEST-PORT,8443\n"
        ),
    }
    requests: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("User-Agent")))
            body = payloads.get(self.path)
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        (tmp_path / "template").mkdir()
        (tmp_path / "template" / "remote.yaml").write_text(
            """proxies:
{{ proxies }}
rules:
{{ remote_rules("DIRECT") }}
{{ remote_legacy("DIRECT") }}
{{ remote_surge_rules("DIRECT") }}
"""
        )
        (tmp_path / "template" / "remote-surge.conf").write_text(
            """[Proxy]
{{ proxies }}
[Proxy Group]
{{ proxies_names }}
[Rule]
{{ remote_surge_rules("DIRECT") }}
"""
        )
        (tmp_path / "config.toml").write_text(
            f"""
[[uploader]]
name = "example-gist"
type = "gist"
token = "ENV_SUBIO_EXAMPLE_GIST_TOKEN"
id = "example-gist"

[[provider]]
name = "remote-mihomo"
type = "mihomo"
url = "http://127.0.0.1:{port}/provider.age"
user_agent = "SubIO-E2E/1.0"
age_secret_key = "{secret_key}"
[provider.rename]
add_prefix = "downloaded-"

[[provider]]
name = "remote-surge"
type = "surge"
url = "http://127.0.0.1:{port}/surge.conf"
user_agent = "SubIO-E2E/1.0"
[provider.rename]
add_prefix = "remote-"
replace = [{{ old = "surge", new = "edge" }}]

[[ruleset]]
name = "rules"
url = "http://127.0.0.1:{port}/rules.list"
type = "mihomo"
behavior = "classical"
format = "text"

[[ruleset]]
name = "legacy"
url = "http://127.0.0.1:{port}/rules.list"

[[ruleset]]
name = "surge_rules"
url = "http://127.0.0.1:{port}/surge-rules.list"
type = "surge"
behavior = "classical"
format = "text"

[[artifact]]
name = "remote-mihomo.age"
type = "mihomo"
template = "remote.yaml"
providers = ["remote-mihomo"]
age_public_key = "{public_key}"
[[artifact.upload]]
to = "example-gist"
[[artifact.upload]]
to = "example-gist"
file_name = "remote-mihomo-mirror.age"

[[artifact]]
name = "remote-surge.conf"
type = "surge"
template = "remote-surge.conf"
providers = ["remote-surge"]
""".strip()
        )

        completed = run_subio(tmp_path)

        assert completed.returncode == 0, completed.stdout + completed.stderr
        encrypted = (tmp_path / "dist" / "remote-mihomo.age").read_bytes()
        assert age.is_age_encrypted(encrypted)
        rendered = yaml.safe_load(age.decrypt_bytes(encrypted, secret_key))
        assert [proxy["name"] for proxy in rendered["proxies"]] == [
            "downloaded-remote-ss"
        ]
        assert rendered["rules"] == [
            "DOMAIN-SUFFIX,remote.example.test,DIRECT",
            "DST-PORT,443,DIRECT",
            "MATCH,DIRECT",
            "DOMAIN-SUFFIX,remote.example.test,DIRECT",
            "DST-PORT,443,DIRECT",
            "MATCH,DIRECT",
            "DOMAIN-SUFFIX,remote-surge.example.test,DIRECT",
            "DST-PORT,8443,DIRECT",
        ]
        assert ("/provider.age", "SubIO-E2E/1.0") in requests
        assert ("/surge.conf", "SubIO-E2E/1.0") in requests
        assert sum(path == "/rules.list" for path, _ in requests) == 1
        surge_output = (tmp_path / "dist" / "remote-surge.conf").read_text()
        assert "remote-edge-ss = ss" in surge_output
        assert "DEST-PORT,8443,DIRECT" in surge_output
        assert "Would upload 2 file(s)" in completed.stdout
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_example_configs_are_offline_by_default_and_do_not_commit_keys():
    config = toml.loads((EXAMPLE_DIR / "config.toml").read_text())
    assert "allow_conversion_errors" not in config
    assert "ruleset" not in config
    assert all(
        "file" in provider and "url" not in provider for provider in config["provider"]
    )

    advanced = toml.loads((EXAMPLE_DIR / "config.remote.toml").read_text())
    assert all(
        provider["url"].startswith("http://127.0.0.1:")
        for provider in advanced["provider"]
    )
    assert all(
        ruleset["url"].startswith("http://127.0.0.1:")
        for ruleset in advanced["ruleset"]
    )

    forbidden = (
        "AGE-SECRET-KEY-1",
        "BEGIN OPENSSH PRIVATE KEY",
        "gist.github.com/",
        "raw.githubusercontent.com/",
    )
    checked_paths = [
        EXAMPLE_DIR / "config.toml",
        EXAMPLE_DIR / "config.remote.toml",
        EXAMPLE_DIR / "snippet" / "workflow_rules",
        *(EXAMPLE_DIR / "provider").iterdir(),
        *(EXAMPLE_DIR / "template").iterdir(),
    ]
    for path in checked_paths:
        text = path.read_text(errors="ignore")
        assert not any(value in text for value in forbidden), path
