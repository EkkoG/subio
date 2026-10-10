import json
from pathlib import Path

import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.singbox.emitter import SingBoxEmitter
from subio_v2.core.errors import ArtifactGenerationError, TemplateRenderError
from subio_v2.core.nodes import (
    MieruNode,
    MieruTransport,
    OpenVPNNode,
    ShadowsocksNode,
)
from subio_v2.workflow.config import ArtifactConfig, ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine


def _write(path: Path, content: str) -> Path:
    path.write_text(content.strip() + "\n")
    return path


def _mixed_nodes(*, detour: str = "edge") -> str:
    return f"""
proxies:
  - name: edge
    type: ss
    server: edge.example.com
    port: 8388
    cipher: aes-256-gcm
    password: outbound-secret
  - name: vpn
    type: openvpn
    server: vpn.example.com
    port: 1194
    ca: ca-secret
    username: alice
    password: endpoint-secret
    dialer-proxy: {detour}
"""


def _workflow_config(*, provider_options: str = "", artifact_options: str = "") -> str:
    return f"""
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"
{provider_options}

[[artifact]]
name = "client.json"
type = "sing-box"
providers = ["source"]
{artifact_options}
"""


def test_singbox_artifact_emits_mixed_outbounds_and_endpoints_json(
    tmp_path, monkeypatch
):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(config_path), dry_run=True).run()

    assert result.errors == []
    assert result.generated == ["client.json"]
    raw_content = (tmp_path / "dist/client.json").read_text()
    content = json.loads(raw_content)
    assert [item["tag"] for item in content["outbounds"]] == ["edge"]
    assert [item["tag"] for item in content["endpoints"]] == ["vpn"]
    assert content["endpoints"][0]["detour"] == "edge"
    assert content["outbounds"][0]["type"] == "shadowsocks"
    assert content["endpoints"][0]["type"] == "openvpn-client"

    parser = get_parser("sing-box")
    assert parser is not None
    parsed = parser.parse_result(raw_content)
    assert parsed.issues == []
    assert [node.name for node in parsed.nodes] == ["edge", "vpn"]
    assert parsed.nodes[1].dialer_proxy == "edge"


def test_singbox_artifact_config_is_typed_and_supports_json_templates(tmp_path, monkeypatch):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )

    config = ConfigLoader.load(str(config_path))

    assert isinstance(config.artifacts[0], ArtifactConfig)
    assert config.artifacts[0].artifact_type == "sing-box"
    assert isinstance(get_emitter("sing-box"), SingBoxEmitter)

    _write(
        tmp_path / "client.json.j2",
        """
{
  "log": {"level": "info"},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
  "outbounds": {{ nodes.outbounds() }},
  "endpoints": {{ nodes.endpoints() }},
  "route": {"final": "edge"}
}
""",
    )
    template_config = _write(
        tmp_path / "template.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    assert ConfigLoader.load(str(template_config)).artifacts[0].template == "client.json.j2"
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(template_config), dry_run=True).run()

    assert result.errors == []
    content = json.loads((tmp_path / "dist/client.json").read_text())
    assert content["log"] == {"level": "info"}
    assert [item["tag"] for item in content["outbounds"]] == ["edge"]
    assert [item["tag"] for item in content["endpoints"]] == ["vpn"]
    assert content["inbounds"][0]["type"] == "mixed"
    assert content["route"]["final"] == "edge"


@pytest.mark.parametrize("template", ['{"outbounds": ', '[1, 2]'])
def test_singbox_template_must_render_a_json_object_before_publish(
    tmp_path, monkeypatch, template
):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    _write(tmp_path / "client.json.j2", template)
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(TemplateRenderError, match="sing-box template"):
        WorkflowEngine(str(config_path), dry_run=True).run()

    assert not (tmp_path / "dist").exists()


def test_singbox_template_can_combine_nodes_and_converted_rules(
    tmp_path, monkeypatch
):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    snippets = tmp_path / "snippet"
    snippets.mkdir()
    _write(
        snippets / "route_rules",
        """
edge, fallback
DOMAIN-SUFFIX,example.test,{{ edge }}
DST-PORT,443,{{ fallback }}
MATCH,{{ fallback }}
""",
    )
    _write(
        tmp_path / "client.json.j2",
        """
{
  "log": {"level": "info"},
  "outbounds": {{ nodes.outbounds() }},
  "endpoints": {{ nodes.endpoints() }},
  "route": {
    "rules": {{ route_rules("edge", "edge") }},
    "final": "edge"
  }
}
""",
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(config_path), dry_run=True).run()

    assert result.errors == []
    content = json.loads((tmp_path / "dist/client.json").read_text())
    assert [item["tag"] for item in content["outbounds"]] == ["edge"]
    assert [item["tag"] for item in content["endpoints"]] == ["vpn"]
    assert content["route"]["rules"] == [
        {
            "domain_suffix": "example.test",
            "action": "route",
            "outbound": "edge",
        },
        {"port": 443, "action": "route", "outbound": "edge"},
        {"action": "route", "outbound": "edge"},
    ]


def test_singbox_template_blocks_publish_for_unsupported_converted_rule(
    tmp_path, monkeypatch
):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    snippets = tmp_path / "snippet"
    snippets.mkdir()
    _write(
        snippets / "route_rules",
        """
proxy
IP-CIDR,192.0.2.0/24,{{ proxy }},no-resolve
""",
    )
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, '
        '"route": {"rules": {{ route_rules("edge") }}}}',
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(config_path), dry_run=True).run()

    assert [issue.code for issue in exc_info.value.issues] == [
        "ruleset.unsupported-target-option"
    ]
    assert not (tmp_path / "dist").exists()


def test_singbox_emitter_rejects_duplicate_and_empty_tags_without_secret_leaks():
    duplicate_outbound = ShadowsocksNode(
        name="shared",
        server="edge.example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="outbound-secret",
    )
    duplicate_endpoint = OpenVPNNode(
        name="shared",
        server="vpn.example.com",
        port=1194,
        ca="ca-secret",
        username="alice",
        password="endpoint-secret",
    )
    empty_tag = ShadowsocksNode(
        name="",
        server="empty.example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="empty-secret",
    )

    emission = SingBoxEmitter().emit_result(
        [duplicate_outbound, duplicate_endpoint, empty_tag]
    )

    assert [item["tag"] for item in emission.content["outbounds"]] == ["shared"]
    assert emission.content["endpoints"] == []
    assert {issue.code for issue in emission.errors} >= {
        "conversion.duplicate-node-name"
    }
    assert any(issue.field == "name" for issue in emission.errors)
    assert "outbound-secret" not in repr(emission.issues)
    assert "endpoint-secret" not in repr(emission.issues)
    assert "empty-secret" not in repr(emission.issues)
    assert "ca-secret" not in repr(emission.issues)


def test_singbox_emitter_counts_duplicate_object_occurrences_independently():
    node = ShadowsocksNode(
        name="shared",
        server="edge.example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="outbound-secret",
    )

    emission = SingBoxEmitter().emit_result([node, node])

    assert [item["tag"] for item in emission.content["outbounds"]] == ["shared"]
    assert emission.supported_nodes == [node]
    assert [issue.code for issue in emission.errors] == [
        "conversion.duplicate-node-name"
    ]


def test_singbox_artifact_duplicate_tags_abort_before_publication(
    tmp_path, monkeypatch
):
    _write(
        tmp_path / "nodes.yaml",
        _mixed_nodes().replace("name: vpn", "name: edge"),
    )
    _write(tmp_path / "client.json.j2", '{"outbounds": {{ nodes.outbounds() }}}')
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(config_path), dry_run=True).run()

    assert [issue.code for issue in exc_info.value.issues] == [
        "conversion.duplicate-node-name"
    ]
    assert not (tmp_path / "dist").exists()
    assert "outbound-secret" not in repr(exc_info.value.issues)
    assert "endpoint-secret" not in repr(exc_info.value.issues)


@pytest.mark.parametrize("detour", ["vpn", "missing"])
def test_singbox_artifact_endpoint_detour_must_reference_emitted_outbound(
    tmp_path, monkeypatch, detour
):
    _write(tmp_path / "nodes.yaml", _mixed_nodes(detour=detour))
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(artifact_options='template = "client.json.j2"'),
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(config_path), dry_run=True).run()

    issue = next(
        issue
        for issue in exc_info.value.issues
        if issue.code == "conversion.invalid-endpoint-detour"
    )
    assert issue.node == "vpn"
    assert issue.field == "dialer_proxy"
    assert issue.artifact == "client.json"
    assert not (tmp_path / "dist").exists()
    assert "endpoint-secret" not in repr(exc_info.value.issues)
    assert "ca-secret" not in repr(exc_info.value.issues)


def test_singbox_artifact_reports_detour_to_filtered_outbound(tmp_path, monkeypatch):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(
            provider_options='[provider.filters]\nexclude = "^edge$"',
            artifact_options='template = "client.json.j2"',
        ),
    )
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ArtifactGenerationError) as exc_info:
        WorkflowEngine(str(config_path), dry_run=True).run()

    assert any(
        issue.code == "conversion.invalid-endpoint-detour"
        and issue.field == "dialer_proxy"
        for issue in exc_info.value.issues
    )
    assert not (tmp_path / "dist").exists()


def test_singbox_artifact_allow_empty_emits_empty_json(tmp_path, monkeypatch):
    _write(
        tmp_path / "nodes.yaml",
        """
proxies:
  - name: unsupported
    type: mieru
    server: mieru.example.com
    port: 443
    transport: TCP
    username: alice
    password: unsupported-secret
""",
    )
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(
            artifact_options=(
                'template = "client.json.j2"\n'
                "allow_conversion_errors = true\nallow_empty = true"
            )
        ),
    )
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    monkeypatch.chdir(tmp_path)

    result = WorkflowEngine(str(config_path), dry_run=True).run()

    assert result.generated == ["client.json"]
    assert json.loads((tmp_path / "dist/client.json").read_text()) == {
        "outbounds": [],
        "endpoints": [],
    }
    assert any(issue.field == "type" for issue in result.errors)
    assert "unsupported-secret" not in repr(result.issues)


def test_singbox_artifact_json_flows_through_age_and_upload(tmp_path, monkeypatch):
    _write(tmp_path / "nodes.yaml", _mixed_nodes())
    config_path = _write(
        tmp_path / "config.toml",
        _workflow_config(
            artifact_options=(
                'template = "client.json.j2"\n'
                'age_public_key = "age1-test"\n'
                'upload = [{to = "gist", file_name = "client.age"}]'
            )
        )
        + """

[[uploader]]
name = "gist"
type = "gist"
id = "gist-id"
""",
    )
    _write(
        tmp_path / "client.json.j2",
        '{"outbounds": {{ nodes.outbounds() }}, "endpoints": {{ nodes.endpoints() }}}',
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "subio_v2.workflow.engine.age.verify_public_key", lambda _key: None
    )
    plaintext: list[str] = []

    def encrypt_bytes(content, public_key):
        plaintext.append(content)
        assert public_key == "age1-test"
        return b"age-encrypted-payload\n"

    monkeypatch.setattr("subio_v2.workflow.artifacts.age.encrypt_bytes", encrypt_bytes)
    engine = WorkflowEngine(str(config_path), dry_run=True)
    queued_content: list[str] = []
    real_add = engine.batch_uploader.add

    def capture_add(content, *args, **kwargs):
        queued_content.append(content)
        return real_add(content, *args, **kwargs)

    monkeypatch.setattr(engine.batch_uploader, "add", capture_add)
    monkeypatch.setattr(engine.batch_uploader, "flush", lambda: None)

    result = engine.run()

    assert len(plaintext) == 1
    assert [item["tag"] for item in json.loads(plaintext[0])["outbounds"]] == ["edge"]
    assert (tmp_path / "dist/client.json").read_text() == "age-encrypted-payload\n"
    assert queued_content == ["age-encrypted-payload\n"]
    assert engine.batch_uploader.pending_uploads() == ["gist-id:client.age"]
    assert result.generated == ["client.json"]
    assert result.uploaded == []


@pytest.mark.parametrize(
    ("outbound", "outbound_field", "secret"),
    [
        (
            ShadowsocksNode(
                name="edge",
                server="edge.example.com",
                port=8388,
                cipher="unsupported-cipher",
                password="failed-secret",
            ),
            "cipher",
            "failed-secret",
        ),
        (
            MieruNode(
                name="edge",
                server="edge.example.com",
                port=443,
                transport=MieruTransport.TCP,
                username="alice",
                password="unsupported-secret",
            ),
            "type",
            "unsupported-secret",
        ),
    ],
    ids=["failed", "unsupported"],
)
def test_singbox_emitter_reports_detour_to_unemitted_outbound(
    outbound, outbound_field, secret
):
    endpoint = OpenVPNNode(
        name="vpn",
        server="vpn.example.com",
        port=1194,
        ca="ca-secret",
        username="alice",
        password="endpoint-secret",
        dialer_proxy="edge",
    )

    emission = SingBoxEmitter().emit_result([outbound, endpoint])

    assert emission.content == {"outbounds": [], "endpoints": []}
    assert any(
        issue.node == "edge" and issue.field == outbound_field
        for issue in emission.errors
    )
    assert any(
        issue.node == "vpn"
        and issue.field == "dialer_proxy"
        and issue.code == "conversion.invalid-endpoint-detour"
        for issue in emission.errors
    )
    assert secret not in repr(emission.issues)
    assert "endpoint-secret" not in repr(emission.issues)
    assert "ca-secret" not in repr(emission.issues)
