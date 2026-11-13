import base64
import json

import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.workflow.engine import WorkflowEngine


CERT = "-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC\n-----END OPENSSH PRIVATE KEY-----"
PATH = "./credential-canary.key"


def credential_document(format_name, field, value):
    if format_name == "subio":
        node = {"name": "bad", "type": "ssh", "server": "example.test",
                "port": 22, "username": "u", "private_key": value}
        if field != "ssh":
            node = {"name": "bad", "type": "trojan", "server": "example.test",
                    "port": 443, "password": "p", "tls": {"enabled": True, field: value}}
        return json.dumps({"version": 2, "nodes": [node,
            {"name": "good", "type": "direct"}]})
    if format_name == "sing-box":
        return {"outbounds": [{"tag": "bad", "type": "ssh", "server": "example.test",
            "server_port": 22, "user": "u", "private_key": value},
            {"tag": "good", "type": "direct"}]}
    if format_name == "surge":
        encoded = base64.b64encode(value.encode()).decode()
        return ("[Proxy]\nbad = ssh, example.test, 22, username=u, private-key=key\n"
                "good = direct\n[Keystore]\nkey = type = openssh-private-key, base64 = " + encoded)
    node = {"name": "bad", "type": "ssh", "server": "example.test",
            "port": 22, "username": "u", "private-key": value}
    if field != "ssh":
        node = {"name": "bad", "type": "trojan", "server": "example.test",
                "port": 443, "password": "p", field.replace("_", "-"): value}
    return {"proxies": [node, {"name": "good", "type": "ss", "server": "example.test",
        "port": 443, "cipher": "aes-128-gcm", "password": "p"}]}


CASES = [(fmt, field) for fmt in ("mihomo", "clash-meta", "stash", "subio")
         for field in ("ssh", "certificate", "private_key")] + [
             ("sing-box", "ssh"), ("surge", "ssh")]


@pytest.mark.parametrize("format_name,field", CASES)
@pytest.mark.parametrize("source_kind", ["remote", "unknown", "local"])
@pytest.mark.parametrize("inline", [False, True])
def test_credentials_follow_source_authority(format_name, field, source_kind, inline):
    value = (CERT if field == "certificate" else KEY) if inline else PATH
    result = get_parser(format_name, source_kind=source_kind).parse_result(
        credential_document(format_name, field, value))
    if inline or source_kind == "local":
        assert not result.issues
        assert [node.name for node in result.nodes] == ["bad", "good"]
    else:
        assert [node.name for node in result.nodes] == ["good"]
        assert result.issues and all(issue.severity.value == "error" for issue in result.issues)
        assert all(PATH not in issue.message for issue in result.issues)
        assert any(issue.code == "security.local-credential-blocked" for issue in result.issues)


@pytest.mark.parametrize("format_name", ["mihomo", "stash", "subio"])
@pytest.mark.parametrize("source_kind", ["remote", "unknown", "local"])
def test_user_override_cannot_add_local_key_reference(format_name, source_kind):
    document = credential_document(format_name, "ssh", KEY)
    if isinstance(document, str):
        document = json.loads(document)
        document["nodes"][0]["users"] = {"alice": {"private_key": PATH}}
        document = json.dumps(document)
    else:
        document["proxies"][0]["users"] = {"alice": {"private_key": PATH}}
    result = get_parser(format_name, source_kind=source_kind).parse_result(document)
    assert len(result.nodes) == (2 if source_kind == "local" else 1)
    if source_kind != "local":
        assert any("users.alice.private_key" in issue.field for issue in result.issues)


@pytest.mark.parametrize("source_kind", ["remote", "unknown", "local"])
@pytest.mark.parametrize("interactive", [False, True])
def test_tailscale_interactive_state_needs_local_authority(source_kind, interactive):
    content = ("[Proxy]\nbad = tailscale, section-name=office\ngood = direct\n"
               "[Tailscale office]\n" + ("interactive-login=true" if interactive else "auth-key=synthetic"))
    parsed = get_parser("surge", source_kind=source_kind,
                        allow_unsafe_external=True).parse_result(content)
    allowed = not interactive or source_kind == "local"
    assert len(parsed.nodes) == (2 if allowed else 1)
    if allowed:
        assert not parsed.issues
        assert not get_emitter("surge").emit_result(parsed.nodes).errors
    else:
        assert any(issue.field == "interactive_login" for issue in parsed.issues)


@pytest.mark.parametrize("raw_type", ["future-protocol", "ss"])
@pytest.mark.parametrize("field", ["certificate", "private-key-path"])
def test_clash_replay_cannot_restore_known_local_credential_fields(raw_type, field):
    parsed = get_parser("mihomo", source_kind="remote").parse_result({"proxies": [{
        "name": "opaque", "type": raw_type, "server": "example.test", "port": 443,
        "cipher": "aes-128-gcm", "password": "p", field: PATH}]})
    assert not parsed.nodes
    assert any(issue.code == "security.local-credential-blocked" for issue in parsed.issues)


@pytest.mark.parametrize("protocol,fields", [
    ("wireguard", {"private-key": PATH, "public-key": "public", "ip": "10.0.0.2"}),
    ("masque", {"private-key": PATH, "public-key": "public", "ip": "10.0.0.2"}),
])
def test_protocol_keys_do_not_gain_file_semantics(protocol, fields):
    result = get_parser("mihomo", source_kind="remote").parse_result({"proxies": [{
        "name": "protocol", "type": protocol, "server": "example.test", "port": 443, **fields}]})
    assert not result.issues
    assert len(result.nodes) == 1


def test_provider_authority_reaches_real_artifact_gate(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('''[remote.cache]
enabled = false
[[provider]]
name = "remote"
type = "mihomo"
url = "https://source.example.test/nodes"
[[artifact]]
name = "output.yaml"
type = "mihomo"
providers = ["remote"]
''')
    from subio_v2.infrastructure.remote import RunRemoteLoader

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(RunRemoteLoader, "fetch", lambda *args, **kwargs:
        json.dumps(credential_document("mihomo", "ssh", PATH)).encode())
    with pytest.raises(ArtifactGenerationError) as error:
        WorkflowEngine(str(config), dry_run=True).run()
    assert any(issue.code == "security.local-credential-blocked" for issue in error.value.issues)
    assert not (tmp_path / "dist").exists()
