import json

import pytest
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.nodes import (
    AnyTLSNode, HttpNode, HttpVariant, ShadowQUICNode, SnellNode, SSHNode,
    TLSSettings, TransportSettings, TrojanNode, VlessNode, VmessNode,
)
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.protocols.user_overrides import clone_node_for_user
from subio_v2.workflow.engine import WorkflowEngine


@pytest.mark.parametrize("protocol,credentials", [
    ("vmess", {"uuid": "11111111-1111-4111-8111-111111111111"}),
    ("vless", {"uuid": "11111111-1111-4111-8111-111111111111"}),
    ("trojan", {"password": "synthetic", "tls": True}),
])
def test_mihomo_default_tcp_is_representable_by_singbox(protocol, credentials):
    parsed = get_parser("mihomo").parse_result({"proxies": [{
        "name": "tcp", "type": protocol, "server": "example.test", "port": 443,
        **credentials,
    }]})
    assert not parsed.issues
    result = get_emitter("sing-box").emit_result(parsed.nodes)
    assert not result.errors
    assert len(result.supported_nodes) == 1


def test_mihomo_trojan_implicit_tls_keeps_verification_settings():
    parsed = get_parser("mihomo").parse_result({"proxies": [{
        "name": "trojan", "type": "trojan", "server": "example.test", "port": 443,
        "password": "synthetic", "sni": "edge.test", "alpn": ["h2"],
        "skip-cert-verify": True,
    }]})
    assert not parsed.issues
    assert parsed.nodes[0].tls.enabled
    result = get_emitter("mihomo").emit_result(parsed.nodes)
    assert not result.errors
    proxy = result.content["proxies"][0]
    assert proxy["sni"] == "edge.test"
    assert proxy["alpn"] == ["h2"]
    assert proxy["skip-cert-verify"] is True


@pytest.mark.parametrize("variant,enabled", [
    (HttpVariant.HTTPS, False), (HttpVariant.H2_CONNECT, False),
    (HttpVariant.HTTP, True),
])
@pytest.mark.parametrize("target", ["mihomo", "surge", "dae", "sing-box"])
def test_http_variant_tls_conflict_is_rejected_before_encoding(variant, enabled, target):
    node = HttpNode(name="http", server="example.test", port=443, udp=False,
                    variant=variant, tls=TLSSettings(enabled=enabled))
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == "tls.enabled" for issue in result.errors)


def test_masque_user_private_key_is_not_replaced_by_tls_copy():
    parsed = get_parser("mihomo", source_kind="local").parse_result({"proxies": [{
        "name": "masque", "type": "masque", "server": "example.test", "port": 443,
        "private-key": "original", "public-key": "public", "ip": "10.0.0.2",
        "users": {"alice": {"private_key": "replacement"}},
    }]})
    assert not parsed.issues
    node = clone_node_for_user(parsed.nodes[0], "alice")
    assert node.tls.private_key is None
    result = get_emitter("mihomo").emit_result([node])
    assert not result.errors
    assert result.content["proxies"][0]["private-key"] == "replacement"


@pytest.mark.parametrize("target,node,field", [
    ("mihomo", ShadowQUICNode(name="sq", server="example.test", port=443,
        username="u", password="p", tls=TLSSettings(enabled=True,
        certificate_sha256="ab" * 32)), "tls.certificate_sha256"),
    ("mihomo", SnellNode(name="sn", server="example.test", port=443,
        psk="p", version=4, tls=TLSSettings(enabled=True)), "tls"),
    ("surge", SnellNode(name="sn", server="example.test", port=443,
        psk="p", version=3, tls=TLSSettings(enabled=True)), "tls"),
    ("mihomo", TrojanNode(name="tr", server="example.test", port=443,
        password="p", tls=TLSSettings(enabled=True, sni_disabled=True)), "tls.sni_disabled"),
    ("stash", TrojanNode(name="tr", server="example.test", port=443,
        password="p", tls=TLSSettings(enabled=True, sni_disabled=True)), "tls.sni_disabled"),
    ("v2rayn", VmessNode(name="vm", server="example.test", port=443,
        uuid="11111111-1111-4111-8111-111111111111",
        tls=TLSSettings(enabled=True, skip_cert_verify=True)), "tls.skip_cert_verify"),
    ("dae", AnyTLSNode(name="any", server="example.test", port=443,
        password="p", tls=TLSSettings(enabled=True, client_fingerprint="chrome")), "tls.client_fingerprint"),
])
def test_target_rejects_unrepresentable_tls_settings(target, node, field):
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == field for issue in result.errors)


@pytest.mark.parametrize("target", ["stash", "surge"])
@pytest.mark.parametrize("field,value", [
    ("host_key", ["ssh-ed25519 synthetic"]),
    ("host_key_algorithms", ["ssh-ed25519"]),
])
def test_ssh_host_key_requirements_cannot_be_dropped(target, field, value):
    node = SSHNode(name="ssh", server="example.test", port=22, username="u",
                   password="p", udp=False, **{field: value})
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == field for issue in result.errors)


@pytest.mark.parametrize("node_class,credentials", [
    (TrojanNode, {"password": "p"}),
    (VmessNode, {"uuid": "11111111-1111-4111-8111-111111111111"}),
])
@pytest.mark.parametrize("field,value", [
    ("certificate", "synthetic-cert"), ("private_key", "synthetic-key"),
    ("ech_opts", {"enable": True}), ("client_fingerprint", "chrome"),
])
def test_surge_rejects_tls_fields_it_cannot_serialize(node_class, credentials, field, value):
    node = node_class(name="tls", server="example.test", port=443,
        tls=TLSSettings(enabled=True, **{field: value}), **credentials)
    result = get_emitter("surge").emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == "tls." + field for issue in result.errors)


@pytest.mark.parametrize("target", ["v2rayn", "dae", "surge", "mihomo"])
def test_trojan_tls_disabled_is_not_silently_reenabled(target):
    node = TrojanNode(name="plain", server="example.test", port=443,
                      password="p", tls=TLSSettings(enabled=False))
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == "tls.enabled" for issue in result.errors)


@pytest.mark.parametrize("protocol,credentials,field,value", [
    ("http", {}, "ech_opts", {"enable": True}),
    ("anytls", {"password": "p"}, "ech_opts", {"enable": True}),
    ("hysteria2", {"password": "p"}, "client_fingerprint", "chrome"),
    ("masque", {"private_key": "protocol-key", "public_key": "public", "interface_ip": "10.0.0.2"}, "verify_name", "verify.test"),
    ("masque", {"private_key": "protocol-key", "public_key": "public", "interface_ip": "10.0.0.2"}, "private_key", "tls-key"),
])
def test_tls_ownership_filter_reports_unrepresentable_typed_fields(protocol, credentials, field, value):
    parsed = get_parser("subio").parse_result(json.dumps({"version": 2, "nodes": [{
        "name": "unsafe", "type": protocol, "server": "example.test", "port": 443,
        **credentials, "tls": {"enabled": True, field: value},
    }]}))
    assert not parsed.issues
    result = get_emitter("mihomo").emit_result(parsed.nodes)
    assert not result.supported_nodes
    assert any(issue.field == "tls." + field for issue in result.errors)


@pytest.mark.parametrize("node_class,credentials", [
    (VmessNode, {"uuid": "11111111-1111-4111-8111-111111111111"}),
    (VlessNode, {"uuid": "11111111-1111-4111-8111-111111111111"}),
    (TrojanNode, {"password": "p"}),
])
@pytest.mark.parametrize("method,valid", [(None, True), ("GET", True), ("POST", False)])
def test_singbox_default_tcp_method_equivalence(node_class, credentials, method, valid):
    node = node_class(name="tcp", server="example.test", port=443,
        tls=TLSSettings(enabled=True), transport=TransportSettings(method=method), **credentials)
    result = get_emitter("sing-box").emit_result([node])
    assert bool(result.supported_nodes) == valid
    assert bool(result.errors) != valid


@pytest.mark.parametrize("target,bad,field", [
    ("mihomo", {"type": "http", "tls": {"enabled": True, "ech_opts": {"enable": True}}}, "tls.ech_opts"),
    ("stash", {"type": "trojan", "password": "p", "tls": {"enabled": True, "verify_name": "verify.test"}}, "tls.verify_name"),
    ("surge", {"type": "ssh", "username": "u", "password": "p", "udp": False, "host_key": ["ssh-ed25519 synthetic"]}, "host_key"),
])
@pytest.mark.parametrize("allow_errors", [False, True])
def test_tls_and_ssh_errors_reach_the_real_artifact_gate(tmp_path, monkeypatch, target, bad, field, allow_errors):
    (tmp_path / "nodes.json").write_text(json.dumps({"version": 2, "nodes": [
        {"name": "unsafe", "server": "example.test", "port": 443, **bad},
        {"name": "safe", "type": "http", "server": "example.test", "port": 8080},
    ]}))
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "provider": [{"name": "source", "type": "subio", "file": "nodes.json"}],
        "artifact": [{"name": "out.txt", "type": target, "providers": ["source"], "allow_conversion_errors": allow_errors}],
    }))
    monkeypatch.chdir(tmp_path)
    engine = WorkflowEngine(str(config), dry_run=True)
    if allow_errors:
        result = engine.run()
        assert any(issue.field == field for issue in result.errors)
        content = (tmp_path / "dist/out.txt").read_text()
        assert "safe" in content and "unsafe" not in content
    else:
        monkeypatch.setattr(engine.batch_uploader, "flush", lambda: pytest.fail("Flushed a failed artifact"))
        with pytest.raises(ArtifactGenerationError) as error:
            engine.run()
        assert any(issue.field == field for issue in error.value.issues)
        assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("protocol,credentials", [
    ("trojan", {"password": "p"}),
    ("vmess", {"uuid": "11111111-1111-4111-8111-111111111111"}),
])
@pytest.mark.parametrize("target,field,value", [
    ("stash", "verify_name", "verify.test"),
    ("stash", "certificate", "synthetic-cert"),
    ("stash", "private_key", "synthetic-key"),
    ("stash", "ech_opts", {"enable": True}),
    ("stash", "client_fingerprint", "chrome"),
    ("clash", "ech_opts", {"enable": True}),
])
def test_final_dialect_trimming_cannot_drop_typed_tls_requirements(protocol, credentials, target, field, value):
    parsed = get_parser("subio").parse_result(json.dumps({"version": 2, "nodes": [{
        "name": "tls", "type": protocol, "server": "example.test", "port": 443,
        **credentials, "tls": {"enabled": True, field: value},
    }]}))
    assert not parsed.issues
    result = get_emitter(target).emit_result(parsed.nodes)
    assert not result.supported_nodes
    assert any(issue.field == "tls." + field for issue in result.errors)
    positive = get_emitter("mihomo").emit_result(parsed.nodes)
    assert len(positive.supported_nodes) == 1 and not positive.errors


def test_stash_final_tls_fingerprint_alias_is_representable():
    node = TrojanNode(name="tls", server="example.test", port=443, password="p",
        tls=TLSSettings(enabled=True, certificate_sha256="ab" * 32))
    result = get_emitter("stash").emit_result([node])
    assert not result.issues
    assert result.content["proxies"][0]["server-cert-fingerprint"] == "ab" * 32
