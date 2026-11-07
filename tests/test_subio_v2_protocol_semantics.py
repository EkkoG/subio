import json
from dataclasses import replace

import pytest

import subio_v2.protocols as registry
from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.nodes import (
    MieruNode,
    MieruTransport,
    OpenConnectNode,
    ShadowsocksNode,
    SSHNode,
    TUICNode,
    WireguardNode,
    WireguardPeer,
)
from subio_v2.core.validation import validate_node


@pytest.mark.parametrize(
    "node,change,field",
    [
        (
            ShadowsocksNode(name="ss", server="example.test", port=443, cipher="none"),
            {"cipher": "aes-256-gcm"},
            "password",
        ),
        (
            SSHNode(
                name="ssh",
                server="example.test",
                port=22,
                username="alice",
                private_key="synthetic",
            ),
            {"private_key": None},
            "password",
        ),
        (
            TUICNode(
                name="tuic4",
                server="example.test",
                port=443,
                version=4,
                token="synthetic",
            ),
            {"uuid": "unexpected-v5"},
            "uuid",
        ),
        (
            TUICNode(
                name="tuic5",
                server="example.test",
                port=443,
                version=5,
                uuid="synthetic",
                password="synthetic",
            ),
            {"password": ""},
            "password",
        ),
        (
            MieruNode(
                name="mieru",
                server="example.test",
                port=None,
                port_range="443-445",
                transport=MieruTransport.TCP,
                username="alice",
                password="synthetic",
            ),
            {"port": 443},
            "port_range",
        ),
        (
            WireguardNode(
                name="wg",
                private_key="synthetic",
                peers=[
                    WireguardPeer(
                        server="example.test",
                        port=443,
                        public_key="synthetic",
                        allowed_ips=["0.0.0.0/0"],
                    ),
                ],
            ),
            {"peers": []},
            "public_key",
        ),
        (
            OpenConnectNode(name="oc", server="https://example.test", port=None),
            {"server": "https://user:synthetic@example.test"},
            "server",
        ),
    ],
)
def test_conditional_semantics_do_not_need_any_clash_codec(
    monkeypatch, node, change, field
):
    monkeypatch.setattr(registry, "_registry", {})
    definition = registry.get_definition(node.type)
    assert definition is not None
    assert validate_node(node, definition=definition) == []
    assert field in {
        error.field
        for error in validate_node(replace(node, **change), definition=definition)
    }


def test_native_and_singbox_consumers_validate_without_clash_registry(monkeypatch):
    monkeypatch.setattr(registry, "_registry", {})
    native = get_parser("subio").parse_result(
        json.dumps(
            {
                "version": 2,
                "nodes": [
                    {
                        "type": "shadowsocks",
                        "name": "ss",
                        "server": "example.test",
                        "port": 443,
                        "cipher": "none",
                    },
                    {
                        "type": "vmess",
                        "name": "invalid",
                        "server": "example.test",
                        "port": 443,
                    },
                ],
            }
        )
    )
    assert [node.name for node in native.nodes] == ["ss"]
    assert any(issue.field.endswith("uuid") for issue in native.issues)
    encoded = get_emitter("sing-box").emit_result(native.nodes)
    assert [node.name for node in encoded.supported_nodes] == ["ss"]
    assert not encoded.errors
    parsed = get_parser("sing-box").parse_result(encoded.content)
    assert [node.name for node in parsed.nodes] == ["ss"]
    assert not parsed.issues
