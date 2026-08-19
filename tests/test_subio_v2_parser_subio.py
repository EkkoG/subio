import json
import types
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
import yaml

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import (
    Protocol,
    ShadowsocksNode,
    VlessNode,
)
from subio_v2.parser.subio import SubioParser
from subio_v2.protocols.definitions import TERMINAL_NATIVE_COMMON_FIELDS
from subio_v2.subio_format.schema import (
    PUBLIC_NESTED_FIELDS,
    PUBLIC_PROTOCOLS,
    build_json_schema,
    public_mapping_spec,
    public_node_fields,
    public_user_override_fields,
)

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "subio-node-v2.schema.json"


def _native_ss_document() -> dict:
    return {
        "version": 2,
        "nodes": [
            {
                "name": "n1",
                "type": "shadowsocks",
                "server": "s",
                "port": 8388,
                "cipher": "aes-256-gcm",
                "password": "p",
            }
        ],
    }


def _all_native_protocol_nodes() -> list[dict]:
    endpoint = {"server": "example.com", "port": 443}
    return [
        {
            "name": "ss",
            "type": "shadowsocks",
            **endpoint,
            "cipher": "aes-256-gcm",
            "password": "p",
            "shadow_tls": {"password": "shadow", "version": 2},
            "surge_options": {"test_timeout": 5},
        },
        {
            "name": "ssr",
            "type": "shadowsocksr",
            **endpoint,
            "cipher": "aes-256-cfb",
            "password": "p",
            "obfs": "plain",
            "ssr_protocol": "origin",
        },
        {"name": "vmess", "type": "vmess", **endpoint, "uuid": "u"},
        {"name": "vless", "type": "vless", **endpoint, "uuid": "u"},
        {"name": "trojan", "type": "trojan", **endpoint, "password": "p"},
        {"name": "socks", "type": "socks5", **endpoint},
        {"name": "http", "type": "http", **endpoint},
        {
            "name": "wireguard",
            "type": "wireguard",
            **endpoint,
            "private_key": "private",
            "public_key": "",
            "interface_ip": ["10.0.0.2/32", "fd00::2/128"],
            "peers": [
                {
                    "server": "peer.example.com",
                    "port": 51820,
                    "public_key": "public",
                    "preshared_key": "shared",
                    "allowed_ips": ["0.0.0.0/0", "::/0"],
                    "reserved": [1, 2, 3],
                }
            ],
        },
        {"name": "tailscale", "type": "tailscale", "auth_key": "tskey"},
        {"name": "masque", "type": "masque", **endpoint},
        {
            "name": "trusttunnel",
            "type": "trusttunnel",
            **endpoint,
            "username": "u",
            "password": "p",
        },
        {"name": "direct", "type": "direct"},
        {"name": "dns", "type": "dns"},
        {
            "name": "rematch",
            "type": "rematch",
            "target_rematch_name": "streaming",
        },
        {"name": "gost", "type": "gost-relay", **endpoint},
        {"name": "shadowquic", "type": "shadowquic", **endpoint},
        {
            "name": "openvpn",
            "type": "openvpn",
            **endpoint,
            "ca": "ca",
            "username": "u",
            "peer_info": {"IV_VER": "3"},
        },
        {
            "name": "sudoku",
            "type": "sudoku",
            **endpoint,
            "key": "key",
            "httpmask": {"mode": "auto", "host": "mask.example.com"},
        },
        {"name": "reject", "type": "reject", "mode": "reject-drop"},
        {"name": "anytls", "type": "anytls", **endpoint, "password": "p"},
        {"name": "hysteria", "type": "hysteria", **endpoint},
        {
            "name": "hysteria2",
            "type": "hysteria2",
            **endpoint,
            "password": "p",
        },
        {
            "name": "ssh",
            "type": "ssh",
            **endpoint,
            "username": "root",
            "password": "p",
        },
        {"name": "snell", "type": "snell", **endpoint, "psk": "p"},
        {
            "name": "mieru",
            "type": "mieru",
            **endpoint,
            "transport": "TCP",
            "username": "u",
            "password": "p",
            "multiplexing": "MULTIPLEXING_LOW",
        },
        {
            "name": "juicity",
            "type": "juicity",
            **endpoint,
            "uuid": "u",
            "password": "p",
        },
        {"name": "tuic", "type": "tuic", **endpoint, "token": "token"},
    ]


@pytest.mark.parametrize(
    ("content", "source_format"),
    [
        (
            'version = 2\nnodes = [{name = "n1", type = "shadowsocks", '
            'server = "s", port = 8388, cipher = "aes-256-gcm", password = "p"}]',
            "toml",
        ),
        (json.dumps(_native_ss_document()), "json"),
        (
            "{version: 2, nodes: [{name: 'n1', type: 'shadowsocks', "
            "server: 's', port: 8388, cipher: 'aes-256-gcm', password: 'p',},]}",
            "json5",
        ),
        (yaml.safe_dump(_native_ss_document(), sort_keys=False), "yaml"),
    ],
)
def test_subio_native_format_decodes_directly_to_node_ir(content, source_format):
    result = SubioParser().parse_result(content)

    assert result.issues == []
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert isinstance(node, ShadowsocksNode)
    assert node.type == Protocol.SHADOWSOCKS
    assert node.source_context.dialect == "subio"
    assert node.source_context.format == source_format
    assert node.extra == {}
    assert node.source_extensions == {}


def test_subio_native_format_decodes_nested_settings_and_user_overrides():
    result = SubioParser().parse_result(
        """
version = 2

[[nodes]]
name = "vless"
type = "vless"
server = "example.com"
port = 443
uuid = "00000000-0000-0000-0000-000000000000"

[nodes.tls]
enabled = true
server_name = "example.com"
skip_cert_verify = false

[nodes.transport]
network = "ws"
path = "/proxy"
headers = { Host = "example.com" }

[nodes.users.alice]
uuid = "11111111-1111-1111-1111-111111111111"
server = "alice.example.com"
"""
    )

    assert result.issues == []
    node = result.nodes[0]
    assert isinstance(node, VlessNode)
    assert node.tls.enabled is True
    assert node.tls.server_name == "example.com"
    assert node.transport.network_value == "ws"
    assert node.transport.path == "/proxy"
    assert node.users == {
        "alice": {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "server": "alice.example.com",
        }
    }


def test_subio_native_format_preserves_protocol_nested_defaults():
    result = SubioParser().parse_result(
        """
version = 2

[[nodes]]
name = "anytls"
type = "anytls"
server = "example.com"
port = 443
password = "secret"

[nodes.tls]
server_name = "example.com"
"""
    )

    assert result.issues == []
    assert result.nodes[0].tls.enabled is True
    assert result.nodes[0].tls.server_name == "example.com"


def test_subio_native_format_validates_user_specific_node_credentials():
    result = SubioParser().parse_result(
        """
version = 2

[[nodes]]
name = "ssh"
type = "ssh"
server = "example.com"
port = 22
username = "default"

[nodes.users.alice]
username = "alice"
private_key = "alice-key"

[nodes.users.bob]
username = "bob"
password = "bob-password"
"""
    )

    assert result.issues == []
    assert len(result.nodes) == 1
    assert result.nodes[0].users == {
        "alice": {"username": "alice", "private_key": "alice-key"},
        "bob": {"username": "bob", "password": "bob-password"},
    }


def test_subio_native_format_reports_invalid_user_specific_node():
    result = SubioParser().parse_result(
        """
version = 2

[[nodes]]
name = "ssh"
type = "ssh"
server = "example.com"
port = 22
username = "default"

[nodes.users.alice]
username = "alice"
"""
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.subio.invalid-combination"
    assert result.issues[0].field == "nodes[0].users.alice.password"
    assert "alice" in result.issues[0].message


def test_subio_native_format_rejects_meaningless_user_overrides():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: direct
    type: direct
    users:
      alice:
        server: ignored.example.com
  - name: openvpn
    type: openvpn
    server: example.com
    port: 1194
    ca: ca
    username: alice
    users:
      alice:
        cipher: AES-256-GCM
"""
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.subio.unknown-field",
        "parse.subio.unknown-field",
    ]
    assert [issue.field for issue in result.issues] == [
        "nodes[0].users.alice.server",
        "nodes[1].users.alice.cipher",
    ]


def test_subio_native_format_reports_structured_document_errors():
    missing = SubioParser().parse_result("{}")
    unsupported = SubioParser().parse_result("version = 1\nnodes = []")
    conflict = SubioParser().parse_result("version = 2\nnodes = []\nproxies = []")

    assert missing.issues[0].code == "parse.subio.missing-nodes"
    assert unsupported.issues[0].code == "parse.subio.unsupported-version"
    assert conflict.issues[0].code == "parse.subio.invalid-document"
    assert missing.nodes == unsupported.nodes == conflict.nodes == []


def test_subio_native_format_rejects_platform_aliases_and_internal_fields():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: bad-alias
    type: ss
    server: example.com
    port: 8388
  - name: bad-field
    type: shadowsocks
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
    source_context: forged
  - name: good
    type: shadowsocks
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
"""
    )

    assert [node.name for node in result.nodes] == ["good"]
    assert [issue.code for issue in result.issues] == [
        "parse.subio.unknown-type",
        "parse.subio.unknown-field",
    ]
    assert result.issues[1].field == "nodes[1].source_context"


def test_subio_native_format_rejects_null_and_source_passthrough():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: null-password
    type: shadowsocks
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password:
  - name: future
    type: source-passthrough
"""
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.subio.invalid-field",
        "parse.subio.unknown-type",
    ]
    assert "null-password" not in " ".join(issue.message for issue in result.issues)


def test_subio_native_format_decodes_canonical_mapping_objects():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: ss-plugin
    type: shadowsocks
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
    plugin: v2ray-plugin
    plugin_opts:
      mode: websocket
      private_key: key
      skip_cert_verify: true
      ech_opts:
        enable: true
        query_server_name: ech.example.com
    smux:
      enabled: true
      brutal_opts:
        enabled: true
        up: 10
        down: 50
  - name: vless-reality
    type: vless
    server: example.com
    port: 443
    uuid: u
    tls:
      enabled: true
      reality_opts:
        public_key: public
        short_id: short
      ech_opts:
        config: ZWNo
  - name: wireguard-amnezia
    type: wireguard
    server: example.com
    port: 51820
    private_key: private
    public_key: public
    amnezia_wg_option:
      jc: 4
      h1: header
  - name: snell-obfs
    type: snell
    server: example.com
    port: 443
    psk: secret
    obfs_opts:
      mode: restls
      version_hint: tls13
      skip_cert_verify: true
"""
    )

    assert result.issues == []
    ss, vless, wireguard, snell = result.nodes
    assert ss.plugin_opts == {
        "mode": "websocket",
        "private-key": "key",
        "skip-cert-verify": True,
        "ech-opts": {"enable": True, "query-server-name": "ech.example.com"},
    }
    assert ss.smux.brutal_opts == {"enabled": True, "up": 10, "down": 50}
    assert vless.tls.reality_opts == {
        "public-key": "public",
        "short-id": "short",
    }
    assert vless.tls.ech_opts == {"config": "ZWNo"}
    assert wireguard.amnezia_wg_option == {"jc": 4, "h1": "header"}
    assert snell.obfs_opts == {
        "mode": "restls",
        "version-hint": "tls13",
        "skip-cert-verify": True,
    }


def test_subio_native_format_rejects_unknown_mapping_fields():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: bad-ech
    type: vless
    server: example.com
    port: 443
    uuid: u
    tls:
      ech_opts:
        query-server-name: wrong-key-style
"""
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.subio.unknown-field"
    assert result.issues[0].field == "nodes[0].tls.ech_opts.query-server-name"


def test_subio_native_format_rejects_invalid_public_enums():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: bad-network
    type: vmess
    server: example.com
    port: 443
    uuid: u
    transport:
      network: future-transport
  - name: bad-tuic
    type: tuic
    server: example.com
    port: 443
    token: token
    version: 3
"""
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.subio.invalid-field",
        "parse.subio.invalid-field",
    ]
    assert [issue.field for issue in result.issues] == [
        "nodes[0].transport.network",
        "nodes[1].version",
    ]


def test_subio_native_format_validates_explicit_tuic_version():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: mismatched-tuic
    type: tuic
    server: example.com
    port: 443
    version: 4
    uuid: u
    password: p
"""
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.subio.invalid-combination"
    assert result.issues[0].field == "nodes[0].token"
    assert result.issues[1].field == "nodes[0].uuid"


def test_subio_native_format_rejects_source_bound_resource_references():
    result = SubioParser().parse_result(
        """
version: 2
nodes:
  - name: ssh-state
    type: ssh
    server: example.com
    port: 22
    username: root
    keystore_id: local-key
  - name: tls-state
    type: http
    server: example.com
    port: 443
    tls:
      enabled: true
      client_cert_ref: local-cert
  - name: tailscale-state
    type: tailscale
    interactive_login: true
"""
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.subio.unknown-field",
        "parse.subio.unknown-field",
        "parse.subio.unknown-field",
    ]
    assert [issue.field for issue in result.issues] == [
        "nodes[0].keystore_id",
        "nodes[1].tls.client_cert_ref",
        "nodes[2].interactive_login",
    ]


def test_subio_legacy_proxies_are_explicitly_rejected_without_fallback():
    result = SubioParser().parse_result(
        """
proxies:
  - name: good
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: bad
    type: ss
    server: example.com
    port: invalid
    cipher: aes-256-gcm
    password: p
"""
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.subio.legacy-format-removed"
    ]
    assert result.issues[0].severity.value == "error"


def test_subio_public_field_contract_covers_every_concrete_protocol():
    registered = {descriptor.protocol for descriptor in protocol_registry.all()}
    assert PUBLIC_PROTOCOLS == registered
    assert Protocol.SOURCE_PASSTHROUGH not in PUBLIC_PROTOCOLS

    for descriptor in protocol_registry.all():
        assert public_node_fields(descriptor.protocol) == (
            TERMINAL_NATIVE_COMMON_FIELDS | descriptor.definition.terminal_native_fields
        ), descriptor.protocol.value


def test_subio_user_override_contract_is_explicit_and_valid():
    for descriptor in protocol_registry.all():
        protocol = descriptor.protocol
        model_fields = get_type_hints(descriptor.node_class).keys()
        override_fields = public_user_override_fields(protocol)
        assert override_fields <= model_fields


def test_subio_public_mapping_contract_covers_unconstrained_objects():
    def contains_unconstrained_mapping(expected):
        origin = get_origin(expected)
        if origin in {Union, types.UnionType}:
            return any(
                contains_unconstrained_mapping(arg) for arg in get_args(expected)
            )
        if origin is not dict:
            return False
        _, value_type = get_args(expected)
        return value_type is Any

    owners = list(PUBLIC_NESTED_FIELDS.items())
    owners.extend(
        (descriptor.node_class, public_node_fields(descriptor.protocol))
        for descriptor in protocol_registry.all()
    )

    for owner, public_fields in owners:
        hints = get_type_hints(owner)
        for name in public_fields:
            if name == "users":
                continue
            expected = hints[name]
            if contains_unconstrained_mapping(expected):
                assert public_mapping_spec(owner, name) is not None, (
                    owner.__name__,
                    name,
                )


def test_subio_json_schema_snapshot_matches_runtime_contract():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema == build_json_schema()

    ssh_schema = next(
        item
        for item in schema["properties"]["nodes"]["items"]["oneOf"]
        if item["title"] == "ssh"
    )
    user_schema = ssh_schema["properties"]["users"]
    overrides = user_schema["additionalProperties"]
    assert overrides["additionalProperties"] is False
    assert set(overrides["properties"]) == {
        "password",
        "port",
        "private_key",
        "private_key_passphrase",
        "server",
        "username",
    }


def test_subio_native_format_constructs_every_public_protocol():
    result = SubioParser().node_codec.decode_document(
        {"version": 2, "nodes": _all_native_protocol_nodes()}, "json"
    )

    assert result.issues == []
    assert {node.type for node in result.nodes} == PUBLIC_PROTOCOLS
    by_type = {node.type: node for node in result.nodes}
    for protocol in (
        Protocol.ANYTLS,
        Protocol.HYSTERIA,
        Protocol.HYSTERIA2,
        Protocol.TUIC,
    ):
        assert by_type[protocol].tls.enabled is True


def test_subio_parser_rejects_non_string_content():
    with pytest.raises(ValueError, match="Invalid content type"):
        SubioParser().parse_result(123)
