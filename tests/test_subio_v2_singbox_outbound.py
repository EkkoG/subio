import json
from pathlib import Path

import pytest

from subio_v2.adapters.singbox.outbound import (
    SINGBOX_OUTBOUND_CODECS,
    SINGBOX_OUTBOUND_CODECS_BY_TYPE,
    encode_outbound,
)
from subio_v2.adapters.singbox.parser import SingBoxParser
from subio_v2.adapters.subio.schema import PUBLIC_PROTOCOLS
from subio_v2.adapters.target import TargetValidationService
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.core.nodes import (
    HysteriaNode,
    NaiveNode,
    Protocol,
    RejectMode,
    RejectNode,
    ShadowsocksNode,
    ShadowTLSNode,
    SnellNode,
    Socks5Node,
    SourcePassthroughNode,
    TLSSettings,
    VmessNode,
)


SUPPORTED_TYPES = {
    "anytls",
    "block",
    "direct",
    "http",
    "hysteria",
    "hysteria2",
    "naive",
    "shadowsocks",
    "shadowtls",
    "snell",
    "socks",
    "ssh",
    "trojan",
    "tuic",
    "vless",
    "vmess",
}


def _schema_fixture() -> dict:
    return json.loads(
        (
            Path(__file__).parent
            / "fixtures/singbox/schema/type-disposition-v1.14.3.json"
        ).read_text()
    )


def _mixed_outbounds() -> list[dict]:
    tls = {"enabled": True, "server_name": "tls.example", "alpn": ["h2"]}
    return [
        {
            "type": "anytls",
            "tag": "anytls",
            "server": "anytls.example",
            "server_port": 443,
            "password": "any-secret",
            "tls": tls,
        },
        {"type": "block", "tag": "block"},
        {"type": "direct", "tag": "direct"},
        {
            "type": "http",
            "tag": "http",
            "server": "http.example",
            "server_port": 8080,
            "username": "user",
            "password": "http-secret",
        },
        {
            "type": "hysteria",
            "tag": "hysteria",
            "server": "hy.example",
            "server_port": 443,
            "auth_str": "hy-secret",
            "tls": tls,
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "server": "hy2.example",
            "server_port": 443,
            "password": "hy2-secret",
            "tls": tls,
        },
        {
            "type": "naive",
            "tag": "naive",
            "server": "naive.example",
            "server_port": 443,
            "username": "user",
            "password": "naive-secret",
            "tls": tls,
        },
        {
            "type": "shadowsocks",
            "tag": "ss",
            "server": "ss.example",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "ss-secret",
            "network": "tcp",
        },
        {
            "type": "shadowtls",
            "tag": "shadowtls",
            "server": "shadowtls.example",
            "server_port": 443,
            "version": 3,
            "password": "shadow-secret",
            "tls": tls,
        },
        {
            "type": "snell",
            "tag": "snell-v4",
            "server": "snell4.example",
            "server_port": 443,
            "version": 4,
            "psk": "snell-secret",
            "reuse": True,
            "obfs_mode": "http",
            "obfs_host": "example.com",
        },
        {
            "type": "snell",
            "tag": "snell-v6",
            "server": "snell6.example",
            "server_port": 443,
            "version": 6,
            "psk": "snell-secret",
            "mode": "unshaped",
        },
        {
            "type": "socks",
            "tag": "socks",
            "server": "socks.example",
            "server_port": 1080,
            "version": "5",
            "username": "user",
            "password": "socks-secret",
        },
        {
            "type": "ssh",
            "tag": "ssh",
            "server": "ssh.example",
            "server_port": 22,
            "user": "root",
            "password": "ssh-secret",
        },
        {
            "type": "trojan",
            "tag": "trojan",
            "server": "trojan.example",
            "server_port": 443,
            "password": "trojan-secret",
            "tls": tls,
        },
        {
            "type": "tuic",
            "tag": "tuic",
            "server": "tuic.example",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000",
            "password": "tuic-secret",
            "tls": tls,
        },
        {
            "type": "vless",
            "tag": "vless",
            "server": "vless.example",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "flow": "xtls-rprx-vision",
            "network": "tcp",
            "tls": tls,
        },
        {
            "type": "vmess",
            "tag": "vmess",
            "server": "vmess.example",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000002",
            "security": "auto",
            "network": "tcp",
            "tls": tls,
        },
    ]


def test_singbox_outbound_codec_registry_matches_pinned_supported_partition():
    fixture = _schema_fixture()

    assert set(SINGBOX_OUTBOUND_CODECS_BY_TYPE) == set(fixture["outbound"]["supported"])
    assert fixture["outbound"]["nested_variants"] == {"snell": [4, 6]}


def test_singbox_mixed_supported_outbounds_round_trip_through_target_codecs():
    parser = SingBoxParser()
    original = _mixed_outbounds()

    parsed = parser.parse_result({"outbounds": original})

    assert parsed.issues == []
    assert {item["type"] for item in original} == SUPPORTED_TYPES
    assert len(parsed.nodes) == len(original)

    service = TargetValidationService("sing-box")
    encoded = []
    for node in parsed.nodes:
        codec = SINGBOX_OUTBOUND_CODECS[node.type]
        result = service.encode_node(node, codec.encode)
        assert result.issues == [], (node.name, result.issues)
        assert result.supported_node is node
        encoded.append(result.content)

    reparsed = parser.parse_result({"outbounds": encoded})
    assert reparsed.issues == []
    assert reparsed.nodes == parsed.nodes


def test_singbox_standalone_shadowtls_does_not_use_inner_wrapper():
    result = SingBoxParser().parse_result(
        {
            "outbounds": [
                {
                    "type": "shadowtls",
                    "tag": "standalone",
                    "server": "shadow.example",
                    "server_port": 443,
                    "version": 3,
                    "password": "secret",
                    "tls": {"enabled": True, "server_name": "cover.example"},
                }
            ]
        }
    )

    assert result.issues == []
    node = result.nodes[0]
    assert isinstance(node, ShadowTLSNode)
    assert node.shadow_tls.enabled is False
    assert encode_outbound(node)["type"] == "shadowtls"


def test_singbox_shadowtls_uses_official_v1_default_without_password():
    result = SingBoxParser().parse_result(
        {
            "outbounds": [
                {
                    "type": "shadowtls",
                    "tag": "default-version",
                    "server": "shadow.example",
                    "server_port": 443,
                    "tls": {"enabled": True},
                }
            ]
        }
    )

    assert result.issues == []
    node = result.nodes[0]
    assert isinstance(node, ShadowTLSNode)
    assert node.version == 1
    assert encode_outbound(node)["version"] == 1


def test_singbox_shadowtls_v1_rejects_password():
    result = SingBoxParser().parse_result(
        {
            "outbounds": [
                {
                    "type": "shadowtls",
                    "tag": "invalid-v1",
                    "server": "shadow.example",
                    "server_port": 443,
                    "version": 1,
                    "password": "secret",
                    "tls": {"enabled": True},
                }
            ]
        }
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.singbox.unsupported-protocol-variant"
    assert "secret" not in repr(result.issues)


@pytest.mark.parametrize(
    "tls",
    [None, {"enabled": False}],
)
def test_singbox_shadowtls_requires_explicit_enabled_tls(tls):
    outbound = {
        "type": "shadowtls",
        "tag": "shadowtls",
        "server": "shadow.example",
        "server_port": 443,
        "version": 3,
        "password": "secret",
    }
    if tls is not None:
        outbound["tls"] = tls

    result = SingBoxParser().parse_result({"outbounds": [outbound]})

    assert result.nodes == []
    assert result.issues[0].field in {
        "outbounds[0].tls",
        "outbounds[0].tls.enabled",
    }
    assert "secret" not in repr(result.issues)


@pytest.mark.parametrize(
    "outbound_type", ["bridge", "selector", "tor", "urltest", "future"]
)
def test_singbox_excluded_and_unknown_types_fail_without_passthrough(outbound_type):
    result = SingBoxParser().parse_result(
        {"outbounds": [{"type": outbound_type, "tag": "rejected"}]}
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.singbox.unsupported-type"
    assert result.issues[0].protocol == outbound_type


@pytest.mark.parametrize(
    "outbound,field",
    [
        (
            {
                "type": "ssh",
                "tag": "ssh",
                "server": "ssh.example",
                "server_port": 22,
                "user": "root",
                "private_key_path": "/tmp/DO-NOT-READ",
            },
            "private_key_path",
        ),
        (
            {
                "type": "naive",
                "tag": "naive",
                "server": "naive.example",
                "server_port": 443,
                "password": "secret",
                "tls": {
                    "enabled": True,
                    "certificate_path": "/tmp/DO-NOT-READ",
                },
            },
            "tls.certificate_path",
        ),
        (
            {
                "type": "vmess",
                "tag": "vmess",
                "server": "vmess.example",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": {"type": "ws", "path": "/secret"},
            },
            "transport",
        ),
    ],
)
def test_singbox_unmapped_and_path_fields_reject_whole_node_without_secret_leak(
    outbound, field
):
    result = SingBoxParser().parse_result({"outbounds": [outbound]})

    assert result.nodes == []
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.field == f"outbounds[0].{field}"
    assert issue.code in {
        "parse.singbox.unsafe-field",
        "parse.singbox.unsupported-field",
    }
    assert "DO-NOT-READ" not in repr(result.issues)
    assert "/secret" not in repr(result.issues)


def test_singbox_block_only_accepts_reject_mode():
    node = RejectNode(name="blocked", mode=RejectMode.DROP, udp=False)
    check = TargetValidationService("sing-box").check_node(node)

    assert not check.supported
    assert any(issue.field == "mode" for issue in check.warnings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detour", "proxy"),
        ("bind_interface", "en0"),
        ("routing_mark", 1),
        ("tcp_fast_open", True),
        ("tcp_multi_path", True),
    ],
)
def test_singbox_block_rejects_shared_dial_fields(field, value):
    result = SingBoxParser().parse_result(
        {"outbounds": [{"type": "block", "tag": "blocked", field: value}]}
    )

    assert result.nodes == []
    assert result.issues[0].field == f"outbounds[0].{field}"
    assert result.issues[0].code == "parse.singbox.unsupported-field"


def test_singbox_block_emits_only_official_type_and_tag():
    node = RejectNode(name="blocked", mode=RejectMode.REJECT, udp=False)

    assert encode_outbound(node) == {"type": "block", "tag": "blocked"}

    node.interface_name = "en0"
    check = TargetValidationService("sing-box").check_node(node)
    assert not check.supported
    assert any(issue.field == "interface_name" for issue in check.warnings)


def test_singbox_routing_mark_uses_official_unsigned_32_bit_range():
    contract = _schema_fixture()["corrective_contracts"]["routing_mark"]
    valid = {
        "type": "direct",
        "tag": "direct",
        "routing_mark": contract["maximum"],
    }

    parsed = SingBoxParser().parse_result({"outbounds": [valid]})
    assert parsed.issues == []
    assert encode_outbound(parsed.nodes[0])["routing_mark"] == contract["maximum"]

    for value in (contract["minimum"] - 1, contract["maximum"] + 1):
        rejected = SingBoxParser().parse_result(
            {"outbounds": [{**valid, "routing_mark": value}]}
        )
        assert rejected.nodes == []
        assert rejected.issues[0].code == "parse.singbox.invalid-field"


def test_singbox_official_shadowsocks_method_matrix():
    methods = _schema_fixture()["corrective_contracts"]["shadowsocks_method"]
    for method in methods:
        result = SingBoxParser().parse_result(
            {
                "outbounds": [
                    {
                        "type": "shadowsocks",
                        "tag": method,
                        "server": "ss.example",
                        "server_port": 8388,
                        "method": method,
                        "password": "secret",
                    }
                ]
            }
        )
        assert result.issues == [], method

    invalid = ShadowsocksNode(
        name="invalid",
        server="ss.example",
        port=8388,
        cipher="future-cipher",
        password="secret",
    )
    check = TargetValidationService("sing-box").check_node(invalid)
    assert not check.supported
    assert any(issue.field == "cipher" for issue in check.warnings)


def test_singbox_official_vmess_enum_matrix():
    contract = _schema_fixture()["corrective_contracts"]
    base = {
        "type": "vmess",
        "tag": "vmess",
        "server": "vmess.example",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
    }
    for security in contract["vmess_security"]:
        result = SingBoxParser().parse_result(
            {"outbounds": [{**base, "security": security}]}
        )
        assert result.issues == [], security
    for packet_encoding in contract["vmess_packet_encoding"]:
        result = SingBoxParser().parse_result(
            {"outbounds": [{**base, "packet_encoding": packet_encoding}]}
        )
        assert result.issues == [], packet_encoding

    invalid = VmessNode(
        name="invalid",
        server="vmess.example",
        port=443,
        uuid=base["uuid"],
        cipher="future-security",
        packet_encoding="future-packet",
    )
    check = TargetValidationService("sing-box").check_node(invalid)
    assert not check.supported
    assert {issue.field for issue in check.warnings} >= {"cipher", "packet_encoding"}


def test_singbox_official_snell_variant_enum_matrix():
    contract = _schema_fixture()["corrective_contracts"]
    base = {
        "type": "snell",
        "tag": "snell",
        "server": "snell.example",
        "server_port": 443,
        "psk": "secret",
    }
    for obfs_mode in contract["snell_v4_obfs_mode"]:
        result = SingBoxParser().parse_result(
            {"outbounds": [{**base, "version": 4, "obfs_mode": obfs_mode}]}
        )
        assert result.issues == [], obfs_mode
    for mode in contract["snell_v6_mode"]:
        result = SingBoxParser().parse_result(
            {"outbounds": [{**base, "version": 6, "mode": mode}]}
        )
        assert result.issues == [], mode

    invalid = SnellNode(
        name="invalid",
        server="snell.example",
        port=443,
        version=4,
        psk="secret",
        obfs="future-obfs",
    )
    check = TargetValidationService("sing-box").check_node(invalid)
    assert not check.supported
    assert any(issue.field == "obfs" for issue in check.warnings)


@pytest.mark.parametrize(
    ("outbound", "field", "code"),
    [
        (
            {
                "type": "shadowsocks",
                "tag": "ss",
                "server": "ss.example",
                "server_port": 8388,
                "method": "future-cipher",
                "password": "secret",
            },
            "method",
            "parse.singbox.invalid-field",
        ),
        (
            {
                "type": "vmess",
                "tag": "vmess-security",
                "server": "vmess.example",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "security": "future-security",
            },
            "security",
            "parse.singbox.invalid-field",
        ),
        (
            {
                "type": "vmess",
                "tag": "vmess-packet",
                "server": "vmess.example",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "packet_encoding": "future-packet",
            },
            "packet_encoding",
            "parse.singbox.invalid-field",
        ),
        (
            {
                "type": "snell",
                "tag": "snell-v4-mode",
                "server": "snell.example",
                "server_port": 443,
                "version": 4,
                "psk": "secret",
                "mode": "default",
            },
            "mode",
            "parse.singbox.unsupported-protocol-variant",
        ),
        (
            {
                "type": "snell",
                "tag": "snell-v6-obfs",
                "server": "snell.example",
                "server_port": 443,
                "version": 6,
                "psk": "secret",
                "obfs_mode": "http",
            },
            "obfs_mode",
            "parse.singbox.unsupported-protocol-variant",
        ),
    ],
)
def test_singbox_rejects_values_outside_official_variant_contracts(
    outbound, field, code
):
    result = SingBoxParser().parse_result({"outbounds": [outbound]})

    assert result.nodes == []
    assert result.issues[0].field == f"outbounds[0].{field}"
    assert result.issues[0].code == code


def test_singbox_socks_tls_is_rejected_instead_of_dropped():
    node = Socks5Node(
        name="socks",
        server="socks.example",
        port=1080,
        tls=TLSSettings(enabled=True, server_name="socks.example"),
    )

    result = TargetValidationService("sing-box").encode_node(node, encode_outbound)

    assert result.content is None
    assert result.supported_node is None
    assert any(issue.field == "tls" for issue in result.issues)


def test_singbox_common_target_diagnostics_match_emitted_bind_and_mark_fields():
    node = ShadowsocksNode(
        name="ss",
        server="ss.example",
        port=8388,
        cipher="aes-256-gcm",
        password="secret",
        interface_name="en0",
        routing_mark=7,
    )

    result = TargetValidationService("sing-box").encode_node(node, encode_outbound)

    assert result.issues == []
    assert result.content["bind_interface"] == "en0"
    assert result.content["routing_mark"] == 7


def test_singbox_new_runtime_nodes_have_explicit_non_public_native_policy():
    assert Protocol.NAIVE not in PUBLIC_PROTOCOLS
    assert Protocol.SHADOWTLS not in PUBLIC_PROTOCOLS

    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/subio-node-v2.schema.json").read_text()
    )
    titles = {item["title"] for item in schema["properties"]["nodes"]["items"]["oneOf"]}
    assert {"naive", "shadowtls"}.isdisjoint(titles)

    documentation = (
        Path(__file__).parents[1] / "docs/subio_node_format.md"
    ).read_text()
    assert "`naive` 与独立 `shadowtls`" in documentation


def test_singbox_runtime_node_repr_hides_credentials():
    assert "secret" not in repr(
        NaiveNode(
            name="naive",
            server="naive.example",
            port=443,
            password="secret",
        )
    )
    assert "secret" not in repr(
        ShadowTLSNode(
            name="shadowtls",
            server="shadow.example",
            port=443,
            password="secret",
        )
    )
    assert "secret" not in repr(
        HysteriaNode(
            name="hysteria",
            server="hysteria.example",
            port=443,
            auth_str="secret",
        )
    )
    assert "secret" not in repr(
        HysteriaNode(
            name="hysteria-obfs",
            server="hysteria.example",
            port=443,
            obfs="secret",
        )
    )


@pytest.mark.parametrize("outbound_type", ["naive", "shadowtls"])
def test_singbox_only_protocols_do_not_change_mihomo_unknown_passthrough(
    outbound_type,
):
    result = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "future",
                    "type": outbound_type,
                    "server": "example.com",
                    "port": 443,
                }
            ]
        }
    )

    assert result.issues == []
    assert isinstance(result.nodes[0], SourcePassthroughNode)
