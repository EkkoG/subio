import base64
import json
from pathlib import Path
from uuid import UUID, uuid5

import pytest

from subio_v2.adapters.catalog import get_emitter
from subio_v2.adapters.subio.parser import SubioParser
from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.core.nodes import (
    Network,
    Protocol,
    TLSSettings,
    TransportSettings,
    VlessNode,
    VmessNode,
)

USER_ID = "2cae91b3-f85c-433b-88ee-a002b9ed6d61"
PUBLIC_KEY = "dwrjY6KiAMPxKdlF7T4AWFXXBtsxeHCXtBQYeCOdZV4"
BASE = f"node = vless, example.com, 443, username={USER_ID}"


def test_surge_vless_reality_vision_round_trip():
    parsed = SurgeParser().parse_result(
        BASE
        + f", flow=xtls-rprx-vision, sni=www.example.com, reality-public-key={PUBLIC_KEY}, reality-short-id=0123456789abcdef"
    )
    assert parsed.issues == []
    node = parsed.nodes[0]
    assert isinstance(node, VlessNode)
    assert node.tls.enabled is True
    assert node.udp is True
    assert node.packet_encoding == "xudp"
    assert node.tls.reality_opts == {
        "public-key": PUBLIC_KEY,
        "short-id": "0123456789abcdef",
    }
    emitted = SurgeEmitter().emit_result(parsed.nodes)
    assert emitted.errors == []
    assert "udp-relay" not in emitted.content
    again = SurgeParser().parse_result(emitted.content)
    assert again.issues == []
    assert again.nodes[0].tls == node.tls
    assert again.nodes[0].flow == node.flow
    assert again.nodes[0].packet_encoding == "xudp"


def test_surge_vless_grpc_preserves_literal_path_mode_authority_and_alpn():
    parsed = SurgeParser().parse_result(
        BASE
        + ', grpc=true, grpc-service-name=/my/path/tun|tunmulti, grpc-mode=multi, grpc-authority=edge.example.com, tls=true, alpn="h2,http/1.1"'
    )
    assert parsed.issues == []
    node = parsed.nodes[0]
    assert node.transport.network == Network.GRPC
    assert node.transport.grpc_service_name == "/my/path/tun|tunmulti"
    assert node.transport.grpc_mode == "multi"
    assert node.transport.grpc_authority == "edge.example.com"
    assert node.tls.server_name is None
    assert node.tls.alpn == ["h2", "http/1.1"]
    emitted = SurgeEmitter().emit_result(parsed.nodes)
    assert emitted.errors == []
    again = SurgeParser().parse_result(emitted.content)
    assert again.issues == []
    assert again.nodes[0].transport == node.transport
    assert again.nodes[0].tls == node.tls


@pytest.mark.parametrize(
    "extra",
    [
        "",
        ", tls=true",
        ", ws=true",
        ", ws=true, tls=true",
        ", tls=true, flow=xtls-rprx-vision",
        ", tls=true, flow=xtls-rprx-vision-udp443",
        f", grpc=true, sni=www.example.com, reality-public-key={PUBLIC_KEY}",
    ],
)
def test_surge_vless_supported_combinations(extra):
    parsed = SurgeParser().parse_result(BASE + extra)
    assert parsed.issues == []
    emitted = SurgeEmitter().emit_result(parsed.nodes)
    assert emitted.errors == []
    assert len(SurgeParser().parse_result(emitted.content).nodes) == 1


@pytest.mark.parametrize(
    "extra,field",
    [
        (", ws=true, grpc=true, tls=true", "transport.network"),
        (", grpc=true", "tls.enabled"),
        (", flow=xtls-rprx-vision", "flow"),
        (", ws=true, tls=true, flow=xtls-rprx-vision", "flow"),
        (", flow=unknown, tls=true", "flow"),
        (", encryption=unsupported", "encryption"),
        (", reality-short-id=00", "tls.reality_opts.short-id"),
        (f", reality-public-key={PUBLIC_KEY}", "tls.server_name"),
        (
            ", reality-public-key=invalid, sni=www.example.com",
            "tls.reality_opts.public-key",
        ),
        (
            f", reality-public-key={PUBLIC_KEY}, sni=www.example.com, reality-short-id=xyz",
            "tls.reality_opts.short-id",
        ),
        (
            f", ws=true, reality-public-key={PUBLIC_KEY}, sni=www.example.com",
            "transport.network",
        ),
        (", grpc=true, tls=true, grpc-mode=unknown", "transport.grpc_mode"),
        (", grpc-authority=example.com", "transport.grpc_authority"),
    ],
)
def test_surge_vless_invalid_source_is_rejected_with_safe_field(extra, field):
    result = SurgeParser().parse_result(BASE + extra)
    assert result.nodes == []
    assert any(issue.field == field for issue in result.issues)
    assert all(
        USER_ID not in issue.message and PUBLIC_KEY not in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize("user", ["my-user", "a" * 30, "用户"])
def test_surge_vless_short_id_normalization(user):
    result = SurgeParser().parse_result(
        f"node = vless, example.com, 443, username={user}"
    )
    assert result.issues == []
    assert result.nodes[0].uuid == str(uuid5(UUID(int=0), user))


@pytest.mark.parametrize("user", ["", "a" * 31, "用" * 11])
def test_surge_vless_invalid_username_does_not_leak(user):
    result = SurgeParser().parse_result(
        f"node = vless, example.com, 443, username={user}"
    )
    assert result.nodes == []
    assert result.issues[0].field == "uuid"
    assert "username=" not in result.issues[0].message


def test_native_grpc_fields_and_unsupported_targets_use_real_emitters():
    parsed = SubioParser().parse_result(
        json.dumps(
            {
                "version": 2,
                "nodes": [
                    {
                        "name": "node",
                        "type": "vless",
                        "server": "example.com",
                        "port": 443,
                        "uuid": USER_ID,
                        "tls": {"enabled": True},
                        "transport": {
                            "network": "grpc",
                            "grpc_mode": "multi",
                            "grpc_authority": "edge.example.com",
                        },
                    }
                ],
            }
        )
    )
    assert parsed.issues == []
    assert SurgeEmitter().emit_result(parsed.nodes).errors == []
    for target in ("mihomo", "stash", "sing-box"):
        emitted = get_emitter(target).emit_result(parsed.nodes)
        assert emitted.supported_nodes == []
        assert {issue.field for issue in emitted.errors} >= {
            "transport.grpc_mode",
            "transport.grpc_authority",
        }


def test_direct_node_cannot_bypass_vless_target_checks():
    node = VlessNode(
        name="node",
        type=Protocol.VLESS,
        server="example.com",
        port=443,
        uuid=USER_ID,
        transport=TransportSettings(network=Network.GRPC),
    )
    result = SurgeEmitter().emit_result([node])
    assert result.supported_nodes == []
    assert result.errors[0].field == "tls.enabled"


@pytest.mark.parametrize(
    "target", ["surge", "mihomo", "stash", "sing-box", "v2rayn", "dae"]
)
def test_shared_grpc_fields_cannot_be_ignored_by_other_protocols(target):
    node = VmessNode(
        name="node",
        type=Protocol.VMESS,
        server="example.com",
        port=443,
        uuid=USER_ID,
        tls=TLSSettings(enabled=True),
        transport=TransportSettings(
            network=Network.GRPC, grpc_mode="multi", grpc_authority="edge.example.com"
        ),
    )
    result = get_emitter(target).emit_result([node])
    assert result.supported_nodes == []
    assert {issue.field for issue in result.errors} >= {
        "transport.grpc_mode",
        "transport.grpc_authority",
    }


def test_reality_source_normalizes_ignored_certificate_options_with_diagnostics():
    parsed = SurgeParser().parse_result(
        BASE
        + f", reality-public-key={PUBLIC_KEY}, sni=www.example.com, skip-cert-verify=true, server-cert-fingerprint-sha256={'a' * 64}"
    )
    assert len(parsed.nodes) == 1
    assert {issue.field for issue in parsed.issues} == {
        "tls.skip_cert_verify",
        "tls.certificate_sha256",
    }
    assert all(issue.severity.value == "warning" for issue in parsed.issues)
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    assert "skip-cert-verify" not in output.content
    assert "server-cert-fingerprint-sha256" not in output.content
    parsed.nodes[0].tls.certificate_sha256 = "a" * 64
    rejected = SurgeEmitter().emit_result(parsed.nodes)
    assert rejected.supported_nodes == []
    assert rejected.errors[0].field == "tls.certificate_sha256"


def test_vless_unknown_safe_parameters_and_shadow_tls_keep_existing_boundaries():
    parsed = SurgeParser().parse_result(
        BASE
        + ", future-safe=value, shadow-tls-password=test, shadow-tls-sni=cover.example.com, shadow-tls-version=3"
    )
    assert parsed.issues == []
    result = SurgeEmitter().emit_result(parsed.nodes)
    assert result.errors == []
    assert "future-safe=value" in result.content
    assert "shadow-tls-version=3" in result.content
    cross = get_emitter("mihomo").emit_result(parsed.nodes)
    assert any(
        issue.code == "conversion.unconsumed-source-field" for issue in cross.issues
    )


def test_vless_automatic_udp_and_packet_encoding_are_explicit():
    node = VlessNode(
        name="node",
        type=Protocol.VLESS,
        server="example.com",
        port=443,
        uuid=USER_ID,
        udp=False,
    )
    output = SurgeEmitter().emit_result([node])
    assert output.errors == []
    assert any(
        issue.field == "udp" and issue.code == "conversion.automatic-udp"
        for issue in output.issues
    )
    assert "udp-relay" not in output.content
    node.packet_encoding = "packetaddr"
    output = SurgeEmitter().emit_result([node])
    assert output.supported_nodes == []
    assert output.errors[0].field == "packet_encoding"


def test_vless_duplicate_consumed_values_cannot_revive_normalized_settings():
    parsed = SurgeParser().parse_result(
        BASE
        + ", ws=true, ws=false, encryption=unsupported, encryption=none, tls=true, tls=false"
    )
    assert parsed.issues == []
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    again = SurgeParser().parse_result(output.content)
    assert again.issues == []
    assert again.nodes[0].transport.network_value == "tcp"
    assert again.nodes[0].tls.enabled is False
    assert "encryption=unsupported" not in output.content


@pytest.mark.parametrize(
    "key",
    [
        PUBLIC_KEY,
        base64.b64encode(b"\xff" * 32).decode(),
        base64.urlsafe_b64encode(b"\xff" * 32).decode(),
    ],
)
def test_vless_reality_accepts_official_base64_forms(key):
    parsed = SurgeParser().parse_result(
        BASE + f", reality-public-key={key}, sni=www.example.com"
    )
    assert parsed.issues == []
    assert SurgeEmitter().emit_result(parsed.nodes).errors == []


@pytest.mark.parametrize(
    "sni", ["a?b.example", "example..com", "-example.com", "example.com/path", "off"]
)
def test_vless_reality_rejects_invalid_sni(sni):
    parsed = SurgeParser().parse_result(
        BASE + f", reality-public-key={PUBLIC_KEY}, sni={sni}"
    )
    assert parsed.nodes == []
    assert any(issue.field == "tls.server_name" for issue in parsed.issues)


def test_surge_vless_official_fixture():
    source = Path(__file__).parent / "fixtures/surge/official/vless.conf"
    parsed = SurgeParser().parse_result(source.read_text())
    assert parsed.issues == []
    assert len(parsed.nodes) == 4
    assert SurgeEmitter().emit_result(parsed.nodes).errors == []
