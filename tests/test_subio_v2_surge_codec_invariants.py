from pathlib import Path

import pytest

from tests.support_target_views import all_platform_capabilities
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import Protocol
from subio_v2.parser.surge import SurgeParser
from subio_v2.surge.codecs import (
    DEFAULT_SURGE_TARGET,
    SURGE_CODEC_BY_KEYWORD,
    SURGE_CODEC_SPECS,
    SURGE_COMMON_PARAMETER_PATHS,
    SURGE_COMMON_PARAMETERS,
    SURGE_NODE_PROTOCOLS,
    SURGE_PROTOCOL_CODECS,
    SurgePolicyKind,
    SurgeUdpBehavior,
)
from subio_v2.surge.syntax import parse_proxy_line

PLATFORM_CAPABILITIES = all_platform_capabilities()
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "surge" / "official"


def test_surge_capabilities_and_emitters_derive_from_codec_registry():
    assert PLATFORM_CAPABILITIES["surge"]["protocols"] == set(SURGE_NODE_PROTOCOLS)
    assert {protocol.value for protocol in SURGE_PROTOCOL_CODECS} == set(
        SURGE_NODE_PROTOCOLS
    )
    assert all(callable(codec.emitter) for codec in SURGE_PROTOCOL_CODECS.values())


def test_surge_codec_keywords_are_unique_and_cover_official_fixtures():
    assert len(SURGE_CODEC_BY_KEYWORD) == len(SURGE_CODEC_SPECS)

    fixture_keywords: set[str] = set()
    for fixture in FIXTURE_DIR.glob("*.conf"):
        in_proxy = False
        for raw_line in fixture.read_text().splitlines():
            line = raw_line.strip()
            if line.lower() == "[proxy]":
                in_proxy = True
                continue
            if line.startswith("[") and line.endswith("]"):
                in_proxy = False
                continue
            if in_proxy and line and not line.startswith(("#", "//")):
                fixture_keywords.add(parse_proxy_line(line).type.lower())

    assert fixture_keywords - {"external"} <= set(SURGE_CODEC_BY_KEYWORD)
    assert "external" not in SURGE_CODEC_BY_KEYWORD


def test_every_consumed_parameter_has_an_emit_or_normalization_path():
    assert SURGE_COMMON_PARAMETERS <= SURGE_COMMON_PARAMETER_PATHS
    for codec in SURGE_CODEC_SPECS:
        assert codec.consumed_parameters <= codec.parameter_path_sources, codec.keyword


def test_every_node_codec_has_protocol_and_emitter():
    for codec in SURGE_CODEC_SPECS:
        if codec.policy_kind != SurgePolicyKind.NODE:
            continue
        assert codec.protocol is not None
        assert codec.emitter is not None


@pytest.mark.parametrize(
    ("keyword", "line", "protocol"),
    [
        (
            "ss",
            "node = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p",
            Protocol.SHADOWSOCKS,
        ),
        ("vmess", "node = vmess, example.com, 443, username=u", Protocol.VMESS),
        ("trojan", "node = trojan, example.com, 443, password=p", Protocol.TROJAN),
        ("socks5", "node = socks5, example.com, 1080", Protocol.SOCKS5),
        (
            "socks5-tls",
            "node = socks5-tls, example.com, 1080",
            Protocol.SOCKS5,
        ),
        ("http", "node = http, example.com, 80", Protocol.HTTP),
        ("https", "node = https, example.com, 443", Protocol.HTTP),
        (
            "h2-connect",
            "node = h2-connect, example.com, 443",
            Protocol.HTTP,
        ),
        ("anytls", "node = anytls, example.com, 443, password=p", Protocol.ANYTLS),
        (
            "ssh",
            "node = ssh, example.com, 22, username=root, password=p",
            Protocol.SSH,
        ),
        (
            "snell",
            "node = snell, example.com, 443, psk=p, version=5",
            Protocol.SNELL,
        ),
        ("tuic", "node = tuic, example.com, 443, token=t", Protocol.TUIC),
        (
            "tuic-v5",
            "node = tuic-v5, example.com, 443, uuid=u, password=p",
            Protocol.TUIC,
        ),
        (
            "hysteria2",
            "node = hysteria2, example.com, 443, password=p",
            Protocol.HYSTERIA2,
        ),
        (
            "masque",
            "node = masque, example.com, 443, username=u, password=p",
            Protocol.MASQUE,
        ),
        (
            "trust-tunnel",
            "node = trust-tunnel, example.com, 443, username=u, password=p",
            Protocol.TRUSTTUNNEL,
        ),
        ("direct", "node = direct", Protocol.DIRECT),
        ("reject", "node = reject", Protocol.REJECT),
        ("reject-drop", "node = reject-drop", Protocol.REJECT),
        ("reject-no-drop", "node = reject-no-drop", Protocol.REJECT),
        ("reject-tinygif", "node = reject-tinygif", Protocol.REJECT),
    ],
)
def test_node_codec_keywords_have_parser_paths(keyword, line, protocol):
    codec = SURGE_CODEC_BY_KEYWORD[keyword]
    result = SurgeParser().parse_result(line)

    assert result.issues == []
    assert len(result.nodes) == 1
    assert result.nodes[0].type == protocol == codec.protocol


def test_parser_path_samples_cover_all_non_resource_node_codecs():
    sampled = {
        "ss",
        "vmess",
        "trojan",
        "socks5",
        "socks5-tls",
        "http",
        "https",
        "h2-connect",
        "anytls",
        "ssh",
        "snell",
        "tuic",
        "tuic-v5",
        "hysteria2",
        "masque",
        "trust-tunnel",
        "direct",
        "reject",
        "reject-drop",
        "reject-no-drop",
        "reject-tinygif",
    }
    registered = {
        codec.keyword
        for codec in SURGE_CODEC_SPECS
        if codec.policy_kind == SurgePolicyKind.NODE
        and codec.keyword not in {"wireguard", "tailscale"}
    }
    assert sampled == registered
    parser_keywords = {
        codec.keyword for codec in SURGE_CODEC_SPECS if codec.parser is not None
    }
    assert parser_keywords == registered - {
        "direct",
        "reject",
        "reject-drop",
        "reject-no-drop",
        "reject-tinygif",
        "masque",
        "trust-tunnel",
    }
    assert all(
        callable(codec.parser)
        for codec in SURGE_CODEC_SPECS
        if codec.parser is not None
    )


@pytest.mark.parametrize(
    ("behavior", "keywords"),
    [
        (
            SurgeUdpBehavior.EXPLICIT,
            {"ss", "socks5", "socks5-tls", "h2-connect"},
        ),
        (
            SurgeUdpBehavior.AUTOMATIC,
            {
                "vmess",
                "trojan",
                "tuic",
                "tuic-v5",
                "hysteria2",
                "anytls",
                "wireguard",
                "tailscale",
                "masque",
                "direct",
            },
        ),
        (SurgeUdpBehavior.VERSIONED, {"snell"}),
        (
            SurgeUdpBehavior.UNSUPPORTED,
            {
                "http",
                "https",
                "ssh",
                "trust-tunnel",
                "reject",
                "reject-drop",
                "reject-no-drop",
                "reject-tinygif",
            },
        ),
    ],
)
def test_surge_udp_behavior_matrix(behavior, keywords):
    actual = {
        codec.keyword for codec in SURGE_CODEC_SPECS if codec.udp_behavior == behavior
    }
    assert actual == keywords


@pytest.mark.parametrize(
    "line",
    [
        "http = http, example.com, 80, udp-relay=true",
        "vmess = vmess, example.com, 443, username=u, udp-relay=false",
        "snell = snell, example.com, 443, psk=p, version=5, udp-relay=true",
        "masque = masque, example.com, 443, udp-relay=true",
        "trust = trust-tunnel, example.com, 443, username=u, password=p, udp-relay=false",
    ],
)
def test_non_explicit_udp_codecs_reject_udp_relay_parameter(line):
    result = SurgeParser().parse_result(line)

    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"


@pytest.mark.parametrize("keyword", ["direct", "reject", "reject-drop"])
def test_builtin_aliases_reject_positional_arguments(keyword):
    result = SurgeParser().parse_result(f"Alias = {keyword}, unexpected")

    assert result.nodes == []
    assert result.issues[0].code == "parse.line"


def test_latest_is_the_only_current_surge_target():
    assert DEFAULT_SURGE_TARGET == "latest"
    assert SurgeParser(target_version="latest").target_version == "latest"
    assert SurgeEmitter(target_version="latest").target_version == "latest"
    with pytest.raises(ValueError, match="latest Surge target"):
        SurgeParser(target_version="6.8")
    with pytest.raises(ValueError, match="latest Surge target"):
        SurgeEmitter(target_version="6.8")
