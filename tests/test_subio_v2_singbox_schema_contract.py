import json
from pathlib import Path


FIXTURE = (
    Path(__file__).parent
    / "fixtures/singbox/schema/type-disposition-v1.14.3.json"
)

EXPECTED_OUTBOUND_TYPES = [
    "anytls",
    "block",
    "bridge",
    "direct",
    "http",
    "hysteria",
    "hysteria2",
    "naive",
    "selector",
    "shadowsocks",
    "shadowtls",
    "snell",
    "socks",
    "ssh",
    "tor",
    "trojan",
    "tuic",
    "urltest",
    "vless",
    "vmess",
]
EXPECTED_SUPPORTED_OUTBOUNDS = [
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
]
EXPECTED_EXCLUDED_OUTBOUNDS = ["bridge", "selector", "tor", "urltest"]

EXPECTED_ENDPOINT_TYPES = [
    "openconnect",
    "openvpn-client",
    "openvpn-server",
    "tailscale",
    "wireguard",
]
EXPECTED_SUPPORTED_ENDPOINTS = [
    "openconnect",
    "openvpn-client",
    "tailscale",
    "wireguard",
]
EXPECTED_EXCLUDED_ENDPOINTS = ["openvpn-server"]


def _load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _assert_exhaustive_partition(
    schema_types: list[str], supported: list[str], excluded: list[str]
) -> None:
    known = set(schema_types)
    supported_set = set(supported)
    excluded_set = set(excluded)

    assert len(known) == len(schema_types)
    assert len(supported_set) == len(supported)
    assert len(excluded_set) == len(excluded)
    assert supported_set.isdisjoint(excluded_set)
    assert supported_set | excluded_set == known


def test_singbox_schema_fixture_pins_official_v1_14_3_provenance():
    fixture = _load_fixture()

    assert fixture["source"] == {
        "url": (
            "https://raw.githubusercontent.com/SagerNet/sing-box/"
            "v1.14.3/docs/schema.json"
        ),
        "version": "v1.14.3",
        "sha256": (
            "15133dc518142b7082f120fa7ed08dabb"
            "5b28768850e4bebcde67272cbd58d47"
        ),
        "extracted_at": "2026-10-10",
        "definitions": {
            "outbound": "#/$defs/Outbound",
            "endpoint": "#/$defs/Endpoint",
        },
    }


def test_singbox_outbound_disposition_is_exhaustive_and_disjoint():
    outbound = _load_fixture()["outbound"]

    assert outbound["schema_types"] == EXPECTED_OUTBOUND_TYPES
    assert outbound["nested_variants"] == {"snell": [4, 6]}
    assert outbound["supported"] == EXPECTED_SUPPORTED_OUTBOUNDS
    assert outbound["excluded"] == EXPECTED_EXCLUDED_OUTBOUNDS
    _assert_exhaustive_partition(
        outbound["schema_types"], outbound["supported"], outbound["excluded"]
    )


def test_singbox_endpoint_disposition_is_exhaustive_and_disjoint():
    endpoint = _load_fixture()["endpoint"]

    assert endpoint["schema_types"] == EXPECTED_ENDPOINT_TYPES
    assert endpoint["supported"] == EXPECTED_SUPPORTED_ENDPOINTS
    assert endpoint["excluded"] == EXPECTED_EXCLUDED_ENDPOINTS
    _assert_exhaustive_partition(
        endpoint["schema_types"], endpoint["supported"], endpoint["excluded"]
    )


def test_singbox_types_after_the_pinned_baseline_remain_excluded():
    fixture = _load_fixture()
    policy = fixture["future_type_policy"]

    assert policy == {
        "unknown": "excluded",
        "known_after_baseline": {
            "outbound": ["tailcat"],
            "endpoint": ["masque"],
        },
    }
    assert set(policy["known_after_baseline"]["outbound"]).isdisjoint(
        fixture["outbound"]["schema_types"]
    )
    assert set(policy["known_after_baseline"]["endpoint"]).isdisjoint(
        fixture["endpoint"]["schema_types"]
    )
