import ipaddress
import struct
from pathlib import Path

import pytest
import zstandard

from subio_v2.core.errors import ConfigError
from subio_v2.rules import mrs


def _compress(payload: bytes) -> bytes:
    return zstandard.ZstdCompressor().compress(payload)


def _mrs_payload(behavior: int, count: int, body: bytes) -> bytes:
    return b"MRS\x01" + bytes([behavior]) + struct.pack(">qq", count, 0) + body


def _ip_range_body(first: str, last: str) -> bytes:
    first_address = ipaddress.ip_address(first)
    last_address = ipaddress.ip_address(last)
    if first_address.version == 4:
        first_address = ipaddress.ip_address(f"::ffff:{first_address}")
    if last_address.version == 4:
        last_address = ipaddress.ip_address(f"::ffff:{last_address}")
    return b"\x01" + struct.pack(">q", 1) + first_address.packed + last_address.packed


@pytest.mark.parametrize(
    ("behavior", "fixture_name", "expected"),
    [
        (
            "domain",
            "domain.mrs",
            ["*.cdn.example.net", "+.example.com", "exact.example.org"],
        ),
        ("ipcidr", "ipcidr.mrs", ["192.0.2.0/24", "2001:db8::/32"]),
    ],
)
def test_decode_official_mrs_fixtures(behavior, fixture_name, expected):
    fixture = Path(__file__).parent / "fixtures/rulesets/mrs" / fixture_name

    assert mrs.decode_mrs(fixture.read_bytes(), behavior) == expected


def test_decode_mrs_rejects_behavior_mismatch():
    content = _compress(_mrs_payload(1, 1, _ip_range_body("192.0.2.0", "192.0.2.0")))

    with pytest.raises(ConfigError, match="behavior does not match"):
        mrs.decode_mrs(content, "domain")


def test_decode_mrs_rejects_invalid_range_and_count():
    invalid_range = _compress(
        _mrs_payload(1, 1, _ip_range_body("192.0.2.2", "192.0.2.1"))
    )
    wrong_count = _compress(
        _mrs_payload(1, 2, _ip_range_body("192.0.2.0", "192.0.2.255"))
    )

    with pytest.raises(ConfigError, match="Invalid MRS IP address range"):
        mrs.decode_mrs(invalid_range, "ipcidr")
    with pytest.raises(ConfigError, match="rule count does not match"):
        mrs.decode_mrs(wrong_count, "ipcidr")


def test_decode_mrs_rejects_trailing_compressed_or_payload_data():
    payload = _mrs_payload(1, 1, _ip_range_body("192.0.2.0", "192.0.2.0"))

    with pytest.raises(ConfigError, match="zstd stream"):
        mrs.decode_mrs(_compress(payload) + _compress(payload), "ipcidr")
    with pytest.raises(ConfigError, match="Unexpected trailing data"):
        mrs.decode_mrs(_compress(payload + b"x"), "ipcidr")


def test_decode_mrs_enforces_compressed_and_decompressed_limits(monkeypatch):
    payload = _mrs_payload(1, 1, _ip_range_body("192.0.2.0", "192.0.2.0"))
    content = _compress(payload)

    monkeypatch.setattr(mrs, "MAX_MRS_INPUT_SIZE", len(content) - 1)
    with pytest.raises(ConfigError, match="compressed input exceeds"):
        mrs.decode_mrs(content, "ipcidr")

    monkeypatch.setattr(mrs, "MAX_MRS_INPUT_SIZE", len(content))
    monkeypatch.setattr(mrs, "MAX_MRS_OUTPUT_SIZE", len(payload) - 1)
    with pytest.raises(ConfigError, match="decompressed output exceeds"):
        mrs.decode_mrs(content, "ipcidr")
