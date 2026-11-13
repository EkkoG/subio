import ipaddress
import hashlib
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


def _domain_mrs(domains):
    trie = {}
    for domain in domains:
        node = trie
        for char in domain[::-1].encode():
            node = node.setdefault(char, {})
        node[None] = None
    queue = [trie]
    leaves = []
    label_bits = []
    labels = bytearray()
    for node in queue:
        leaves.append(int(None in node))
        for char in sorted(key for key in node if key is not None):
            queue.append(node[char])
            labels.append(char)
            label_bits.append(0)
        label_bits.append(1)

    def bitmap(bits):
        words = [0] * ((len(bits) + 63) // 64)
        for index, bit in enumerate(bits):
            words[index // 64] |= bit << (index % 64)
        return struct.pack(">q", len(words)) + b"".join(struct.pack(">Q", word) for word in words)

    body = b"\x01" + bitmap(leaves) + bitmap(label_bits) + struct.pack(">q", len(labels)) + labels
    return _compress(_mrs_payload(0, len(domains), body))


def test_domain_trie_bitmap_budget_counts_nodes_instead_of_rules():
    # Each unique prefix adds several trie nodes to one rule.
    domains = [hashlib.sha256(str(index).encode()).hexdigest()[:24] + ".example.test" for index in range(32768)]
    assert mrs.decode_mrs(_domain_mrs(domains), "domain") == sorted(domains)


@pytest.mark.parametrize("first,last,expected", [
    ("::", "::ffff:ffff:ffff", "::/80"),
    ("192.0.2.0", "192.0.2.255", "192.0.2.0/24"),
    ("::ffff:ffff:ff00", "::1:0:0:0", None),
])
def test_mapped_ipv4_ranges_are_unmapped_as_a_pair(first, last, expected):
    prefixes = list(ipaddress.summarize_address_range(ipaddress.ip_address(first), ipaddress.ip_address(last)))
    body = _ip_range_body(first, last)
    count = 1 if expected else len(prefixes)
    actual = mrs.decode_mrs(_compress(_mrs_payload(1, count, body)), "ipcidr")
    assert actual == ([expected] if expected else [str(prefix) for prefix in prefixes])


def test_domain_bitmap_length_cannot_exceed_available_payload():
    body = b"\x01" + struct.pack(">q", 2**40)
    with pytest.raises(ConfigError, match="domain leaves length"):
        mrs.decode_mrs(_compress(_mrs_payload(0, 1, body)), "domain")


def test_domain_bitmap_must_match_trie_structure():
    body = b"\x01" + struct.pack(">qQqQq", 1, 1 << 63, 1, 3, 1) + b"a"
    with pytest.raises(ConfigError, match="bitmap"):
        mrs.decode_mrs(_compress(_mrs_payload(0, 1, body)), "domain")
