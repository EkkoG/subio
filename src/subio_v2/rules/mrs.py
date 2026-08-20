from __future__ import annotations

import ipaddress
import struct

import zstandard

from subio_v2.core.errors import ConfigError

MRS_MAGIC = b"MRS\x01"
MRS_BEHAVIOR = {"domain": 0, "ipcidr": 1}
MAX_MRS_INPUT_SIZE = 16 * 1024 * 1024
MAX_MRS_OUTPUT_SIZE = 64 * 1024 * 1024
MAX_MRS_ITEMS = 1_000_000
MAX_MRS_BITMAP_WORDS = (MAX_MRS_ITEMS + 63) // 64 + 1
MAX_MRS_DOMAIN_LENGTH = 255


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise ConfigError("Invalid MRS payload length")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def byte(self) -> int:
        return self.read(1)[0]

    def int64(self) -> int:
        return struct.unpack(">q", self.read(8))[0]

    def uint64(self) -> int:
        return struct.unpack(">Q", self.read(8))[0]

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset


def decode_mrs(content: bytes, behavior: str) -> list[str]:
    if behavior not in MRS_BEHAVIOR:
        raise ConfigError(f"MRS does not support behavior {behavior!r}")
    if not isinstance(content, bytes) or not content:
        raise ConfigError("MRS content must be non-empty bytes")
    if len(content) > MAX_MRS_INPUT_SIZE:
        raise ConfigError("MRS compressed input exceeds the size limit")

    try:
        frame_size = zstandard.frame_content_size(content)
        if frame_size == zstandard.CONTENTSIZE_ERROR:
            raise ConfigError("Invalid MRS zstd frame")
        if (
            frame_size != zstandard.CONTENTSIZE_UNKNOWN
            and frame_size > MAX_MRS_OUTPUT_SIZE
        ):
            raise ConfigError("MRS decompressed output exceeds the size limit")
        payload = zstandard.ZstdDecompressor().decompress(
            content,
            max_output_size=MAX_MRS_OUTPUT_SIZE,
            allow_extra_data=False,
        )
    except zstandard.ZstdError as exc:
        raise ConfigError(f"Invalid MRS zstd stream: {exc}") from exc
    if len(payload) > MAX_MRS_OUTPUT_SIZE:
        raise ConfigError("MRS decompressed output exceeds the size limit")

    reader = _Reader(payload)
    if reader.read(4) != MRS_MAGIC:
        raise ConfigError("Invalid MRS magic or version")
    if reader.byte() != MRS_BEHAVIOR[behavior]:
        raise ConfigError("MRS behavior does not match its configuration")

    count = reader.int64()
    if count < 1 or count > MAX_MRS_ITEMS:
        raise ConfigError("Invalid MRS rule count")

    extra_length = reader.int64()
    if extra_length < 0 or extra_length > MAX_MRS_OUTPUT_SIZE:
        raise ConfigError("Invalid MRS extra data length")
    reader.read(extra_length)

    if behavior == "domain":
        rules = _decode_domain_set(reader)
        if len(rules) != count:
            raise ConfigError("MRS domain rule count does not match its payload")
    else:
        rules = _decode_ipcidr_set(reader)
        if len(rules) != count:
            raise ConfigError("MRS IP CIDR rule count does not match its payload")

    if reader.remaining:
        raise ConfigError("Unexpected trailing data in MRS payload")
    return rules


def _decode_domain_set(reader: _Reader) -> list[str]:
    if reader.byte() != 1:
        raise ConfigError("Unsupported MRS domain-set version")

    leaves = _Bitmap(_read_bitmap(reader, "domain leaves"))
    label_bitmap = _Bitmap(_read_bitmap(reader, "domain label bitmap"))
    labels_length = reader.int64()
    if labels_length < 1 or labels_length > MAX_MRS_OUTPUT_SIZE:
        raise ConfigError("Invalid MRS domain label length")
    labels = reader.read(labels_length)

    keys: list[str] = []
    current = bytearray()

    def traverse(node_id: int, bitmap_index: int) -> None:
        if len(current) > MAX_MRS_DOMAIN_LENGTH:
            raise ConfigError("MRS domain exceeds the length limit")
        if leaves.bit(node_id):
            try:
                keys.append(bytes(current).decode("utf-8")[::-1])
            except UnicodeDecodeError as exc:
                raise ConfigError("Invalid UTF-8 domain in MRS payload") from exc
            if len(keys) > MAX_MRS_ITEMS:
                raise ConfigError("MRS domain rule count exceeds the limit")

        while True:
            if label_bitmap.bit(bitmap_index):
                return
            label_index = bitmap_index - node_id
            if label_index < 0 or label_index >= len(labels):
                raise ConfigError("Invalid MRS domain trie label index")
            current.append(labels[label_index])
            next_node_id = label_bitmap.count_zeros(bitmap_index + 1)
            next_bitmap_index = label_bitmap.select_one(next_node_id - 1) + 1
            traverse(next_node_id, next_bitmap_index)
            current.pop()
            bitmap_index += 1

    traverse(0, 0)
    ordered = sorted(keys)
    key_set = set(ordered)
    return [key for key in ordered if f"+.{key}" not in key_set]


def _decode_ipcidr_set(reader: _Reader) -> list[str]:
    if reader.byte() != 1:
        raise ConfigError("Unsupported MRS ipcidr-set version")

    length = reader.int64()
    if length < 1 or length > MAX_MRS_ITEMS:
        raise ConfigError("Invalid MRS IP range count")

    prefixes: list[str] = []
    for _ in range(length):
        first = _unmap_address(ipaddress.ip_address(reader.read(16)))
        last = _unmap_address(ipaddress.ip_address(reader.read(16)))
        if first.version != last.version or int(first) > int(last):
            raise ConfigError("Invalid MRS IP address range")
        prefixes.extend(
            str(prefix) for prefix in ipaddress.summarize_address_range(first, last)
        )
    return prefixes


def _read_bitmap(reader: _Reader, label: str) -> tuple[int, ...]:
    length = reader.int64()
    if length < 1 or length > MAX_MRS_BITMAP_WORDS:
        raise ConfigError(f"Invalid MRS {label} length")
    return tuple(reader.uint64() for _ in range(length))


class _Bitmap:
    def __init__(self, words: tuple[int, ...]):
        self.words = words
        prefix = [0]
        for word in words:
            prefix.append(prefix[-1] + word.bit_count())
        self._ones_prefix = tuple(prefix)

    def bit(self, index: int) -> int:
        if index < 0 or index >> 6 >= len(self.words):
            raise ConfigError("Invalid MRS bitmap index")
        return 1 if self.words[index >> 6] & (1 << (index & 63)) else 0

    def count_zeros(self, end: int) -> int:
        if end < 0 or end > len(self.words) * 64:
            raise ConfigError("Invalid MRS bitmap rank index")
        word_index, bit_count = divmod(end, 64)
        ones = self._ones_prefix[word_index]
        if bit_count:
            ones += (self.words[word_index] & ((1 << bit_count) - 1)).bit_count()
        return end - ones

    def select_one(self, ordinal: int) -> int:
        if ordinal < 0 or ordinal >= self._ones_prefix[-1]:
            raise ConfigError("Invalid MRS bitmap ordinal")

        low = 0
        high = len(self.words)
        while low < high:
            middle = (low + high) // 2
            if self._ones_prefix[middle + 1] <= ordinal:
                low = middle + 1
            else:
                high = middle

        word_index = low
        remaining = ordinal - self._ones_prefix[word_index]
        word = self.words[word_index]
        while remaining:
            word &= word - 1
            remaining -= 1
        bit_index = (word & -word).bit_length() - 1
        return word_index * 64 + bit_index


def _unmap_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address
