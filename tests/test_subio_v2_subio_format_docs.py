import re
from pathlib import Path

from subio_v2.parser.subio import SubioParser
from subio_v2.subio_format.schema import PUBLIC_PROTOCOLS


REPOSITORY_ROOT = Path(__file__).parents[1]
FORMAT_DOC_PATH = REPOSITORY_ROOT / "docs" / "subio_node_format.md"
EXAMPLE_PROVIDER_DIR = REPOSITORY_ROOT / "example" / "provider"


def test_subio_native_examples_follow_v1_contract():
    expected_counts = {
        "self.toml": 16,
        "nodes.json5": 3,
        "multiuser.yml": 8,
    }
    parser = SubioParser()

    for filename, expected_count in expected_counts.items():
        result = parser.parse_result(
            (EXAMPLE_PROVIDER_DIR / filename).read_text(encoding="utf-8")
        )
        assert result.issues == [], filename
        assert len(result.nodes) == expected_count, filename


def test_subio_format_document_lists_every_public_protocol():
    document = FORMAT_DOC_PATH.read_text(encoding="utf-8")
    protocol_section = document.split("## 6. 协议字段索引", 1)[1].split(
        "## 7. 目标平台兼容性", 1
    )[0]
    documented_protocols = set(
        re.findall(r"^\| `([^`]+)` \|", protocol_section, re.MULTILINE)
    ) - {"type"}

    assert documented_protocols == {protocol.value for protocol in PUBLIC_PROTOCOLS}
