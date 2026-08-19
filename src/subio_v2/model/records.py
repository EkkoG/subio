from dataclasses import dataclass, field
from typing import Any

from subio_v2.dialect import DialectContext


@dataclass
class NodeRecord:
    original_name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    source_extensions: dict[str, Any] = field(default_factory=dict)
    source_provider: str | None = None
    source_context: DialectContext | None = None
    opaque_type: str | None = None
    opaque_raw: Any = field(default=None, repr=False)
