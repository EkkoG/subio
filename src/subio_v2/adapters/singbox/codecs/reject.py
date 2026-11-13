from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_no_fields,
    _keys,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    RejectMode,
    RejectNode,
)


def _parse_reject(data: dict[str, Any]) -> dict[str, Any]:
    return {"mode": RejectMode.REJECT}


def _check_reject(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, RejectNode) and node.mode != RejectMode.REJECT:
        unsupported.append("mode")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "block",
    Protocol.REJECT,
    RejectNode,
    frozenset(),
    _keys("mode", "udp"),
    parse_fields=_parse_reject,
    emit_fields=_emit_no_fields,
    check_fields=_check_reject,
    endpoint=False,
    tcp_only=True,
    common_options=False,
)
