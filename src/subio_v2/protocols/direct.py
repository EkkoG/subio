from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import smux_group


class DirectDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.DIRECT
    clash_type = "direct"
    fields = (smux_group(),)

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        kwargs["server"] = None
        kwargs["port"] = None
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out.pop("server", None)
        out.pop("port", None)


DESCRIPTOR = DirectDescriptor()
