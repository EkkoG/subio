from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import smux_group


class DNSCodec(StructuredClashProtocolCodec):
    protocol = Protocol.DNS
    clash_type = "dns"
    target_constraints = {"mihomo": {"features": {"smux"}}}
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


CODEC = DNSCodec()
