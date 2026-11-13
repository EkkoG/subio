from __future__ import annotations

from typing import Any, Dict

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
)
from subio_v2.core.nodes import Node, Protocol
from subio_v2.protocols.rematch import SPEC


class RematchCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.REMATCH
    clash_type = "rematch"
    target_constraints = {"mihomo": {"features": {"smux"}}}
    fields = (
        scalar_field(
            "target-rematch-name",
            "target_rematch_name",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "target-sub-rule",
            "target_sub_rule",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        smux_group(),
    )

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        kwargs["server"] = None
        kwargs["port"] = None
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out.pop("server", None)
        out.pop("port", None)


CODEC = RematchCodec()
