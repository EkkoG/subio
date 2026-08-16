from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol, RematchNode
from subio_v2.protocols import register
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class RematchDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.REMATCH
    clash_type = "rematch"
    node_class = RematchNode
    requires_endpoint = False
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

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if isinstance(node, RematchNode) and (
            node.target_rematch_name is None and node.target_sub_rule is None
        ):
            errors.append(
                NodeValidationError(
                    "target_rematch_name",
                    "Rematch requires target-rematch-name or target-sub-rule",
                )
            )
        return errors


register(RematchDescriptor())
