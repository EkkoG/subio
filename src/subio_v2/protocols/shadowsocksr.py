from __future__ import annotations

from subio_v2.model.nodes import Protocol, ShadowsocksRNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class ShadowsocksRDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKSR
    clash_type = "ssr"
    node_class = ShadowsocksRNode
    fields = (
        scalar_field(
            "cipher", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field("obfs", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "protocol", "ssr_protocol", default="", emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field("obfs-param", "obfs_param", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("protocol-param", "protocol_param", emit_policy=EmitPolicy.TRUTHY),
        smux_group(),
    )


register(ShadowsocksRDescriptor())
