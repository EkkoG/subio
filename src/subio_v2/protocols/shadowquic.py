from __future__ import annotations

import copy
from collections.abc import Mapping, MutableMapping

from subio_v2.model.nodes import Node, Protocol, ShadowQUICNode, TLSSettings
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    smux_group,
)

_CONGESTION_CONTROLLERS = {"cubic", "new_reno", "bbr_meta_v1", "bbr_meta_v2", "bbr"}
_BBR_PROFILES = {"standard", "conservative", "aggressive"}


def _parse_tls(data: Mapping[str, object]) -> dict[str, object]:
    return {
        "tls": TLSSettings(
            enabled=True,
            server_name=data.get("sni"),
            alpn=copy.deepcopy(data.get("alpn")),
        )
    }


def _emit_tls(out: MutableMapping[str, object], node: Node) -> None:
    assert isinstance(node, ShadowQUICNode)
    if node.tls.server_name is not None:
        out["sni"] = node.tls.server_name
    if node.tls.alpn is not None:
        out["alpn"] = copy.deepcopy(node.tls.alpn)


class ShadowQUICDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SHADOWQUIC
    clash_type = "shadowquic"
    target_constraints = {"mihomo": {"features": {"smux"}}}
    fields = (
        scalar_field("username", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("password", emit_policy=EmitPolicy.NOT_NONE),
        field_group(
            consumed_keys=("sni", "alpn"),
            node_attrs=("tls",),
            parse_kwargs=_parse_tls,
            emit_into=_emit_tls,
        ),
        scalar_field("quic-versions", "quic_versions", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "udp-over-stream", "udp_over_stream", default=False, emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field("zero-rtt", "zero_rtt", default=False, emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "keep-alive-interval", "keep_alive_interval", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field(
            "congestion-controller", "congestion_controller", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field("up", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("down", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("cwnd", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("bbr-profile", "bbr_profile", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("recv-window-conn", "recv_window_conn", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("recv-window", "recv_window", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "disable-mtu-discovery",
            "disable_mtu_discovery",
            default=False,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field(
            "max-datagram-frame-size",
            "max_datagram_frame_size",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("max-open-streams", "max_open_streams", emit_policy=EmitPolicy.NOT_NONE),
        smux_group(),
    )

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, ShadowQUICNode):
            return errors
        if (
            node.congestion_controller is not None
            and node.congestion_controller not in _CONGESTION_CONTROLLERS
        ):
            errors.append(
                NodeValidationError(
                    "congestion_controller",
                    f"Unsupported ShadowQUIC congestion controller: {node.congestion_controller}",
                )
            )
        if node.bbr_profile is not None and node.bbr_profile not in _BBR_PROFILES:
            errors.append(
                NodeValidationError(
                    "bbr_profile",
                    f"Unsupported ShadowQUIC BBR profile: {node.bbr_profile}",
                )
            )
        return errors


DESCRIPTOR = ShadowQUICDescriptor()
