from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, ShadowQUICNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec

_CONGESTION_CONTROLLERS = {"cubic", "new_reno", "bbr_meta_v1", "bbr_meta_v2", "bbr"}


_BBR_PROFILES = {"standard", "conservative", "aggressive"}


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
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


SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWQUIC,
    validator=_validate,
    node_class=ShadowQUICNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "cwnd",
            "disable_mtu_discovery",
            "down",
            "keep_alive_interval",
            "max_datagram_frame_size",
            "max_open_streams",
            "password",
            "quic_versions",
            "recv_window",
            "recv_window_conn",
            "smux",
            "tls",
            "udp_over_stream",
            "up",
            "username",
            "zero_rtt",
        }
    ),
)
