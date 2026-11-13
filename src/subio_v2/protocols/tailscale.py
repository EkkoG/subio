from __future__ import annotations

from subio_v2.core.nodes import Protocol, TailscaleNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.TAILSCALE,
    node_class=TailscaleNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port", "auth_key"}),
    terminal_native_user_override_fields=frozenset({"auth_key"}),
    terminal_native_fields=frozenset(
        {
            "accept_routes",
            "auth_key",
            "auto_add_magic_dns_rule",
            "control_url",
            "derp_only",
            "dns_servers",
            "ephemeral",
            "exit_node",
            "exit_node_allow_lan_access",
            "exit_node_auto_fallback",
            "hostname",
            "idle_keepalive",
            "mtu",
            "prefer_ipv6",
            "smux",
            "state_dir",
        }
    ),
    terminal_native_excluded_fields=frozenset({"interactive_login"}),
)
