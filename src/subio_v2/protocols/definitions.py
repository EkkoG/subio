"""Shared native field classification used by every local ProtocolSpec."""

from subio_v2.protocols.spec import ProtocolSpec

ProtocolDefinition = ProtocolSpec

TERMINAL_NATIVE_COMMON_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "ip_version",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "users",
        "interface_name",
        "routing_mark",
        "surge_options",
        "shadow_tls",
    }
)
TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS = frozenset({"record"})
