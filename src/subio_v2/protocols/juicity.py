from subio_v2.core.nodes import JuicityNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.JUICITY,
    required_fields=("uuid", "password"),
    node_class=JuicityNode,
    user_override_fields=frozenset({"server", "port", "uuid", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "uuid", "password"}
    ),
    terminal_native_fields=frozenset({"password", "tls", "uuid"}),
)
