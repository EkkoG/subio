from __future__ import annotations

import copy

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import Node, SourcePassthroughNode

_OPAQUE_USER_OVERRIDE_FIELDS = frozenset({"server", "port"})


def user_override_fields(node: Node) -> frozenset[str]:
    definition = protocol_registry.get_definition(node.type)
    if definition is not None:
        return definition.user_override_fields
    if isinstance(node, SourcePassthroughNode):
        return _OPAQUE_USER_OVERRIDE_FIELDS
    return frozenset()


def clone_node_for_user(node: Node, username: str) -> Node | None:
    if not node.users or username not in node.users:
        return None

    new_node = copy.deepcopy(node)
    user_overrides = node.users[username]
    if not isinstance(user_overrides, dict):
        # Preserve the existing workflow error contract during the ownership move.
        raise ValueError(  # noqa: TRY004
            f"Overrides for user '{username}' must be an object"
        )

    allowed_fields = user_override_fields(node)
    for key, value in user_overrides.items():
        normalized_key = key.replace("-", "_")
        if normalized_key not in allowed_fields or not hasattr(new_node, normalized_key):
            raise ValueError(f"User '{username}' cannot override node field '{key}'")
        if normalized_key == "port" and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= 65535
        ):
            raise ValueError(f"Invalid port override for user '{username}'")
        setattr(new_node, normalized_key, value)

    new_node.users = None
    return new_node


def get_nodes_for_user(nodes: list[Node], username: str) -> list[Node]:
    result: list[Node] = []
    for node in nodes:
        if node.users:
            if username in node.users:
                user_node = clone_node_for_user(node, username)
                if user_node is not None:
                    result.append(user_node)
        else:
            result.append(copy.deepcopy(node))
    return result
