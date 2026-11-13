from __future__ import annotations

from subio_v2.core.nodes import Node, SSHNode, SourcePassthroughNode, TailscaleNode
from subio_v2.core.results import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.protocols.user_overrides import clone_node_for_user


_CERTIFICATE = ("CERTIFICATE",)
_PRIVATE_KEY = tuple(prefix + "PRIVATE KEY" for prefix in (
    "", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ",
))


def _is_inline_pem(value: object, labels: tuple[str, ...]) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    return any(
        value.startswith((f"-----BEGIN {label}-----\n", f"-----BEGIN {label}-----\r\n"))
        and value.endswith(f"\n-----END {label}-----")
        for label in labels
    )


def _credential_fields(node: Node):
    tls = getattr(node, "tls", None)
    if tls is not None:
        yield "tls.certificate", tls.certificate, _CERTIFICATE
        yield "tls.private_key", tls.private_key, _PRIVATE_KEY
    if isinstance(node, SSHNode):
        yield "private_key", node.private_key, _PRIVATE_KEY

    # Known file references can also be replayed through same-dialect extras.
    raw = node.raw if isinstance(node, SourcePassthroughNode) else node.extra
    if isinstance(raw, dict):
        for key, pattern in (("certificate", _CERTIFICATE), ("private-key", _PRIVATE_KEY)):
            yield key, raw.get(key), pattern
        for key in ("certificate-path", "private-key-path"):
            yield key, raw.get(key), None


def restrict_source_credentials(result: ParseResult, source_kind: str) -> ParseResult:
    """Apply source authority after decoding, including effective user credentials."""
    if source_kind == "local":
        return result
    retained = []
    for node in result.nodes:
        blocked_fields = []
        candidates = [("", node)]
        if node.users:
            try:
                candidates.extend(
                    (f"users.{username}.", clone_node_for_user(node, username))
                    for username in node.users
                )
            except (TypeError, ValueError):
                blocked_fields.append("users")
        for prefix, candidate in candidates:
            if candidate is None:
                continue
            for field, value, labels in _credential_fields(candidate):
                if value and not (labels is not None and _is_inline_pem(value, labels)):
                    blocked_fields.append(prefix + field)
            if isinstance(candidate, TailscaleNode) and candidate.interactive_login:
                blocked_fields.append(prefix + "interactive_login")
        if not blocked_fields:
            retained.append(node)
            continue
        result.issues.extend(
            ConversionIssue(
                severity=IssueSeverity.ERROR, node=node.name,
                protocol=node.type.value, source=None, target=None, field=field,
                message="This credential or local state reference requires a local source",
                stage="parse", code="security.local-credential-blocked",
            )
            for field in dict.fromkeys(blocked_fields)
        )
    result.nodes = retained
    return result
