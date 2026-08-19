_STASH_ENDPOINT_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "tfo",
        "dialer-proxy",
        "interface-name",
    }
)
_STASH_TLS_FIELDS = frozenset(
    {"tls", "skip-cert-verify", "server-cert-fingerprint", "sni", "alpn"}
)
_STASH_TRANSPORT_FIELDS = frozenset(
    {"network", "ws-opts", "h2-opts", "http-opts", "grpc-opts", "xhttp-opts"}
)


def stash_fields(
    *fields: str,
    endpoint: bool = True,
    tls: bool = False,
    transport: bool = False,
) -> frozenset[str]:
    result = set(fields)
    if endpoint:
        result.update(_STASH_ENDPOINT_FIELDS)
    if tls:
        result.update(_STASH_TLS_FIELDS)
    if transport:
        result.update(_STASH_TRANSPORT_FIELDS)
    return frozenset(result)
