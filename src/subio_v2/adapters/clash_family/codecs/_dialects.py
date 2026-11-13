from subio_v2.protocols.values import SS_CIPHERS_EXTENDED, VMESS_CIPHERS

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


SS_CIPHERS_STASH = SS_CIPHERS_EXTENDED | {
    "aes-192-gcm",
    "chacha20",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
}

VMESS_CIPHERS_STASH = VMESS_CIPHERS - {"zero"}
