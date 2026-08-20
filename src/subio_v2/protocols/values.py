"""Shared protocol value domains without target support semantics."""

SS_CIPHERS_BASIC = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
}
SS_CIPHERS_EXTENDED = SS_CIPHERS_BASIC | {
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "xchacha20-ietf-poly1305",
}
SS_CIPHERS_2022 = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
SS_CIPHERS_STASH = SS_CIPHERS_EXTENDED | {
    "aes-192-gcm",
    "chacha20",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
}

VMESS_CIPHERS = {
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
    "none",
    "zero",
}
VMESS_CIPHERS_STASH = VMESS_CIPHERS - {"zero"}

TRANSPORT_TCP = "tcp"
TRANSPORT_WS = "ws"
TRANSPORT_H2 = "h2"
TRANSPORT_GRPC = "grpc"
TRANSPORT_HTTP = "http"
TRANSPORT_XHTTP = "xhttp"
