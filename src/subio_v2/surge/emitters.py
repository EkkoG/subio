from collections.abc import Callable

from subio_v2.model.nodes import (
    AnyTLSNode,
    DirectNode,
    HttpNode,
    HttpVariant,
    Hysteria2Node,
    MasqueMode,
    MasqueNode,
    Network,
    Node,
    RejectNode,
    ShadowsocksNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TailscaleNode,
    TrojanNode,
    TrustTunnelNode,
    TUICNode,
    VmessNode,
    WireguardNode,
)

SurgeProtocolEmitter = Callable[[Node, dict[int, str]], list[str]]


def _server_str(node: Node) -> str:
    server = node.server
    return str(server[0]) if isinstance(server, list) else str(server)


def emit_direct(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, DirectNode)
    return ["direct"]


def emit_reject(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, RejectNode)
    return [node.mode.value]


def emit_shadowsocks(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, ShadowsocksNode)
    parts = ["ss", _server_str(node), str(node.port), f"encrypt-method={node.cipher}"]
    if node.password or node.cipher != "none":
        parts.append(f"password={node.password}")
    if node.udp_port is not None:
        parts.append(f"udp-port={node.udp_port}")
    if node.plugin == "obfs":
        mode = node.plugin_opts.get("mode", "http") if node.plugin_opts else "http"
        parts.append(f"obfs={mode}")
        host = node.plugin_opts.get("host", "") if node.plugin_opts else ""
        if host:
            parts.append(f"obfs-host={host}")
    return parts


def emit_vmess(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, VmessNode)
    parts = ["vmess", _server_str(node), str(node.port), f"username={node.uuid}"]
    if node.vmess_aead:
        parts.append("vmess-aead=true")
    if node.cipher and node.cipher != "aes-128-gcm":
        parts.append(f"encrypt-method={node.cipher}")
    if node.transport.network == Network.WS:
        parts.append("ws=true")
        if node.transport.path:
            parts.append(f"ws-path={node.transport.path}")
        if node.transport.headers:
            headers = "|".join(
                f"{key}:{value}" for key, value in node.transport.headers.items()
            )
            parts.append(f"ws-headers={headers}")
    return parts


def emit_trojan(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TrojanNode)
    parts = [
        "trojan",
        _server_str(node),
        str(node.port),
        f"password={node.password}",
    ]
    if node.transport.network == Network.WS:
        parts.append("ws=true")
        if node.transport.path:
            parts.append(f"ws-path={node.transport.path}")
        if node.transport.headers:
            headers = "|".join(
                f"{key}:{value}" for key, value in node.transport.headers.items()
            )
            parts.append(f"ws-headers={headers}")
    return parts


def emit_socks5(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, Socks5Node)
    proxy_type = "socks5-tls" if node.tls.enabled else "socks5"
    parts = [proxy_type, _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    return parts


def emit_http(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, HttpNode)
    if node.variant == HttpVariant.H2_CONNECT:
        proxy_type = "h2-connect"
    elif node.variant == HttpVariant.HTTP:
        proxy_type = "http"
    elif node.variant == HttpVariant.HTTPS:
        proxy_type = "https"
    else:
        proxy_type = "https" if node.tls.enabled else "http"
    parts = [proxy_type, _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    if node.headers:
        headers = "|".join(f"{key}:{value}" for key, value in node.headers.items())
        parts.append(f"headers={headers}")
    if node.max_streams is not None:
        parts.append(f"max-streams={node.max_streams}")
    if node.variant == HttpVariant.H2_CONNECT and node.udp:
        parts.append("udp-relay=true")
    return parts


def emit_anytls(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, AnyTLSNode)
    parts = ["anytls", _server_str(node), str(node.port), f"password={node.password}"]
    if not node.reuse:
        parts.append("reuse=false")
    return parts


def emit_wireguard(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, WireguardNode)
    extension = node.source_extensions.get("surge", {})
    return ["wireguard", f"section-name={extension.get('section_name') or node.name}"]


def emit_tailscale(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TailscaleNode)
    extension = node.source_extensions.get("surge", {})
    return ["tailscale", f"section-name={extension.get('section_name') or node.name}"]


def emit_masque(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, MasqueNode)
    if node.mode != MasqueMode.FORWARD_PROXY:
        raise ValueError(f"Surge does not support MASQUE mode '{node.mode.value}'")
    parts = ["masque", _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts


def emit_trust_tunnel(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TrustTunnelNode)
    parts = [
        "trust-tunnel",
        _server_str(node),
        str(node.port),
        f"username={node.username}",
        f"password={node.password}",
    ]
    if node.headers:
        parts.append(f"headers={node.headers}")
    if node.max_streams is not None:
        parts.append(f"max-streams={node.max_streams}")
    if node.quic:
        parts.append("h3=true")
    if node.websocket:
        parts.append("ws=true")
    return parts


def emit_ssh(node: Node, node_keystore_map: dict[int, str]) -> list[str]:
    assert isinstance(node, SSHNode)
    parts = ["ssh", _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    keystore_id = node.keystore_id or node_keystore_map.get(id(node))
    if keystore_id:
        parts.append(f"private-key={keystore_id}")
    elif node.private_key:
        parts.append(f"private-key={node.private_key}")
    if node.idle_timeout is not None:
        parts.append(f"idle-timeout={node.idle_timeout}")
    parts.extend(
        f"server-fingerprint={fingerprint}"
        for fingerprint in node.server_fingerprints or []
    )
    return parts


def emit_snell(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, SnellNode)
    parts = ["snell", _server_str(node), str(node.port), f"psk={node.psk}"]
    if node.version:
        parts.append(f"version={node.version}")
    if node.reuse is not None:
        parts.append(f"reuse={str(node.reuse).lower()}")
    if node.udp_port is not None:
        parts.append(f"udp-port={node.udp_port}")
    if node.mode:
        parts.append(f"mode={node.mode}")
    if node.obfs:
        parts.append(f"obfs={node.obfs}")
    if node.obfs_host:
        parts.append(f"obfs-host={node.obfs_host}")
    return parts


def emit_tuic(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TUICNode)
    if node.version == 5:
        parts = ["tuic-v5", _server_str(node), str(node.port)]
        if node.password:
            parts.append(f"password={node.password}")
        if node.uuid:
            parts.append(f"uuid={node.uuid}")
    else:
        parts = ["tuic", _server_str(node), str(node.port)]
        if node.token:
            parts.append(f"token={node.token}")
        if node.version:
            parts.append(f"version={node.version}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts


def emit_hysteria2(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, Hysteria2Node)
    parts = ["hysteria2", _server_str(node), str(node.port)]
    if node.password:
        parts.append(f"password={node.password}")
    if node.down:
        parts.append(f"download-bandwidth={node.down}")
    if node.up:
        parts.append(f"upload-bandwidth={node.up}")
    if node.obfs == "salamander" and node.obfs_password:
        parts.append(f"salamander-password={node.obfs_password}")
    elif node.obfs == "gecko" and node.obfs_password:
        parts.append(f"gecko-password={node.obfs_password}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts
