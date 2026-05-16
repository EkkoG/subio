from typing import Any, Dict, List

from subio_v2.clash.helpers import (
    emit_base,
    emit_passthrough,
    emit_smux,
    emit_tls,
    emit_transport,
    merge_extra,
)
from subio_v2.emitter.base import BaseEmitter
from subio_v2.model.nodes import (
    AnyTLSNode,
    ClashPassthroughNode,
    Hysteria2Node,
    HysteriaNode,
    HttpNode,
    Node,
    Protocol,
    ShadowsocksNode,
    ShadowsocksRNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
    WireguardNode,
)


class ClashEmitter(BaseEmitter):
    platform = "clash-meta"

    def __init__(self, platform: str = "clash-meta"):
        self.platform = platform
        super().__init__()

    def emit(self, nodes: List[Node]) -> Dict[str, Any]:
        supported_nodes, _ = self.emit_with_check(nodes)
        proxies = []
        for node in supported_nodes:
            proxy = self._emit_node(node)
            if proxy:
                proxies.append(proxy)
        return {"proxies": proxies}

    def _emit_node(self, node: Node) -> Dict[str, Any] | None:
        if isinstance(node, ClashPassthroughNode):
            return emit_passthrough(node)

        if isinstance(node, ShadowsocksNode):
            return self._emit_ss(node)
        if isinstance(node, ShadowsocksRNode):
            return self._emit_ssr(node)
        if isinstance(node, VmessNode):
            return self._emit_vmess(node)
        if isinstance(node, VlessNode):
            return self._emit_vless(node)
        if isinstance(node, TrojanNode):
            return self._emit_trojan(node)
        if isinstance(node, Socks5Node):
            return self._emit_socks5(node)
        if isinstance(node, HttpNode):
            return self._emit_http(node)
        if isinstance(node, WireguardNode):
            return self._emit_wireguard(node)
        if isinstance(node, AnyTLSNode):
            return self._emit_anytls(node)
        if isinstance(node, Hysteria2Node):
            return self._emit_hysteria2(node)
        if isinstance(node, HysteriaNode):
            return self._emit_hysteria(node)
        if isinstance(node, SSHNode):
            return self._emit_ssh(node)
        if isinstance(node, SnellNode):
            return self._emit_snell(node)
        if isinstance(node, TUICNode):
            return self._emit_tuic(node)
        return None

    def _emit_ss(self, node: ShadowsocksNode) -> Dict[str, Any]:
        base = emit_base(node)
        base.update(
            {
                "cipher": node.cipher,
                "password": node.password,
            }
        )
        if node.plugin:
            base["plugin"] = node.plugin
            if node.plugin_opts:
                base["plugin-opts"] = node.plugin_opts
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_ssr(self, node: ShadowsocksRNode) -> Dict[str, Any]:
        base = emit_base(node)
        base.update(
            {
                "cipher": node.cipher,
                "password": node.password,
                "obfs": node.obfs,
                "protocol": node.ssr_protocol,
            }
        )
        if node.obfs_param:
            base["obfs-param"] = node.obfs_param
        if node.protocol_param:
            base["protocol-param"] = node.protocol_param
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_vmess(self, node: VmessNode) -> Dict[str, Any]:
        base = emit_base(node)
        base.update(
            {
                "uuid": node.uuid,
                "alterId": node.alter_id,
                "cipher": node.cipher,
            }
        )
        if node.global_padding:
            base["global-padding"] = True
        if node.packet_encoding:
            base["packet-encoding"] = node.packet_encoding
        emit_tls(base, node.tls)
        emit_transport(base, node.transport)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_vless(self, node: VlessNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["uuid"] = node.uuid
        if node.flow:
            base["flow"] = node.flow
        if node.packet_encoding:
            base["packet-encoding"] = node.packet_encoding
        emit_tls(base, node.tls)
        emit_transport(base, node.transport)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_trojan(self, node: TrojanNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["password"] = node.password
        emit_tls(base, node.tls)
        emit_transport(base, node.transport)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_socks5(self, node: Socks5Node) -> Dict[str, Any]:
        base = emit_base(node)
        if node.username:
            base["username"] = node.username
        if node.password:
            base["password"] = node.password
        emit_tls(base, node.tls)
        return merge_extra(base, node)

    def _emit_http(self, node: HttpNode) -> Dict[str, Any]:
        base = emit_base(node)
        if node.username:
            base["username"] = node.username
        if node.password:
            base["password"] = node.password
        if node.headers:
            base["headers"] = node.headers
        emit_tls(base, node.tls)
        return merge_extra(base, node)

    def _emit_wireguard(self, node: WireguardNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["private-key"] = node.private_key
        base["udp"] = True
        if node.public_key:
            base["public-key"] = node.public_key
        if node.preshared_key:
            base["preshared-key"] = node.preshared_key
        if node.interface_ip is not None:
            base["ip"] = node.interface_ip
        elif node.allowed_ips and len(node.allowed_ips) > 1:
            base["ip"] = node.allowed_ips
        elif node.allowed_ips:
            base["ip"] = node.allowed_ips[0]
        if node.interface_ipv6 is not None:
            base["ipv6"] = node.interface_ipv6
        if node.allowed_ips and node.interface_ip is None:
            pass
        elif node.allowed_ips and isinstance(node.interface_ip, list):
            if node.allowed_ips != list(node.interface_ip):
                base["allowed-ips"] = node.allowed_ips
        if node.reserved:
            base["reserved"] = node.reserved
        if node.mtu is not None:
            base["mtu"] = node.mtu
        if node.workers is not None:
            base["workers"] = node.workers
        if node.persistent_keepalive is not None:
            base["persistent-keepalive"] = node.persistent_keepalive
        if node.amnezia_wg_option:
            base["amnezia-wg-option"] = node.amnezia_wg_option
        if node.peers:
            base["peers"] = node.peers
        if node.remote_dns_resolve is not None:
            base["remote-dns-resolve"] = node.remote_dns_resolve
        if node.dns_servers:
            base["dns"] = node.dns_servers
        if node.refresh_server_ip_interval is not None:
            base["refresh-server-ip-interval"] = node.refresh_server_ip_interval
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_anytls(self, node: AnyTLSNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["password"] = node.password
        emit_tls(base, node.tls)
        if node.idle_session_check_interval is not None:
            base["idle-session-check-interval"] = node.idle_session_check_interval
        if node.idle_session_timeout is not None:
            base["idle-session-timeout"] = node.idle_session_timeout
        if node.min_idle_session is not None:
            base["min-idle-session"] = node.min_idle_session
        return merge_extra(base, node)

    def _emit_hysteria2(self, node: Hysteria2Node) -> Dict[str, Any]:
        base = emit_base(node)
        base["password"] = node.password
        if node.ports:
            base["ports"] = node.ports
        if node.hop_interval is not None:
            base["hop-interval"] = node.hop_interval
        if node.up:
            base["up"] = node.up
        if node.down:
            base["down"] = node.down
        if node.obfs:
            base["obfs"] = node.obfs
        if node.obfs_password:
            base["obfs-password"] = node.obfs_password
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_hysteria(self, node: HysteriaNode) -> Dict[str, Any]:
        base = emit_base(node)
        if node.ports:
            base["ports"] = node.ports
        if node.hysteria_protocol:
            base["protocol"] = node.hysteria_protocol
        if node.obfs_protocol:
            base["obfs-protocol"] = node.obfs_protocol
        if node.up:
            base["up"] = node.up
        if node.down:
            base["down"] = node.down
        if node.up_speed is not None:
            base["up-speed"] = node.up_speed
        if node.down_speed is not None:
            base["down-speed"] = node.down_speed
        if node.auth_str:
            base["auth-str"] = node.auth_str
        if node.auth:
            base["auth"] = node.auth
        if node.obfs:
            base["obfs"] = node.obfs
        if node.hop_interval is not None:
            base["hop-interval"] = node.hop_interval
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_ssh(self, node: SSHNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["username"] = node.username
        if node.password:
            base["password"] = node.password
        if node.private_key:
            base["private-key"] = node.private_key
        if node.private_key_passphrase:
            base["private-key-passphrase"] = node.private_key_passphrase
        if node.host_key:
            base["host-key"] = node.host_key
        if node.host_key_algorithms:
            base["host-key-algorithms"] = node.host_key_algorithms
        return merge_extra(base, node)

    def _emit_snell(self, node: SnellNode) -> Dict[str, Any]:
        base = emit_base(node)
        base["psk"] = node.psk
        if node.version is not None:
            base["version"] = node.version
        if node.obfs_opts:
            base["obfs-opts"] = node.obfs_opts
        elif node.obfs:
            base["obfs-opts"] = {"mode": node.obfs, "host": node.obfs_host or "bing.com"}
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def _emit_tuic(self, node: TUICNode) -> Dict[str, Any]:
        base = emit_base(node)
        if node.token:
            base["token"] = node.token
        if node.uuid:
            base["uuid"] = node.uuid
        if node.password:
            base["password"] = node.password
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)
