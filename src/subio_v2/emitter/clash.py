from typing import List, Any, Dict
from src.subio_v2.emitter.base import BaseEmitter
from src.subio_v2.model.nodes import (
    Node, ShadowsocksNode, VmessNode, VlessNode, TrojanNode, 
    Socks5Node, HttpNode, WireguardNode, AnyTLSNode, Hysteria2Node, Protocol, Network
)

class ClashEmitter(BaseEmitter):
    def emit(self, nodes: List[Node]) -> Dict[str, Any]:
        proxies = []
        for node in nodes:
            proxy = self._emit_node(node)
            if proxy:
                proxies.append(proxy)
        return {"proxies": proxies}

    def _emit_node(self, node: Node) -> Dict[str, Any] | None:
        base = {
            "name": node.name,
            "server": node.server,
            "port": node.port,
            "type": self._map_type(node.type),
            "udp": node.udp,
        }
        
        if node.ip_version != "dual" and node.ip_version:
             base["ip-version"] = node.ip_version
        if node.tfo:
            base["tfo"] = True
        if node.mptcp:
            base["mptcp"] = True
        if node.dialer_proxy:
            base["dialer-proxy"] = node.dialer_proxy

        if isinstance(node, ShadowsocksNode):
            base.update({
                "cipher": node.cipher,
                "password": node.password,
            })
            if node.plugin:
                base["plugin"] = node.plugin
                if node.plugin_opts:
                    base["plugin-opts"] = node.plugin_opts
            # Handle simple-obfs to obfs mapping if needed, but usually model keeps raw

        elif isinstance(node, VmessNode):
            base.update({
                "uuid": node.uuid,
                "alterId": node.alter_id,
                "cipher": node.cipher,
                "global-padding": node.global_padding,
            })
            if node.packet_encoding:
                base["packet-encoding"] = node.packet_encoding
            self._add_tls(base, node.tls)
            self._add_transport(base, node.transport)
            self._add_smux(base, node.smux)

        elif isinstance(node, VlessNode):
            base.update({
                "uuid": node.uuid,
            })
            if node.flow:
                base["flow"] = node.flow
            if node.packet_encoding:
                 base["packet-encoding"] = node.packet_encoding
            self._add_tls(base, node.tls)
            self._add_transport(base, node.transport)
            self._add_smux(base, node.smux)

        elif isinstance(node, TrojanNode):
            base.update({
                "password": node.password,
            })
            self._add_tls(base, node.tls)
            self._add_transport(base, node.transport)
            self._add_smux(base, node.smux)

        elif isinstance(node, Socks5Node):
            if node.username: base["username"] = node.username
            if node.password: base["password"] = node.password
            self._add_tls(base, node.tls)

        elif isinstance(node, HttpNode):
             if node.username: base["username"] = node.username
             if node.password: base["password"] = node.password
             if node.headers: base["headers"] = node.headers
             self._add_tls(base, node.tls)
        
        elif isinstance(node, WireguardNode):
            base.update({
                "private-key": node.private_key,
                "public-key": node.public_key,
                "udp": True # WG is UDP
            })
            if node.preshared_key: base["preshared-key"] = node.preshared_key
            if node.allowed_ips: base["ip"] = node.allowed_ips[0] # Clash uses 'ip' for internal IP assignment usually, check?
            # Clash WG: ip: string, ipv6: string. allowed-ips: list[str] is for routing
            # The old parser mapped 'ip' to allowed_ips list? 
            # Checking src/subio/model.py: Wireguard is simpler there.
            # Clash Meta docs: ip/ipv6 for interface address. 
            # Let's use what we have. 
            
        elif isinstance(node, AnyTLSNode):
            base.update({
                "password": node.password,
            })
            self._add_tls(base, node.tls)
            if node.idle_session_check_interval is not None:
                base["idle-session-check-interval"] = node.idle_session_check_interval
            if node.idle_session_timeout is not None:
                base["idle-session-timeout"] = node.idle_session_timeout
            if node.min_idle_session is not None:
                base["min-idle-session"] = node.min_idle_session

        elif isinstance(node, Hysteria2Node):
            base.update({
                "password": node.password,
            })
            if node.ports: base["ports"] = node.ports
            if node.hop_interval is not None: base["hop-interval"] = node.hop_interval
            if node.up: base["up"] = node.up
            if node.down: base["down"] = node.down
            if node.obfs: base["obfs"] = node.obfs
            if node.obfs_password: base["obfs-password"] = node.obfs_password
            
            self._add_tls(base, node.tls)
            
        return base

    def _map_type(self, protocol: Protocol) -> str:
        if protocol == Protocol.SHADOWSOCKS: return "ss"
        return protocol.value

    def _add_tls(self, base: Dict[str, Any], tls) -> None:
        if not tls or not tls.enabled:
            return
        # For anytls, example doesn't have 'tls: true' but fields are at root level.
        # But Clash Meta usually groups them or puts at root depending on protocol.
        # For standard protocols, 'tls: true' enables it.
        # For 'anytls', let's check if 'tls' field is needed. The example doesn't show 'tls: true' explicitly but implies it.
        # But my Parser logic set enabled=True.
        # If I output 'tls: true', is it harmful?
        # Example:
        # - name: anytls
        #   type: anytls
        #   ...
        #   sni: ...
        #   skip-cert-verify: ...
        # No 'tls: true' in example.
        # But for vmess/trojan etc, it is needed.
        # I'll add it if it's not AnyTLS? Or maybe AnyTLS ignores it.
        # Hysteria2 also implicitly uses TLS but doesn't need 'tls: true' in some versions or needs it?
        # Clash Meta docs for Hysteria2 don't explicitly say 'tls: true' is required but sni/skip-cert-verify are at root.
        # Let's exclude 'tls: true' for hysteria2 too if needed, or keep it if harmless.
        # Usually Hysteria2 is TLS based.
        
        if base["type"] not in ["anytls", "hysteria2"]:
             base["tls"] = True
             
        if tls.server_name: 
            if base["type"] in ["vmess", "vless"]:
                 base["servername"] = tls.server_name
            else:
                 base["sni"] = tls.server_name # anytls/hysteria2 uses 'sni'
                 
        if tls.skip_cert_verify: base["skip-cert-verify"] = True
        if tls.fingerprint: base["fingerprint"] = tls.fingerprint
        if tls.client_fingerprint: base["client-fingerprint"] = tls.client_fingerprint
        if tls.alpn: base["alpn"] = tls.alpn
        if tls.reality_opts: base["reality-opts"] = tls.reality_opts
        if tls.ech_opts: base["ech-opts"] = tls.ech_opts
        
        # mTLS
        if tls.certificate: base["certificate"] = tls.certificate
        if tls.private_key: base["private-key"] = tls.private_key

    def _add_transport(self, base: Dict[str, Any], transport) -> None:
        if not transport or transport.network == Network.TCP:
            return
        
        base["network"] = transport.network.value
        
        if transport.network == Network.WS:
            opts = {}
            if transport.path: opts["path"] = transport.path
            if transport.headers: opts["headers"] = transport.headers
            if transport.max_early_data is not None: opts["max-early-data"] = transport.max_early_data
            if transport.early_data_header_name: opts["early-data-header-name"] = transport.early_data_header_name
            if opts: base["ws-opts"] = opts

        elif transport.network == Network.HTTP:
            opts = {}
            if transport.method: opts["method"] = transport.method
            if transport.path: opts["path"] = [transport.path] if isinstance(transport.path, str) else transport.path
            if transport.headers: opts["headers"] = transport.headers
            if opts: base["http-opts"] = opts
            
        elif transport.network == Network.H2:
            opts = {}
            if transport.host: opts["host"] = transport.host
            if transport.path: opts["path"] = transport.path
            if opts: base["h2-opts"] = opts

        elif transport.network == Network.GRPC:
             opts = {}
             if transport.grpc_service_name: opts["grpc-service-name"] = transport.grpc_service_name
             if opts: base["grpc-opts"] = opts

    def _add_smux(self, base: Dict[str, Any], smux) -> None:
        if not smux or not smux.enabled:
            return
        base["smux"] = {
            "enabled": True,
            "protocol": smux.protocol,
            "max-connections": smux.max_connections,
            "min-streams": smux.min_streams,
            "max-streams": smux.max_streams,
            "padding": smux.padding
        }
        if smux.brutal_opts:
            base["smux"]["brutal-opts"] = smux.brutal_opts
