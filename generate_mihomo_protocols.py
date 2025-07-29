#!/usr/bin/env python3
"""Generate all mihomo-supported protocol combinations in a YAML file."""
import yaml
from typing import Dict, Any, List

def generate_shadowsocks_variants() -> List[Dict[str, Any]]:
    """Generate Shadowsocks protocol variants."""
    variants = []
    
    # Basic ciphers
    ciphers = [
        'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', 
        '2022-blake3-chacha20-poly1305'
    ]
    
    # Plugins
    plugins = [
        None,
        {'name': 'obfs', 'opts': {'mode': 'tls', 'host': 'example.com'}},
        {'name': 'obfs', 'opts': {'mode': 'http', 'host': 'example.com'}},
        {'name': 'v2ray-plugin', 'opts': {'mode': 'websocket', 'tls': True, 'host': 'example.com', 'path': '/ws'}},
        {'name': 'shadow-tls', 'opts': {'version': 3, 'host': 'example.com', 'password': 'shadow-tls-password'}},
        {'name': 'restls', 'opts': {'version-hint': 'tls13', 'host': 'example.com', 'password': 'restls-password'}}
    ]
    
    for i, cipher in enumerate(ciphers):
        # Basic variant
        variants.append({
            'name': f'ss-{cipher}',
            'type': 'ss',
            'server': '1.2.3.4',
            'port': 8388 + i,
            'cipher': cipher,
            'password': 'password123',
            'udp': True
        })
        
        # With UDP over TCP
        variants.append({
            'name': f'ss-{cipher}-uot',
            'type': 'ss',
            'server': '1.2.3.4',
            'port': 9388 + i,
            'cipher': cipher,
            'password': 'password123',
            'udp': True,
            'udp-over-tcp': True,
            'udp-over-tcp-version': 2
        })
    
    # Plugin variants
    for j, plugin_config in enumerate(plugins):
        if plugin_config:
            variants.append({
                'name': f'ss-plugin-{plugin_config["name"]}-{j}',
                'type': 'ss',
                'server': '1.2.3.4',
                'port': 10388 + j,
                'cipher': 'aes-256-gcm',
                'password': 'password123',
                'plugin': plugin_config['name'],
                'plugin-opts': plugin_config['opts']
            })
    
    return variants


def generate_vmess_variants() -> List[Dict[str, Any]]:
    """Generate VMess protocol variants."""
    variants = []
    
    # Basic variant
    variants.append({
        'name': 'vmess-basic',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000001',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'skip-cert-verify': True
    })
    
    # With different ciphers
    ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']
    for i, cipher in enumerate(ciphers):
        variants.append({
            'name': f'vmess-{cipher}',
            'type': 'vmess',
            'server': '1.2.3.4',
            'port': 10443 + i,
            'uuid': f'0000000{i}-0000-0000-0000-000000000001',
            'alterId': 0,
            'cipher': cipher,
            'tls': False
        })
    
    # With WebSocket
    variants.append({
        'name': 'vmess-ws',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000002',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'ws',
        'ws-opts': {
            'path': '/ws',
            'headers': {'Host': 'example.com'}
        }
    })
    
    # With gRPC
    variants.append({
        'name': 'vmess-grpc',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000003',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'grpc',
        'grpc-opts': {
            'grpc-service-name': 'example'
        }
    })
    
    # With HTTP/2
    variants.append({
        'name': 'vmess-h2',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000004',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'h2',
        'h2-opts': {
            'path': '/h2',
            'host': ['example.com']
        }
    })
    
    # With QUIC
    variants.append({
        'name': 'vmess-quic',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000005',
        'alterId': 0,
        'cipher': 'auto',
        'network': 'quic',
        'quic-opts': {
            'security': 'aes-128-gcm',
            'key': 'password123',
            'header': {'type': 'srtp'}
        }
    })
    
    # With Smux
    variants.append({
        'name': 'vmess-smux',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000006',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'skip-cert-verify': True,
        'smux': {
            'enabled': True,
            'protocol': 'h2mux',
            'max-connections': 4,
            'min-streams': 4,
            'max-streams': 1024,
            'padding': False
        }
    })
    
    return variants


def generate_vless_variants() -> List[Dict[str, Any]]:
    """Generate VLESS protocol variants."""
    variants = []
    
    # Basic variant
    variants.append({
        'name': 'vless-basic',
        'type': 'vless',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000001',
        'encryption': 'none',
        'tls': True,
        'skip-cert-verify': True
    })
    
    # With flow control
    flows = ['xtls-rprx-direct', 'xtls-rprx-vision']
    for i, flow in enumerate(flows):
        variants.append({
            'name': f'vless-{flow}',
            'type': 'vless',
            'server': '1.2.3.4',
            'port': 443 + i,
            'uuid': f'0000000{i}-0000-0000-0000-000000000002',
            'encryption': 'none',
            'flow': flow,
            'tls': True,
            'skip-cert-verify': True
        })
    
    # With Reality
    variants.append({
        'name': 'vless-reality',
        'type': 'vless',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000003',
        'encryption': 'none',
        'flow': 'xtls-rprx-vision',
        'tls': True,
        'reality-opts': {
            'public-key': 'lCWWkpDHGPtWRRIe5Ww8nPbT0GpyLSS1RCWUpI0nYFw',
            'short-id': '6ba85179e30d4fc2'
        },
        'client-fingerprint': 'chrome'
    })
    
    # With WebSocket
    variants.append({
        'name': 'vless-ws',
        'type': 'vless',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000004',
        'encryption': 'none',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'ws',
        'ws-opts': {
            'path': '/ws'
        }
    })
    
    # With gRPC
    variants.append({
        'name': 'vless-grpc',
        'type': 'vless',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000005',
        'encryption': 'none',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'grpc',
        'grpc-opts': {
            'grpc-service-name': 'example'
        }
    })
    
    return variants


def generate_trojan_variants() -> List[Dict[str, Any]]:
    """Generate Trojan protocol variants."""
    variants = []
    
    # Basic variant
    variants.append({
        'name': 'trojan-basic',
        'type': 'trojan',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'sni': 'example.com',
        'skip-cert-verify': True,
        'udp': True
    })
    
    # With WebSocket
    variants.append({
        'name': 'trojan-ws',
        'type': 'trojan',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'sni': 'example.com',
        'skip-cert-verify': True,
        'network': 'ws',
        'ws-opts': {
            'path': '/ws'
        }
    })
    
    # With gRPC
    variants.append({
        'name': 'trojan-grpc',
        'type': 'trojan',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'sni': 'example.com',
        'skip-cert-verify': True,
        'network': 'grpc',
        'grpc-opts': {
            'grpc-service-name': 'example'
        }
    })
    
    # With client fingerprint
    variants.append({
        'name': 'trojan-fingerprint',
        'type': 'trojan',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'sni': 'example.com',
        'skip-cert-verify': True,
        'client-fingerprint': 'firefox',
        'alpn': ['h2', 'http/1.1']
    })
    
    return variants


def generate_hysteria_variants() -> List[Dict[str, Any]]:
    """Generate Hysteria protocol variants."""
    variants = []
    
    # Hysteria v1 - auth
    variants.append({
        'name': 'hysteria-v1-auth',
        'type': 'hysteria',
        'server': '1.2.3.4',
        'port': 443,
        'auth': 'password123',
        'protocol': 'udp',
        'up': '30 Mbps',
        'down': '100 Mbps',
        'skip-cert-verify': True
    })
    
    # Hysteria v1 - auth-str
    variants.append({
        'name': 'hysteria-v1-authstr',
        'type': 'hysteria',
        'server': '1.2.3.4',
        'port': 443,
        'auth-str': 'base64authstring',
        'protocol': 'wechat-video',
        'obfs': 'obfuscation123',
        'skip-cert-verify': True
    })
    
    # Hysteria v1 - with ALPN
    variants.append({
        'name': 'hysteria-v1-alpn',
        'type': 'hysteria',
        'server': '1.2.3.4',
        'port': 443,
        'auth': 'password123',
        'protocol': 'faketcp',
        'alpn': ['h3'],
        'ca': '/path/to/ca.crt',
        'recv-window': 67108864,
        'recv-window-conn': 16777216
    })
    
    # Hysteria v2 - basic
    variants.append({
        'name': 'hysteria2-basic',
        'type': 'hysteria2',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'skip-cert-verify': True
    })
    
    # Hysteria v2 - with obfs
    variants.append({
        'name': 'hysteria2-obfs',
        'type': 'hysteria2',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'obfs': 'salamander',
        'obfs-password': 'obfspassword',
        'skip-cert-verify': True
    })
    
    # Hysteria v2 - with bandwidth
    variants.append({
        'name': 'hysteria2-bandwidth',
        'type': 'hysteria2',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'up': '30 Mbps',
        'down': '100 Mbps',
        'skip-cert-verify': True,
        'alpn': ['h3'],
        'client-fingerprint': 'chrome'
    })
    
    return variants


def generate_wireguard_variants() -> List[Dict[str, Any]]:
    """Generate WireGuard protocol variants."""
    variants = []
    
    # Basic variant
    variants.append({
        'name': 'wireguard-basic',
        'type': 'wireguard',
        'server': '162.159.192.1',
        'port': 2480,
        'private-key': 'eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=',
        'public-key': 'Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=',
        'ip': '172.16.0.2',
        'udp': True
    })
    
    # With IPv6
    variants.append({
        'name': 'wireguard-ipv6',
        'type': 'wireguard',
        'server': '162.159.192.1',
        'port': 2480,
        'private-key': 'eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=',
        'public-key': 'Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=',
        'ip': '172.16.0.2',
        'ipv6': 'fd01:5ca1:ab1e:80fa:ab85:6eea:213f:f4a5',
        'reserved': [0, 0, 0],
        'mtu': 1280,
        'udp': True
    })
    
    # With preshared key
    variants.append({
        'name': 'wireguard-psk',
        'type': 'wireguard',
        'server': '162.159.192.1',
        'port': 2480,
        'private-key': 'eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=',
        'public-key': 'Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=',
        'preshared-key': 'Qq9DBa+nCZNEaGTy36nJvAfK9a1r0wPIc3gmVB21sG8=',
        'ip': '172.16.0.2',
        'udp': True
    })
    
    return variants


def generate_tuic_variants() -> List[Dict[str, Any]]:
    """Generate TUIC protocol variants."""
    variants = []
    
    # V5 with UUID
    variants.append({
        'name': 'tuic-v5-uuid',
        'type': 'tuic',
        'server': '1.2.3.4',
        'port': 10443,
        'uuid': '00000000-0000-0000-0000-000000000001',
        'password': 'password123',
        'alpn': ['h3'],
        'skip-cert-verify': True
    })
    
    # With token
    variants.append({
        'name': 'tuic-token',
        'type': 'tuic',
        'server': '1.2.3.4',
        'port': 10443,
        'token': 'TOKEN123',
        'alpn': ['h3'],
        'skip-cert-verify': True
    })
    
    # With advanced options
    variants.append({
        'name': 'tuic-advanced',
        'type': 'tuic',
        'server': '1.2.3.4',
        'port': 10443,
        'uuid': '00000000-0000-0000-0000-000000000002',
        'password': 'password123',
        'congestion-controller': 'bbr',
        'udp-relay-mode': 'quic',
        'reduce-rtt': True,
        'heartbeat-interval': 10000,
        'max-udp-relay-packet-size': 1500,
        'disable-sni': True,
        'skip-cert-verify': True
    })
    
    # With ECH
    variants.append({
        'name': 'tuic-ech',
        'type': 'tuic',
        'server': 'example.com',
        'port': 10443,
        'uuid': '00000000-0000-0000-0000-000000000003',
        'password': 'password123',
        'alpn': ['h3'],
        'ech-opts': {
            'enable': True,
            'config': 'AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA'
        },
        'skip-cert-verify': True
    })
    
    return variants


def generate_ssh_variants() -> List[Dict[str, Any]]:
    """Generate SSH protocol variants."""
    variants = []
    
    # Basic with password
    variants.append({
        'name': 'ssh-password',
        'type': 'ssh',
        'server': '1.2.3.4',
        'port': 22,
        'username': 'root',
        'password': 'password123'
    })
    
    # With private key
    variants.append({
        'name': 'ssh-privatekey',
        'type': 'ssh',
        'server': '1.2.3.4',
        'port': 22,
        'username': 'ubuntu',
        'private-key': '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4e2D/qPN08pzTac+a8ZmlP1ziJOXk45CynMPtva0rtK/RB26
...
-----END RSA PRIVATE KEY-----'''
    })
    
    # With advanced options
    variants.append({
        'name': 'ssh-advanced',
        'type': 'ssh',
        'server': '1.2.3.4',
        'port': 2222,
        'username': 'admin',
        'password': 'password123',
        'host-key': ['ssh-rsa AAAAB3NzaC1yc2EAAAA...'],
        'host-key-algorithms': ['ssh-rsa', 'ssh-ed25519'],
        'client-version': 'SSH-2.0-OpenSSH_8.9'
    })
    
    return variants


def generate_snell_variants() -> List[Dict[str, Any]]:
    """Generate Snell protocol variants."""
    variants = []
    
    # v1
    variants.append({
        'name': 'snell-v1',
        'type': 'snell',
        'server': '1.2.3.4',
        'port': 44046,
        'psk': 'yourpsk',
        'version': 1
    })
    
    # v2 with obfs
    variants.append({
        'name': 'snell-v2-http',
        'type': 'snell',
        'server': '1.2.3.4',
        'port': 44046,
        'psk': 'yourpsk',
        'version': 2,
        'obfs-opts': {
            'mode': 'http',
            'host': 'bing.com'
        }
    })
    
    # v3 with tls obfs
    variants.append({
        'name': 'snell-v3-tls',
        'type': 'snell',
        'server': '1.2.3.4',
        'port': 44046,
        'psk': 'yourpsk',
        'version': 3,
        'obfs-opts': {
            'mode': 'tls',
            'host': 'example.com'
        }
    })
    
    return variants


def generate_mieru_variants() -> List[Dict[str, Any]]:
    """Generate Mieru protocol variants."""
    variants = []
    
    # Basic
    variants.append({
        'name': 'mieru-basic',
        'type': 'mieru',
        'server': '1.2.3.4',
        'port': 2999,
        'username': 'user',
        'password': 'password',
        'transport': 'TCP'
    })
    
    # With multiplexing
    multiplexing_levels = ['MULTIPLEXING_OFF', 'MULTIPLEXING_LOW', 'MULTIPLEXING_MIDDLE', 'MULTIPLEXING_HIGH']
    for i, level in enumerate(multiplexing_levels):
        variants.append({
            'name': f'mieru-{level.lower()}',
            'type': 'mieru',
            'server': '1.2.3.4',
            'port': 3000 + i,
            'username': 'user',
            'password': 'password',
            'transport': 'TCP',
            'multiplexing': level
        })
    
    # With port range
    variants.append({
        'name': 'mieru-port-range',
        'type': 'mieru',
        'server': '1.2.3.4',
        'port': 2999,
        'username': 'user',
        'password': 'password',
        'transport': 'TCP',
        'port-range': '2090-2099',
        'multiplexing': 'MULTIPLEXING_HIGH'
    })
    
    return variants


def generate_anytls_variants() -> List[Dict[str, Any]]:
    """Generate AnyTLS protocol variants."""
    variants = []
    
    # Basic
    variants.append({
        'name': 'anytls-basic',
        'type': 'anytls',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'secret123',
        'tls': True,
        'skip-cert-verify': True
    })
    
    # With client fingerprint
    variants.append({
        'name': 'anytls-fingerprint',
        'type': 'anytls',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'secret123',
        'tls': True,
        'client-fingerprint': 'chrome',
        'sni': 'example.com',
        'skip-cert-verify': True
    })
    
    # With session options
    variants.append({
        'name': 'anytls-session',
        'type': 'anytls',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'secret123',
        'idle-session-check-interval': 60,
        'idle-session-timeout': 30,
        'min-idle-session': 5,
        'tls': True,
        'skip-cert-verify': True
    })
    
    return variants


def generate_http_socks_variants() -> List[Dict[str, Any]]:
    """Generate HTTP/SOCKS protocol variants."""
    variants = []
    
    # HTTP without auth
    variants.append({
        'name': 'http-basic',
        'type': 'http',
        'server': '1.2.3.4',
        'port': 8080
    })
    
    # HTTP with auth
    variants.append({
        'name': 'http-auth',
        'type': 'http',
        'server': '1.2.3.4',
        'port': 8080,
        'username': 'user',
        'password': 'pass'
    })
    
    # HTTPS
    variants.append({
        'name': 'https',
        'type': 'http',
        'server': '1.2.3.4',
        'port': 8443,
        'tls': True,
        'skip-cert-verify': True
    })
    
    # SOCKS5 without auth
    variants.append({
        'name': 'socks5-basic',
        'type': 'socks5',
        'server': '1.2.3.4',
        'port': 1080
    })
    
    # SOCKS5 with auth
    variants.append({
        'name': 'socks5-auth',
        'type': 'socks5',
        'server': '1.2.3.4',
        'port': 1080,
        'username': 'user',
        'password': 'pass'
    })
    
    # SOCKS5 with TLS
    variants.append({
        'name': 'socks5-tls',
        'type': 'socks5',
        'server': '1.2.3.4',
        'port': 1443,
        'tls': True,
        'skip-cert-verify': True
    })
    
    return variants


def generate_special_combinations() -> List[Dict[str, Any]]:
    """Generate special protocol combinations."""
    variants = []
    
    # VMess with Reality (theoretical combination)
    variants.append({
        'name': 'special-vmess-reality',
        'type': 'vmess',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000099',
        'alterId': 0,
        'cipher': 'auto',
        'tls': True,
        'reality-opts': {
            'public-key': 'lCWWkpDHGPtWRRIe5Ww8nPbT0GpyLSS1RCWUpI0nYFw',
            'short-id': '6ba85179e30d4fc2'
        },
        'client-fingerprint': 'safari'
    })
    
    # Shadowsocks with WebSocket transport
    variants.append({
        'name': 'special-ss-ws',
        'type': 'ss',
        'server': '1.2.3.4',
        'port': 443,
        'cipher': 'aes-256-gcm',
        'password': 'password123',
        'network': 'ws',
        'ws-opts': {
            'path': '/ws',
            'headers': {'Host': 'example.com'}
        },
        'tls': True,
        'skip-cert-verify': True
    })
    
    # Trojan with QUIC transport
    variants.append({
        'name': 'special-trojan-quic',
        'type': 'trojan',
        'server': '1.2.3.4',
        'port': 443,
        'password': 'password123',
        'network': 'quic',
        'quic-opts': {
            'security': 'chacha20-poly1305',
            'key': 'password123'
        }
    })
    
    # VLESS with multiple transports and smux
    variants.append({
        'name': 'special-vless-multi',
        'type': 'vless',
        'server': '1.2.3.4',
        'port': 443,
        'uuid': '00000000-0000-0000-0000-000000000098',
        'encryption': 'none',
        'tls': True,
        'skip-cert-verify': True,
        'network': 'grpc',
        'grpc-opts': {
            'grpc-service-name': 'example'
        },
        'smux': {
            'enabled': True,
            'protocol': 'yamux',
            'max-connections': 8,
            'min-streams': 4,
            'max-streams': 2048,
            'padding': True,
            'statistic': True,
            'only-tcp': False
        }
    })
    
    return variants


def main():
    """Generate the YAML file with all protocol combinations."""
    all_proxies = []
    
    # Generate all protocol variants
    all_proxies.extend(generate_shadowsocks_variants())
    all_proxies.extend(generate_vmess_variants())
    all_proxies.extend(generate_vless_variants())
    all_proxies.extend(generate_trojan_variants())
    all_proxies.extend(generate_hysteria_variants())
    all_proxies.extend(generate_wireguard_variants())
    all_proxies.extend(generate_tuic_variants())
    all_proxies.extend(generate_ssh_variants())
    all_proxies.extend(generate_snell_variants())
    all_proxies.extend(generate_mieru_variants())
    all_proxies.extend(generate_anytls_variants())
    all_proxies.extend(generate_http_socks_variants())
    all_proxies.extend(generate_special_combinations())
    
    # Create the complete config
    config = {
        'proxies': all_proxies,
        'proxy-groups': [
            {
                'name': 'All Proxies',
                'type': 'select',
                'proxies': [proxy['name'] for proxy in all_proxies]
            },
            {
                'name': 'Shadowsocks',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'ss']
            },
            {
                'name': 'VMess',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'vmess']
            },
            {
                'name': 'VLESS',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'vless']
            },
            {
                'name': 'Trojan',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'trojan']
            },
            {
                'name': 'Hysteria',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] in ['hysteria', 'hysteria2']]
            },
            {
                'name': 'WireGuard',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'wireguard']
            },
            {
                'name': 'TUIC',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'tuic']
            },
            {
                'name': 'SSH',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'ssh']
            },
            {
                'name': 'Snell',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'snell']
            },
            {
                'name': 'Mieru',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'mieru']
            },
            {
                'name': 'AnyTLS',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] == 'anytls']
            },
            {
                'name': 'HTTP/SOCKS',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['type'] in ['http', 'socks5']]
            },
            {
                'name': 'Special Combinations',
                'type': 'select',
                'proxies': [p['name'] for p in all_proxies if p['name'].startswith('special-')]
            }
        ],
        'rules': [
            'MATCH,All Proxies'
        ]
    }
    
    # Write to file
    with open('mihomo_all_protocols.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"Generated mihomo_all_protocols.yaml with {len(all_proxies)} proxy configurations")
    print(f"Protocols covered:")
    protocol_counts = {}
    for proxy in all_proxies:
        ptype = proxy['type']
        protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1
    
    for ptype, count in sorted(protocol_counts.items()):
        print(f"  - {ptype}: {count} variants")


if __name__ == '__main__':
    main()