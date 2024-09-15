from typing import Self
from .const import SubIOProtocol
from dataclasses import dataclass
from typing import Any
import urllib
import base64
from functools import lru_cache
import json

import enum


class Unsupport(Exception):
    pass


# def _trans(node):
#     if node["type"] == "http":
#         scheme = "http"
#         if "tls" in node and node["tls"]:
#             scheme = "https"
#         userinfo = ""
#         if node["username"] and node["password"]:
#             userinfo = f"{node['username']}:{node['password']}@"
#         return f"{scheme}://{userinfo}{node['server']}:{node['port']}#{quote(node['name'])}"
#     elif node["type"] == "socks5":
#         scheme = "socks5"
#         if "tls" in node and node["tls"]:
#             scheme = "socks5-tls"
#         userinfo = ""
#         if node["username"] and node["password"]:
#             userinfo = f"{node['username']}:{node['password']}@"
#         return f"{scheme}://{userinfo}{node['server']}:{node['port']}"
#     elif node["type"] == "ss":
#         plugin = ""
#         if "obfs" in node:
#             mode = node["obfs"]
#             if mode == "tls":
#                 if "obfs-host" in node:
#                     host = node["obfs-host"]
#                     plugin = f";obfs={mode};obfs-host={host}"
#             plugin = f"/?plugin=obfs-local{quote(plugin)}"

#         if "2022" in node["cipher"]:
#             return f"ss://{node['cipher']}:{node['password']}@{node['server']}:{node['port']}{plugin}#{quote(node['name'])}"
#         else:
#             userinfo = f"{node['cipher']}:{node['password']}"
#             userinfo = base64.b64encode(userinfo.encode("utf-8")).decode("utf-8")
#             userinfo = userinfo.replace("=", "")
#             return f"ss://{userinfo}@{node['server']}:{node['port']}{plugin}#{quote(node['name'])}"
#     elif node["type"] == "trojan":
#         options = ""
#         if "allowInsecure" in node:
#             value = 1 if node["allowInsecure"] else 0
#             options += f"allowInsecure={value};"
#         if options != "":
#             options = f"?{options}"

#         return f"trojan://{node['password']}@{node['server']}:{node['port']}?{options}#{quote(node['name'])}"
#     return ""


class TLSBase:
    @dataclass
    class RealityOpts:
        public_key: str
        short_id: str

    tls: bool = False
    sni: str = None
    fingerprint: str = None
    alpn: list[str] = None
    skip_cert_verify: bool = False
    client_fingerprint: str = None
    reality_opts: RealityOpts = None

    def setup_tls_from_clash_meta(self, node: dict) -> Self:
        self.tls = node.get("tls", False)
        self.skip_cert_verify = node.get("skip-cert-verify", False)
        if node["type"] == "vmess" or node["type"] == "vless":
            self.sni = node.get("servername", None)
        else:
            self.sni = node.get("sni", None)
        self.fingerprint = node.get("fingerprint", None)
        self.client_fingerprint = node.get("client-fingerprint", None)
        if node.get("reality-opts", None):
            self.reality_opts = TLSBase.RealityOpts(
                public_key=node["reality-opts"]["public-key"],
                short_id=node["reality-opts"]["short-id"],
            )
        return self

    def setup_tls_from_v2rayn(self, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        self.tls = True if url.scheme == "https" else False
        self.sni = url.hostname
        return self

    def setup_tls_from_trojan_url(self, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        q = urllib.parse.parse_qs(url.query)
        allow_insecure = False
        if q:
            if "allowInsecure" in q:
                allow_insecure = True if q["allowInsecure"][0] == "1" else False
        self.tls = True
        self.skip_cert_verify = allow_insecure
        return self

    # to
    def tls_to_clash_meta(self) -> dict:
        ret = {
            "tls": self.tls,
            "sni": self.sni,
            "fingerprint": self.fingerprint,
            "alpn": self.alpn,
            "skip-cert-verify": self.skip_cert_verify,
            "client-fingerprint": self.client_fingerprint,
        }
        if self.reality_opts:
            ret["reality-opts"] = {
                "public-key": self.reality_opts.public_key,
                "short-id": self.reality_opts.short_id,
            }
        return ret

    def tls_to_surge_base(self) -> str | None:
        all = [f"tls={self.tls}"]
        if self.tls:
            all.append(f"skip-cert-verify={self.skip_cert_verify}")
        else:
            return None

        if self.sni:
            all.append(f"sni={self.sni}")
        if self.fingerprint:
            all.append(f"server-cert-fingerprint-sha256={self.fingerprint}")
        return ", ".join(all)


class TransportBase:
    class Network(enum.StrEnum):
        tcp = "tcp"
        ws = "ws"
        http = "http"
        h2 = "h2"
        grpc = "grpc"

    @dataclass
    class WSOpts(object):
        path: str
        headers: dict
        max_early_data: int
        early_data_header_name: str

    @dataclass
    class HTTPOpts(object):
        method: str
        path: list[str]
        headers: dict

    @dataclass
    class H2Opts(object):
        host: list[str]
        path: str

    @dataclass
    class GRPCOpts(object):
        grpc_service_name: str

    network: Network = None
    ws_opts: WSOpts = None
    http_opts: HTTPOpts = None
    h2_opts: H2Opts = None
    grpc_opts: GRPCOpts = None

    def setup_tranport_from_clash_meta(self, node: dict) -> Self:
        if node.get("network", None):
            self.network = TransportBase.Network(node["network"])

            if node.get("ws-opts", None):
                self.ws_opts = TransportBase.WSOpts(
                    path=node["ws-opts"]["path"],
                    headers=node["ws-opts"]["headers"],
                    max_early_data=node["ws-opts"].get("max-early-data", None),
                    early_data_header_name=node["ws-opts"].get(
                        "early-data-header-name", None
                    ),
                )
            if node.get("http-opts", None):
                self.http_opts = TransportBase.HTTPOpts(
                    method=node["http-opts"]["method"],
                    path=node["http-opts"]["path"],
                    headers=node["http-opts"]["headers"],
                )
            if node.get("h2-opts", None):
                self.h2_opts = TransportBase.H2Opts(
                    host=node["h2-opts"]["host"],
                    path=node["h2-opts"]["path"],
                )
            if node.get("grpc-opts", None):
                self.grpc_opts = TransportBase.GRPCOpts(
                    grpc_service_name=node["grpc-opts"]["grpc-service-name"],
                )
        return self

    def transport_to_clash_meta(self) -> dict | None:
        if self.network:
            ret = {
                "network": self.network.value,
            }
            if self.ws_opts:
                ret["ws-opts"] = {
                    "path": self.ws_opts.path,
                    "headers": self.ws_opts.headers,
                }
                if self.ws_opts.max_early_data:
                    ret["ws-opts"]["max-early-data"] = self.ws_opts.max_early_data
                if self.ws_opts.early_data_header_name:
                    ret["ws-opts"]["early-data-header-name"] = (
                        self.ws_opts.early_data_header_name
                    )

            if self.http_opts:
                ret["http-opts"] = {
                    "method": self.http_opts.method,
                    "path": self.http_opts.path,
                    "headers": self.http_opts.headers,
                }
            if self.h2_opts:
                ret["h2-opts"] = {
                    "host": self.h2_opts.host,
                    "path": self.h2_opts.path,
                }
            if self.grpc_opts:
                ret["grpc-opts"] = {
                    "grpc-service-name": self.grpc_opts.grpc_service_name,
                }
            return ret

        return None


class SmuxBase:
    @dataclass
    class Smux:
        @dataclass
        class BrutalOpts:
            enabled: bool
            up: int
            down: int

        enabled: bool
        protocol: str
        max_connections: int
        min_streams: int
        max_streams: int
        statistic: bool
        only_tcp: bool
        padding: bool
        brutal_opts: BrutalOpts = None

        def __init__(self, opts):
            self.enabled = opts["enabled"]
            self.protocol = opts["protocol"]
            self.max_connections = opts["max-connections"]
            self.min_streams = opts["min-streams"]
            self.max_streams = opts["max-streams"]
            self.statistic = opts["statistic"]
            self.only_tcp = opts["only-tcp"]
            self.padding = opts["padding"]
            if opts.get("brutal-opts", None):
                self.brutal_opts = SmuxBase.Smux.BrutalOpts(
                    enabled=opts["brutal-opts"]["enabled"],
                    up=opts["brutal-opts"]["up"],
                    down=opts["brutal-opts"]["down"],
                )

    smux: Smux = None

    def sumux_from_clash_meta(self, node: dict) -> Self:
        if node.get("smux", None):
            self.smux = SmuxBase.Smux(node["smux"])
        return self

    # to
    def smux_to_clash_meta(self) -> dict:
        ret = None
        if self.smux:
            ret = {
                "enabled": self.smux.enabled,
                "protocol": self.smux.protocol,
                "max-connections": self.smux.max_connections,
                "min-streams": self.smux.min_streams,
                "max-streams": self.smux.max_streams,
                "statistic": self.smux.statistic,
                "only-tcp": self.smux.only_tcp,
                "padding": self.smux.padding,
            }
            if self.smux.brutal_opts:
                ret["brutal-opts"] = {
                    "enabled": self.smux.brutal_opts.enabled,
                    "up": self.smux.brutal_opts.up,
                    "down": self.smux.brutal_opts.down,
                }

        return {"smux": ret}


class PacketEncodingBase:
    packet_encoding: str = None

    def setup_packet_encoding_from_clash_meta(self, node: dict) -> Self:
        if node.get("packet-encoding", None):
            self.packet_encoding = node["packet-encoding"]
        return self

    def packet_encoding_to_clash_meta(self) -> dict:
        return {"packet-encoding": self.packet_encoding}


class Base:
    type: SubIOProtocol
    node: Any
    name: str
    server: str
    port: int
    udp: bool
    tfo: bool
    ip_version: str
    mptcp: bool

    def __hash__(self) -> int:
        if isinstance(self.node, dict):
            return hash(json.dumps(self.node, sort_keys=True))
        elif isinstance(self.node, str):
            return self.node.__hash__()
        else:
            raise Unsupport(f"Unsupport {self.__class__.__name__} hash")

    @classmethod
    def __post_init__(cls):
        cls.__hash__ = Base.__hash__

    def setup_type(self, type: SubIOProtocol) -> Self:
        self.type = type
        return self

    def setup_general_from_clash_meta(self, node: dict) -> Self:
        self.node = node
        self.name = node["name"]
        self.server = node["server"]
        self.port = node["port"]
        self.udp = node.get("udp", False)
        self.tfo = node.get("tfo", False)
        self.ip_version = node.get("ip-version", "dual")
        self.mptcp = node.get("mptcp", False)
        return self

    def setup_general_from_ss_url(self, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        self.node = node
        if url.fragment:
            # url decode
            self.name = urllib.parse.unquote(url.fragment)
        else:
            self.name = f"{url.hostname}:{url.port}"
        self.server = url.hostname
        self.port = url.port
        self.udp = True
        self.tfo = False
        self.ip_version = "dual"
        self.mptcp = False
        return self

    def setup_general_from_trojan_url(self, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        self.node = node
        self.name = url.fragment if url.fragment else f"{url.hostname}:{url.port}"
        self.server = url.hostname
        self.port = url.port
        self.udp = True
        if url.query:
            q = urllib.parse.parse_qs(url.query)
            if "tfo" in q:
                self.tfo = True if q["tfo"] == 1 else False
        self.ip_version = "dual"
        self.mptcp = False
        return self

    def setup_general_from_http_url(self, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        self.node = node
        self.name = url.fragment if url.fragment else f"{url.hostname}:{url.port}"
        self.server = url.hostname
        self.port = url.port
        self.udp = False
        self.tfo = False
        self.ip_version = "dual"
        self.mptcp = False
        return self

    # from
    @classmethod
    def from_surge(cls, text: str) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from Surge")

    @classmethod
    def from_clash(cls, node: dict) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from Clash")

    @classmethod
    def from_v2rayn(cls, node: str) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from V2rayN")

    @classmethod
    def from_dae(cls, node: str) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from Dae")

    @classmethod
    def from_subio(cls, node: dict) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from SubIO")

    @classmethod
    def from_quantumultx(cls, node: str) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from QuantumultX")

    @classmethod
    def from_stash(cls, node: dict) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from Stash")

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        raise Unsupport(f"Unsupport {cls.__name__} from Clash.Meta")

    # to
    def to_surge(self) -> str:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to Surge")

    def to_clash(self) -> dict:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to Clash")

    def to_v2rayn(self) -> str:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to V2rayN")

    def to_dae(self) -> str:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to Dae")

    def to_subio(self) -> dict:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to SubIO")

    def to_quantumultx(self) -> str:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to QuantumultX")

    def to_stash(self) -> dict:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to Stash")

    def to_clash_meta(self) -> dict:
        raise Unsupport(f"Unsupport {self.__class__.__name__} to Clash.Meta")

    def to_clash_meta_base(self) -> dict:
        return {
            "type": self.type.meta_type,
            "name": self.name,
            "server": self.server,
            "port": self.port,
            "udp": self.udp,
            "tfo": self.tfo,
            "ip-version": self.ip_version,
            "mptcp": self.mptcp,
        }

    def to_surge_base(self) -> str:
        return f"{self.name} = {self.type}, {self.server}, {self.port}"


@dataclass
class Shadowsocks(Base, SmuxBase):
    class Plugin(enum.StrEnum):
        obfs = "obfs"
        v2ray_plugin = "v2ray-plugin"
        shadow_tls = "shadow-tls"
        restls = "restls"

    class OptsBase:
        def to_clash_meta(self) -> dict:
            return self.__dict__

    @dataclass
    class ObfsOptions(OptsBase):
        class Mode(enum.StrEnum):
            tls = "tls"
            http = "http"

        mode: Mode
        host: str

    @dataclass
    class V2rayOptions(OptsBase):
        tls: bool
        skip_cert_verify: bool
        fingerprint: str
        host: str
        path: str
        mux: bool
        headers: dict
        v2ray_http_upgrade: bool

    @dataclass
    class ShadowTLSOptions(OptsBase):
        host: str
        password: str
        version: int

    @dataclass
    class RestlsOptions(OptsBase):
        host: str
        password: str
        version_hint: str
        restls_script: str

    @dataclass
    class Cipher(enum.StrEnum):
        ases_128_ctr = "aes-128-ctr"
        aes_192_ctr = "aes-192-ctr"
        aes_256_ctr = "aes-256-ctr"
        aes_128_cfb = "aes-128-cfb"
        aes_192_cfb = "aes-192-cfb"
        aes_256_cfb = "aes-256-cfb"
        aes_128_gcm = "aes-128-gcm"
        aes_192_gcm = "aes-192-gcm"
        aes_256_gcm = "aes-256-gcm"
        aes_128_ccm = "aes-128-ccm"
        aes_192_ccm = "aes-192-ccm"
        aes_256_ccm = "aes-256-ccm"
        aes_128_gcm_siv = "aes-128-gcm-siv"
        aes_256_gcm_siv = "aes-256-gcm-siv"
        chacha20_ietf = "chacha20-ietf"
        chacha20 = "chacha20"
        xchacha20 = "xchacha20"
        chacha20_ietf_poly1305 = "chacha20-ietf-poly1305"
        xchacha20_ietf_poly1305 = "xchacha20-ietf-poly1305"
        chacha8_ietf_poly1305 = "chacha8-ietf-poly1305"
        xchacha8_ietf_poly1305 = "xchacha8-ietf-poly1305"
        blake3_aes_128_gcm = "2022-blake3-aes-128-gcm"
        blake3_aes_256_gcm = "2022-blake3-aes-256-gcm"
        blake3_chacha20_poly1305 = "2022-blake3-chacha20-poly1305"
        lea_128_gcm = "lea-128-gcm"
        lea_192_gcm = "lea-192-gcm"
        lea_256_gcm = "lea-256-gcm"
        rabbit128_poly130 = "rabbit128-poly1305"
        aegis_128l = "aegis-128l"
        aegis_256 = "aegis-256"
        aez_384 = "aez-384"
        deoxys_ii_256_128 = "deoxys-ii-256-128"
        rc4_md5 = "rc4-md5"
        none = "none"

        def __eq__(self, value: object) -> bool:
            return self.value == value

        @property
        def is_2022(self):
            return self in [
                Shadowsocks.Cipher.blake3_aes_128_gcm,
                Shadowsocks.Cipher.blake3_aes_256_gcm,
                Shadowsocks.Cipher.blake3_chacha20_poly1305,
            ]

    cipher: Cipher
    password: str
    plugin: Plugin = None
    plugin_opts: ObfsOptions | V2rayOptions | ShadowTLSOptions | RestlsOptions = None

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        options = None
        if node.get("plugin-opts", None):
            if node["plugin"] == "obfs":
                options = Shadowsocks.ObfsOptions(
                    mode=node["plugin-opts"]["mode"],
                    host=node["plugin-opts"]["host"],
                )
            elif node["plugin"] == "v2ray-plugin":
                options = Shadowsocks.V2rayOptions(
                    tls=node["plugin-opts"]["tls"],
                    skip_cert_verify=node["plugin-opts"]["skip-cert-verify"],
                    fingerprint=node["plugin-opts"]["fingerprint"],
                    host=node["plugin-opts"]["host"],
                    path=node["plugin-opts"]["path"],
                    mux=node["plugin-opts"]["mux"],
                    headers=node["plugin-opts"]["headers"],
                    v2ray_http_upgrade=node["plugin-opts"].get(
                        "v2ray-http-upgrade", False
                    ),
                )
            elif node["plugin"] == "shadow-tls":
                options = Shadowsocks.ShadowTLSOptions(
                    host=node["plugin-opts"]["host"],
                    password=node["plugin-opts"]["password"],
                    version=node["plugin-opts"]["version"],
                )
            elif node["plugin"] == "restls":
                options = Shadowsocks.RestlsOptions(
                    host=node["plugin-opts"]["host"],
                    password=node["plugin-opts"]["password"],
                    version_hint=node["plugin-opts"]["version-hint"],
                    restls_script=node["plugin-opts"]["restls-script"],
                )
            else:
                raise Unsupport(f"Unsupport plugin: {node['plugin']}")

        return (
            Shadowsocks(
                cipher=Shadowsocks.Cipher(node["cipher"]),
                password=node["password"],
                plugin=node.get("plugin", None),
                plugin_opts=options,
            )
            .sumux_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.SHADOWSOCKS)
        )

    # v2rayN
    def line_to_proxy(line):
        # parse text as url
        url = urllib.parse.urlparse(line)
        username = url.username
        password = url.password
        netloc = url.netloc
        str_before_at = netloc.split("@")[0]
        q = urllib.parse.parse_qs(url.query)

        cipher = None

        # ss2022
        if ":" in str_before_at:
            cipher = username
            password = password
        else:
            # padding
            str_before_a = str_before_at + "=" * (4 - len(str_before_at) % 4)
            t = base64.b64decode(str_before_a).decode("utf-8")
            component = t.split(":")
            cipher = component[0]
            password = component[1]

        plugin = None
        obfs_opts: Shadowsocks.ObfsOptions = None

        if q:
            # q = {'plugin': ['obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com'], 'group': ['RGxlc']}
            if "plugin" in q:
                # plugin = obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com
                plugin_str = urllib.parse.unquote(q["plugin"][0])
                component = plugin_str.split(";")
                if component[0] == "obfs-local":
                    plugin = "obfs"
                else:
                    plugin = plugin[0]

                opts = {}
                for opt in component[1:]:
                    k, v = opt.split("=")
                    opts[k] = v

                if plugin == "obfs":
                    obfs_opts = Shadowsocks.ObfsOptions(
                        mode=opts["obfs"],
                        host=opts["obfs-host"],
                    )
                else:
                    raise Unsupport(
                        f"Unsupport plugin: {plugin} of {Self.__class__.__name__} from V2rayN"
                    )

        return (
            Shadowsocks(
                cipher=Shadowsocks.Cipher(cipher),
                password=password,
                plugin=plugin,
                plugin_opts=obfs_opts,
            )
            .setup_general_from_ss_url(line)
            .setup_type(SubIOProtocol.SHADOWSOCKS)
        )

    @classmethod
    def from_v2rayn(cls, node: str) -> Self:
        return Shadowsocks.line_to_proxy(node).setup_type(SubIOProtocol.SHADOWSOCKS)

    # to

    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {
            "cipher": self.cipher.value,
            "password": self.password,
            "plugin": self.plugin,
        }
        if self.plugin_opts:
            ret["plugin-opts"] = self.plugin_opts.to_clash_meta()
        ret.update(self.to_clash_meta_base())
        ret.update(self.smux_to_clash_meta())
        return ret

    @lru_cache
    def to_surge(self) -> str:
        ret = f"{self.to_surge_base()}, encrypt-method={self.cipher}, password={self.password}, udp-relay={"true" if self.udp else "false"}"
        if self.plugin:
            if self.plugin == Shadowsocks.Plugin.obfs:
                ret += (
                    f", obfs={self.plugin_opts.mode}, obfs-host={self.plugin_opts.host}"
                )
            else:
                raise Unsupport(
                    f"Unsupport plugin: {self.plugin} of {self.__class__.__name__} to Surge"
                )
        return ret

    @lru_cache
    def to_v2rayn(self) -> str:
        def plugin_text() -> str | None:
            if self.plugin == Shadowsocks.Plugin.obfs:
                if self.plugin_opts.mode in [
                    Shadowsocks.ObfsOptions.Mode.tls,
                    Shadowsocks.ObfsOptions.Mode.http,
                ]:
                    plugin = f"obfs-local;obfs={self.plugin_opts.mode};obfs-host={self.plugin_opts.host}"
                    return f"plugin={plugin}"
            return None

        def cipher_and_password() -> str:
            if self.cipher.is_2022:
                return f"{self.cipher}:{self.password}"
            else:
                return (
                    base64.b64encode(f"{self.cipher}:{self.password}".encode("utf-8"))
                    .decode("utf-8")
                    .replace("=", "")
                )

        all = [f"ss://{cipher_and_password()}@{self.server}:{self.port}"]
        if self.plugin:
            all.append(plugin_text())
        all.append(f"#{urllib.parse.quote(self.name)}")
        return "/?".join(all)

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Vmess(Base, TLSBase, TransportBase, SmuxBase, PacketEncodingBase):
    uuid: str
    alter_id: int
    cipher: str
    global_padding: bool

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        return (
            Vmess(
                uuid=node["uuid"],
                alter_id=node["alterId"],
                cipher=node["cipher"],
                global_padding=node.get("global-padding", False),
            )
            .setup_tls_from_clash_meta(node)
            .setup_tranport_from_clash_meta(node)
            .sumux_from_clash_meta(node)
            .setup_packet_encoding_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.VMESS)
        )

    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {
            "uuid": self.uuid,
            "alterId": self.alter_id,
            "cipher": self.cipher,
            "global-padding": self.global_padding,
        }
        ret.update(self.tls_to_clash_meta())
        ret.update(self.transport_to_clash_meta())
        ret.update(self.smux_to_clash_meta())
        ret.update(self.packet_encoding_to_clash_meta())
        ret.update(self.to_clash_meta_base())
        return ret

    @lru_cache
    def to_surge(self) -> str:
        ret = f"{self.to_surge_base()}, username={self.uuid}, encryption={self.cipher}"
        if self.network:
            if self.network == TransportBase.Network.ws:
                ret += f", ws=true, ws-path={self.ws_opts.path}, ws-headers={self.ws_opts.headers}"
            else:
                raise Unsupport(
                    f"Unsupport network: {self.network} of {self.__class__.__name__} to Surge"
                )
        return ", ".join([x for x in [ret, self.tls_to_surge_base()] if x])

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Trojan(Base, TLSBase, SmuxBase, TransportBase):
    password: str

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        return (
            Trojan(
                password=node["password"],
            )
            .setup_tls_from_clash_meta(node)
            .sumux_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.TROJAN)
        )

    # v2rayN
    @classmethod
    def from_v2rayn(cls, node: str) -> Self:
        # trojan://ahh@example.com:1111?allowInsecure=1&tfo=0#ahh
        url = urllib.parse.urlparse(node)
        netloc = url.netloc
        str_before_at = netloc.split("@")[0]

        return (
            Trojan(
                password=str_before_at,
            )
            .setup_tls_from_trojan_url(node)
            .setup_general_from_trojan_url(node)
            .setup_type(SubIOProtocol.TROJAN)
        )

    # to
    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {"password": self.password}
        ret.update(self.tls_to_clash_meta())
        ret.update(self.smux_to_clash_meta())
        ret.update(self.to_clash_meta_base())
        return ret

    @lru_cache
    def to_surge(self) -> str:
        ret = self.to_surge_base() + f", password={self.password}"
        if self.network:
            if self.network == TransportBase.Network.ws:
                ret += f", ws=true, ws-path={self.ws_opts.path}, ws-headers={self.ws_opts.headers}"
            else:
                raise Unsupport(
                    f"Unsupport network: {self.network} of {self.__class__.__name__} to Surge"
                )
        return ", ".join([x for x in [ret, self.tls_to_surge_base()] if x])

    @lru_cache
    def to_v2rayn(self) -> str:
        def tls_text() -> list[str]:
            all = []
            if self.sni:
                all.append(f"sni={self.sni}")
            if self.skip_cert_verify:
                all.append("allowInsecure=1")
            return all

        if self.network is not None and self.ws_opts is not TransportBase.Network.tcp:
            raise Unsupport(
                f"Unsupport network: {self.network} of {self.__class__.__name__}"
            )

        return f"trojan://{self.password}@{self.server}:{self.port}?{'&'.join(tls_text())}#{self.name}"

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Socks5(Base, TLSBase):
    username: str
    password: str

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        return (
            Socks5(
                username=node["username"],
                password=node["password"],
            )
            .setup_tls_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.SOCKS5)
        )

    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {
            "username": self.username,
            "password": self.password,
        }
        ret.update(self.tls_to_clash_meta())
        ret.update(self.to_clash_meta_base())
        return ret

    @lru_cache
    def to_surge(self) -> str:
        ret = (
            self.to_surge_base()
            + f", {self.username}, {self.password}, udp-relay={"true" if self.udp else "false"}"
        )
        return ",".join([x for x in [ret, self.tls_to_surge_base()] if x])

    @lru_cache
    def to_v2rayn(self) -> str:
        return f"socks5://{self.username}:{self.password}@{self.server}:{self.port}#{self.name}"

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Http(Base, TLSBase):
    username: str
    password: str
    headers: dict

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        return (
            Http(
                username=node["username"],
                password=node["password"],
                headers=node.get("headers", None),
            )
            .setup_tls_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.HTTP)
        )

    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {
            "username": self.username,
            "password": self.password,
            "headers": self.headers,
        }
        ret.update(self.tls_to_clash_meta())
        ret.update(self.to_clash_meta_base())
        return ret

    @classmethod
    def from_v2rayn(cls, node: str) -> Self:
        url = urllib.parse.urlparse(node)
        username = url.username
        password = url.password

        return (
            Http(
                username=username,
                password=password,
                headers=None,
            )
            .setup_tls_from_v2rayn(node)
            .setup_general_from_http_url(node)
            .setup_type(SubIOProtocol.HTTP)
        )

    @classmethod
    def from_subio(cls, node: dict) -> Self:
        return (
            Http(
                username=node["username"],
                password=node["password"],
                headers=node.get("headers", None),
            )
            .setup_tls_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.HTTP)
        )

    @lru_cache
    def to_surge(self) -> str:
        ret = self.to_surge_base() + f", {self.username}, {self.password}"
        return ",".join([x for x in [ret, self.tls_to_surge_base()] if x])

    @lru_cache
    def to_v2rayn(self) -> str:
        return f"http://{self.username}:{self.password}@{self.server}:{self.port}#{self.name}"

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Vless(Base, SmuxBase, TransportBase, PacketEncodingBase, TLSBase):
    class VlessFlow(enum.StrEnum):
        xtls_rprx_vision = "xtls-rprx-vision"

    uuid: str
    flow: VlessFlow

    @classmethod
    def from_clash_meta(cls, node: dict) -> Self:
        return (
            Vless(
                uuid=node["uuid"],
                flow=node.get("flow", None),
            )
            .sumux_from_clash_meta(node)
            .setup_tranport_from_clash_meta(node)
            .setup_packet_encoding_from_clash_meta(node)
            .setup_general_from_clash_meta(node)
            .setup_type(SubIOProtocol.VLESS)
        )

    @lru_cache
    def to_clash_meta(self) -> dict:
        ret = {
            "uuid": self.uuid,
            "flow": self.flow,
        }
        ret.update(self.smux_to_clash_meta())
        ret.update(self.transport_to_clash_meta())
        ret.update(self.packet_encoding_to_clash_meta())
        ret.update(self.tls_to_clash_meta())
        ret.update(self.to_clash_meta_base())
        return ret

    @lru_cache
    def to_dae(self) -> str:
        return self.to_v2rayn()


@dataclass
class Wireguard(Base):
    private_key: str
    public_key: str
    preshared_key: str
    endpoint: str
    allowed_ips: str
    persistent_keepalive: int


@dataclass
class Hysteria(Base):
    up: int
    down: int


@dataclass
class Snell(Base):
    psk: str
    obfs: str
    obfs_host: str
    mode: str
    host: str
    port: int
    tls: bool = False


@dataclass
class Tuic(Base):
    password: str
    tls: bool = False


@dataclass
class Juicity(Base):
    password: str
    tls: bool = False
