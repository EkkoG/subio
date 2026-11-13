import base64
import urllib.parse

from subio_v2.adapters.links.codecs._base import (
    LinkCodec,
    LinkValueError,
    format_authority,
    quote_name,
)
from subio_v2.core.nodes import Node, Protocol, ShadowsocksNode


def build(node: Node) -> str:
    assert isinstance(node, ShadowsocksNode)
    userinfo = f"{node.cipher}:{node.password}"
    encoded = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
    url = f"ss://{encoded}@{format_authority(node.server, node.port)}"
    if node.plugin:
        if ";" in node.plugin:
            raise LinkValueError(
                "Plugin name is not representable in a share link", field="plugin"
            )
        plugin = [node.plugin]
        for key, value in (node.plugin_opts or {}).items():
            if ";" in key or "=" in key or ";" in str(value):
                raise LinkValueError(
                    "Plugin option is not representable in a share link",
                    field="plugin_opts",
                )
            if isinstance(value, bool):
                if value:
                    plugin.append(key)
            else:
                plugin.append(f"{key}={value}")
        url += f"/?plugin={urllib.parse.quote(';'.join(plugin), safe='')}"
    return f"{url}#{quote_name(node.name)}"


def parse(line: str) -> Node | None:
    try:
        url = urllib.parse.urlparse(line)
        if "@" not in url.netloc:
            payload = urllib.parse.unquote(url.netloc + url.path)
            decoded = base64.urlsafe_b64decode(
                payload + "=" * ((4 - len(payload) % 4) % 4)
            ).decode()
            if "@" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            authority = urllib.parse.urlsplit("//" + hostport)
            server, port = authority.hostname, authority.port
        else:
            server, port = url.hostname, url.port
            if url.username and ":" not in url.username and not url.password:
                auth = base64.urlsafe_b64decode(
                    url.username + "=" * ((4 - len(url.username) % 4) % 4)
                ).decode()
                method, password = auth.split(":", 1)
            else:
                method = urllib.parse.unquote(url.username or "")
                password = urllib.parse.unquote(url.password or "")
        name = urllib.parse.unquote(url.fragment) if url.fragment else f"{server}:{port}"
        query = urllib.parse.parse_qs(url.query)
        plugin_value = query.get("plugin", [None])[0]
        plugin = None
        plugin_opts = None
        if plugin_value:
            parts = plugin_value.split(";")
            plugin = parts[0]
            plugin_opts = {}
            for part in parts[1:]:
                if not part:
                    return None
                key, separator, value = part.partition("=")
                plugin_opts[key] = value if separator else True
        return ShadowsocksNode(
            name=name,
            type=Protocol.SHADOWSOCKS,
            server=server,
            port=port,
            cipher=method,
            password=password,
            plugin=plugin,
            plugin_opts=plugin_opts,
        )
    except Exception:  # noqa: BLE001
        return None


CODEC = LinkCodec(
    Protocol.SHADOWSOCKS,
    frozenset({"dae", "v2rayn"}),
    build,
    schemes=frozenset({"ss"}),
    parse=parse,
    target_constraints={
        "dae": {
            "ciphers": frozenset(
                {
                    "2022-blake3-aes-128-gcm",
                    "2022-blake3-aes-256-gcm",
                    "2022-blake3-chacha20-poly1305",
                    "aes-128-cfb",
                    "aes-128-ctr",
                    "aes-128-gcm",
                    "aes-192-cfb",
                    "aes-192-ctr",
                    "aes-256-cfb",
                    "aes-256-ctr",
                    "aes-256-gcm",
                    "chacha20-ietf",
                    "chacha20-ietf-poly1305",
                    "rc4-md5",
                    "xchacha20",
                    "xchacha20-ietf-poly1305",
                }
            ),
            "plugins": {"obfs", "shadow-tls"},
        },
        "v2rayn": {
            "ciphers": frozenset(
                {
                    "2022-blake3-aes-128-gcm",
                    "2022-blake3-aes-256-gcm",
                    "2022-blake3-chacha20-poly1305",
                    "aes-128-cfb",
                    "aes-128-ctr",
                    "aes-128-gcm",
                    "aes-192-cfb",
                    "aes-192-ctr",
                    "aes-256-cfb",
                    "aes-256-ctr",
                    "aes-256-gcm",
                    "chacha20-ietf",
                    "chacha20-ietf-poly1305",
                    "rc4-md5",
                    "xchacha20",
                    "xchacha20-ietf-poly1305",
                }
            ),
            "plugins": {"obfs", "v2ray-plugin"},
        },
    },
)
