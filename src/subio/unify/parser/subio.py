from subio.model import Shadowsocks, Vmess, Vless, Trojan, Socks5, Http, Wireguard
from subio.tools.tools import load_with_ext
from subio.log import log


def parse(file: str):
    d = load_with_ext(file)
    parsed_nodes = []
    for node in d["nodes"]:
        try:
            if node["type"] == "ss":
                parsed_nodes.append(Shadowsocks.from_clash_meta(node))
            elif node["type"] == "vmess":
                parsed_nodes.append(Vmess.from_clash_meta(node))
            elif node["type"] == "vless":
                parsed_nodes.append(Vless.from_clash_meta(node))
            elif node["type"] == "trojan":
                parsed_nodes.append(Trojan.from_clash_meta(node))
            elif node["type"] == "socks5":
                parsed_nodes.append(Socks5.from_clash_meta(node))
            elif node["type"] == "http":
                parsed_nodes.append(Http.from_clash_meta(node))
            elif node["type"] == "wireguard":
                parsed_nodes.append(Wireguard.from_clash_meta(node))
            else:
                log.logger.error(
                    f"Unsupport to parse node type: {node['type']} in clash format"
                )
                continue
        except Exception as e:
            # import traceback
            # traceback.print_exc()
            log.logger.error(f"解析节点失败，错误信息：{e}")
            continue

    return parsed_nodes
