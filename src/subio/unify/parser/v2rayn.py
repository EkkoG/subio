import base64
import urllib
import urllib.parse
from subio.model import Shadowsocks, Vmess, Vless, Trojan, Socks5, Http, Wireguard
from subio.log import log


def parse(file):
    with open(file, "r") as f:
        sub_text = f.read()
        # 兼容两种订阅格式，一种是明文，一种是base64编码
        try:
            plain_text = base64.b64decode(sub_text).decode("utf-8")
        except Exception:
            plain_text = sub_text
    all = []
    for line in plain_text.split("\n"):
        line = line.strip()
        if line:
            url = urllib.parse.urlparse(line)
            scheme = url.scheme
            try:
                if scheme == "ss":
                    all.append(Shadowsocks.from_v2rayn(line))
                elif scheme == "vmess":
                    all.append(Vmess.from_v2rayn(line))
                elif scheme == "vless":
                    all.append(Vless.from_v2rayn(line))
                elif scheme == "trojan":
                    all.append(Trojan.from_v2rayn(line))
                elif scheme == "socks":
                    all.append(Socks5.from_v2rayn(line))
                elif scheme == "http":
                    all.append(Http.from_v2rayn(line))
                elif scheme == "wireguard":
                    all.append(Wireguard.from_v2rayn(line))
                else:
                    log.logger.error(
                        f"Unsupport to parse node type: {scheme} in v2rayn format"
                    )
                    continue
            except Exception as e:
                log.logger.error(f"解析节点失败，错误信息：{e}")
                continue
    return all
