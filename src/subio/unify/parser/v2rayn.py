import base64
import urllib
import urllib.parse
from .ss import line_to_proxy as ss_line_to_proxy
from .common import _origin_to_unify_trans


def line_to_proxy(line):
    # parse text as url
    url = urllib.parse.urlparse(line)
    server = url.hostname
    port = url.port
    username = url.username
    password = url.password
    netloc = url.netloc
    str_before_at = netloc.split("@")[0]
    q = urllib.parse.parse_qs(url.query)

    if url.scheme == "http" or url.scheme == "https":
        p = {}
        p["type"] = "http"
        if url.scheme == "https":
            p["tls"] = True
        p["server"] = server
        p["port"] = port
        p["password"] = password
        p["username"] = username
        p['name'] = url.fragment if url.fragment else f"{server}:{port}"

        return p
    elif url.scheme == "socks5" or url.scheme == "socks5-tls":
        p = {}
        p["type"] = "socks5"
        if url.scheme == "socks5-tls":
            p["tls"] = True
        p["server"] = server
        p["port"] = port
        p["password"] = password
        p["username"] = username
        return p
    elif url.scheme == "ss":
        return ss_line_to_proxy(line)

    return None

def parse(file):
    with open(file, "r") as f:
        sub_text = f.read()
        plain_text = base64.b64decode(sub_text).decode("utf-8")
    all = []
    for line in plain_text.split("\n"):
        line = line.strip()
        if line:
            proxy = line_to_proxy(line)
            if proxy:
                all.append(proxy)
    return all

def origin_to_unify_trans(lst, unify_map):
    return _origin_to_unify_trans(lst, unify_map)