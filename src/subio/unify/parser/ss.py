import base64
import urllib.parse


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

    if url.scheme == "ss":
        p = {}
        p["type"] = "ss"
        p["server"] = server
        p["port"] = port
        # ss2022
        if ":" in str_before_at:
            p["cipher"] = username
            p["password"] = password
        else:
            # padding
            str_before_a = str_before_at + "=" * (4 - len(str_before_at) % 4)
            t = base64.b64decode(str_before_a).decode("utf-8")
            method = t.split(":")[0]
            password = t.split(":")[1]
            p["password"] = password
            p["cipher"] = method
        if url.fragment:
            tag = urllib.parse.unquote(url.fragment)
            p["name"] = tag
        if q:
            # q = {'plugin': ['obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com'], 'group': ['RGxlc']}
            if "plugin" in q:
                # plugin = obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com
                plugin = q["plugin"][0]
                # plugin = obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com
                plugin = urllib.parse.unquote(plugin)
                # 
                plugin = plugin.split(";")
                if plugin[0] == "obfs-local":
                    p["plugin"] = "obfs"
                else:
                    p["plugin"] = plugin[0]
                for opt in plugin[1:]:
                    k, v = opt.split("=")
                    p[k] = v
        return p

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