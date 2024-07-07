import base64
import hashlib
import json
from urllib.parse import quote, urlencode

import yaml

from subio.unify.parser.surge import surge_anonymous_keys
from ..const import SubIOPlatform

def to_dae(data):
    def dae_trans(d):
        name = d["name"]
        return f"{name} {_trans(d)}"
    return "\n".join(list(map(dae_trans, data)))

def _trans(node):
    if node["type"] == "http":
        scheme = "http"
        if "tls" in node and node["tls"]:
            scheme = "https"
        userinfo = ""
        if node["username"] and node["password"]:
            userinfo = f"{node['username']}:{node['password']}@"
        return (
            f"{scheme}://{userinfo}{node['server']}:{node['port']}#{quote(node['name'])}"
        )
    elif node["type"] == "socks5":
        scheme = "socks5"
        if "tls" in node and node["tls"]:
            scheme = "socks5-tls"
        userinfo = ""
        if node["username"] and node["password"]:
            userinfo = f"{node['username']}:{node['password']}@"
        return (
            f"{scheme}://{userinfo}{node['server']}:{node['port']}"
        )
    elif node["type"] == "ss":
        plugin = ""
        if "obfs" in node:
            mode = node["obfs"]
            if mode == "tls":
                if "obfs-host" in node:
                    host = node["obfs-host"]
                    plugin = f"/?plugin=obfs-local;obfs={mode};obfs-host={host}"
            plugin = quote(plugin)


        if "2022" in node["cipher"]:
            return f"ss://{node['cipher']}:{node['password']}@{node['server']}:{node['port']}{plugin}#{quote(node['name'])}"
        else:
            userinfo = f"{node['cipher']}:{node['password']}"
            userinfo = base64.b64encode(userinfo.encode("utf-8")).decode("utf-8")
            userinfo = userinfo.replace("=", "")
            return f"ss://{userinfo}@{node['server']}:{node['port']}{plugin}#{quote(node['name'])}"
    elif node["type"] == "trojan":
        options = ""
        if "allowInsecure" in node:
            value = 1 if node["allowInsecure"] else 0
            options += f"allowInsecure={value};"
        if options != "":
            options = f"?{options}"

        return f"trojan://{node['password']}@{node['server']}:{node['port']}?{options}#{quote(node['name'])}"
    return ""

def to_v2rayn(data):

    all_text = "\n".join(list(map(_trans, data)))
    return base64.b64encode(all_text.encode("utf-8")).decode("utf-8")


def to_surge(data):
    def trans(node):
        # filter out surge anonymous keys exsits in node
        all_exist_anonymoues_keys = list(
            filter(lambda x: x in node, surge_anonymous_keys)
        )
        anonymous_key_text = ", ".join(
            map(lambda x: f"{node[x]}", all_exist_anonymoues_keys)
        )
        other_keys = list(filter(lambda x: x not in surge_anonymous_keys, node.keys()))
        other_keys = list(filter(lambda x: x != "name", other_keys))

        def trans_values(value):
            if isinstance(value, bool):
                return "true" if value else "false"
            return f"{value}"

        other_text = ", ".join(
            map(lambda x: f"{x}={trans_values(node[x])}", other_keys)
        )

        return f"= {anonymous_key_text}, {other_text}"

    return "\n".join(list(map(trans, data)))


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def to_yaml(data):
    return yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True)


def md5_to_uuid4(md5):
    return f"{md5[0:8]}-{md5[8:12]}-{md5[12:16]}-{md5[16:20]}-{md5[20:32]}"


def shadowrocketUUID(name):
    return md5_to_uuid4(hashlib.md5(name.encode("utf-8")).hexdigest())


def to_json(data):
    # all dict
    if isinstance(data, list) and all(
        isinstance(x, dict) and "name" in x for x in data
    ):
        # set uuid key for shadowrocket
        for x in data:
            x["uuid"] = shadowrocketUUID(x["name"])

    return json.dumps(data, ensure_ascii=False)


def to_name_list(data):
    return ", ".join(map(lambda x: x["name"], data))


def to_name(data):
    return list(map(lambda x: x["name"], data))


# 只接受字符串数组参数
def list_to_names(type, nodelist):
    if type in SubIOPlatform.clash_like():
        return nodelist
    if type == "dae":
        return ", ".join(map(lambda x: f"'{x}'", nodelist))
    if type == "surge":
        return ", ".join(nodelist)
    return nodelist
