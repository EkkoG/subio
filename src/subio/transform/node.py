import base64
import hashlib
import json

import yaml

from subio.unify.parser.surge import surge_anonymous_keys
from ..const import clash_like


def to_url(data):
    def trans(node):
        if node['type'] == 'http':
            scheme = 'http'
            if 'tls' in node and node['tls']:
                scheme = 'https'
            userinfo = ''
            if node['username'] and node['password']:
                userinfo = f"{node['username']}:{node['password']}@"
            return f"{node['name']} {scheme}://{userinfo}{node['server']}:{node['port']}"
        elif node['type'] == 'socks5':
            scheme = 'socks5'
            if 'tls' in node and node['tls']:
                scheme = 'socks5-tls'
            userinfo = ''
            if node['username'] and node['password']:
                userinfo = f"{node['name']} {node['username']}:{node['password']}@"
            return f"{node['name']} {scheme}://{userinfo}{node['server']}:{node['port']}"
        elif node['type'] == 'ss':
            if '2022' in node['cipher']:
                return f"{node['name']} ss://{node['cipher']}:{node['password']}@{node['server']}:{node['port']}"
            else:
                userinfo = f"{node['name']} {node['cipher']}:{node['password']}"
                userinfo = base64.b64encode(userinfo.encode('utf-8')).decode('utf-8')
                userinfo = userinfo.replace('=', '')
                return f"{node['name']} ss://{userinfo}@{node['server']}:{node['port']}"
        return ''
    return '\n'.join(list(map(trans, data)))


def to_surge(data):
    def trans(node):
        # filter out surge anonymous keys exsits in node
        all_exist_anonymoues_keys = list(filter(lambda x: x in node, surge_anonymous_keys))
        anonymous_key_text = ', '.join(map(lambda x: f"{node[x]}", all_exist_anonymoues_keys))
        other_keys = list(filter(lambda x: x not in surge_anonymous_keys, node.keys()))
        other_keys = list(filter(lambda x: x != 'name', other_keys))

        def trans_values(value):
            if isinstance(value, bool):
                return 'true' if value else 'false'
            return f"{value}"
        other_text = ', '.join(map(lambda x: f"{x}={trans_values(node[x])}", other_keys))

        return f"{node['name']} = {anonymous_key_text}, {other_text}"
    return '\n'.join(list(map(trans, data)))


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def to_yaml(data):
    return yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True)


def md5_to_uuid4(md5):
    return f"{md5[0:8]}-{md5[8:12]}-{md5[12:16]}-{md5[16:20]}-{md5[20:32]}"


def shadowrocketUUID(name):
    return md5_to_uuid4(hashlib.md5(name.encode('utf-8')).hexdigest())


def to_json(data):
    # all dict
    if isinstance(data, list) and all(isinstance(x, dict) and 'name' in x for x in data):
        # set uuid key for shadowrocket
        for x in data:
            x['uuid'] = shadowrocketUUID(x['name'])

    return json.dumps(data, ensure_ascii=False)


def to_name_list(data):
    return ', '.join(map(lambda x: x['name'], data))


def to_name(data):
    return list(map(lambda x: x['name'], data))
# 只接受字符串数组参数
def list_to_names(type, nodelist):
    if type in clash_like:
        return nodelist
    if type == 'dae':
        return ', '.join(map(lambda x: f"\'{x}\'", nodelist))
    if type == 'surge':
        return ', '.join(nodelist)
    return nodelist