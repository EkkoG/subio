from configparser import ConfigParser
from .common import _origin_to_unify_trans
from subio.app.log import logger

surge_anonymous_keys = ['type', 'server', 'port', 'username', 'password']

def parse(sub_text):
    config = ConfigParser()
    config.optionxform=str
    config.read_string(sub_text)
    all_proxies = []
    for k, v in config['Proxy'].items():
        node = {
            "name": k,
        }
        all_comps = v.split(',')
        # remove space
        all_comps = list(map(lambda x: x.strip(), all_comps))
        first_5_keys = surge_anonymous_keys
        for i in range(len(all_comps)):
            if '=' in all_comps[i]:
                # split by first '='
                k, v = all_comps[i].split('=', 1)
                if v == 'true':
                    v = True
                elif v == 'false':
                    v = False

                node[k] = v
            else:
                if i < len(first_5_keys):
                    node[first_5_keys[i]] = all_comps[i]
                else:
                    logger.warning(f"{k} has too many components")
        if node['type'] == 'https':
            node['type'] = 'http'
            node['tls'] = True
        if node['type'] == 'socks5-tls':
            node['type'] = 'socks5'
            node['tls'] = True
        if node['type'] in ['vmess', 'trojan']:
            if node['ws']:
                node['network'] = 'ws'
                def parse_headers(header_str):
                    # ws-headers=X-Header-1:value|X-Header-2:value
                    headers = {}
                    for header in header_str.split('|'):
                        k, v = header.split(':', 1)
                        headers[k] = v
                    return headers

                node['ws-headers'] = parse_headers(node['ws-headers']) if 'ws-headers' in node else {}
                node.pop('ws', None)
        if node['type'] == 'ss':
            if 'shadow-tls-password' in node:
                node['plugin'] = 'shadow-tls'
                node['plugin-opts-version'] = 2
        all_proxies.append(node)

    return all_proxies

def origin_to_unify_trans(lst, unify_map):
    common_trans =  _origin_to_unify_trans(lst, unify_map)
    def fix(node):
        if node['type'] == 'ss':
            if 'plugin-opts-mode' in node:
                node['plugin'] = 'obfs'
        return node
    return list(map(fix, common_trans))
