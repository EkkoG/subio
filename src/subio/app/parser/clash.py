import yaml
import re
import base64

from .common import _origin_to_unify_trans

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def origin_to_unify_trans(lst, unify_map):
    common_trans = _origin_to_unify_trans(lst, unify_map)
    def fix(node):
        if node['type'] == 'hysteria':
            # only keep numbers of up and down, remove unit
            node['up'] = int(re.sub(r'\D', '', node['up']))
            node['down'] = int(re.sub(r'\D', '', node['down']))

        return node
    return list(map(fix, common_trans))