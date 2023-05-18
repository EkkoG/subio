import yaml
import re

from .common import common_transform_list

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def transform_list(lst, unify_map):
    common_trans = common_transform_list(lst, unify_map)
    def fix(node):
        if node['type'] == 'hysteria':
            # only keep numbers of up and down, remove unit
            node['up'] = int(re.sub(r'\D', '', node['up']))
            node['down'] = int(re.sub(r'\D', '', node['down']))
        return node
    return list(map(fix, common_trans))