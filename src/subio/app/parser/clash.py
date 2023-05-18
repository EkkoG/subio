import yaml

from .common import common_transform_list

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def transform_list(lst, unify_map):
    return common_transform_list(lst, unify_map)