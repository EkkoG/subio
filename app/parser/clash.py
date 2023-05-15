import yaml

def get_type(node):
    type_components = [node['type'], node.get('plugin', ''), node.get('network', ''), node.get('flow', '')]
    # remove empty string or None
    type_components = [i for i in type_components if i]
    node_type = '.'.join(type_components).lower()
    return node_type

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def transform_list(lst, unify_map):
    unified_nodes = []
    for node in lst:
        new_node = {}
        node_type = get_type(node)
        new_node['node_type'] = node_type
        if node_type in unify_map:
            for k, v in node.items():
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if f"{k}.{k1}" in unify_map[node_type]:
                            new_node[unify_map[node_type][f"{k}.{k1}"]] = v1

                else:
                    if k in unify_map[node_type]:
                        new_node[unify_map[node_type][k]] = v
            unified_nodes.append(new_node)
        else:
            print(f"Warning: type {node_type} not found in map.json")
        
    return unified_nodes