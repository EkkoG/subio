import yaml

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def transform_list(lst, unify_map):
    unified_nodes = []
    for node in lst:
        new_node = {}
        if node['type'] in unify_map:
            for k, v in node.items():
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if f"{k}.{k1}" in unify_map[node['type']]:
                            new_node[unify_map[node['type']][f"{k}.{k1}"]] = v1

                else:
                    if k in unify_map[node['type']]:
                        new_node[unify_map[node['type']][k]] = v
            unified_nodes.append(new_node)
        else:
            print(f"Warning: type {node['type']} not found in map.json")
        
    return unified_nodes