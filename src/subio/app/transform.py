
def tarnsform_to(nodes, dest, tansform_map):
    to = _tarnsform_to(nodes, dest, tansform_map)
    def fix(node):
        if node['type'] in ['vmess', 'trojan']:
            if 'network' in node and node['network'] == 'ws':
                node['ws'] = True
                node.pop('network', None)

            if 'ws-headers' in node:
                def dict_to_str(d):
                    return '|'.join([f'{k}:{v}' for k, v in d.items()])
                node['ws-headers'] = dict_to_str(node['ws-headers'])
        return node
    return list(map(lambda x: fix(x), to))

def _tarnsform_to(nodes, dest, tansform_map):
    all_nodes = []
    for node in nodes:
        new_node = {}
        node_type = node['type']
        for key, value in node.items():
            if 'origin' in tansform_map[node_type]['map'][key][dest]:
                dest_key = tansform_map[node_type]['map'][key][dest]['origin']
                if '.' in dest_key:
                    all_level = dest_key.split('.')
                    def set_value(node, level, value):
                        if level == len(all_level) - 1:
                            node[all_level[level]] = value
                            return
                        if all_level[level] not in node:
                            node[all_level[level]] = {}
                        set_value(node[all_level[level]], level + 1, value)

                    set_value(new_node, 0, value)
                else:
                    new_node[dest_key] = value
        all_nodes.append(new_node)
    return all_nodes