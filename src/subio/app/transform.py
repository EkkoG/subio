
def tarnsform_to(nodes, dest, tansform_map):
    all_nodes = []
    for node in nodes:
        new_node = {}
        node_type = node['type']
        for key, value in node.items():
            if 'origin' in tansform_map[node_type]['map'][key][dest]:
                dest_key = tansform_map[node_type]['map'][key][dest]['origin']
                if '.' in dest_key:
                    k, k1 = dest_key.split('.')
                    if k not in new_node:
                        new_node[k] = {}
                    new_node[k][k1] = value
                else:
                    new_node[dest_key] = value
        all_nodes.append(new_node)
    return all_nodes