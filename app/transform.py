def tarnsform_to(nodes, dest, tansform_map):
    all_nodes = []
    for node in nodes:
        new_node = {}
        for key, value in node.items():
            dest_key = tansform_map[node['type']][key][dest]['origin']
            new_node[dest_key] = value
        all_nodes.append(new_node)
    return all_nodes