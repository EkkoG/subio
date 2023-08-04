from subio.tools.tools import set_value

def tarnsform_to(nodes, dest, tansform_map):
    to = _tarnsform_to(nodes, dest, tansform_map)
    def fix(node):
        if node['type'] in ['ss']:
            if 'plugin' in node:
                node.pop('plugin', None)

        if node['type'] in ['vmess', 'trojan']:
            if 'network' in node and node['network'] == 'ws':
                node['ws'] = True
                node.pop('network', None)

            if 'ws-headers' in node:
                def dict_to_str(d):
                    return '|'.join([f'{k}:{v}' for k, v in d.items()])
                node['ws-headers'] = dict_to_str(node['ws-headers'])

        if node['type'] in ['ss']:
            if 'plugin-opts-version' in node:
                node.pop('plugin-opts-version', None)
        if node['type'] == 'tuic':
            if 'uuid' in node:
                if dest in ['stash', 'surge']:
                    node['version'] = 5
                elif dest == 'clash-meta':
                    node.pop('version', None)
            if dest == 'surge':
                if 'alpn' in node:
                    node['alpn'] = node['alpn'][0]

                if 'peers' in node:
                    def fix(peer):
                        if 'reserved' in peer:
                            peer['reserved'] = '/'.join(peer['reserved'])
                        return peer
                    node['peers'] = list(map(fix, node['peers'])) 
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
                    set_value(new_node, 0, value, dest_key)
                else:
                    new_node[dest_key] = value
        all_nodes.append(new_node)
    return all_nodes
