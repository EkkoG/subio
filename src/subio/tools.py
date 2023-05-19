
def set_value(node, level, value, dest_key):
    all_level = dest_key.split('.')
    if level == len(all_level) - 1:
        node[all_level[level]] = value
        return
    if all_level[level] not in node:
        node[all_level[level]] = {}
    set_value(node[all_level[level]], level + 1, value, dest_key)