
def validation(nodes, dest, validate_map):

    def validator(node):
        def get_value(key, field, default_value):
            return validate_map.get(node['type'], {}).get(field, {}).get(dest, {}).get(key, default_value)

        if node['type'] not in validate_map:
            print(f"Unknown node type: {node['type']} for {dest}, skip")
            return False
        if get_value('policy', '_protocol', None) == 'unsupport':
            print(f"Node {node['name']}, type {node['type']} is not valid for {dest}, skip, reason: protocol not supported")
            return False


        for k, v in node.items():
            if get_value('policy', k, None) == 'unsupport':
                print(f"Node {node['name']}, type {node['type']} is not valid for {dest}, skip, reason: field {k} not supported")
                return False
            if get_value('policy', k, None) == 'allow_skip':
                pass

            # allow_values
            allow_values = get_value('allow_values', k, [])
            if len(allow_values) > 0 and v not in allow_values:
                print(f"Node {node['name']}, type {node['type']} is not valid for {dest}, skip, reason: field {k} not in allow_values")
                return False

        return True


    return list(filter(validator, nodes))