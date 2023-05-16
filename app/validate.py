
def validation(nodes, dest, validate_map):

    def validator(node):
        node_type = node['type']
        def get_value(key, field, default_value):
            return validate_map.get(node_type, {})['map'].get(field, {}).get(dest, {}).get(key, default_value)

        if node_type not in validate_map:
            print(f"Unknown node type: {node_type} for {dest}, skip")
            return False
        if get_value('policy', 'protocol', None) == 'unsupport':
            print(f"Node {node['name']}, type {node_type} is not valid for {dest}, skip, reason: protocol not supported")
            return False


        for k, v in node.items():
            if get_value('policy', k, None) == 'unsupport':
                print(f"Node {node['name']}, type {node_type} is not valid for {dest}, skip, reason: field {k} not supported")
                return False
            if get_value('policy', k, None) == 'allow_skip':
                pass

            # allow_values
            conditions = get_value('allow_values_when', k, [])
            if len(conditions) > 0:
                for condition in conditions:
                    when = condition['when']
                    if eval(when):
                        allow_values = condition['allow_values']
                        if len(allow_values) > 0 and v not in allow_values:
                            print(f"Node {node['name']}, type {node_type} is not valid for {dest}, skip, reason: field {k} not in allow_values")
                            return False

            allow_values = get_value('allow_values', k, [])
            if len(allow_values) > 0 and v not in allow_values:
                print(f"Node {node['name']}, type {node_type} is not valid for {dest}, skip, reason: field {k} value {v} not in allow_values")
                return False

            if get_value('any_key_value', k, False) and not isinstance(v, dict):
                print(f"Node {node['name']}, type {node_type} is not valid for {dest}, skip, reason: field {k} should be dict")
                return False

        return True


    return list(filter(validator, nodes))