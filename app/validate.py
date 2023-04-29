import jsonschema
import json
import os

def validation(nodes, dest, validate_map):


    def validator(node):
        if node['type'] not in validate_map:
            print(f"Unknown node type: {node['type']} for {dest}, skip")
            return False
        if validate_map.get(node['type'], {}).get('_protocol', {}).get(dest, {}).get('support', False) is False:
            print(f"Node {node['name']}, type {node['type']} is not valid for {dest}, skip, reason: protocol not supported")
            return False


        for k, v in node.items():
            if validate_map.get(node['type'], {}).get(k, {}).get(dest, {}).get('support', False) is False:
                print(f"Node {node['name']}, type {node['type']} is not valid for {dest} , skip, reason: field {k} not supported")
                return False
            # allow_values
            allow_values = validate_map.get(node['type'], {}).get(k, {}).get(dest, {}).get('allow_values', [])
            if len(allow_values) > 0 and v not in allow_values:
                print(f"Node {node['name']}, type {node['type']} is not valid for {dest}, skip, reason: field {k} not in allow_values")
                return False

        return True


    return list(filter(validator, nodes))