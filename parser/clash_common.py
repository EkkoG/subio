import yaml

def parse(config, sub_text):
    nodes = yaml.load(sub_text, Loader=yaml.FullLoader)['proxies']
    return nodes

def transform_list(lst, unify_key_map, unify_value_map):
    new_lst = []
    for item in lst:
        if isinstance(item, list):
            new_lst.append(transform_list(item))
        elif isinstance(item, dict):
            new_dict = {}
            for key, value in item.items():
                new_key = unify(key, unify_key_map)
                if isinstance(value, list):
                    new_value = transform_list(value, unify_key_map, unify_value_map)
                elif isinstance(value, dict):
                    new_value = transform_list(value.items(), unify_key_map, unify_value_map)
                else:
                    new_value = unify(value, unify_value_map)
                new_dict[new_key] = new_value
            new_lst.append(new_dict)
        else:
            new_lst.append(unify(item, unify_value_map))
    return new_lst


def unify(text, unify_map):
    if text in unify_map:
        return unify_map[text]
    return text