def set_value(node, level, value, dest_key):
    all_level = dest_key.split(".")
    if level == len(all_level) - 1:
        node[all_level[level]] = value
        return
    if all_level[level] not in node:
        node[all_level[level]] = {}
    set_value(node[all_level[level]], level + 1, value, dest_key)


from typing import Dict
import json5
import toml
import yaml
import json
import os


def load(file: str) -> Dict:
    all_format = ["toml", "yaml", "yml", "json", "json5"]
    config = None
    select_file = None
    for format in all_format:
        path = f"{file}.{format}"
        if not os.path.exists(path):
            continue
        with open(path, "r") as f:
            if format == "toml":
                config = toml.load(f)
            elif format == "yaml" or format == "yml":
                config = yaml.safe_load(f)
            elif format == "json":
                config = json.load(f)
            elif format == "json5":
                config = json5.load(f)
        select_file = path
        break

    return config, select_file


def load_with_ext(file: str) -> Dict:
    ext = os.path.splitext(file)[1]
    config = None
    with open(file, "r") as f:
        if ext == ".toml":
            config = toml.load(f)
        elif ext == ".yaml" or ext == ".yml":
            config = yaml.safe_load(f)
        elif ext == ".json":
            config = json.load(f)
        elif ext == ".json5":
            config = json5.load(f)

    return config
