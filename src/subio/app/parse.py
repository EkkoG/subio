
from .parser import clash, surge
from . import tools
from ..subio_platform import surge_like, clash_like
import toml
import json
import yaml

def parse(config, origin, sub_text):
    if origin == 'subio':
        try:
            nodes = toml.loads(sub_text)
            return nodes['nodes']
        except:
            try:
                nodes = json.loads(sub_text)
                return nodes['nodes']
            except:
                try:
                    nodes = yaml.safe_load(sub_text)
                    return nodes['nodes']
                except:
                    return []
    if origin in clash_like: 
        nodes = clash.parse(config, sub_text)

        unify_map = tools.build_map(origin)

        return clash.origin_to_unify_trans(nodes, unify_map)
    elif origin in surge_like:
        nodes = surge.parse(sub_text)

        unify_map = tools.build_map(origin)

        return surge.origin_to_unify_trans(nodes, unify_map)
    return []
