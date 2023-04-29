
from .parser import clash
from . import tools

def parse(config, origin, sub_text):
    nodes = clash.parse(config, sub_text)

    unify_map = tools.build_map(origin)

    return clash.transform_list(nodes, unify_map)