
from . import clash_common


def parse(config, sub_text):
    nodes = clash_common.parse(config, sub_text)
    return clash_common.transform_list(nodes, unify_map, unify_map)


unify_map = {
}