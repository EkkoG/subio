import json


def build_map(t):
    m = {}
    # remove the last two element of the path
    map_path = "/".join(__file__.split("/")[:-2]) + "/map.json"
    with open(map_path, "r", encoding="utf-8") as f:
        transform_map = json.load(f)
    for k, v in transform_map.items():
        for k1, v1 in v["map"].items():
            if t in v1:
                if k not in m:
                    m[k] = {}

                if "origin" in v1[t]:
                    m[k][v1[t]["origin"]] = k1
    return m
