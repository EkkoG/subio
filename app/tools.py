import json

def build_map(t):
    m = {}
    transform_map = json.load(open('map.json', 'r'))
    for k, v in transform_map.items():
        for k1, v1 in v.items():
            if k1 != '_protocol':
                if t in v1:
                    if k not in m:
                        m[k] = {}
                    if 'origin' in v1[t]:
                        m[k][v1[t]['origin']] = k1
    return m 
