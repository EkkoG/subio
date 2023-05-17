import yaml
import json

cache = {}

filed_name_map = {
    "hysteria": {
        "stash": {
            "down-speed": "down",
            "up-speed": "up",
        }
    }
}

def gen_clash(file, ftype):
    if file.endswith('.yaml'):
        t = yaml.load(open(file, 'r'), Loader=yaml.FullLoader)
    else:
        t = json.load(open(file, 'r'))

    for p in t['proxies']:
        proxy_type = p['type']

        if proxy_type not in cache:
            cache[proxy_type] = {
                "protocol": {},
            }
        if ftype not in cache[proxy_type]["protocol"]:
            cache[proxy_type]["protocol"][ftype] = {}


        def gen(proxy):
            mm = {}
            for k, v in proxy.items():
                if isinstance(v, dict):
                    if 'headers' in k.lower():
                        mm[k] = {
                            "origin": k,
                            "any_key_value": True,
                        }
                    else:
                        for k1, v1 in gen(v).items():
                            mm[f'{k}.{k1}'] = {
                                "origin": f'{k}.{k1}',
                            }
                            if v1.get('any_key_value'):
                                mm[f'{k}.{k1}']['any_key_value'] = True
                elif isinstance(v, list):
                    # check if all items are str
                    if all(isinstance(i, str) for i in v):
                        mm[k] = {
                            "origin": k,
                            "is_list": True,
                        }
                    #TODO: support list of dict
                    elif all(isinstance(i, dict) for i in v):
                        mm[k] = {
                            "origin": k,
                            "is_list": True,
                        }
                        for i in v:
                            for k1, v1 in gen(i).items():
                                mm[f'{k}.{k1}'] = {
                                    "origin": f'{k}.{k1}',
                                    "dict_in_list": True,
                                }
                    else:
                        mm[k] = {
                            "origin": k,
                        }
                else:
                    unify_key = k
                    if proxy_type in filed_name_map:
                        if ftype in filed_name_map[proxy_type]:
                            if k in filed_name_map[proxy_type][ftype]:
                                unify_key = filed_name_map[proxy_type][ftype][k]
                    mm[unify_key] = {
                        "origin": k,
                    }
            return mm

        for k, v in gen(p).items():
            k = k.replace('-', '_').replace('.', '_').lower()
            if 'map' not in cache[proxy_type]:
                cache[proxy_type]['map'] = {}
            if k not in cache[proxy_type]['map']:
                cache[proxy_type]['map'][k] = {}
            cache[proxy_type]['map'][k][ftype] = v




def gen():
    gen_clash('mapgen/meta.yaml', 'clash-meta')
    gen_clash('mapgen/clash.yaml', 'clash')
    gen_clash('mapgen/stash.yaml', 'stash')

    for ptype, config in cache.items():
        all_platform = ['clash', 'clash-meta', 'stash']
        protocol = config['protocol'].copy()
        for k, v in protocol.items():
            for platform in all_platform:
                if platform not in protocol:
                    cache[ptype]['protocol'][platform] = {
                        'policy': 'unsupport',
                    }

        for k, v in config['map'].items():
            allow_skip_keys = ['smux', 'fingerprint', 'client_fingerprint', 'ip_version', 'fast_open', 'disable_sni', 'reduce_rtt', 'request_timeout', 'udp_relay_mode']
            # lower
            allow_skip_keys = list(map(lambda x: x.lower(), allow_skip_keys))
            # - to _
            allow_skip_keys = list(map(lambda x: x.replace('-', '_'), allow_skip_keys))

            for platform in all_platform:
                if platform not in v:

                    if k in allow_skip_keys:
                        cache[ptype]['map'][k][platform] = {
                            'policy': 'allow_skip',
                        }
                    else:
                        cache[ptype]['map'][k][platform] = {
                            'policy': 'unsupport',
                        }

        with open('mapgen/allow_values.json') as f:
            allow_values_obj = json.load(f)
            for k, v in allow_values_obj.items():
                all_level = k.split('.')
                def set_value(node, level, value):
                    if level == len(all_level) - 1:
                        node[all_level[level]] = value
                        return
                    if all_level[level] not in node:
                        node[all_level[level]] = {}
                    set_value(node[all_level[level]], level + 1, value)
                set_value(cache, 0, v)
            

    print(json.dumps(cache, indent=4))