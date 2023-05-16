import yaml
import json

cache = {}

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
                    for k1, v1 in gen(v).items():
                        mm[f'{k}.{k1}'] = {
                            "origin": f'{k}.{k1}',
                        }
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
                    mm[k] = {
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
            allow_skip_keys = ['fingerprint', 'client_fingerprint', 'ip_version', 'fast-open']
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
                key_paths = k.split('.')
                exp = "cache"
                for key_path in key_paths:
                    exp += f"[\"{key_path}\"]"
                exp += " = v"
                exec(exp)
            

    print(json.dumps(cache, indent=4))