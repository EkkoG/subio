import yaml
import json
from subio.unify.parser import surge
from subio.tools.tools import set_value
from subio.unify.parser import dae
from subio.const import supported_artifact

cache = {}
with open('filed_name_map.json', 'r') as f:
    filed_name_map = json.load(f)
def gen_clash(file, ftype):
    if file.endswith('.yaml'):
        t = yaml.load(open(file, 'r'), Loader=yaml.FullLoader)
    else:
        t = json.load(open(file, 'r'))
    
    gen_with(t['proxies'], ftype)

def gen_with(proxies, ftype):
    for p in proxies:
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
                unify_key = k
                if proxy_type in filed_name_map:
                    if ftype in filed_name_map[proxy_type]:
                        if k in filed_name_map[proxy_type][ftype]:
                            unify_key = filed_name_map[proxy_type][ftype][k]
                if isinstance(v, dict):
                    if 'headers' in k.lower():
                        mm[unify_key] = {
                            "origin": k,
                            "any-key-value": True,
                        }
                    else:
                        for k1, v1 in gen(v).items():
                            mm[f'{k}.{k1}'] = {
                                "origin": f'{k}.{k1}',
                            }
                            if v1.get('any-key-value'):
                                mm[f'{k}.{k1}']['any-key-value'] = True
                elif isinstance(v, list):
                    # check if all items are str
                    if all(isinstance(i, str) for i in v):
                        mm[k] = {
                            "origin": k,
                            "is-list": True,
                        }
                    #TODO: support list of dict
                    elif all(isinstance(i, dict) for i in v):
                        mm[k] = {
                            "origin": k,
                            "is-list": True,
                        }
                        for i in v:
                            for k1, v1 in gen(i).items():
                                mm[f'{k}.{k1}'] = {
                                    "origin": f'{k}.{k1}',
                                    "dict-in-list": True,
                                }
                    else:
                        mm[k] = {
                            "origin": k,
                        }
                else:
                    mm[unify_key] = {
                        "origin": k,
                    }
            return mm

        for k, v in gen(p).items():
            k = k.replace('.', '-').lower()
            if 'map' not in cache[proxy_type]:
                cache[proxy_type]['map'] = {}
            if k not in cache[proxy_type]['map']:
                cache[proxy_type]['map'][k] = {}
            cache[proxy_type]['map'][k][ftype] = v


def gen_surge_like(file, ftype):
    with open(file, 'r') as f:
        text = f.read()
    proxies = surge.parse(text)

    gen_with(proxies, ftype)

def gen_dae(file, ftype):
    with open(file, 'r') as f:
        text = f.read()
        proxies = dae.parse(text)
        gen_with(proxies, ftype)

def gen():
    gen_surge_like('config/surge.conf', 'surge')
    gen_clash('config/meta.yaml', 'clash-meta')
    gen_clash('config/clash.yaml', 'clash')
    gen_clash('config/stash.yaml', 'stash')
    gen_dae('config/dae.conf', 'dae')

    for ptype, config in cache.items():
        all_platform = supported_artifact
        protocol = config['protocol'].copy()
        for k, v in protocol.items():
            for platform in all_platform:
                if platform not in protocol:
                    cache[ptype]['protocol'][platform] = {
                        'policy': 'unsupport',
                    }

        with open('allow_skip.json', 'r') as f:
            allow_skip = json.load(f)

        common_allow_skip_keys = allow_skip['common'] if 'common' in allow_skip else []
        allow_skip_keys = allow_skip[ptype] if ptype in allow_skip else []
        allow_skip_keys = allow_skip_keys + common_allow_skip_keys
        # lower
        allow_skip_keys = list(map(lambda x: x.lower(), allow_skip_keys))
        # - to _
        # allow_skip_keys = list(map(lambda x: x.replace('-', '_'), allow_skip_keys))
        for k, v in config['map'].items():
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

    with open('allow_values.json') as f:
        allow_values_obj = json.load(f)
        # merge cache and allow_values_obj only if the key is not in cache
        def merge(obj, allow_values_obj):
            for k, v in allow_values_obj.items():
                if k not in obj:
                    obj[k] = v
                elif isinstance(v, dict):
                    merge(obj[k], v)
        merge(cache, allow_values_obj)

    with open('../map.json', 'w') as f:
        json.dump(cache, f, indent=4)

if __name__ == '__main__':
    gen()