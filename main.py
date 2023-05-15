from functools import reduce
import toml
import requests
import jinja2
import os
import json
from app import transform
from app import validate
from app import parse

from app.filter import all_filters

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_remote_resource(url):
    import hashlib
    file_name = f"cache/{hashlib.md5(url.encode('utf-8')).hexdigest()}"
    import os
    if os.path.exists(file_name):
        text = open(file_name, 'r').read()
    else:
        text = requests.get(url).text
        with open(file_name, 'w') as f:
            f.write(text)

    return text


def load_nodes(config):
    all_nodes = {}
    for provider in config['provider']:
        if provider['type'] == 'custom':
            all_nodes[provider['name']] = provider['nodes']
        else:
            sub_text = load_remote_resource(provider['url'])
            all_nodes[provider['name']] = parse.parse(config, provider['type'], sub_text)
    return all_nodes


def load_rulset(config):
    all_rule_set = {}
    for ruleset in config['ruleset']:
        all_rule_set[ruleset['name']] = load_remote_resource(ruleset['url'])
    return all_rule_set


def to_yaml(data):
    import yaml
    return yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True)


def to_json(data):
    import json
    return json.dumps(data, ensure_ascii=False)


def to_name(data):
    return list(map(lambda x: x['name'], data))


def render_ruleset_generic(text, policy):
    lines = text.split('\n')

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == '#':
            return line
        return f"{line}, {policy}"
    return '\n'.join(map(trans, lines))


def render_ruleset_in_clash(text, policy=None):
    lines = text.split('\n')
    lines = list(filter(lambda x: 'USER-AGENT' not in x, lines))

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == '#':
            return line
        line = line.replace(',no-resolve', '')
        if policy is None:
            return f"- {line}"
        return f"- {line},{policy}"
    return '\n'.join(map(trans, lines))

def filter_nodes(nodes, artifact, validate_map):
    all_nodes_for_artifact = [nodes[provider]
                                for provider in artifact['providers']]
    all_nodes_for_artifact = reduce(
        lambda x, y: x + y, all_nodes_for_artifact)
    all_nodes_for_artifact = validate.validation(all_nodes_for_artifact, artifact['type'], validate_map)
    all_nodes_for_artifact = transform.tarnsform_to(all_nodes_for_artifact, artifact['type'], validate_map)
    return all_nodes_for_artifact

def build_template(artifact):
    template_text = open(f"template/{artifact['template']}", 'r').read()
    final_snippet_text = ''
    for snippet_file in os.listdir('snippet'):
        snippet_file_path = os.path.join('snippet', snippet_file)
        snippet_text = "{{% import '{}' as {} -%}}\n".format(
            snippet_file_path, snippet_file)
        final_snippet_text += snippet_text + '\n'

    template_text_with_macro = final_snippet_text + template_text
    return template_text_with_macro

if __name__ == '__main__':
    with open('config.toml', 'r') as f:
        config = toml.load(f)

    all_nodes = load_nodes(config)
    remote_ruleset = load_rulset(config)

    validate_map = json.load(open('map.json', 'r'))
    for artifact in config['artifact']:
        all_nodes_for_artifact = filter_nodes(all_nodes, artifact, validate_map)

        template_text_with_macro = build_template(artifact)

        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        template = env.from_string(template_text_with_macro)

        def get_proxies():
            return all_nodes_for_artifact

        def get_proxies_names():
            return to_name(get_proxies())

        def render(*args, **kwargs):
            if artifact['type'] == 'clash' or artifact['type'] == 'clash-meta':
                return render_ruleset_in_clash(*args, **kwargs)

            return render_ruleset_generic(*args, **kwargs)

        env.globals['get_proxies'] = get_proxies
        env.globals['get_proxies_names'] = get_proxies_names
        env.globals['to_yaml'] = to_yaml
        env.globals['to_json'] = to_json
        env.globals['to_name'] = to_name
        env.globals['filter'] = all_filters
        env.globals['render'] = render
        env.globals['remote_ruleset'] = remote_ruleset

        if not os.path.exists('dist'):
            os.mkdir('dist')

        with open('dist/' + artifact['name'], 'w') as f:
            final_config = template.render(options=artifact['options'])
            f.write(final_config)
