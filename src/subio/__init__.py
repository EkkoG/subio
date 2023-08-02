from functools import reduce
import toml
import requests
import jinja2
import os
import json
import json5
import yaml
import hashlib

from subio.app.ruleset_transform import render_ruleset_in_clash
from subio.app.ruleset_transform import render_ruleset_generic
from subio.app.ruleset_transform import render_ruleset_in_dae

from .app import transform
from .app import validate
from .app import parse
from .app import upload
from .app import log
from .subio_platform import supported_artifact, supported_provider, clash_like
from .app.parser.surge import surge_anonymous_keys

from .app.filter import all_filters

def md5_to_uuid4(md5):
    return f"{md5[0:8]}-{md5[8:12]}-{md5[12:16]}-{md5[16:20]}-{md5[20:32]}"

def shadowrocketUUID(name):
    return md5_to_uuid4(hashlib.md5(name.encode('utf-8')).hexdigest())

class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_remote_resource(url, ua=None):
    headers = {
        'User-Agent': ua 
        }
    if os.getenv('DEBUG'):
        file_name = f"cache/{hashlib.md5(url.encode('utf-8')).hexdigest()}"
        if not os.path.exists('cache'):
            os.mkdir('cache')
        if os.path.exists(file_name):
            text = open(file_name, 'r').read()
        else:
            text = requests.get(url, headers=headers).text
            with open(file_name, 'w') as f:
                f.write(text)
    else:
        text = requests.get(url, headers=headers).text

    return text

def rename_node(node, rename):
    if rename.get('add-prefix'):
        node['name'] = rename['add-prefix'] + node['name']
    if rename.get('add-suffix'):
        node['name'] = rename['add-suffix'] + node['name']
    if rename.get('replace'):
        for r in rename['replace']:
            node['name'] = node['name'].replace(r['old'], r['new'])

    return node

def load_nodes(config):
    all_nodes = {}
    for provider in config['provider']:
        log.logger.info(f"加载 {provider['name']} 节点")
        if 'file' in provider:
            sub_text = open(f"provider/{provider['file']}", 'r').read()
        else:
            sub_text = load_remote_resource(provider['url'], provider.get('user-agent', None))
        log.logger.info(f"加载 {provider['name']} 节点成功, 开始解析")
        try:
            all_nodes[provider['name']] = parse.parse(config, provider['type'], sub_text)
        except Exception as e:
            log.logger.error(f"解析 {provider['name']} 节点失败，错误信息：{e}")
            exit(1)
        if provider.get('rename'):
            all_nodes[provider['name']] = list(map(lambda x: rename_node(x, provider['rename']), all_nodes[provider['name']]))
        log.logger.info(f"解析 {provider['name']} 节点成功，数量：{len(all_nodes[provider['name']])}")
    log.logger.info(f"加载节点成功，总数量：{reduce(lambda x, y: x + len(y), all_nodes.values(), 0)}")
    return all_nodes

def wrap_with_jinja2_macro(text, name):
    def append_rule(rule):
        if rule.strip() == '':
            return ''
        if rule.strip().startswith('#'):
            return rule
        if rule.strip().startswith('//'):
            return rule
        if '//' in rule:
            rule = rule.split('//')[0].strip()
            return rule + ',{{ rule }}'
        if ',no-resolve' in rule:
            return rule.replace(',no-resolve', ',{{ rule }},no-resolve')
        return rule + ',{{ rule }}'
    text = '\n'.join(map(append_rule, text.split('\n')))
    return "{{% macro {}(rule) -%}}\n{}\n{{%- endmacro -%}}".format(
                f"remote_{name}", text)

def load_rulset(config):
    all_rule_set = {}
    for ruleset in config['ruleset']:
        all_rule_set[ruleset['name']] = wrap_with_jinja2_macro(load_remote_resource(ruleset['url'], ruleset.get('user-agent', None)), ruleset['name'])
    return all_rule_set


def to_yaml(data):
    return yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True)

def to_name_list(data):
    return ', '.join(map(lambda x: x['name'], data))

def to_json(data):
    # all dict
    if isinstance(data, list) and all(isinstance(x, dict) and 'name' in x for x in data):
        # set uuid key for shadowrocket
        for x in data:
            x['uuid'] = shadowrocketUUID(x['name'])

    return json.dumps(data, ensure_ascii=False)

def to_surge(data):
    def trans(node):
        # filter out surge anonymous keys exsits in node
        all_exist_anonymoues_keys = list(filter(lambda x: x in node, surge_anonymous_keys))
        anonymous_key_text = ', '.join(map(lambda x: f"{node[x]}", all_exist_anonymoues_keys))
        other_keys = list(filter(lambda x: x not in surge_anonymous_keys, node.keys()))
        other_keys = list(filter(lambda x: x != 'name', other_keys))

        def trans_values(value):
            if isinstance(value, bool):
                return 'true' if value else 'false'
            return f"{value}"
        other_text = ', '.join(map(lambda x: f"{x}={trans_values(node[x])}", other_keys))

        return f"{node['name']} = {anonymous_key_text}, {other_text}"
    return '\n'.join(list(map(trans, data)))
        

def to_name(data):
    return list(map(lambda x: x['name'], data))


def filter_nodes(nodes, artifact, validate_map):
    all_nodes_for_artifact = [nodes[provider]
                                for provider in artifact['providers']]
    all_nodes_for_artifact = reduce(
        lambda x, y: x + y, all_nodes_for_artifact)
    all_nodes_for_artifact = validate.validation(all_nodes_for_artifact, artifact['type'], validate_map)
    all_nodes_for_artifact = transform.tarnsform_to(all_nodes_for_artifact, artifact['type'], validate_map)
    return all_nodes_for_artifact

def build_template(artifact, remote_ruleset):
    template_text = open(f"template/{artifact['template']}", 'r').read()
    final_snippet_text = ''
    if os.path.exists('snippet'):
        for snippet_file in os.listdir('snippet'):
            snippet_text = open(os.path.join('snippet', snippet_file), 'r').read()
            args = snippet_text.split('\n')[0].strip()
            if args == '':
                log.logger.error(f"snippet {snippet_file} 缺少参数")
                exit(1)
            content = '\n'.join(snippet_text.split('\n')[1:])
            # {% macro apple(default_rule, api_rule, cdn_rule, location_rule, apple_news_rule) -%}
            final_snippet_text += f"{{% macro {snippet_file}({args}) -%}}\n{content}\n{{%- endmacro -%}}\n"

    final_ruleset_text = ''
    for name, ruleset in remote_ruleset.items():
        final_ruleset_text += ruleset + '\n'

    template_text_with_macro = final_ruleset_text + '\n' + final_snippet_text + template_text
    return template_text_with_macro

def laod_config():
    if os.path.exists('config.toml'):
        with open('config.toml', 'r') as f:
            config = toml.load(f)
    elif os.path.exists('config.yaml'):
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    elif os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            config = json5.load(f)
    return config


def main():
    config = laod_config()
    if not config:
        log.logger.error('配置文件不存在或者格式错误')
        return

    log.logger.setLevel(config['log-level'])

    # 检查配置文件
    log.logger.info('检查配置文件')
    for provider in config['provider']:
        if provider['type'] not in supported_provider:
            log.logger.error(f"不支持的 provider 类型 {provider['type']}")
            return
    for artifact in config['artifact']:
        if artifact['type'] not in supported_artifact:
            log.logger.error(f"不支持的 artifact 类型 {artifact['type']}")
            return
        if artifact['providers'] is None or len(artifact['providers']) == 0:
            log.logger.error(f"artifact {artifact['name']} 没有 provider")
            return
        for provider in artifact['providers']:
            if list(filter(lambda x: x['name'] == provider, config['provider'])) == []:
                log.logger.error(f"artifact {artifact['name']} 的 provider {provider} 不存在")
                return
        if artifact['template'] is None:
            log.logger.error(f"artifact {artifact['name']} 没有 template")
            return
    log.logger.info('配置文件检查通过')

    log.logger.info('开始转换')

    all_nodes = load_nodes(config)
    remote_ruleset = load_rulset(config)

    map_path = '/'.join(__file__.split('/')[:-1]) + '/map.json'
    validate_map = json.load(open(map_path, 'r'))
    for artifact in config['artifact']:
        log.logger.info(f"开始转换 {artifact['name']}，类型为 {artifact['type']}")
        log.logger.info(f"使用 {artifact['providers']} 作为数据源")
        log.logger.info(f"使用 {artifact['template']} 作为模板")
        log.logger.info("过滤可用节点")
        all_nodes_for_artifact = filter_nodes(all_nodes, artifact, validate_map)
        log.logger.info(f"可用节点数量：{len(all_nodes_for_artifact)}")
        if len(all_nodes_for_artifact) == 0:
            log.logger.error(f"artifact {artifact['name']} 没有可用节点")
            return

        template_text_with_macro = build_template(artifact, remote_ruleset)

        log.logger.info(f"开始生成 {artifact['name']}")
        # check if node names are duplicated
        node_names = to_name(all_nodes_for_artifact)
        if len(node_names) != len(set(node_names)):
            log.logger.error(f"artifact {artifact['name']} 有重复的节点名")
            return

        def render(*args, **kwargs):
            if artifact['type'] in clash_like:
                return render_ruleset_in_clash(*args, **kwargs)

            return render_ruleset_generic(*args, **kwargs)

        env = jinja2.Environment(loader=jinja2.FileSystemLoader('./'))
        env.filters['to_surge'] = to_surge
        env.filters['to_yaml'] = to_yaml
        env.filters['to_json'] = to_json
        env.filters['render'] = render
        template = env.from_string(template_text_with_macro)

        def get_proxies():
            return all_nodes_for_artifact

        def get_proxies_names():
            return to_name(get_proxies())

        env.globals['get_proxies'] = get_proxies
        env.globals['get_proxies_names'] = get_proxies_names
        env.globals['to_name'] = to_name
        env.globals['to_name_list'] = to_name_list
        env.globals['filter'] = all_filters
        env.globals['remote_ruleset'] = remote_ruleset

        if not os.path.exists('dist'):
            os.mkdir('dist')

        with open('dist/' + artifact['name'], 'w') as f:
            final_config = template.render(options=artifact['options'])
            log.logger.info(f"生成 {artifact['name']} 成功")
            f.write(final_config)
            if 'upload' in artifact:
                log.logger.info(f"开始上传 {artifact['name']}")
                for upload_info in artifact['upload']:
                    log.logger.info(f"上传 {artifact['name']} 到 {upload_info['to']}")
                    upload_info['description'] = 'subio'
                    upload_info['file_name'] = artifact['name']
                    upload_info['content'] = final_config
                    success = upload.upload(upload_info)
                    if success:
                        log.logger.info(f"上传 {artifact['name']} 到 {upload_info['to']} 成功")
                    else:
                        log.logger.error(f"上传 {artifact['name']} 到 {upload_info['to']} 失败")


if __name__ == '__main__':
    main()