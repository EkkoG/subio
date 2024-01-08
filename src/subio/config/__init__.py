import json5
import requests
from functools import reduce

import toml
import yaml
import json

import hashlib
import os

from ..log import log
from ..unify import parse

from ..transform import transform
from ..transform import validate
from ..const import supported_artifact, supported_provider
from .model import Config, Rename, Artifact

map_path = '/'.join(__file__.split('/')[:-2]) + '/map.json'
validate_map = json.load(open(map_path, 'r'))

def nodes_of(artifact: Artifact, nodes):
    all_nodes_for_artifact = [nodes[provider]
                                for provider in artifact.providers]
    all_nodes_for_artifact = reduce(
        lambda x, y: x + y, all_nodes_for_artifact)
    all_nodes_for_artifact = validate.validation(all_nodes_for_artifact, artifact.type, validate_map)
    all_nodes_for_artifact = transform.tarnsform_to(all_nodes_for_artifact, artifact.type, validate_map)
    return all_nodes_for_artifact


def check(config: Config):
    # 检查配置文件
    log.logger.info('检查配置文件')
    for provider in config.provider:
        if provider.type not in supported_provider:
            log.logger.error(f"不支持的 provider 类型 {provider.type}")
            return False
    for artifact in config.artifact:
        if artifact.type not in supported_artifact:
            log.logger.error(f"不支持的 artifact 类型 {artifact.type}")
            return False
        if artifact.providers is None or len(artifact.providers) == 0:
            log.logger.error(f"artifact {artifact.name} 没有 provider")
            return False
        for provider in artifact.providers:
            if list(filter(lambda x: x.name == provider, config.provider)) == []:
                log.logger.error(f"artifact {artifact.name} 的 provider {provider} 不存在")
                return False
        if artifact.template is None:
            log.logger.error(f"artifact {artifact.name} 没有 template")
            return False
        if artifact.upload is not None:
            for index, up in enumerate(artifact.upload):
                if up.to is None:
                    log.logger.error(f"upload {index} 没有配置 to")
                    return False
                else:
                    if list(filter(lambda x: x.name == up.to, config.uploader)) == []:
                        log.logger.error(f"artifact {artifact.name} 的 upload {up.to} 不存在")
                        return False
    return True

def load_nodes(config: Config):
    all_nodes = {}
    for provider in config.provider:
        log.logger.info(f"加载 {provider.name} 节点")
        if provider.file is not None:
            sub_text = open(f"provider/{provider.file}", 'r').read()
        else:
            sub_text = load_remote_resource(provider.url, provider.user_agent)
        log.logger.info(f"加载 {provider.name} 节点成功, 开始解析")
        try:
            all_nodes[provider.name] = parse.parse(config, provider.type, sub_text)
        except Exception as e:
            log.logger.error(f"解析 {provider.name} 节点失败，错误信息：{e}")
            exit(1)
        if provider.rename is not None:
            all_nodes[provider.name] = list(map(lambda x: rename_node(x, provider.rename), all_nodes[provider.name]))
        log.logger.info(f"解析 {provider.name} 节点成功，数量：{len(all_nodes[provider.name])}")
    log.logger.info(f"加载节点成功，总数量：{reduce(lambda x, y: x + len(y), all_nodes.values(), 0)}")
    return all_nodes

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


def rename_node(node, rename: Rename):
    if rename.add_prefix:
        node['name'] = rename.add_prefix + node['name']
    if rename.add_suffix:
        node['name'] = node['name'] + rename.add_suffix
    if rename.replace:
        for r in rename.replace:
            node['name'] = node['name'].replace(r.old, r.new)

    return node


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


def load_rulset(config: Config):
    all_rule_set = {}
    for ruleset in config.ruleset:
        all_rule_set[ruleset.name] = wrap_with_jinja2_macro(load_remote_resource(ruleset.url, ruleset.user_agent), ruleset.name)
    return all_rule_set

from dacite import from_dict

def laod_config() -> Config:
    if os.path.exists('config.toml'):
        with open('config.toml', 'r') as f:
            config = toml.load(f)
    elif os.path.exists('config.yaml'):
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    elif os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            config = json5.load(f)
    else:
        log.logger.error('找不到配置文件')
        exit(1)

    return from_dict(data_class=Config, data=config)