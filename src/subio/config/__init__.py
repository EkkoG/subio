from dacite import from_dict
from dacite import Config as DaciteConfig
import requests
from functools import reduce

import hashlib
import os

from ..log import log
from ..unify import parse
from ..tools.tools import load

from ..const import SubIOPlatform
from .model import Config, Rename, Artifact
import tempfile
from subio.model import Base

def nodes_of(artifact: Artifact, nodes: dict[str, list[Base]]) -> list[Base]:
    all_nodes_for_artifact = [nodes[provider] for provider in artifact.providers]
    all_nodes_for_artifact = reduce(lambda x, y: x + y, all_nodes_for_artifact)
    all_valid_nodes = []
    for node in all_nodes_for_artifact:
        if artifact.type in SubIOPlatform.clash_like():
            try:
                node.to_clash_meta()
                all_valid_nodes.append(node)
            except Exception as e:
                log.logger.error(
                    f"节点 {node.name} 无法转换为 clash 格式，错误信息：{e}"
                )
        elif artifact.type == SubIOPlatform.DAE:
            try:
                node.to_dae()
                all_valid_nodes.append(node)
            except Exception as e:
                log.logger.error(f"节点 {node.name} 无法转换为 dae 格式，错误信息：{e}")
        elif artifact.type == SubIOPlatform.SURGE:
            try:
                node.to_surge()
                all_valid_nodes.append(node)
            except Exception as e:
                log.logger.error(
                    f"节点 {node.name} 无法转换为 surge 格式，错误信息：{e}"
                )
        elif artifact.type == SubIOPlatform.V2RAYN:
            try:
                node.to_v2rayn()
                all_valid_nodes.append(node)
            except Exception as e:
                log.logger.error(
                    f"节点 {node.name} 无法转换为 v2rayn 格式，错误信息：{e}"
                )
        else:
            log.logger.error(f"不支持的 artifact 类型 {artifact.type}")
    return all_valid_nodes

def check(config: Config):
    # 检查配置文件
    log.logger.info("检查配置文件")
    for provider in config.provider:
        if provider.type not in SubIOPlatform.supported_provider():
            log.logger.error(f"不支持的 provider 类型 {provider.type}")
            return False
    for artifact in config.artifact:
        if artifact.type not in SubIOPlatform.supported_artifact():
            log.logger.error(f"不支持的 artifact 类型 {artifact.type}")
            return False
        if artifact.providers is None or len(artifact.providers) == 0:
            log.logger.error(f"artifact {artifact.name} 没有 provider")
            return False
        for provider in artifact.providers:
            if list(filter(lambda x: x.name == provider, config.provider)) == []:
                log.logger.error(
                    f"artifact {artifact.name} 的 provider {provider} 不存在"
                )
                return False
        if artifact.template is None:
            log.logger.error(f"artifact {artifact.name} 没有 template")
            return False
        if artifact.upload:
            for index, up in enumerate(artifact.upload):
                if up.to is None:
                    log.logger.error(f"upload {index} 没有配置 to")
                    return False
                else:
                    if list(filter(lambda x: x.name == up.to, config.uploader)) == []:
                        log.logger.error(
                            f"artifact {artifact.name} 的 upload {up.to} 不存在"
                        )
                        return False
        # check articate name duplication
        artifact_names = list(map(lambda x: x.name, config.artifact))
        if len(artifact_names) != len(set(artifact_names)):
            # find duplicated names
            duplicated_names = set(
                [x for x in artifact_names if artifact_names.count(x) > 1]
            )
            # log.logger.error(f"artifact 名称重复：{duplicated_names}")
            for name in duplicated_names:
                log.logger.error(f"artifact 名称重复：{name}, 重复次数：{artifact_names.count(name)}")
        
            return False
    return True


def load_nodes(config: Config) -> list[Base]:
    all_nodes: dict[str, list[Base]] = {}
    for provider in config.provider:
        log.logger.info(f"加载 {provider.name} 节点")
        if provider.file is None:
            sub_text = load_remote_resource(provider.url, provider.user_agent)
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                f.write(sub_text)
                file = f.name
        else:
            file = f"provider/{provider.file}"
        log.logger.info(f"加载 {provider.name} 节点成功, 开始解析")
        try:
            all_nodes[provider.name] = parse.parse(provider.type, file)
            if provider.file is None:
                os.remove(file)
        except Exception as e:
            log.logger.error(f"解析 {provider.name} 节点失败，错误信息：{e}")
            exit(1)
        if provider.rename:
            all_nodes[provider.name] = list(
                map(lambda x: rename_node(x, provider.rename), all_nodes[provider.name])
            )
        log.logger.info(
            f"解析 {provider.name} 节点成功，数量：{len(all_nodes[provider.name])}"
        )
        if provider.privacy_endpoint:
            log.logger.info(f"使用 {provider.privacy_endpoint} 作为隐私节点")
            def use_privacy_endpoint(proxy: Base):
                proxy.privacy_endpoint = provider.privacy_endpoint
                return proxy
            all_nodes[provider.name] = list(
                map(
                    lambda x: use_privacy_endpoint(x),
                    all_nodes[provider.name],
                )
            )
    log.logger.info(
        f"加载节点成功，总数量：{reduce(lambda x, y: x + len(y), all_nodes.values(), 0)}"
    )
    return all_nodes


def load_remote_resource(url: str, ua=None) -> str:
    headers = {"User-Agent": ua}
    if os.getenv("DEBUG"):
        file_name = f"cache/{hashlib.md5(url.encode('utf-8')).hexdigest()}"
        if not os.path.exists("cache"):
            os.mkdir("cache")
        if os.path.exists(file_name):
            text = open(file_name, "r").read()
        else:
            text = requests.get(url, headers=headers).text
            with open(file_name, "w") as f:
                f.write(text)
    else:
        text = requests.get(url, headers=headers).text

    return text


def rename_node(node, rename: Rename):
    if rename.add_prefix:
        node.name = rename.add_prefix + node.name
    if rename.add_suffix:
        node.name = node.name + rename.add_suffix
    if rename.replace:
        for r in rename.replace:
            node.name = node.name.replace(r.old, r.new)

    return node


def wrap_with_jinja2_macro(text, name):
    def append_rule(rule):
        if rule.strip() == "":
            return ""
        if rule.strip().startswith("#"):
            return rule
        if rule.strip().startswith("//"):
            return rule
        if "//" in rule:
            rule = rule.split("//")[0].strip()
            return rule + ",{{ rule }}"
        if ",no-resolve" in rule:
            return rule.replace(",no-resolve", ",{{ rule }},no-resolve")
        return rule + ",{{ rule }}"

    text = "\n".join(map(append_rule, text.split("\n")))
    return "{{% macro {}(rule) -%}}\n{}\n{{%- endmacro -%}}".format(
        f"remote_{name}", text
    )


def load_rulset(config: Config) -> dict[str, str]:
    all_rule_set = {}
    for ruleset in config.ruleset:
        all_rule_set[ruleset.name] = wrap_with_jinja2_macro(
            load_remote_resource(ruleset.url, ruleset.user_agent), ruleset.name
        )
    return all_rule_set


def load_config() -> Config:
    config, file = load("config")

    log.logger.info(f"发现 {file}， 使用 {file} 文件作为配置文件")

    if config is None:
        log.logger.error("没有找到配置文件")
        return None

    return from_dict(
        data_class=Config, data=config, config=DaciteConfig(cast=[SubIOPlatform])
    )
