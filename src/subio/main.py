import jinja2
import os

from subio.config import load_nodes
from subio.config import load_rulset
from subio.config import load_config
from subio.config import check
from subio.config import nodes_of

from subio.transform.node import to_v2rayn
from subio.transform.node import to_surge
from subio.transform.node import to_clash_meta
from subio.transform.node import to_name
from subio.transform.node import list_to_names
from subio.transform.node import to_dae, to_dae_subscription
from subio.transform.node import convert_privacy_node


from subio.transform.ruleset import render_ruleset_in_clash
from subio.transform.ruleset import render_ruleset_generic
from subio.transform.ruleset import render_ruleset_in_dae

from subio.upload import upload
from subio.log import log
from subio.const import SubIOPlatform

from subio.nodefilter.filter import all_filters
import sys
import re
from subio.model import Base


def get_snippets():
    final_snippet_text = ""
    if os.path.exists("snippet"):
        for snippet_file in os.listdir("snippet"):
            # Validate filename to prevent path traversal
            if '..' in snippet_file or '/' in snippet_file or '\\' in snippet_file:
                log.logger.error(f"Invalid snippet filename: {snippet_file}")
                continue
            
            snippet_path = os.path.join("snippet", snippet_file)
            try:
                with open(snippet_path, "r", encoding="utf-8") as f:
                    snippet_text = f.read()
            except (OSError, UnicodeDecodeError) as e:
                log.logger.error(f"Failed to read snippet {snippet_file}: {e}")
                continue
            args = snippet_text.split("\n")[0].strip()
            if args == "":
                log.logger.error(f"snippet {snippet_file} 缺少参数")
                sys.exit(1)
            content = "\n".join(snippet_text.split("\n")[1:])
            # {% macro apple(default_rule, api_rule, cdn_rule, location_rule, apple_news_rule) -%}
            final_snippet_text += f"{{% macro {snippet_file}({args}) -%}}\n{content}\n{{%- endmacro -%}}\n"
    return final_snippet_text


def build_template(artifact, remote_ruleset):
    # Validate template filename to prevent path traversal
    template_name = artifact.template
    if '..' in template_name or '/' in template_name or '\\' in template_name:
        log.logger.error(f"Invalid template filename: {template_name}")
        return ""
    
    template_path = os.path.join("template", template_name)
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template_text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        log.logger.error(f"Failed to read template {template_name}: {e}")
        return ""

    final_snippet_text = get_snippets()

    final_ruleset_text = ""
    for name, ruleset in remote_ruleset.items():
        final_ruleset_text += ruleset + "\n"

    template_text_with_macro = (
        final_ruleset_text + "\n" + final_snippet_text + template_text
    )
    return template_text_with_macro


def run():
    if os.getenv("RUN_EXAMPLE"):
        os.chdir("./example")

    log.logger.setLevel("INFO")
    config = load_config()
    if not config:
        log.logger.error("配置文件不存在或者格式错误")
        return

    log.logger.setLevel(config.log_level)
    if not check(config):
        log.logger.error("配置文件不合法")
        sys.exit(1)
        return

    log.logger.info("配置文件检查通过")

    log.logger.info("开始转换")

    all_nodes_of_providers = load_nodes(config)
    remote_ruleset = load_rulset(config)

    for artifact in config.artifact:
        log.logger.info(f"开始转换 {artifact.name}，类型为 {artifact.type}")
        log.logger.info(f"使用 {artifact.providers} 作为数据源")
        log.logger.info(f"使用 {artifact.template} 作为模板")
        log.logger.info("过滤可用节点，并转换为当前平台的格式")
        nodes_of_artifact = nodes_of(artifact, all_nodes_of_providers)
        nodes_of_artifact = convert_privacy_node(nodes_of_artifact, artifact.type)
        filters = artifact.filters if artifact.filters else config.filters
        if filters:
            if "include" in filters:
                # 过滤节点, 只保留 include 中的节点，使用 re
                nodes_of_artifact = list(
                    filter(
                        lambda x: re.search(filters["include"], x.name, re.IGNORECASE),
                        nodes_of_artifact,
                    )
                )
            if "exclude" in filters:
                # 过滤节点, 排除 exclude 中的节点，使用 re
                nodes_of_artifact = list(
                    filter(
                        lambda x: not re.search(
                            filters["exclude"], x.name, re.IGNORECASE
                        ),
                        nodes_of_artifact,
                    )
                )
        log.logger.info(f"可用节点数量：{len(nodes_of_artifact)}")
        if len(nodes_of_artifact) == 0:
            log.logger.error(f"artifact {artifact.name} 没有可用节点")
            return

        template_text = build_template(artifact, remote_ruleset)

        log.logger.info(f"开始生成 {artifact.name}")

        # # check if node names are duplicated
        # node_names = to_name(nodes_of_artifact)
        # if len(node_names) != len(set(node_names)):
        #     log.logger.error(f"artifact {artifact.name} 有重复的节点名")
        #     # print diff
        #     from collections import Counter
        #     counter = Counter(node_names)
        #     for name, count in counter.items():
        #         if count > 1:
        #             log.logger.error(f"{name} 重复 {count} 次")
        #     return

        def render_rules(*args, **kwargs):
            if artifact.type in SubIOPlatform.clash_like():
                return render_ruleset_in_clash(*args, **kwargs)
            if artifact.type == SubIOPlatform.DAE:
                return render_ruleset_in_dae(*args, **kwargs)

            return render_ruleset_generic(*args, **kwargs)

        def render_proxies(nodes: list[Base]) -> str | None:
            if artifact.type in SubIOPlatform.clash_like():
                return to_clash_meta(nodes)
            if artifact.type == SubIOPlatform.V2RAYN:
                return to_v2rayn(nodes)
            if artifact.type == SubIOPlatform.SURGE:
                return to_surge(nodes)
            if artifact.type == SubIOPlatform.DAE:
                return to_dae(nodes)
            return None

        def render_subsctiption(nodes: list[Base]) -> str | None:
            if artifact.type == SubIOPlatform.DAE:
                return to_dae_subscription(nodes)
            return render_proxies(nodes)

        # 只接受字符串数组参数
        def render_proxies_names(*args, **kwargs):
            return list_to_names(artifact.type, *args, **kwargs)

        def render(*args, **kwargs):
            if isinstance(args[0], str):
                return render_rules(*args, **kwargs)
            else:
                return render_proxies_names(*args, **kwargs)

        env = jinja2.Environment(loader=jinja2.FileSystemLoader("./"))
        env.filters["render"] = render
        env.filters["render_proxies"] = render_proxies
        template = env.from_string(template_text)

        rendered_proxied = render_proxies(nodes_of_artifact)
        env.globals["proxies"] = rendered_proxied
        env.globals["subscription"] = render_subsctiption(nodes_of_artifact)
        env.globals["proxies_obj"] = nodes_of_artifact
        env.globals["proxies_names"] = to_name(nodes_of_artifact)
        env.globals["filter"] = all_filters
        env.globals["remote_ruleset"] = remote_ruleset
        env.globals["global_options"] = config.options

        if not os.path.exists("dist"):
            os.mkdir("dist")

        with open("dist/" + artifact.name, "w") as f:
            final_config = template.render(options=artifact.options)
            f.write(final_config)
            log.logger.info(f"生成 {artifact.name} 成功")
            upload.upload(final_config, artifact, config.uploader)


if __name__ == "__main__":
    run()
