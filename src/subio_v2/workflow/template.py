"""
模板渲染模块

使用方式：{{ ai('DIRECT') }}

macro 内容根据目标平台动态生成，由 Jinja2 完成渲染
"""
import jinja2
import yaml
import sys
from typing import Any, Dict, Optional
from subio_v2.utils.logger import logger
from subio_v2.workflow.filters import all_filters
from subio_v2.workflow.ruleset import RuleSetStore
import os


class TemplateRenderer:
    def __init__(self, template_dir: str):
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir), undefined=jinja2.Undefined
        )
        self._register_base_filters()
        self._register_globals()

    def _register_base_filters(self):
        def to_yaml_filter(value):
            return yaml.dump(value, allow_unicode=True, sort_keys=False).strip()

        self.env.filters["to_yaml"] = to_yaml_filter

    def _register_globals(self):
        self.env.globals["filter"] = all_filters

    def render(
        self,
        template_name: str,
        context: Dict[str, Any],
        artifact_type: str = None,
        rulesets: Optional[RuleSetStore] = None,
    ) -> str:
        """
        渲染模板
        
        Args:
            template_name: 模板文件名
            context: 模板上下文变量
            artifact_type: 目标平台类型
            rulesets: RuleSetStore 对象
        
        Returns:
            渲染后的字符串
        """
        try:
            template_path = os.path.join(self.env.loader.searchpath[0], template_name)
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template not found: {template_name}")

            with open(template_path, "r", encoding="utf-8") as f:
                template_source = f.read()

            # 根据平台生成 macros
            platform = artifact_type or "clash-meta"
            macros = ""
            if rulesets:
                macros = rulesets.generate_macros(platform)
            
            # 将 macros 拼接到模板前面
            full_source = f"{macros}\n{template_source}" if macros else template_source

            template = self.env.from_string(full_source)
            return template.render(**context)

        except FileNotFoundError as e:
            logger.error(f"Template error: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error rendering template {template_name}: {e}")
            sys.exit(1)
