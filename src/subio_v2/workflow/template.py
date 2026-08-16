"""Render artifact templates with data-only ruleset callables."""

import jinja2
import yaml
from dataclasses import dataclass
from typing import Any, Dict, Optional

from subio_v2.conversion import ConversionIssue
from subio_v2.workflow.errors import TemplateRenderError
from subio_v2.workflow.filters import all_filters
from subio_v2.workflow.ruleset import RuleIssueCollector, RuleSetStore


@dataclass(frozen=True)
class TemplateRenderResult:
    content: str
    issues: tuple[ConversionIssue, ...] = ()


class TemplateRenderer:
    def __init__(self, template_dir: str):
        def finalize_unicode(value):
            """Finalize function to preserve Unicode characters in output"""
            if value is None:
                return ""
            # For lists, convert to YAML format with allow_unicode=True.
            # Use width=float('inf') so flow-style sequences stay on one line; otherwise
            # PyYAML wraps and continuation lines break YAML (flow sequence must be
            # sufficiently indented or end with ]).
            if isinstance(value, list):
                return yaml.dump(
                    value,
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=True,
                    width=float("inf"),
                ).strip()
            return str(value)

        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            undefined=jinja2.StrictUndefined,
            finalize=finalize_unicode,
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
        return self.render_result(
            template_name,
            context,
            artifact_type=artifact_type,
            rulesets=rulesets,
        ).content

    def render_result(
        self,
        template_name: str,
        context: Dict[str, Any],
        artifact_type: str = None,
        rulesets: Optional[RuleSetStore] = None,
    ) -> TemplateRenderResult:
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
            platform = artifact_type or "mihomo"
            render_context = dict(context)
            collector = RuleIssueCollector()
            if rulesets:
                callables = rulesets.get_callables(platform, collector)
                conflicts = sorted(
                    set(callables) & (set(render_context) | set(self.env.globals))
                )
                if conflicts:
                    raise ValueError(
                        "Ruleset callable name conflicts with template context/global: "
                        + ", ".join(conflicts)
                    )
                render_context.update(callables)

            template = self.env.get_template(template_name)
            return TemplateRenderResult(
                content=template.render(**render_context),
                issues=tuple(collector.issues),
            )

        except TemplateRenderError:
            raise
        except Exception as e:
            raise TemplateRenderError(
                f"Error rendering template '{template_name}': {e}"
            ) from e
