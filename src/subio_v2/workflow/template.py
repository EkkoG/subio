"""Render artifact templates with data-only ruleset callables."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import CodeType, MappingProxyType
from typing import Any, Dict, Optional

import jinja2
import yaml
from jinja2.loaders import split_template_path

from subio_v2.core.errors import TemplateRenderError
from subio_v2.core.parameters import MissingParameterError
from subio_v2.core.results import ConversionIssue
from subio_v2.rules.runtime import RuleIssueCollector, RuleSetStore
from subio_v2.workflow.filters import all_filters


@dataclass(frozen=True)
class TemplateRenderResult:
    content: str
    issues: tuple[ConversionIssue, ...] = ()


class _TemplateParameters(dict):
    def __missing__(self, key):
        raise MissingParameterError("Missing rendering parameter")


def _template_name(name: str) -> str:
    return "/".join(split_template_path(name))


class _CapturedTemplateLoader(jinja2.BaseLoader):
    def __init__(self, sources, compiled):
        self._sources = sources
        self._compiled = compiled

    def get_source(self, environment, template):
        template = _template_name(template)
        if template not in self._sources:
            raise jinja2.TemplateNotFound(template)
        source = self._sources[template]
        if source is None:
            # Existing-but-broken entries must not be swallowed by ignore missing.
            raise jinja2.TemplateError("Prepared template source is unavailable")
        return source, None, None

    def load(self, environment, name, globals=None):
        name = _template_name(name)
        code = self._compiled.get(name)
        if code is not None:
            return environment.template_class.from_code(environment, code, globals or {})
        return super().load(environment, name, globals)


@dataclass(frozen=True)
class PreparedTemplates:
    _sources: Mapping[str, str | None] = field(repr=False)
    _compiled: Mapping[str, CodeType] = field(repr=False)
    failed_roots: frozenset[str]

    @classmethod
    def capture(cls, template_dir: str, roots: set[str]) -> "PreparedTemplates":
        renderer = TemplateRenderer(template_dir)
        loader = renderer.env.loader
        sources: dict[str, str | None] = {}
        compiled: dict[str, CodeType] = {}
        failed_roots = set()
        root_names = {}
        for name in roots:
            try:
                root_names[name] = _template_name(name)
            except jinja2.TemplateNotFound:
                failed_roots.add(name)
        # FileSystemLoader deliberately does not traverse directory symlinks.
        discovered = {_template_name(name) for name in loader.list_templates()}
        for name in sorted(discovered | set(root_names.values())):
            try:
                sources[name] = loader.get_source(renderer.env, name)[0]
            except jinja2.TemplateNotFound:
                if name in discovered:
                    sources[name] = None
            except Exception:
                sources[name] = None
        for name in sorted(set(root_names.values())):
            try:
                compiled[name] = renderer.env.compile(sources[name], name=name)
            except Exception:
                failed_roots.update(root for root in roots if root_names.get(root) == name)
        return cls(
            MappingProxyType(sources), MappingProxyType(compiled),
            frozenset(failed_roots),
        )

    def renderer(self) -> "TemplateRenderer":
        # Each request owns Jinja caches/modules and globals; only source/code is shared.
        return TemplateRenderer(loader=_CapturedTemplateLoader(self._sources, self._compiled))


class TemplateRenderer:
    def __init__(self, template_dir: str = "", *, loader: jinja2.BaseLoader | None = None):
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
            loader=loader if loader is not None else jinja2.FileSystemLoader(template_dir),
            undefined=jinja2.StrictUndefined,
            finalize=finalize_unicode,
        )
        self._register_base_filters()
        self._register_globals()

    def _register_base_filters(self):
        def to_yaml_filter(value):
            if isinstance(value, Mapping) and not isinstance(value, dict):
                value = dict(value)
            return yaml.dump(value, allow_unicode=True, sort_keys=False).strip()

        self.env.filters["to_yaml"] = to_yaml_filter
        builtin_tojson = self.env.filters["tojson"]

        @jinja2.pass_eval_context
        def to_json_filter(eval_context, value, indent=None):
            if isinstance(value, Mapping) and not isinstance(value, dict):
                value = dict(value)
            return builtin_tojson(eval_context, value, indent)

        self.env.filters["tojson"] = to_json_filter

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
            if isinstance(render_context.get("params"), Mapping):
                # Missing request fields are input errors, including before Jinja filters.
                render_context["params"] = MappingProxyType(
                    _TemplateParameters(render_context["params"])
                )
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
