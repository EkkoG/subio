"""
Platform Capability Checker

检查节点是否被目标平台支持，并生成警告信息
"""

from dataclasses import dataclass, field

import subio_v2.protocols as protocol_registry
from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node
from subio_v2.platforms import normalize_platform
from subio_v2.validation import validate_node
from .definitions import get_platform_capabilities, normalize_protocol_name


@dataclass
class CheckResult:
    """检查结果"""

    supported: bool  # 是否支持（可渲染）
    warnings: list[IssueDraft] = field(default_factory=list)

    def add_issue(
        self,
        severity: IssueSeverity,
        message: str,
        field: str | None = None,
        suggestion: str | None = None,
        code: str = "conversion",
    ) -> None:
        self.warnings.append(
            IssueDraft(severity, message, field, suggestion, code)
        )

    def add_error(
        self,
        message: str,
        field: str | None = None,
        suggestion: str | None = None,
        code: str = "conversion",
    ) -> None:
        self.add_issue(IssueSeverity.ERROR, message, field, suggestion, code)
        self.supported = False

    def has_errors(self) -> bool:
        return any(issue.severity == IssueSeverity.ERROR for issue in self.warnings)

    def has_warnings(self) -> bool:
        return any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.INFO}
            for issue in self.warnings
        )


class CapabilityChecker:
    """平台能力检查器"""

    def __init__(self, platform: str):
        self.platform = normalize_platform(platform)
        self.capabilities = get_platform_capabilities(self.platform)
        if not self.capabilities:
            raise ValueError(f"Unknown platform: {platform}")

    def check_node(self, node: Node) -> CheckResult:
        """
        检查节点是否被当前平台支持

        返回:
            CheckResult: 包含是否支持和警告列表
        """
        result = CheckResult(supported=True)

        protocol = normalize_protocol_name(node.type.value)
        desc = protocol_registry.get(node.type)

        for error in validate_node(node):
            result.add_error(error.message, field=error.field)

        if result.has_errors():
            return result

        if protocol not in self.capabilities.get("protocols", set()):
            result.add_error(
                f"Protocol '{protocol}' is not supported by {self.platform}",
                field="type",
                suggestion=(
                    "Use a supported protocol: "
                    + ", ".join(sorted(self.capabilities.get("protocols", set())))
                ),
            )
            return result

        proto_caps = self.capabilities.get(protocol, {})

        if desc:
            for warning in desc.check(node, proto_caps, self.platform):
                result.warnings.append(warning)
                if warning.severity == IssueSeverity.ERROR:
                    result.supported = False

        self._check_global_features(node, result)
        return result

    def _check_global_features(self, node: Node, result: CheckResult):
        """检查全局特性"""
        global_features = self.capabilities.get("global_features", {})

        if hasattr(node, "tfo") and node.tfo and not global_features.get("tfo", False):
            result.add_issue(
                IssueSeverity.INFO,
                f"TFO is not supported by {self.platform}, will be ignored",
                field="tfo",
            )

        if (
            hasattr(node, "mptcp")
            and node.mptcp
            and not global_features.get("mptcp", False)
        ):
            result.add_issue(
                IssueSeverity.INFO,
                f"MPTCP is not supported by {self.platform}, will be ignored",
                field="mptcp",
            )

        if (
            hasattr(node, "dialer_proxy")
            and node.dialer_proxy
            and not global_features.get("dialer_proxy", False)
        ):
            result.add_issue(
                IssueSeverity.INFO,
                f"Dialer proxy is not supported by {self.platform}, will be ignored",
                field="dialer_proxy",
            )

        if self.platform == "stash" and node.dialer_proxy and node.interface_name:
            result.add_error(
                "Stash dialer-proxy cannot be combined with interface-name",
                field="dialer_proxy",
                code="conversion.unsupported-field-combination",
            )


def check_node_for_platform(node: Node, platform: str) -> CheckResult:
    """
    便捷函数：检查节点是否被指定平台支持

    Args:
        node: 要检查的节点
        platform: 目标平台名称

    Returns:
        CheckResult: 检查结果
    """
    checker = CapabilityChecker(platform)
    return checker.check_node(node)
