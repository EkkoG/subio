"""
Platform Capability Checker

检查节点是否被目标平台支持，并生成警告信息
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import Node
from .definitions import get_platform_capabilities, normalize_protocol_name


class WarningLevel(Enum):
    """警告级别"""

    INFO = "info"  # 信息，不影响功能
    WARNING = "warning"  # 警告，可能影响部分功能
    ERROR = "error"  # 错误，节点无法使用


@dataclass
class CapabilityWarning:
    """能力检查警告"""

    level: WarningLevel
    message: str
    field: Optional[str] = None  # 相关字段名
    suggestion: Optional[str] = None  # 建议


@dataclass
class CheckResult:
    """检查结果"""

    supported: bool  # 是否支持（可渲染）
    warnings: List[CapabilityWarning] = field(default_factory=list)

    def add_warning(
        self,
        level: WarningLevel,
        message: str,
        field: Optional[str] = None,
        suggestion: Optional[str] = None,
    ):
        self.warnings.append(CapabilityWarning(level, message, field, suggestion))

    def add_error(
        self, message: str, field: Optional[str] = None, suggestion: Optional[str] = None
    ):
        self.add_warning(WarningLevel.ERROR, message, field, suggestion)
        self.supported = False

    def has_errors(self) -> bool:
        return any(w.level == WarningLevel.ERROR for w in self.warnings)

    def has_warnings(self) -> bool:
        return any(w.level == WarningLevel.WARNING for w in self.warnings)


class CapabilityChecker:
    """平台能力检查器"""

    def __init__(self, platform: str):
        self.platform = platform
        self.capabilities = get_platform_capabilities(platform)
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

        desc = protocol_registry.get(node.type)
        if desc:
            for warning in desc.check(node, proto_caps, self.platform):
                result.warnings.append(warning)
                if warning.level == WarningLevel.ERROR:
                    result.supported = False

        self._check_global_features(node, result)
        return result

    def _check_global_features(self, node: Node, result: CheckResult):
        """检查全局特性"""
        global_features = self.capabilities.get("global_features", {})

        if hasattr(node, "tfo") and node.tfo and not global_features.get("tfo", False):
            result.add_warning(
                WarningLevel.INFO,
                f"TFO is not supported by {self.platform}, will be ignored",
                field="tfo",
            )

        if hasattr(node, "mptcp") and node.mptcp and not global_features.get(
            "mptcp", False
        ):
            result.add_warning(
                WarningLevel.INFO,
                f"MPTCP is not supported by {self.platform}, will be ignored",
                field="mptcp",
            )

        if hasattr(node, "dialer_proxy") and node.dialer_proxy and not global_features.get(
            "dialer_proxy", False
        ):
            result.add_warning(
                WarningLevel.INFO,
                f"Dialer proxy is not supported by {self.platform}, will be ignored",
                field="dialer_proxy",
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
