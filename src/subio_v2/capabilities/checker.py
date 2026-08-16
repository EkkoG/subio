"""
Platform Capability Checker

检查节点是否被目标平台支持，并生成警告信息
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import NativeNode, Node, Protocol, RejectMode, RejectNode
from subio_v2.platforms import normalize_platform
from subio_v2.surge.security import is_authorized_local_external
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
    code: str = "conversion"


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
        code: str = "conversion",
    ):
        self.warnings.append(CapabilityWarning(level, message, field, suggestion, code))

    def add_error(
        self,
        message: str,
        field: Optional[str] = None,
        suggestion: Optional[str] = None,
        code: str = "conversion",
    ):
        self.add_warning(WarningLevel.ERROR, message, field, suggestion, code)
        self.supported = False

    def has_errors(self) -> bool:
        return any(w.level == WarningLevel.ERROR for w in self.warnings)

    def has_warnings(self) -> bool:
        return any(
            warning.level in {WarningLevel.WARNING, WarningLevel.INFO}
            for warning in self.warnings
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

        if not node.name:
            result.add_error("Node name is required", field="name")
        if isinstance(node, NativeNode) and node.type == Protocol.EXTERNAL:
            external = node.source_extensions.get("surge", {})
            if self.platform != "surge" or node.native_format != "surge":
                result.add_error(
                    "External Proxy Program cannot be converted across platforms",
                    field="native_format",
                    code="security.external-cross-platform",
                )
            elif not (
                node.unsafe
                and external.get("source_kind") == "local"
                and external.get("authorized") is True
                and is_authorized_local_external(node)
            ):
                result.add_error(
                    "External policy is not authorized for Surge emission",
                    field="source_extensions.surge",
                    code="security.external-rejected",
                )
        if isinstance(node, RejectNode) and not isinstance(node.mode, RejectMode):
            result.add_error(
                "Reject mode is invalid",
                field="mode",
            )
        if desc and not desc.passthrough:
            if desc.requires_endpoint:
                if not node.server:
                    result.add_error("Server is required", field="server")
                if (
                    not isinstance(node.port, int)
                    or isinstance(node.port, bool)
                    or not 1 <= node.port <= 65535
                ):
                    result.add_error(
                        f"Port must be between 1 and 65535, got {node.port!r}",
                        field="port",
                    )
            for error in desc.validate(node):
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

        if (
            hasattr(node, "mptcp")
            and node.mptcp
            and not global_features.get("mptcp", False)
        ):
            result.add_warning(
                WarningLevel.INFO,
                f"MPTCP is not supported by {self.platform}, will be ignored",
                field="mptcp",
            )

        if (
            hasattr(node, "dialer_proxy")
            and node.dialer_proxy
            and not global_features.get("dialer_proxy", False)
        ):
            result.add_warning(
                WarningLevel.INFO,
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
