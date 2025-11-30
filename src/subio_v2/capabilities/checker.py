"""
Platform Capability Checker

检查节点是否被目标平台支持，并生成警告信息
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any
from enum import Enum

from subio_v2.model.nodes import (
    Node,
    Protocol,
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    WireguardNode,
    Hysteria2Node,
    SSHNode,
    SnellNode,
    TUICNode,
    AnyTLSNode,
    Network,
)
from .definitions import (
    PLATFORM_CAPABILITIES,
    normalize_protocol_name,
    get_platform_capabilities,
    get_protocol_capabilities,
)


class WarningLevel(Enum):
    """警告级别"""
    INFO = "info"           # 信息，不影响功能
    WARNING = "warning"     # 警告，可能影响部分功能
    ERROR = "error"         # 错误，节点无法使用


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
    
    def add_warning(self, level: WarningLevel, message: str, 
                    field: Optional[str] = None, suggestion: Optional[str] = None):
        self.warnings.append(CapabilityWarning(level, message, field, suggestion))
    
    def add_error(self, message: str, field: Optional[str] = None, suggestion: Optional[str] = None):
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
        
        # 获取协议名称
        protocol = self._get_protocol_name(node)
        
        # 1. 检查协议是否支持
        if protocol not in self.capabilities.get("protocols", set()):
            result.add_error(
                f"Protocol '{protocol}' is not supported by {self.platform}",
                field="type",
                suggestion=f"Use a supported protocol: {', '.join(sorted(self.capabilities.get('protocols', set())))}"
            )
            return result
        
        # 2. 获取协议特定的能力定义
        proto_caps = self.capabilities.get(protocol, {})
        
        # 3. 检查协议特定的属性
        if isinstance(node, ShadowsocksNode):
            self._check_shadowsocks(node, proto_caps, result)
        elif isinstance(node, VmessNode):
            self._check_vmess(node, proto_caps, result)
        elif isinstance(node, VlessNode):
            self._check_vless(node, proto_caps, result)
        elif isinstance(node, TrojanNode):
            self._check_trojan(node, proto_caps, result)
        elif isinstance(node, SnellNode):
            self._check_snell(node, proto_caps, result)
        elif isinstance(node, TUICNode):
            self._check_tuic(node, proto_caps, result)
        elif isinstance(node, Hysteria2Node):
            self._check_hysteria2(node, proto_caps, result)
        elif isinstance(node, WireguardNode):
            self._check_wireguard(node, proto_caps, result)
        elif isinstance(node, SSHNode):
            self._check_ssh(node, proto_caps, result)
        
        # 4. 检查全局特性
        self._check_global_features(node, result)
        
        return result
    
    def _get_protocol_name(self, node: Node) -> str:
        """获取标准化的协议名称"""
        return normalize_protocol_name(node.type.value)
    
    def _check_shadowsocks(self, node: ShadowsocksNode, proto_caps: dict, result: CheckResult):
        """检查 Shadowsocks 节点"""
        # 检查加密方法
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            result.add_error(
                f"Cipher '{node.cipher}' is not supported by {self.platform}",
                field="cipher",
                suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}"
            )
        
        # 检查插件
        if node.plugin:
            supported_plugins = proto_caps.get("plugins", set())
            if node.plugin not in supported_plugins:
                result.add_error(
                    f"Plugin '{node.plugin}' is not supported by {self.platform}",
                    field="plugin",
                    suggestion=f"Supported plugins: {', '.join(sorted(supported_plugins))}" if supported_plugins else "No plugins supported"
                )
    
    def _check_vmess(self, node: VmessNode, proto_caps: dict, result: CheckResult):
        """检查 VMess 节点"""
        # 检查加密方法
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            result.add_warning(
                WarningLevel.WARNING,
                f"Cipher '{node.cipher}' may not be supported, using 'auto'",
                field="cipher"
            )
        
        # 检查传输方式
        self._check_transport(node.transport, proto_caps, result)
        
        # 检查 SMUX
        if hasattr(node, 'smux') and node.smux and node.smux.enabled:
            if "smux" not in proto_caps.get("features", set()):
                result.add_warning(
                    WarningLevel.WARNING,
                    f"SMUX is not supported by {self.platform}, will be ignored",
                    field="smux"
                )
    
    def _check_vless(self, node: VlessNode, proto_caps: dict, result: CheckResult):
        """检查 VLESS 节点"""
        # 检查传输方式
        self._check_transport(node.transport, proto_caps, result)
        
        # 检查 flow
        if node.flow:
            supported_flows = proto_caps.get("flows", set())
            if node.flow not in supported_flows:
                result.add_error(
                    f"Flow '{node.flow}' is not supported by {self.platform}",
                    field="flow",
                    suggestion=f"Supported flows: {', '.join(sorted(supported_flows))}" if supported_flows else "No flows supported"
                )
        
        # 检查 Reality
        if node.tls and node.tls.reality_opts:
            if "reality" not in proto_caps.get("features", set()):
                result.add_error(
                    f"Reality is not supported by {self.platform}",
                    field="reality"
                )
    
    def _check_trojan(self, node: TrojanNode, proto_caps: dict, result: CheckResult):
        """检查 Trojan 节点"""
        # 检查传输方式
        self._check_transport(node.transport, proto_caps, result)
        
        # 检查 SMUX
        if hasattr(node, 'smux') and node.smux and node.smux.enabled:
            if "smux" not in proto_caps.get("features", set()):
                result.add_warning(
                    WarningLevel.WARNING,
                    f"SMUX is not supported by {self.platform}, will be ignored",
                    field="smux"
                )
    
    def _check_snell(self, node: SnellNode, proto_caps: dict, result: CheckResult):
        """检查 Snell 节点"""
        # 检查版本
        if node.version:
            supported_versions = proto_caps.get("versions", set())
            if supported_versions and node.version not in supported_versions:
                result.add_error(
                    f"Snell version {node.version} is not supported by {self.platform}",
                    field="version",
                    suggestion=f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                )
        
        # 检查 obfs 模式
        if node.obfs:
            supported_obfs = proto_caps.get("obfs_modes", set())
            if supported_obfs and node.obfs not in supported_obfs:
                result.add_warning(
                    WarningLevel.WARNING,
                    f"Obfs mode '{node.obfs}' may not be supported",
                    field="obfs"
                )
    
    def _check_tuic(self, node: TUICNode, proto_caps: dict, result: CheckResult):
        """检查 TUIC 节点"""
        # 检查版本
        if node.version:
            supported_versions = proto_caps.get("versions", set())
            if supported_versions and node.version not in supported_versions:
                result.add_error(
                    f"TUIC version {node.version} is not supported by {self.platform}",
                    field="version",
                    suggestion=f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                )
    
    def _check_hysteria2(self, node: Hysteria2Node, proto_caps: dict, result: CheckResult):
        """检查 Hysteria2 节点"""
        # 检查 obfs
        if node.obfs:
            if "obfs" not in proto_caps.get("features", set()):
                result.add_warning(
                    WarningLevel.WARNING,
                    f"Obfs is not supported for Hysteria2 on {self.platform}, will be ignored",
                    field="obfs"
                )
    
    def _check_wireguard(self, node: WireguardNode, proto_caps: dict, result: CheckResult):
        """检查 WireGuard 节点"""
        # WireGuard 通常没有太多可选配置，主要检查协议支持
        pass
    
    def _check_ssh(self, node: SSHNode, proto_caps: dict, result: CheckResult):
        """检查 SSH 节点"""
        # 检查认证方式
        supported_auth = proto_caps.get("auth_methods", set())
        if node.private_key and "private_key" not in supported_auth:
            result.add_error(
                f"SSH private key authentication is not supported by {self.platform}",
                field="private_key"
            )
        if node.password and "password" not in supported_auth:
            result.add_error(
                f"SSH password authentication is not supported by {self.platform}",
                field="password"
            )
    
    def _check_transport(self, transport, proto_caps: dict, result: CheckResult):
        """检查传输方式"""
        if not transport:
            return
        
        supported_transports = proto_caps.get("transports", set())
        if not supported_transports:
            return
        
        network = transport.network.value if transport.network else "tcp"
        if network not in supported_transports:
            result.add_error(
                f"Transport '{network}' is not supported by {self.platform}",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}"
            )
    
    def _check_global_features(self, node: Node, result: CheckResult):
        """检查全局特性"""
        global_features = self.capabilities.get("global_features", {})
        
        # 检查 TFO
        if hasattr(node, 'tfo') and node.tfo:
            if not global_features.get("tfo", False):
                result.add_warning(
                    WarningLevel.INFO,
                    f"TFO is not supported by {self.platform}, will be ignored",
                    field="tfo"
                )
        
        # 检查 MPTCP
        if hasattr(node, 'mptcp') and node.mptcp:
            if not global_features.get("mptcp", False):
                result.add_warning(
                    WarningLevel.INFO,
                    f"MPTCP is not supported by {self.platform}, will be ignored",
                    field="mptcp"
                )
        
        # 检查 dialer_proxy
        if hasattr(node, 'dialer_proxy') and node.dialer_proxy:
            if not global_features.get("dialer_proxy", False):
                result.add_warning(
                    WarningLevel.INFO,
                    f"Dialer proxy is not supported by {self.platform}, will be ignored",
                    field="dialer_proxy"
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

