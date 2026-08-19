"""
Platform Capabilities Module

定义和检查各平台对代理协议的支持情况
"""

from .checker import CapabilityChecker, check_node_for_platform
from .definitions import all_platform_capabilities, get_platform_capabilities

__all__ = [
    "all_platform_capabilities",
    "get_platform_capabilities",
    "CapabilityChecker",
    "check_node_for_platform",
]
