"""
Platform Capabilities Module

定义和检查各平台对代理协议的支持情况
"""

from .definitions import PLATFORM_CAPABILITIES, get_platform_capabilities
from .checker import CapabilityChecker, check_node_for_platform

__all__ = [
    "PLATFORM_CAPABILITIES",
    "get_platform_capabilities",
    "CapabilityChecker",
    "check_node_for_platform",
]

