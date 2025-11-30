from abc import ABC, abstractmethod
from typing import List, Any, Optional, Tuple
from subio_v2.model.nodes import Node
from subio_v2.capabilities.checker import CapabilityChecker, CheckResult, WarningLevel
from subio_v2.utils.logger import logger


class BaseEmitter(ABC):
    """
    Base class for all emitters.
    
    Subclasses should:
    1. Set `platform` class attribute to the platform name
    2. Implement `_emit_node()` to emit a single node
    3. Implement `emit()` to emit all nodes (can use `emit_with_check()` helper)
    """
    
    platform: str = ""  # Subclass should override this
    
    def __init__(self):
        self._checker: Optional[CapabilityChecker] = None
        if self.platform:
            try:
                self._checker = CapabilityChecker(self.platform)
            except ValueError:
                logger.warning(f"Unknown platform '{self.platform}', capability checking disabled")
    
    @abstractmethod
    def emit(self, nodes: List[Node]) -> Any:
        """
        Emit nodes to a specific format.
        Returns dict (for structure) or str (for text).
        """
        pass
    
    def check_node(self, node: Node) -> CheckResult:
        """
        Check if a node is supported by the target platform.
        
        Returns:
            CheckResult with supported status and warnings
        """
        if not self._checker:
            # No checker available, assume supported
            return CheckResult(supported=True)
        return self._checker.check_node(node)
    
    def emit_with_check(self, nodes: List[Node]) -> Tuple[List[Node], List[Tuple[Node, CheckResult]]]:
        """
        Filter nodes by capability check and return supported nodes with warnings.
        
        Returns:
            Tuple of (supported_nodes, list of (node, check_result) for unsupported/warned nodes)
        """
        supported_nodes = []
        issues = []
        
        for node in nodes:
            result = self.check_node(node)
            
            if result.supported:
                supported_nodes.append(node)
                # Log warnings for supported nodes
                if result.has_warnings():
                    for warning in result.warnings:
                        if warning.level == WarningLevel.WARNING:
                            logger.warning(
                                f"[{self.platform}] Node '{node.name}': {warning.message}"
                                + (f" ({warning.suggestion})" if warning.suggestion else "")
                            )
                        elif warning.level == WarningLevel.INFO:
                            logger.debug(
                                f"[{self.platform}] Node '{node.name}': {warning.message}"
                            )
            else:
                # Log errors for unsupported nodes
                issues.append((node, result))
                for warning in result.warnings:
                    if warning.level == WarningLevel.ERROR:
                        logger.warning(
                            f"[{self.platform}] Node '{node.name}' skipped: {warning.message}"
                            + (f" ({warning.suggestion})" if warning.suggestion else "")
                        )
        
        return supported_nodes, issues
