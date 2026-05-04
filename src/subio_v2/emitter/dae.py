"""
dae emitter

输出 dae `node { ... }` 块所需的 `'name': 'link'` 列表，以及
dae 订阅文件所需的纯文本 URL 列表（每行一条）。

dae dialer chain 支持：当节点的 `dialer_proxy` 指向同一 emit 列表中
的另一节点时，输出 `'name': 'link -> dialer_link'`；否则降级为单节点
链接并发出 warning。
"""

from typing import List, Dict
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter import link
from subio_v2.model.nodes import Node
from subio_v2.utils.logger import logger


class DaeEmitter(BaseEmitter):
    platform = "dae"

    def emit(self, nodes: List[Node]) -> str:
        supported_nodes, _ = self.emit_with_check(nodes)

        # Build name -> link map for dialer chain resolution
        link_by_name: Dict[str, str] = {}
        for node in supported_nodes:
            url = link.build_url(node)
            if url:
                link_by_name[node.name] = url

        lines: List[str] = []
        for node in supported_nodes:
            url = link_by_name.get(node.name)
            if not url:
                continue

            chain_url = self._build_chain_url(node, url, link_by_name)
            lines.append(f"'{node.name}': '{chain_url}'")

        return "\n".join(lines)

    def emit_subscription(self, nodes: List[Node]) -> str:
        """纯文本订阅：每行一条 URL（不做 base64）。"""
        supported_nodes, _ = self.emit_with_check(nodes)

        link_by_name: Dict[str, str] = {}
        for node in supported_nodes:
            url = link.build_url(node)
            if url:
                link_by_name[node.name] = url

        lines: List[str] = []
        for node in supported_nodes:
            url = link_by_name.get(node.name)
            if not url:
                continue
            chain_url = self._build_chain_url(node, url, link_by_name)
            lines.append(chain_url)

        return "\n".join(lines)

    def _build_chain_url(
        self, node: Node, url: str, link_by_name: Dict[str, str]
    ) -> str:
        """Append dialer chain (`-> dialer_link`) when dialer_proxy resolves."""
        dialer_name = getattr(node, "dialer_proxy", None)
        if not dialer_name:
            return url

        dialer_url = link_by_name.get(dialer_name)
        if not dialer_url:
            logger.warning(
                f"[dae] Node '{node.name}' references unknown dialer_proxy "
                f"'{dialer_name}', emitting without chain"
            )
            return url

        return f"{url} -> {dialer_url}"
