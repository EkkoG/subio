from __future__ import annotations

from typing import Any

from subio_v2.clash.stash import post_stash_emit
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.model.nodes import Node


class StashEmitter(ClashEmitter):
    """Internal Stash YAML emitter; exposed through EmitterFactory in stage 9."""

    def __init__(self):
        super().__init__(platform="stash")

    def _post_descriptor_emit(
        self, proxy: dict[str, Any], node: Node
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        output, dropped = super()._post_descriptor_emit(proxy, node)
        output, stash_dropped = post_stash_emit(output, node)
        return output, tuple(sorted({*dropped, *stash_dropped}))
