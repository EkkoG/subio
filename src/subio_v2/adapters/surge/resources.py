from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from subio_v2.adapters.surge.syntax import SurgeParameters


@dataclass
class SurgeKeystoreEntry:
    values: dict[str, str] = field(default_factory=dict, repr=False)
    tokens: SurgeParameters = field(default_factory=SurgeParameters, repr=False)


@dataclass
class SurgeNamedSection:
    kind: str
    name: str
    lines: tuple[str, ...] = field(default_factory=tuple, repr=False)
    order: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind.lower(), self.name)


@dataclass
class SurgeNodeAttachments:
    """Surge source data required to emit one retained node."""

    keystore: dict[str, SurgeKeystoreEntry] = field(default_factory=dict, repr=False)
    named_sections: dict[tuple[str, str], SurgeNamedSection] = field(
        default_factory=dict, repr=False
    )

    def clone(self) -> "SurgeNodeAttachments":
        return copy.deepcopy(self)

    def merge(self, other: "SurgeNodeAttachments") -> None:
        for key_id, entry in other.keystore.items():
            existing = self.keystore.get(key_id)
            if existing is not None and existing.values != entry.values:
                raise ValueError(f"conflicting Surge keystore entry '{key_id}'")
            if existing is None:
                self.keystore[key_id] = copy.deepcopy(entry)

        for key, section in other.named_sections.items():
            existing = self.named_sections.get(key)
            if existing is not None and existing.lines != section.lines:
                kind, name = key
                raise ValueError(f"conflicting Surge {kind} section '{name}'")
            if existing is None:
                self.named_sections[key] = copy.deepcopy(section)


def get_surge_node_attachments(node: Any) -> SurgeNodeAttachments:
    surge = node.source_extensions.setdefault("surge", {})
    attachments = surge.get("attachments")
    if attachments is None:
        attachments = SurgeNodeAttachments()
        surge["attachments"] = attachments
    if not isinstance(attachments, SurgeNodeAttachments):
        raise TypeError("Surge node attachments have an invalid type")
    return attachments


def peek_surge_node_attachments(node: Any) -> SurgeNodeAttachments | None:
    surge = node.source_extensions.get("surge", {})
    attachments = surge.get("attachments")
    if attachments is None:
        return None
    if not isinstance(attachments, SurgeNodeAttachments):
        raise TypeError("Surge node attachments have an invalid type")
    return attachments
