from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping

from subio_v2.surge.syntax import SurgeParameters, SurgeProxyRecord


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
class SurgeOpaquePolicy:
    record: SurgeProxyRecord = field(repr=False)
    order: int = 0
    associated_section: tuple[str, str] | None = None
    source_kind: str = "unknown"

    @property
    def name(self) -> str:
        return self.record.name


@dataclass
class SurgeExternalPolicy:
    record: SurgeProxyRecord = field(repr=False)
    order: int = 0
    source_kind: str = "unknown"
    authorized: bool = False

    @property
    def name(self) -> str:
        return self.record.name


@dataclass
class SurgeDocumentResources(Mapping[str, Any]):
    keystore: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    keystore_tokens: dict[str, SurgeParameters] = field(
        default_factory=dict, repr=False
    )
    named_sections: dict[tuple[str, str], SurgeNamedSection] = field(
        default_factory=dict, repr=False
    )
    policies: list[SurgeOpaquePolicy] = field(default_factory=list, repr=False)
    external_policies: list[SurgeExternalPolicy] = field(
        default_factory=list, repr=False
    )

    def __getitem__(self, key: str) -> Any:
        if key == "keystore":
            return self.keystore
        if key == "surge":
            return self
        if key == "named_sections":
            return self.named_sections
        if key == "policies":
            return self.policies
        if key == "external_policies":
            return self.external_policies
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(
            ("keystore", "surge", "named_sections", "policies", "external_policies")
        )

    def __len__(self) -> int:
        return 5

    def clone(self) -> "SurgeDocumentResources":
        return copy.deepcopy(self)

    def merge(self, other: "SurgeDocumentResources") -> None:
        for key_id, entry in other.keystore.items():
            existing = self.keystore.get(key_id)
            if existing is not None and existing != entry:
                raise ValueError(f"conflicting Surge keystore entry '{key_id}'")
            self.keystore[key_id] = copy.deepcopy(entry)
            if key_id in other.keystore_tokens:
                self.keystore_tokens[key_id] = copy.deepcopy(
                    other.keystore_tokens[key_id]
                )

        for key, section in other.named_sections.items():
            existing = self.named_sections.get(key)
            if existing is not None and existing.lines != section.lines:
                kind, name = key
                raise ValueError(f"conflicting Surge {kind} section '{name}'")
            if existing is None:
                self.named_sections[key] = copy.deepcopy(section)

        existing_policies = {
            policy.name: policy for policy in [*self.policies, *self.external_policies]
        }
        for policy in [*other.policies, *other.external_policies]:
            existing = existing_policies.get(policy.name)
            if existing is not None:
                same_kind = type(existing) is type(policy)
                same_record = existing.record == policy.record
                same_section = getattr(existing, "associated_section", None) == getattr(
                    policy, "associated_section", None
                )
                if not (same_kind and same_record and same_section):
                    raise ValueError(
                        f"conflicting Surge document policy '{policy.name}'"
                    )
                continue
            copied = copy.deepcopy(policy)
            if isinstance(copied, SurgeExternalPolicy):
                self.external_policies.append(copied)
            else:
                self.policies.append(copied)
            existing_policies[copied.name] = copied


def coerce_surge_resources(resources: Any) -> SurgeDocumentResources:
    if isinstance(resources, SurgeDocumentResources):
        return resources.clone()
    if isinstance(resources, Mapping):
        surge = resources.get("surge")
        if isinstance(surge, SurgeDocumentResources):
            return surge.clone()
        keystore = resources.get("keystore", {})
        if isinstance(keystore, dict):
            return SurgeDocumentResources(keystore=copy.deepcopy(keystore))
    return SurgeDocumentResources()
