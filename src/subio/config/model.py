from dataclasses import dataclass
from typing import List
from subio.const import SubIOPlatform


@dataclass
class Replace:
    old: str
    new: str


@dataclass
class Rename:
    add_prefix: str | None
    add_suffix: str | None
    replace: List[Replace] | None


@dataclass
class ArtifactUpload:
    to: str
    file_name: str | None


@dataclass
class Artifact:
    name: str
    providers: List[str]
    template: str
    type: str
    upload: List[ArtifactUpload] | None
    options: dict | None
    filters: dict | None

    def _type(self):
        return SubIOPlatform(self.type)


@dataclass
class Provider:
    name: str
    type: SubIOPlatform
    url: str | None
    file: str | None
    user_agent: str | None
    rename: Rename | None


@dataclass
class Ruleset:
    name: str
    url: str
    user_agent: str | None


@dataclass
class Uploader:
    id: str
    name: str
    token: str
    type: str


@dataclass
class Config:
    log_level: str
    artifact: List[Artifact]
    provider: List[Provider]
    ruleset: List[Ruleset] | None
    uploader: List[Uploader] | None
    options: dict | None
    filters: dict | None
