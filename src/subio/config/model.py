
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Replace:
    old: str
    new: str

@dataclass
class Rename:
    add_prefix: Optional[str] = None
    add_suffix: Optional[str] = None
    replace: Optional[List[Replace]] = None


@dataclass
class ArtifactUpload:
    to: str
    file_name: Optional[str] = None

@dataclass
class Artifact:
    name: str
    providers: List[str]
    template: str
    type: str
    upload: Optional[List[ArtifactUpload]] = None
    options: Optional[dict] = None

@dataclass
class Provider:
    name: str
    type: str
    url: Optional[str] = None
    file: Optional[str] = None
    user_agent: Optional[str] = None
    rename: Optional[Rename] = None

@dataclass
class Ruleset:
    name: str
    url: str
    user_agent: Optional[str] = None

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
    ruleset: Optional[List[Ruleset]] = None
    uploader: Optional[List[Uploader]] = None
    options: Optional[dict] = None



