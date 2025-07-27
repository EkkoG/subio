"""Configuration models for SubIO2."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class RenameRule:
    """Node rename rule."""
    add_prefix: Optional[str] = None
    add_suffix: Optional[str] = None
    replace: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Provider:
    """Provider configuration."""
    name: str
    type: str
    url: Optional[str] = None
    file: Optional[str] = None
    privacy_endpoint: Optional[str] = None
    dialer_proxy: Optional[str] = None
    rename: Optional[RenameRule] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UploaderConfig:
    """Uploader configuration."""
    name: str
    type: str
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UploadTarget:
    """Upload target for artifact."""
    to: str
    file_name: Optional[str] = None


@dataclass
class Artifact:
    """Artifact configuration."""
    name: str
    type: str
    template: str
    providers: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    upload: List[UploadTarget] = field(default_factory=list)
    filters: Optional[Dict[str, str]] = None  # Support artifact-level filters


@dataclass
class Ruleset:
    """Ruleset configuration."""
    name: str
    url: str
    type: Optional[str] = None


@dataclass
class FilterConfig:
    """Filter configuration."""
    include: Optional[str] = None
    exclude: Optional[str] = None


@dataclass
class Options:
    """Global options."""
    work_filter: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    """Main configuration."""
    log_level: str = "INFO"
    options: Optional[Options] = None
    filter: Optional[FilterConfig] = None
    uploaders: List[UploaderConfig] = field(default_factory=list)
    providers: List[Provider] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    rulesets: List[Ruleset] = field(default_factory=list)