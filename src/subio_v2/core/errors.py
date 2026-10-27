from typing import Iterable

from subio_v2.core.results import ConversionIssue


class WorkflowError(Exception):
    """Base error for failures that must abort a workflow run."""


class ConfigError(WorkflowError):
    pass


class ConfigParseError(ConfigError):
    """Configuration syntax failure with safe source location metadata."""

    def __init__(
        self, message: str, *, line: int | None = None, column: int | None = None
    ) -> None:
        super().__init__(message)
        self.line = line if type(line) is int and line > 0 else None
        self.column = column if type(column) is int and column > 0 else None


class ProviderLoadError(WorkflowError):
    pass


class ArtifactGenerationError(WorkflowError):
    def __init__(
        self, message: str, issues: Iterable[ConversionIssue] | None = None
    ) -> None:
        super().__init__(message)
        self.issues = tuple(issues or ())


class TemplateRenderError(ArtifactGenerationError):
    pass


class UploadError(WorkflowError):
    pass
