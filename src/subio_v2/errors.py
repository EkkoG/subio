from typing import Iterable

from subio_v2.conversion import ConversionIssue


class WorkflowError(Exception):
    """Base error for failures that must abort a workflow run."""


class ConfigError(WorkflowError):
    pass


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
