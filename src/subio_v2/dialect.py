from dataclasses import dataclass


@dataclass(frozen=True)
class DialectContext:
    """Describe the source or target dialect at a conversion boundary."""

    dialect: str
    format: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.dialect, str) or not self.dialect:
            raise ValueError("Dialect name must be a non-empty string")
        if self.format is not None and (
            not isinstance(self.format, str) or not self.format
        ):
            raise ValueError("Dialect format must be a non-empty string")
        if self.version is not None and (
            not isinstance(self.version, str) or not self.version
        ):
            raise ValueError("Dialect version must be a non-empty string")
