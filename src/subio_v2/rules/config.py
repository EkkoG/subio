from dataclasses import dataclass


@dataclass(frozen=True)
class RuleSetConfig:
    name: str
    url: str
    dialect: str = "mihomo"
    behavior: str = "classical"
    format: str = "text"
    user_agent: str | None = None
