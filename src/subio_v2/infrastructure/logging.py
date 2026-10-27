from contextlib import contextmanager
from datetime import datetime, timezone

from rich.console import Console
from rich.theme import Theme

# Custom theme
custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "highlight": "magenta",
        "dim": "dim",
    }
)


class _SilentStatus:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def update(self, message: str):
        return None

console = Console(theme=custom_theme)
LOG_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}


class Logger:
    def __init__(self, *, timestamps: bool = False):
        self.console = console
        self._quiet = False
        self._level = LOG_LEVELS["info"]
        self._timestamps = timestamps

    @contextmanager
    def at_level(self, level: str):
        previous = self._level
        self._level = LOG_LEVELS[level]
        try:
            yield
        finally:
            self._level = previous

    def _enabled(self, level: str) -> bool:
        return not self._quiet and LOG_LEVELS[level] >= self._level

    def _emit(self, level: str, label: str, style: str, message: str):
        if self._enabled(level):
            prefix = datetime.now(timezone.utc).isoformat(timespec="seconds") + " " if self._timestamps else ""
            self.console.print(f"{prefix}[{style}]{label}[/{style}]: {message}")

    @contextmanager
    def silenced(self):
        previous = self._quiet
        self._quiet = True
        try:
            yield
        finally:
            self._quiet = previous

    def info(self, message: str):
        self._emit("info", "INFO", "info", message)

    def debug(self, message: str):
        self._emit("debug", "DEBUG", "dim", message)

    def success(self, message: str):
        self._emit("info", "SUCCESS", "success", message)

    def warning(self, message: str):
        self._emit("warning", "WARNING", "warning", message)

    def error(self, message: str):
        self._emit("error", "ERROR", "error", message)

    def critical(self, message: str):
        self._emit("critical", "CRITICAL", "error", message)

    def step(self, message: str):
        if not self._enabled("info"):
            return
        self.console.print(f"[bold blue]==>[/bold blue] {message}")

    def dim(self, message: str):
        if not self._enabled("info"):
            return
        self.console.print(f"[dim]{message}[/dim]")

    def status(self, message: str):
        if not self._enabled("info"):
            return _SilentStatus()
        return self.console.status(message, spinner="dots")


logger = Logger()
