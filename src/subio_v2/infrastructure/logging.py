from contextlib import contextmanager

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


class Logger:
    def __init__(self):
        self.console = console
        self._quiet = False

    @contextmanager
    def silenced(self):
        previous = self._quiet
        self._quiet = True
        try:
            yield
        finally:
            self._quiet = previous

    def info(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[info]INFO[/info]: {message}")

    def success(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[success]SUCCESS[/success]: {message}")

    def warning(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[warning]WARNING[/warning]: {message}")

    def error(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[error]ERROR[/error]: {message}")

    def step(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[bold blue]==>[/bold blue] {message}")

    def dim(self, message: str):
        if self._quiet:
            return
        self.console.print(f"[dim]{message}[/dim]")

    def status(self, message: str):
        if self._quiet:
            return _SilentStatus()
        return self.console.status(message, spinner="dots")


logger = Logger()
