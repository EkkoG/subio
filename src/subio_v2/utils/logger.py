from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
import logging

# Custom theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "highlight": "magenta",
    "dim": "dim"
})

console = Console(theme=custom_theme)

class Logger:
    def __init__(self):
        self.console = console

    def info(self, message: str):
        self.console.print(f"[info]INFO[/info]: {message}")

    def success(self, message: str):
        self.console.print(f"[success]SUCCESS[/success]: {message}")

    def warning(self, message: str):
        self.console.print(f"[warning]WARNING[/warning]: {message}")

    def error(self, message: str):
        self.console.print(f"[error]ERROR[/error]: {message}")
    
    def step(self, message: str):
        self.console.print(f"[bold blue]==>[/bold blue] {message}")
        
    def dim(self, message: str):
        self.console.print(f"[dim]{message}[/dim]")

    def status(self, message: str):
        return self.console.status(message, spinner="dots")

logger = Logger()

