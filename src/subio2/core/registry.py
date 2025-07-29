"""Plugin registry for dynamic loading and management."""

from typing import Dict, Type, TypeVar, Generic, Optional
from .interfaces import Parser, Renderer, Filter, Uploader

T = TypeVar("T")


class Registry(Generic[T]):
    """Generic registry for managing plugins."""

    def __init__(self):
        self._items: Dict[str, Type[T]] = {}

    def register(self, name: str, item_class: Type[T]) -> None:
        """Register a new item."""
        if name in self._items:
            raise ValueError(f"Item '{name}' is already registered")
        self._items[name] = item_class

    def get(self, name: str) -> Optional[Type[T]]:
        """Get a registered item by name."""
        return self._items.get(name)

    def create(self, name: str, *args, **kwargs) -> Optional[T]:
        """Create an instance of a registered item."""
        item_class = self.get(name)
        if item_class:
            return item_class(*args, **kwargs)
        return None

    def list(self) -> list[str]:
        """List all registered items."""
        return list(self._items.keys())

    def decorator(self, name: str):
        """Decorator for registering items."""

        def wrapper(cls: Type[T]) -> Type[T]:
            self.register(name, cls)
            return cls

        return wrapper


# Global registries
parser_registry = Registry[Parser]()
renderer_registry = Registry[Renderer]()
filter_registry = Registry[Filter]()
uploader_registry = Registry[Uploader]()
