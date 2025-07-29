"""SubIO2 - A modular and extensible subscription converter."""

__version__ = "0.2.0"

# Import modules to trigger registration
from . import parsers  # noqa: F401
from . import renderers  # noqa: F401
from . import filters  # noqa: F401
from . import uploaders  # noqa: F401
