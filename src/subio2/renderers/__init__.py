"""SubIO2 renderers with new architecture."""

# Import all renderers to trigger registration
from .clash import ClashRenderer
from .v2rayn import V2rayNRenderer
from .surge import SurgeRenderer
from .dae import DAERenderer
from .stash import StashRenderer

__all__ = [
    "ClashRenderer",
    "V2rayNRenderer",
    "SurgeRenderer",
    "DAERenderer",
    "StashRenderer",
]
