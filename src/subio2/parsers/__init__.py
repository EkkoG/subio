"""SubIO2 parsers with new architecture."""

# Import all parsers to trigger registration
from .clash import ClashParser
from .v2rayn import V2rayNParser
from .surge import SurgeParser
from .subio import SubIOParser

__all__ = ['ClashParser', 'V2rayNParser', 'SurgeParser', 'SubIOParser']