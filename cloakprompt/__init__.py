"""
CloakPrompt - Secure text redaction for LLM interactions.

A command-line tool for redacting sensitive information from text before sending to LLMs.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from importlib.metadata import version, PackageNotFoundError
else:
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:
        from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version("cloakprompt")
except PackageNotFoundError:
    __version__ = "0.1.2"  # Fallback version

__author__ = "Kushagra Tandon"
__description__ = "Secure text redaction for LLM interactions"

from .core.parser import ConfigParser
from .core.redactor import TextRedactor
from .utils.file_loader import InputLoader

__all__ = [
    "ConfigParser",
    "TextRedactor",
    "InputLoader",
    "__version__",
    "__author__",
    "__description__"
]
