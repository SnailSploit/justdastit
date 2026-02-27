"""Plugin system for custom scan checks."""

from .base import ScanPlugin, load_plugins

__all__ = ["ScanPlugin", "load_plugins"]
