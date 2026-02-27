"""justdastit - Plugin system base class and auto-discovery."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.engine import HttpEngine
    from ..core.models import Finding, HttpRequest, HttpResponse

__all__ = ["ScanPlugin", "load_plugins"]


class ScanPlugin(ABC):
    """Base class for scan plugins.

    Plugins can implement passive checks (analyze existing responses)
    and/or active checks (send additional requests to test for vulns).
    """

    name: str = "unnamed_plugin"
    description: str = ""
    author: str = ""
    version: str = "1.0"

    def passive_check(
        self, req: "HttpRequest", resp: "HttpResponse"
    ) -> list["Finding"]:
        """Analyze a request/response pair for issues. Override to implement."""
        return []

    async def active_check(
        self, req: "HttpRequest", engine: "HttpEngine"
    ) -> list["Finding"]:
        """Send additional requests to test for vulnerabilities. Override to implement."""
        return []


def load_plugins(plugin_dir: str | Path | None = None) -> list[ScanPlugin]:
    """Auto-discover and load plugins from a directory.

    Looks for Python files containing classes that inherit from ScanPlugin.
    """
    plugins: list[ScanPlugin] = []

    # Default: look in the plugins directory next to this file
    if plugin_dir is None:
        plugin_dir = Path(__file__).parent

    plugin_path = Path(plugin_dir)
    if not plugin_path.exists():
        return plugins

    for py_file in sorted(plugin_path.glob("*.py")):
        if py_file.name.startswith("_") or py_file.name == "base.py":
            continue

        module_name = f"justdastit.plugins.{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScanPlugin)
                        and attr is not ScanPlugin
                    ):
                        plugins.append(attr())
        except Exception:
            continue

    return plugins
