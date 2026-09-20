"""Audit an MCP server's tool declarations before you connect to it.

Tool descriptions are not documentation: they are injected into the model's context, so a
description can carry instructions. This package reads the declaration a client receives
from `tools/list` and reports what a reviewer needs to see — reserved-name collisions,
instruction-shaped text, invisible characters, look-alike names, missing read/write
annotations, unconstrained sink parameters — and it can pin the declarations so a later
change is visible instead of silent.

It is a static review of what a server declares. It is not a behavioural test, and the
README states that plainly rather than letting a clean report read as a clean server.
"""

from .checks import Finding, AuditResult, audit, extract_tools
from .lockfile import Drift, build_lock, compare_lock, fingerprint_tool, load_lock, write_lock

__all__ = [
    "AuditResult",
    "Drift",
    "Finding",
    "audit",
    "build_lock",
    "compare_lock",
    "extract_tools",
    "fingerprint_tool",
    "load_lock",
    "write_lock",
]

__version__ = "0.1.1"
