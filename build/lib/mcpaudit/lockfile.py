"""Pinning a server's declarations so a later change is visible.

The attack this exists for is simple and needs no exploit: you review a server, approve
it, and later the server changes a tool's **description** — or adds a parameter, or adds
a whole tool. Nothing asks you again. The model sees the new text; you saw the old one.
It is the tool-poisoning/rug-pull shape, and the only defence at the client is to have
recorded what you approved.

So `write_lock` records a fingerprint of every tool's declarations and `compare_lock`
reports exactly what changed. A changed *description* is treated as seriously as a
changed schema, because the description is what the model reads as instruction.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

LOCK_VERSION = 1

#: Drift kinds, and how much each one matters.
DRIFT_SEVERITY = {
    "tool-added": "medium",
    "tool-removed": "high",
    "description-changed": "high",
    "schema-changed": "high",
    "annotations-changed": "medium",
    "declaration-changed": "medium",
}


def _hash(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def fingerprint_tool(tool: dict[str, Any]) -> dict[str, str]:
    """Per-field hashes, so drift can say *which* field changed rather than 'it changed'."""
    name = str(tool.get("name", ""))
    description = str(tool.get("description", ""))
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    annotations = tool.get("annotations") or {}
    return {
        "fingerprint": _hash([name, description, schema, annotations]),
        "name_hash": _hash(name),
        "description_hash": _hash(description),
        "schema_hash": _hash(schema),
        "annotations_hash": _hash(annotations),
    }


def build_lock(tools: list[dict[str, Any]], server: str = "") -> dict[str, Any]:
    return {
        "version": LOCK_VERSION,
        "generated_at": round(time.time(), 3),
        "server": server,
        "tools": {
            str(tool.get("name", "")): fingerprint_tool(tool) for tool in tools
        },
    }


def write_lock(path: str | Path, tools: list[dict[str, Any]], server: str = "") -> dict[str, Any]:
    lock = build_lock(tools, server=server)
    Path(path).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def load_lock(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("version") != LOCK_VERSION:
        raise ValueError(
            f"lock file version {payload.get('version')!r} is not {LOCK_VERSION}; "
            "regenerate it with --write-lock after reviewing the server again"
        )
    if not isinstance(payload.get("tools"), dict):
        raise ValueError("lock file has no 'tools' mapping")
    return payload


@dataclass(frozen=True)
class Drift:
    kind: str
    tool: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compare_lock(lock: dict[str, Any], tools: list[dict[str, Any]]) -> list[Drift]:
    """What changed since the lock was written, worst first."""
    recorded: dict[str, dict[str, str]] = lock.get("tools", {})
    current = {str(tool.get("name", "")): fingerprint_tool(tool) for tool in tools}

    drift: list[Drift] = []
    for name in sorted(set(recorded) - set(current)):
        drift.append(Drift("tool-removed", name, DRIFT_SEVERITY["tool-removed"],
                           "the tool is gone from the server"))
    for name in sorted(set(current) - set(recorded)):
        drift.append(Drift("tool-added", name, DRIFT_SEVERITY["tool-added"],
                           "the tool was not present when this server was reviewed"))

    for name in sorted(set(recorded) & set(current)):
        before, after = recorded[name], current[name]
        if before.get("description_hash") != after.get("description_hash"):
            drift.append(Drift(
                "description-changed", name, DRIFT_SEVERITY["description-changed"],
                "the description changed, and the description is what the model reads as "
                "instruction — this is the tool-poisoning shape",
            ))
        if before.get("schema_hash") != after.get("schema_hash"):
            drift.append(Drift("schema-changed", name, DRIFT_SEVERITY["schema-changed"],
                               "the input schema changed: new or altered parameters"))
        if before.get("annotations_hash") != after.get("annotations_hash"):
            drift.append(Drift("annotations-changed", name, DRIFT_SEVERITY["annotations-changed"],
                               "the read/write annotations changed"))
        if (before.get("fingerprint") != after.get("fingerprint")
                and before.get("description_hash") == after.get("description_hash")
                and before.get("schema_hash") == after.get("schema_hash")
                and before.get("annotations_hash") == after.get("annotations_hash")):
            drift.append(Drift("declaration-changed", name, DRIFT_SEVERITY["declaration-changed"],
                               "the tool's declaration changed in a field this tool does not track"))

    drift.sort(key=lambda d: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[d.severity], d.tool))
    return drift
