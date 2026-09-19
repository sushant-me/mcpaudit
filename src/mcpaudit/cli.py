"""The command line: `mcpaudit audit [source]`.

    mcpaudit audit tools.json                 # read a saved tools/list payload
    mcp-client --list | mcpaudit audit -       # or pipe one straight in
    mcpaudit audit tools.json --write-lock mcpaudit.lock.json
    mcpaudit audit tools.json --lock mcpaudit.lock.json   # fail if anything changed

Exit codes are the interface for CI: ``0`` clean, ``1`` findings at or above
``--fail-on`` (or drift against a lock file), ``2`` the input could not be read. A tool
whose exit code means "probably fine" gets wired into a pipeline and then ignored.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import SEVERITY_ORDER, audit, extract_tools
from .lockfile import compare_lock, load_lock, write_lock

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_COLOURS = {
    "critical": "\033[1;41;97m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[90m",
}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def _read_source(source: str) -> Any:
    if source == "-":
        text = sys.stdin.read()
    else:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"no such file: {path}")
        text = path.read_text(encoding="utf-8")
    return json.loads(text)


def _severity_label(severity: str, colour: bool) -> str:
    if not colour:
        return severity.upper().ljust(8)
    return f"{_COLOURS.get(severity, '')}{severity.upper().ljust(8)}{_RESET}"


def _render_text(result, drift, colour: bool) -> str:
    lines: list[str] = []
    counts = result.counts()
    lines.append(f"{_BOLD if colour else ''}mcpaudit — {counts['tools']} tool(s) examined{_RESET if colour else ''}")
    lines.append("")

    if result.findings:
        for finding in result.findings:
            label = _severity_label(finding.severity, colour)
            lines.append(f"{label} [{finding.rule}] {finding.tool}")
            lines.append(f"         {finding.message}")
            if finding.evidence:
                lines.append(f"         {_DIM if colour else ''}evidence: {finding.evidence}{_RESET if colour else ''}")
            if finding.remediation:
                lines.append(f"         fix: {finding.remediation}")
            lines.append("")
    else:
        lines.append("no findings")
        lines.append("")

    if drift:
        lines.append(f"{_BOLD if colour else ''}changes since the lock file was written{_RESET if colour else ''}")
        for item in drift:
            lines.append(f"{_severity_label(item.severity, colour)} [{item.kind}] {item.tool}")
            lines.append(f"         {item.detail}")
        lines.append("")

    summary = ", ".join(
        f"{severity} {counts[severity]}" for severity in SEVERITY_ORDER if counts[severity]
    ) or "none"
    lines.append(f"findings: {summary}   worst: {result.worst() or 'none'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpaudit",
        description="Audit an MCP server's tool declarations before you connect to it.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit_parser = sub.add_parser("audit", help="audit a tools/list payload")
    audit_parser.add_argument(
        "source",
        help="path to a JSON payload containing the tool list, or '-' to read stdin",
    )
    audit_parser.add_argument("--json", action="store_true", help="machine-readable output")
    audit_parser.add_argument(
        "--fail-on", default="high", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
        help="exit non-zero when a finding at or above this severity is present (default: high)",
    )
    audit_parser.add_argument("--lock", help="compare against a lock file and report drift")
    audit_parser.add_argument("--write-lock", metavar="PATH", help="record this server's declarations")
    audit_parser.add_argument("--server", default="", help="a label for the lock file")
    audit_parser.add_argument("--no-colour", action="store_true", help="plain output")
    args = parser.parse_args(argv)

    try:
        payload = _read_source(args.source)
        tools = extract_tools(payload)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"mcpaudit: could not read the tool list: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = audit(tools)

    drift = []
    if args.lock:
        try:
            drift = compare_lock(load_lock(args.lock), tools)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            print(f"mcpaudit: could not read the lock file: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if args.write_lock:
        try:
            write_lock(args.write_lock, tools, server=args.server)
        except OSError as exc:
            print(f"mcpaudit: could not write the lock file: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"wrote {args.write_lock} ({len(tools)} tool(s) recorded)", file=sys.stderr)

    colour = not args.no_colour and sys.stdout.isatty()
    if args.json:
        print(json.dumps({**result.to_dict(), "drift": [d.to_dict() for d in drift]}, indent=2))
    else:
        print(_render_text(result, drift, colour))

    threshold = SEVERITY_ORDER[args.fail_on]
    blocking = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold]
    blocking += [d for d in drift if SEVERITY_ORDER[d.severity] <= threshold]
    return EXIT_FINDINGS if blocking else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
