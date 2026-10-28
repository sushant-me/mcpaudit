"""The checks. Each one answers a question about what a server *declares*.

Everything here reads a tool list — the JSON an MCP client receives from `tools/list` —
and reports what is wrong with the declarations. It is a static review of a declaration,
not a behavioural test of a server, and the README says so in those words.

Every finding carries the rule that produced it, a severity, the tool it concerns, the
evidence, and what to do. A finding a reader cannot act on is noise, and noise is how a
real finding gets ignored.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .unicode_scan import find_confusables, find_invisible, skeleton

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Tool names agent frameworks install outside the normal tool table. Mirrors
#: `policygate.adapters.mcp.RESERVED_TOOL_NAMES`; duplicated rather than imported so this
#: package stays dependency-free and can be piped into any environment.
RESERVED_TOOL_NAMES = frozenset({
    "finish", "set_model_response", "transfer_to_agent", "task_completed",
    "google_search", "google_maps", "google_maps_grounding", "url_context",
    "code_execution", "vertex_ai_search", "load_artifacts", "load_memory",
    "list_skills", "load_skill", "load_skill_resource", "exit_loop",
})

#: Phrases that have no business in a tool description. They are not proof of an attack —
#: a description can quote them — but each one is evidence a reviewer should see, and the
#: finding quotes the match so the judgement stays with the human.
INSTRUCTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
     "instruction override"),
    (r"(?i)disregard\s+(the\s+)?(system|previous|above)", "instruction override"),
    (r"(?i)do\s+not\s+(tell|mention|inform|notify|reveal)", "instruction to conceal"),
    (r"(?i)without\s+(asking|confirming|informing|telling)", "instruction to skip confirmation"),
    (r"(?i)(system|developer)\s+prompt", "references the system prompt"),
    (r"(?i)you\s+must\s+(always|never)", "imperative instruction"),
    (r"(?i)before\s+(answering|responding|replying)", "behavioural precondition"),
    (r"(?i)\b(exfiltrate|exfil|leak|steal)\b", "exfiltration language"),
    (r"(?i)(ssh\s+key|id_rsa|\.env\b|credentials?\b|api[_\s-]?key)", "credential target"),
    (r"(?i)\bbase64\b|\brot13\b|\bhex[- ]?decode", "encoding instruction"),
    (r"(?i)\bcurl\b|\bwget\b|\bfetch\s+https?://", "network fetch instruction"),
    (r"(?i)(/etc/sudoers|/etc/shadow|rm\s+-rf\s+/|chmod\s+777)", "destructive command"),
)

#: Parameter names where a free-form string is a genuine hazard: it reaches a shell, an
#: interpreter, a query engine or the filesystem.
EXECUTION_SINKS = frozenset({
    "command", "cmd", "shell", "script", "code", "exec", "eval", "sql",
    "path", "file", "filename", "filepath", "dir", "directory",
})

#: Parameter names worth a second look but routinely legitimate — a URL parameter on a
#: fetcher, a recipient on a mail tool. Reported at low severity, on purpose: a linter
#: that fires on a docs search's `query` parameter is a linter people turn off. My first
#: version of this file listed `query` as a sink and flagged a read-only search tool.
BROAD_SINKS = frozenset({
    "url", "uri", "endpoint", "host", "target", "destination", "recipient", "address",
})

#: Words that suggest a tool changes state or leaves the machine. If a tool looks like
#: this and declares no annotations, that is worth a conversation.
#:
#: Matched on whole tokens, never as substrings — see `_mentions_mutation`. `"run"` is
#: deliberately absent: it is a generic verb (you run queries, reports and diagnostics),
#: and the tools where it does mean mutation — `run_command`, `run_shell` — are caught by
#: `unconstrained-sink-parameter`, on the parameter that makes them dangerous. `"exec"`
#: stays because it appears in names that execute something.
DESTRUCTIVE_HINTS = (
    "delete", "drop", "remove", "destroy", "purge", "truncate", "write", "update",
    "create", "insert", "execute", "exec", "shell", "spawn", "deploy",
    "upload", "send", "post", "publish", "transfer", "pay", "refund", "grant",
)

#: Splits an identifier or a sentence into lower-case words, in order. Handles
#: snake_case, kebab-case, dotted names and plain prose, plus camelCase boundaries
#: (`deleteBudget` -> ["delete", "budget"]), which is why it is a regex rather than a
#: split on punctuation. Order matters: the convention is verb-first, so the first
#: token is the strongest evidence about what a tool does.
_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")
_MUTATION_TOKENS = frozenset(DESTRUCTIVE_HINTS)

#: A name that opens with one of these is a reader. The convention is `verb_noun`, and
#: several mutation verbs are also ordinary nouns, so `get_grant_balance`,
#: `get_transfer_history` and `list_payment_methods` are read-only tools whose names
#: contain mutation words. Token matching alone cannot tell those from `grant_access`,
#: so the prefix decides, and a description that contradicts the name still reports.
_READ_PREFIXES = frozenset({
    "get", "list", "read", "search", "fetch", "describe", "show", "view", "find",
    "query", "lookup", "check", "inspect", "preview", "scan", "count", "status",
    "explain", "summary", "report", "export", "download",
})


def _tokens(text: str) -> list[str]:
    return [match.group(0).lower() for match in _TOKEN_RE.finditer(text)]


def _mentions_mutation(name: str, description: str) -> bool:
    """Whether a name or description uses a mutation verb as a whole word.

    This was `h in name.lower()`, a substring test, and the difference is not
    academic: `get_runbook` matched `"run"`, `list_postgres_instances` matched
    `"post"`, and `get_updates` matched `"update"`, so a well-behaved server produced
    ten HIGH findings for tools that only read. A severity that fires on a
    documentation fetch is one a reader learns to ignore — the failure this module's
    own docstring already describes, arrived at from a different direction.

    Known limit: a reader-shaped name whose *description* is silent will not report a
    mutation word the name carries as a noun, so `get_delete_log` is not flagged. That
    is the precision-first direction, and it is written down rather than discovered.
    """
    name_tokens = _tokens(name)
    if name_tokens and name_tokens[0] in _READ_PREFIXES:
        # For a reader, a mutation word the name already carries is the object being
        # read, not a verb: `get_grant_balance` reads a grant, and its description
        # says "grant" too. Only a mutation word the name does *not* contain is
        # evidence that the description contradicts the name.
        return bool(set(_tokens(description)) & _MUTATION_TOKENS - set(name_tokens))
    return bool(set(name_tokens) & _MUTATION_TOKENS) or bool(
        set(_tokens(description)) & _MUTATION_TOKENS)


@dataclass
class Finding:
    rule: str
    severity: str
    tool: str
    message: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    tools: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def at_or_above(self, severity: str) -> list[Finding]:
        threshold = SEVERITY_ORDER[severity]
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] <= threshold]

    def counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        counts["tools"] = len(self.tools)
        return counts

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": self.tools,
            "counts": self.counts(),
            "worst": self.worst(),
            "findings": [f.to_dict() for f in self.findings],
        }


# -- individual checks --------------------------------------------------------

def _texts(tool: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Every string a model may read from this tool, with where it came from."""
    yield "name", str(tool.get("name", ""))
    yield "description", str(tool.get("description", ""))
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    try:
        import json
        yield "inputSchema", json.dumps(schema, sort_keys=True, default=str)
    except (TypeError, ValueError):
        yield "inputSchema", str(schema)


def check_reserved_names(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if name in RESERVED_TOOL_NAMES:
            findings.append(Finding(
                rule="reserved-name-collision",
                severity="critical",
                tool=name,
                message=(
                    f"tool name {name!r} collides with a name the agent framework installs "
                    "outside the normal tool table"
                ),
                evidence=f"name == {name!r}, in the reserved set",
                remediation=(
                    "Rename the tool on the server. A collision here is not a duplicate-name "
                    "error: the framework primitive lives outside the tool table, so this tool "
                    "silently displaces it and wins dispatch."
                ),
            ))
    return findings


def check_duplicate_skeletons(tools: list[dict[str, Any]]) -> list[Finding]:
    """Two names that fold to the same ASCII are look-alikes by construction."""
    findings = []
    by_skeleton: dict[str, list[str]] = {}
    for tool in tools:
        name = str(tool.get("name", ""))
        by_skeleton.setdefault(skeleton(name), []).append(name)
    for folded, names in by_skeleton.items():
        distinct = sorted(set(names))
        if len(distinct) > 1:
            findings.append(Finding(
                rule="look-alike-tool-names",
                severity="high",
                tool=", ".join(distinct),
                message=(
                    "two tool names normalise to the same ASCII string, so one can be "
                    "mistaken for the other"
                ),
                evidence=f"{distinct} all normalise to {folded!r}",
                remediation=(
                    "Reject or rename one of them. Look-alike names defeat an allowlist and "
                    "are indistinguishable in a model's context."
                ),
            ))
    return findings


def check_description_patterns(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        for where, text in _texts(tool):
            for pattern, label in INSTRUCTION_PATTERNS:
                match = re.search(pattern, text)
                if match:
                    findings.append(Finding(
                        rule="instruction-in-declaration",
                        severity="high",
                        tool=name,
                        message=f"{label} found in the tool {where}",
                        evidence=f"{where}: …{text[max(0, match.start()-30):match.end()+30]!r}…",
                        remediation=(
                            "A tool description is injected into the model's context, so it can "
                            "carry instructions. Remove the text, or treat the server as untrusted "
                            "and gate its calls."
                        ),
                    ))
    return findings


def check_invisible_characters(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        for where, text in _texts(tool):
            for hit in find_invisible(text):
                decoded = f" decodes to {hit.decoded!r}" if hit.decoded else ""
                findings.append(Finding(
                    rule="invisible-characters",
                    severity="high",
                    tool=name,
                    message=f"invisible characters in the tool {where}",
                    evidence=f"{where}: {hit.detail}{decoded}",
                    remediation=(
                        "Strip the characters and ask why they are there. The tag block encodes "
                        "printable ASCII, so a hidden instruction needs no visible width."
                    ),
                ))
    return findings


def check_confusables(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        hits = find_confusables(name)
        if hits:
            findings.append(Finding(
                rule="confusable-tool-name",
                severity="medium",
                tool=name,
                message="tool name contains characters that look like ASCII but are not",
                evidence="; ".join(h.detail for h in hits[:4]),
                remediation=(
                    "Use ASCII for tool names. Confusables defeat name-based allowlists; note "
                    "that this check uses a partial table, so a clean result is not proof."
                ),
            ))
    return findings


def check_destructive_annotations(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        description = str(tool.get("description", "")).lower()
        looks_destructive = _mentions_mutation(name, description)
        if not looks_destructive:
            continue
        annotations = tool.get("annotations") or {}
        read_only = annotations.get("readOnlyHint")
        destructive = annotations.get("destructiveHint")
        if read_only is True:
            findings.append(Finding(
                rule="destructive-declared-read-only",
                severity="high",
                tool=name,
                message=(
                    "tool looks state-changing but declares readOnlyHint: true, so a client "
                    "may treat it as safe"
                ),
                evidence=f"name/description suggests mutation; annotations={annotations}",
                remediation=(
                    "Correct the annotation or rename the tool. Clients use these hints to "
                    "decide whether to ask a human first."
                ),
            ))
        elif destructive is None and read_only is None:
            findings.append(Finding(
                rule="missing-annotations",
                severity="medium",
                tool=name,
                message="tool looks state-changing but declares no read/write annotations",
                evidence="neither readOnlyHint nor destructiveHint is present",
                remediation=(
                    "Declare destructiveHint (or readOnlyHint). Absent hints mean every client "
                    "guesses, and the guess is usually 'safe to run'."
                ),
            ))
    return findings


def check_sink_parameters(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        properties = schema.get("properties") or {}
        if not isinstance(properties, dict):
            continue
        for param, spec in properties.items():
            lowered = param.lower()
            if not isinstance(spec, dict):
                continue
            if lowered in EXECUTION_SINKS:
                severity, kind = "medium", "execution or filesystem"
            elif lowered in BROAD_SINKS:
                severity, kind = "low", "network or destination"
            else:
                continue
            constrained = any(
                key in spec for key in ("enum", "pattern", "const", "maximum", "maxLength")
            )
            if spec.get("type") == "string" and not constrained:
                findings.append(Finding(
                    rule="unconstrained-sink-parameter",
                    severity=severity,
                    tool=name,
                    message=(
                        f"parameter {param!r} is a free-form string reaching a {kind} sink"
                    ),
                    evidence=f"{param}: {spec}",
                    remediation=(
                        "Constrain it (enum, pattern, or a value list). An unconstrained sink "
                        "parameter is the difference between 'read a file' and 'read any file'."
                        + (" Low severity: this is often legitimate, but it is the parameter an "
                           "allowlist would need to cover." if severity == "low" else "")
                    ),
                ))
    return findings


def check_embedded_urls(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        description = str(tool.get("description", ""))
        for match in re.finditer(r"https?://[^\s'\"<>)]+", description):
            findings.append(Finding(
                rule="url-in-description",
                severity="low",
                tool=name,
                message="description contains a URL",
                evidence=match.group(0)[:120],
                remediation=(
                    "Usually documentation. Worth a look when the domain is not the vendor's: a "
                    "URL in a description is a delivery channel for content the model may fetch."
                ),
            ))
    return findings


def check_empty_descriptions(tools: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if not str(tool.get("description", "")).strip():
            findings.append(Finding(
                rule="undocumented-tool",
                severity="low",
                tool=name,
                message="tool has no description, so it cannot be reviewed before it is called",
                evidence="description is empty",
                remediation="Ask the server author for a description, or leave the tool ungated-off.",
            ))
    return findings


def check_duplicate_names(tools: list[dict[str, Any]]) -> list[Finding]:
    seen: dict[str, int] = {}
    for tool in tools:
        name = str(tool.get("name", ""))
        seen[name] = seen.get(name, 0) + 1
    return [
        Finding(
            rule="duplicate-tool-name",
            severity="high",
            tool=name,
            message=f"tool name appears {count} times in the tool list",
            evidence=f"{name} × {count}",
            remediation=(
                "A duplicate name means one definition wins and the other is unreachable — or, "
                "in a last-wins registry, that a later entry silently replaces an earlier one."
            ),
        )
        for name, count in sorted(seen.items())
        if count > 1
    ]


ALL_CHECKS = (
    check_reserved_names,
    check_duplicate_names,
    check_duplicate_skeletons,
    check_description_patterns,
    check_invisible_characters,
    check_confusables,
    check_destructive_annotations,
    check_sink_parameters,
    check_embedded_urls,
    check_empty_descriptions,
)


def audit(tools: list[dict[str, Any]]) -> AuditResult:
    """Run every check and return the findings, ordered by severity."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(tools))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.tool, f.rule))
    return AuditResult(tools=[str(t.get("name", "")) for t in tools], findings=findings)


def extract_tools(payload: Any) -> list[dict[str, Any]]:
    """Accept the shapes a tool list arrives in and return a list of tool dicts."""
    if isinstance(payload, dict):
        for key in ("tools", "result", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [t for t in value if isinstance(t, dict)]
            if isinstance(value, dict) and isinstance(value.get("tools"), list):
                return [t for t in value["tools"] if isinstance(t, dict)]
        if "name" in payload:
            return [payload]
    if isinstance(payload, list):
        return [t for t in payload if isinstance(t, dict)]
    raise ValueError("could not find a tool list in the payload")
