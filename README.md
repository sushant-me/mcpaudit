# mcpaudit

**Review an MCP server's tool declarations before you connect to it — and pin them, so a
later change is visible instead of silent.**

```bash
pip install -e .                                  # stdlib only
mcpaudit audit examples/tools_poisoned.json       # 11 findings, exit 1
mcpaudit audit examples/tools_clean.json          # no findings, exit 0
mcp-client --list | mcpaudit audit -              # or pipe a live tool list in
```

A tool description is not documentation. It is injected into the model's context, so it
is executable in the only sense that matters: it can carry instructions. `mcpaudit`
reads what a client receives from `tools/list` and reports what a reviewer needs to see.

## What it checks

| rule | severity | catches |
|---|---|---|
| `reserved-name-collision` | **critical** | a tool named `set_model_response`, `google_search`, `finish`… — names the framework installs *outside* the tool table, so the collision silently displaces a primitive |
| `instruction-in-declaration` | high | instruction-shaped text in a name, description or schema: *"ignore previous instructions"*, *"do not tell the user"*, *"without asking"*, credential and exfiltration language |
| `invisible-characters` | high | zero-width, bidirectional and **Unicode tag-block** characters — with the tag payload *decoded*, because that block encodes printable ASCII into text of no visible width |
| `look-alike-tool-names` | high | two names that normalise to the same ASCII (`search` / `ѕearch`) |
| `destructive-declared-read-only` | high | a tool that looks state-changing but declares `readOnlyHint: true` |
| `duplicate-tool-name` | high | the same name twice, where one definition silently wins |
| `confusable-tool-name` | medium | non-ASCII characters that look like ASCII in a name |
| `missing-annotations` | medium | a state-changing tool with no `readOnlyHint`/`destructiveHint`, so every client guesses |
| `unconstrained-sink-parameter` | medium / low | a free-form string reaching a shell, interpreter, filesystem (medium) or network destination (low), with no `enum`/`pattern` |
| `url-in-description` | low | a URL in a description: a fetch channel for content the model may read |
| `undocumented-tool` | low | no description, so it cannot be reviewed before it is called |

**It is silent on a well-behaved server** — the clean example produces zero findings, and
that is a test rather than a claim. My first version listed `query` as a sink and flagged
a read-only documentation search; a linter that fires on legitimate input is a linter
people switch off, so the sink list is split by real risk and the broad cases are low.

## The part that matters most: pinning

Reviewing a server once is not enough, because a server can change after you approve it —
a description, a new parameter, a whole new tool — and nothing asks you again. That is the
tool-poisoning/rug-pull shape, and the only client-side defence is a record of what you
approved.

```bash
mcpaudit audit tools.json --write-lock mcpaudit.lock.json   # what you reviewed
mcpaudit audit tools.json --lock mcpaudit.lock.json         # what it is now
```

```
HIGH     [description-changed] search_docs
         the description changed, and the description is what the model reads as
         instruction — this is the tool-poisoning shape
```

Per-field hashes mean drift says *which* field changed, and a changed **description** is
treated as seriously as a changed schema. An **added tool** is drift too: new capability
appearing after approval is exactly what the check is for.

## Exit codes, because this belongs in a pipeline

`0` clean · `1` findings at or above `--fail-on` (default `high`), or drift against a lock
file · `2` the input could not be read. `--json` for tooling, `--no-colour` for logs.

## What it does not do — read this before trusting a clean report

- **It reviews declarations, not behaviour.** A server can declare a perfectly clean tool
  list and do something else when called. This is a static check of the text a client
  receives; it never runs the server and cannot see what the implementation does.
- **A clean report is not a safe server.** It means no known-bad *pattern* was found in the
  declarations. Absence of evidence, stated plainly.
- **The list-based checks are partial.** The confusables table is a curated subset, not the
  full Unicode confusables data, and the instruction patterns can match a description that
  merely quotes them. Every finding quotes its evidence so the judgement stays with you.
- **It does not connect to a server.** You supply the `tools/list` JSON (or pipe it in), so
  `mcpaudit` needs no network, no credentials and no SDK — and it cannot be turned against
  a server you are not already talking to.
- **It does not gate calls.** Reviewing is not enforcement. For that, the runtime half is
  [policygate](https://github.com/sushant-me/policygate): a fail-closed gate that a model
  cannot authorise, with the reserved-name check enforced before any call happens.

Together with [mcp-nameguard](https://github.com/sushant-me/mcp-nameguard), the three cover
the same class at different moments: *before you connect* (mcpaudit), *at connection*
(nameguard), and *per call* (policygate).

## Status

`v0.1.0`, stdlib only, Python 3.11+, CI on 3.11/3.12/3.13, 41 tests. The claims about this
tool are re-checked weekly by [sushant-me/reputation](https://github.com/sushant-me/reputation).
