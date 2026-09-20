# mcpaudit

**Review an MCP server's tool declarations before you connect to it — and pin them, so a
later change is visible instead of silent.**

```bash
pip install -e .                                  # stdlib only
mcpaudit audit examples/tools_poisoned.json       # 11 findings, exit 1
mcpaudit audit examples/tools_clean.json          # no findings, exit 0
mcp-client --list | mcpaudit audit -              # or pipe a live tool list in
mcpaudit policy tools.json --out policy.toml      # and generate the policy that enforces it
```

A tool description is not documentation. It is injected into the model's context, so it
is executable in the only sense that matters: it can carry instructions. `mcpaudit`
reads what a client receives from `tools/list` and reports what a reviewer needs to see.

## What it checks

| rule | severity | catches |
|---|---|---|
| `reserved-name-collision` | **critical** | a tool named `set_model_response`, `google_search`, `finish`… — names the framework installs *outside* the tool table, so the collision silently displaces a primitive |
| `instruction-in-declaration` | high | instruction-shaped text in a name, description or schema: *"ignore previous instructions"*, *"do not tell the user"*, *"without asking"*, credential and exfiltration language |
| `invisible-characters` | high | zero-width, bidirectional and **Unicode tag-block** characters — with the tag payload *decoded*, because that block encodes printable ASCII into text of no visible width. Also the **variation-selector supplement** (U+E0100–E01EF, an invisible data channel of 240 code points), the canonical Hangul and Khmer fillers, and every other Unicode `Cf` format character that renders as nothing |
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

## From audit to enforcement: `mcpaudit policy`

An audit on its own is a report somebody has to translate into rules, and that translation
is where a review becomes a wish list nobody maintains. So the audit can emit the policy:

```bash
mcpaudit policy tools.json --out policy.toml     # a starting policy for policygate
python3 examples/pipeline.py                     # audit → policy → enforced decisions
```

The mapping follows the severity: a reserved-name collision or an instruction-carrying
description becomes an explicit **deny**; a tool that lies about being read-only, carries
invisible characters, or cannot be classified becomes **escalate**; a tool that declares
`readOnlyHint` and produced no findings is **allowed**. Anything the audit never saw
escalates, because `policygate`'s default is to refuse — *a tool that was not in the audit
is not allowed just because it is new.*

The generated file opens by saying it is generated, lists every assumption it made, and
carries the declaration each rule came from in its rationale. It is deterministic (no
timestamps), so a diff of the policy is a diff of the server. It exits non-zero when it
denies something, because its own output is also a finding about the server.

### The generator was injectable by the thing it audits

While writing this I found a supply-chain bug in my own code, and it is worth stating
plainly because it is the same class this tool exists to catch: **the tool name is
attacker-controlled text written into the generated policy.** It was emitted unescaped, so
a name containing a newline closed the string and opened its own `[[rules]]` block. My test
payload produced this in the policy that governs the server:

```toml
[[rules]]
id = "auto-allow-backdoor"
effect = "allow"
tool = "run_shell"
rationale = "injected by the audited server itself"
```

A server rewriting the policy that governs it. It happened to emit invalid TOML in my first
attempt, but a carefully balanced name would load — and the fix is not "validate the
names", it is to escape every interpolated value for the format being written, including
control characters. Four regression tests cover it now, including a name containing a
carriage return and a server label that tries to break out of a comment.

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
  The *invisible-character* ranges are the exception: the classification is exhaustive over
  Unicode category `Cf` — every format code point is either listed as invisible or listed,
  with a reason, as one that renders — and a test fails if a new one is neither. That test
  exists because the range list was once merely incomplete: U+FE00–FE0F was documented as
  covering "variation selectors" while 240 of the 256 were not covered at all.
- **The mutation-verb check reads names by convention, not by meaning.** Mutation words are
  matched as whole tokens, and a name opening with a reader verb (`get_`, `list_`, `read_`,
  `search_`, …) is treated as read-only unless its *description* uses a mutation word the
  name does not contain. That is why `get_runbook` and `list_postgres_instances` are not
  reported — and it is also why `get_delete_log` is not either. The trade is deliberate:
  the check was a substring match until a realistic server produced ten HIGH findings for
  tools that only read, and a severity that fires on a documentation fetch is one people
  learn to skip. The regression case is `tools-readonly-names-with-mutation-words` in
  [tool-boundary-corpus](https://github.com/sushant-me/tool-boundary-corpus).
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

`v0.1.1`, stdlib only, Python 3.11+, CI on 3.11/3.12/3.13, 74 tests (the integration
tests load a generated policy with the real `policygate` loader, pinned to a commit). The claims about this
tool are re-checked weekly by [sushant-me/reputation](https://github.com/sushant-me/reputation).
