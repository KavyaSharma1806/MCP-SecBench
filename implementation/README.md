# implementation/ — mcp_shield (v2 defence)

This folder is the **research-improvement stage** of MCP-SecBench: a hardened
defence, `mcp_shield`, built to close the gaps our v1 guard documents. It is
kept separate on purpose so the presentation can show three distinct things:

| Folder | What it is | Who wrote it |
|---|---|---|
| `baseline/` | MSB benchmark: tasks, MCP tools, attack corpus | upstream MSB (unmodified) |
| `defenses/mcp_guard.py` | v1 defensive proxy — the measured results in the report | us |
| `implementation/mcp_shield/` | v2 hardened defence (this folder) | us |

Nothing outside this folder was changed. `run_shielded.py` reuses
`cli_runner.py` as a library and swaps only the defence hook, so baseline,
v1 and v2 runs use the same scenarios, the same model and the same oracles.

## What v2 fixes (from the v1 limitations in CONTRIBUTIONS.md / report)

| v1 limitation | v2 mechanism |
|---|---|
| MSB prompt injection not defended (it lands in the system prompt, v1 only scanned tool descriptions) | **System-prompt hardening**: the whole assembled prompt is scanned after MSB builds it; injected blocks/lines removed |
| Near-miss tool names pass (`execute_command_v1`, `get_commands_history`) | **Confusable-name detection** (decorations, edit distance, homoglyphs); decoy quarantined, plain tool kept |
| Blocklist tuned to MSB strings, misses paraphrase / obfuscation | **Canonicalisation** (NFKC, zero-width/bidi/tag chars, homoglyphs, letter-spacing, leetspeak, base64/hex) + **sentence-level semantic classifier** (DATA / INSTRUCTION / MALICIOUS) built on feature families, not phrases |
| Whole response withheld when one marker is found (utility cost) | **Sentence-level redaction**: only the instruction aimed at the agent is removed; the rest of the document survives. Remaining output is **spotlighted** in a random-nonce fence |
| Parameter check = fixed key list | **Strict schema**: undeclared args dropped; **data-soliciting params** (model name, system prompt, history, credentials) detected from the tool schema and stripped |
| "Does it look malicious?" only | **Capability policy** (Level 3): read / write / exec / network / destructive classes; non-read actions need user intent; sensitive paths, secrets (patterns + entropy), dangerous commands, path traversal |
| No view of the action sequence | **Flow monitor** (Level 4): taint tracking (artefacts from untrusted tool output may not reach write/exec/network sinks), sensitive-read → exfil rule, loop guard, call budget |
| — | **Manifest pinning**: SHA-256 of each tool's name/description/schema checked before every call (rug-pull) |
| — | **Fail-closed**: any error inside a check blocks the action |
| — | **Tamper-evident audit**: HMAC hash-chained log of every decision; `verify()` finds the first altered record |
| Semantic detection was future work | Optional **local LLM judge** (`MCP_SHIELD_JUDGE=ollama/llama3.2:3b`) — free, offline; fenced input, fixed JSON schema, can only raise severity |

```
USER ─► LLM AGENT ─► mcp_shield ─► MCP SERVERS / TOOLS
           0 normalise → 1 tool review + pin → 2 system-prompt hardening
           3 call gate: pin → policy → flow/taint      4 response gate: classify → redact → fence
           5 hash-chained audit of every decision
```

## Measured so far (offline, no LLM)

`python implementation/evaluate_offline.py` measures the text detectors on
MSB's own attack material (35 items: every MSB response/description template
× MSB attack goal, and MSB's 4 retrieval documents × goals) and 32 benign
items. Full table: [`results/offline_eval.md`](results/offline_eval.md).

| Detector | Detection (1−FNR) | FPR | Mean latency |
|---|---|---|---|
| v1 mcp_guard | 25/35 = 71.4% | 0/32 = 0% | 0.05 ms |
| v2 mcp_shield | 33/35 = 94.3% | 0/32 = 0% | 0.8 ms |

The gain is all on retrieval injection (v1 10/20 → v2 18/20), which v1 only
caught when a document wrapped the instruction in `<IMPORTANT>`.

**Not measured yet:** end-to-end ASR with an LLM. Run it when ready:

```powershell
.venv\Scripts\python implementation\run_shielded.py --llm ollama/llama3.2:3b --attack_type out_of_scope_parameter
.venv\Scripts\python implementation\run_shielded.py --llm ollama/llama3.1:8b --prompt_mode native --attack_type false_error
.venv\Scripts\python implementation\compare_versions.py --llm ollama/llama3.2:3b
```

Results land in `results/shield/` (never mixed with v1 CSVs) and every guard
decision in `results/shield/audit/*.jsonl`.

## Honest limitations

- Still heuristic at its core; both detectors were designed knowing MSB's
  corpus, so offline numbers show **coverage of MSB**, not robustness to
  unseen attacks. The benign set is small.
- The capability policy infers intent from words in the user's request; a
  request that legitimately needs a write but never says so will be blocked
  (utility cost — measure it before claiming improvement).
- Taint tracking matches concrete artefacts (paths, URLs, IDs); an attack that
  makes the model *invent* a target value is not caught by that rule.
- Integration still relies on `mcp_use` / LangChain internals
  (`_aperform_agent_action`, `_create_system_message_from_tools`), like v1.
- Rate limits and the audit key are per process.

This is a prototype middleware defence against selected MCP attack classes,
evaluated on the benchmark attacks implemented here — not a claim that MCP
agents are secure.

## Layout

```
mcp_shield/
  normalize.py   canonical views + obfuscation signals
  detectors.py   feature families, sentence classifier, redaction
  semantic.py    Classifier protocol, heuristic, optional Ollama judge, ensemble
  tools.py       near-miss names, description cleaning, solicited params, fingerprints
  policy.py      capabilities, intent, secrets, sensitive paths, commands
  flow.py        taint tracking + sequence rules
  audit.py       HMAC hash-chained log + verify
  shield.py      Shield orchestrator + apply_shield(agent)
run_shielded.py      MSB scenarios with the shield (reuses cli_runner)
compare_versions.py  baseline vs v1 vs v2 table from measured CSVs only
evaluate_offline.py  LLM-free FPR/FNR/latency on MSB's own attack data
benign_texts.txt     benign documentation used for FPR
```
