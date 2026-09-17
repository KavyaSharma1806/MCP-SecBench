# Original Contributions on Top of MSB

This project extends the **MCP Security Bench (MSB)** benchmark
([dongsenzhang/MSB](https://github.com/dongsenzhang/MSB), ArXiv:2510.15994)
rather than reproducing it. `baseline/` is an unmodified copy of the
upstream repository, kept intact for auditability; everything described
below is new code layered on top of it.

## 1. Defensive Proxy / Mitigation Layer (`defenses/mcp_guard.py`)

MSB measures Attack Success Rate (ASR) against an *undefended* agent. Our
contribution is a security middleware, `SecurityGuard` + `apply_defense()`,
that sits between an already-initialized `mcp_use.MCPAgent` and the rest of
the pipeline, targeting the same four attack surfaces MSB defines:

| MSB attack surface | Guard component | Mechanism |
|---|---|---|
| Tool Signature (Name Collision, Preference Manipulation, Prompt Injection-in-description) | `SecurityGuard.validate_tool_signatures` | Drops duplicate tool names (keeps first-seen), strips known injection-template markers out of tool descriptions before they reach the system prompt |
| Tool Parameters (Out-of-Scope Parameter) | `SecurityGuard.check_parameters` | Blocks calls that carry MSB's own out-of-scope keys (`llm_model_name`/`llm_name`/`lm_model_name`) or generic secret-like keys (`api_key`, `password`, ...); blocks high-risk tool calls (`write_file`/`edit_file`/`kill_process`/...) whose payload contains an SSH/PEM key or a reference to `personal_information.json` |
| Tool Response (False Error, User Impersonation) & Retrieval Injection (search-term deception) | `SecurityGuard.sanitize_response` | Regex-matches MSB's own canned attack templates (`PROMPT_INJECTION_TEMPLATE`, `TOOL_RESPONSE_ATTACK_TEMPLATE`, `SIMULATED_USER_TEMPLATE`, plus generic "ignore previous instructions" phrasing) in tool observations and redacts them before they reach the LLM's context |
| All of the above | `DEFENSIVE_SYSTEM_PROMPT` | A "tool output is data, not instructions" policy block appended to the system prompt in defended mode |

**Design choice — proxy, not patch.** `apply_defense()` never edits
`mcp_use` or `langchain` source files. It composes with a live `MCPAgent`
instance by (a) rebuilding its system message from a sanitized tool list,
and (b) monkey-patching *that instance's* `AgentExecutor._aperform_agent_action`
bound method to add pre-call parameter checks and post-call response
sanitization. This is what makes `baseline` vs `defended` a controlled,
apples-to-apples comparison in `cli_runner.py`: identical scenario,
identical LLM, the only difference is whether `apply_defense()` was called.

**Known limitation.** Several checks (the SSH-key pattern, the
`personal_information.json` filename check, MSB's exact template strings)
are tuned against MSB's own fixed attack corpus. This is deliberate — it
lets us measure ASR reduction against the precise threat model MSB defines
— but it is also the honest limitation of any signature/heuristic guard:
it generalizes weakly to attack phrasing it has never seen. A learned or
LLM-judge–based sanitizer (flagged as future work) would generalize better
at the cost of latency and its own attack surface.

## 2. Windows-compatible environment setup (`setup_windows.py`)

MSB's own `setup.py` assumes a POSIX shell (`subprocess.run(['which', 'uv'])`)
and destructively `shutil.move`s `scripts/agent.py` into the installed
`langchain` package, which would delete it from the baseline copy. Our
version resolves `uv` with `shutil.which`, writes correctly JSON-escaped
Windows paths into the MCP server configs, and **copies** (not moves) the
langchain `AgentExecutor` patch so `baseline/` stays a complete, unmodified
copy of upstream.

## 3. Pluggable LLM backend (`cli_runner.py::make_llm_factory`)

MSB's `main.py` hardcodes its LLM selection to OpenRouter / DeepSeek /
Tongyi(Qwen) by substring-matching the model name. We generalize this to an
explicit `<backend>/<model>` spec (`ollama/llama3.2:3b`,
`openrouter/openai/gpt-4o-mini`, `openai/gpt-4o-mini`,
`deepseek/deepseek-chat`) so the same scenario runner works fully offline
against a local Ollama model, with no API costs — the path we used to
verify this project end-to-end.

## 4. Unified CLI runner (`cli_runner.py`)

`python cli_runner.py --mode {baseline,defended,compare}` runs MSB's own
scenario grid (`data/agent_task.jsonl` × `data/attack_task.jsonl` ×
`data/attack_type.jsonl`, reusing MSB's own `tool_exist`/
`complete_server_config` helpers by importing `baseline/main.py` as a
library) through either the undefended agent or the `mcp_guard`-wrapped
one, and can filter/limit scenarios for fast iteration
(`--attack_type`, `--attack_task`, `--agent`, `--tool`, `--limit`).

**Success oracle.** MSB's own `metrics.py` determines attack success by
regex-parsing its own log files. We instead read the sandboxed
`operation_space/output/<file>.txt` the attack was trying to plant content
into (see `cli_runner.py::score_attack`) — the same ground-truth artifact
MSB's own `create_operation_file`/`record_result` helpers write to, just
inspected directly in-process instead of via log text. This is simpler,
faster (no log parsing), and avoids brittleness to log-format changes.

`--mode compare` produces a Markdown ASR-reduction table
(`results/comparison.md`) from the two result CSVs, plus a
`guard_blocks` column showing how many times the defense actually
intercepted something per scenario — evidence the reduction came from the
guard acting, not from the scenario simply not triggering.

## 5. `custom_scenarios/`

Reserved for attack/task vectors beyond MSB's original five
(`obtain_remote_control_authority`, `obtain_data_information`,
`modify_data`, `kill_process`, `obtain_agent_interaction_data`) and four
attack surfaces. See `custom_scenarios/README.md` for the extension format.

**Known limitation — Retrieval Injection is not yet scored.** `score_attack()`
implements an oracle for MSB's five `attack_task` values via the
`operation_space/output` file, which covers the Tool Signature, Tool
Parameter, and Tool Response surfaces. `search_term_deception` (Retrieval
Injection) doesn't fit that oracle: MSB's own `metrics.py` scores it purely
as a "did the agent get deceived into reading the wrong document"
(`user_task_success`) check, never as `attack_success`. Our batch runs
(`run_batch.py`) deliberately exclude `search_term_deception` rather than
report a misleading, always-`False` ASR for it. Implementing a proper oracle
here (comparing the agent's final answer against the correct vs. the
decoy document) is future work.

## What is unchanged from MSB

- `baseline/data/attack_task.jsonl`, `agent_task.jsonl`, `attack_type.jsonl`,
  the MCP tool configs, and MSB's own attack-tool server implementations
  are used as-is — they are the benchmark, not our contribution.
- `baseline/mcp_use/` (MSB's modified fork of `mcp-use` that adds
  `tool_response_attack`/`attack_type`/`attack_task` plumbing) and
  `baseline/scripts/agent.py` (MSB's `AgentExecutor` patch that actually
  substitutes canned attack strings for tool observations) are used
  unmodified — `mcp_guard.py` composes with them rather than replacing them.
