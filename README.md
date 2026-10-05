# MCP-SecBench

An extended, original implementation built on top of the **MCP Security
Bench (MSB)** benchmark
([dongsenzhang/MSB](https://github.com/dongsenzhang/MSB), ArXiv:2510.15994),
adding a **Defensive Proxy / Mitigation Layer** to measure how much a
security-aware middleware can reduce Attack Success Rate (ASR) across MSB's
four MCP attack surfaces: Tool Signature, Tool Parameter, Tool Response, and
Retrieval Injection.

See **[CONTRIBUTIONS.md](./CONTRIBUTIONS.md)** for a detailed breakdown of
what's original here vs. what comes from upstream MSB.

## Layout

```
baseline/           Unmodified copy of the MSB benchmark (tasks, tools, attack corpus)
defenses/
  mcp_guard.py       The defensive proxy: tool-signature validation, parameter
                      gating, and tool-response sanitization
cli_runner.py        Unified CLI: run baseline vs. defended scenarios, compare ASR
run_batch.py         Curated multi-scenario batch driver (see file for scope/rationale)
custom_scenarios/    Extension point for attack vectors beyond MSB's original five
results/             CSV results + generated ASR comparison table
setup_windows.py     Windows-compatible replacement for MSB's POSIX-only setup.py
```

## Setup

```
python -m venv .venv
.venv\Scripts\python -m pip install -r baseline\requirements.txt
# install uv (https://astral.sh/uv/install.ps1), then:
cd baseline\data\tools\attack_tools
uv venv && uv add --requirements requirements.txt
cd ..\..\..\..
python setup_windows.py
```

You'll also need an LLM backend. This project was verified end-to-end
against a fully local, free [Ollama](https://ollama.com) model — no API key
required:

```
ollama pull llama3.2:3b
```

## Usage

```
python cli_runner.py --mode baseline --llm ollama/llama3.2:3b --attack_type prompt_injection
python cli_runner.py --mode defended --llm ollama/llama3.2:3b --attack_type prompt_injection
python cli_runner.py --mode compare
```

`--llm` also accepts `openrouter/<model>`, `openai/<model>`, and
`deepseek/<model>` (with the matching API key in `baseline/.env`).
Add `--attack_task`, `--agent`, `--tool`, and `--limit` to narrow scope, or
run `python run_batch.py` for a pre-curated multi-scenario batch across all
three implemented attack surfaces.

## Live demo

`python demo.py --mode both` runs one MSB scenario through the same code path
as the benchmark and narrates each backend stage (servers spawned, attack
injected, tool calls, guard decisions, verdict). `DEMO.md` is a shot-by-shot
guide for screen-recording it.

## Status

Two prompt settings, reported side by side:

- **MSB's exact prompt** (primary): `results/comparison__ollama_llama3_2_3b.md`,
  `results/comparison__ollama_llama3_1_8b.md`.
- **Native tool-call prompt** (`--prompt_mode native`, a reported deviation that
  removes only MSB's legacy text-protocol section): `results/native_prompt/`.

Measured reductions are all on the out-of-scope-parameter attack: `llama3.1:8b`
100% → 0% (native prompt; under MSB's prompt it executed no tools), and
`llama3.2:3b` 36% → 0% / 24% → 0%. `report/report.tex` (v5) and
`CONTRIBUTIONS.md` document the corrections and known gaps: MSB's prompt
injection is not defended, near-miss tool names pass, retrieval injection is
unscored and only partly caught.
