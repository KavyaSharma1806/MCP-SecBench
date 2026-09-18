"""
run_batch.py — drives cli_runner.py across a curated set of scenarios.

Curated (rather than --attack_type all --agent all) on purpose: many of MSB's
normal_tools configs (Supabase, GitHub, Notion, Linear, ClickUp, ...) need
API tokens/credentials we don't have in this environment, and would just
burn the local model's time timing out. This batch sticks to tool/agent
combos already verified to spin up cleanly offline, across one attack type
per MSB attack surface:
  - Tool Signature   -> prompt_injection
  - Tool Parameter   -> out_of_scope_parameter
  - Tool Response    -> false_error
(Retrieval Injection / search_term_deception is intentionally excluded here
 — cli_runner.py's score_attack() doesn't implement an oracle for it yet;
 see CONTRIBUTIONS.md "Known limitations".)
"""
import asyncio
import time

from cli_runner import BASELINE_DIR, build_argparser, run_mode
import os

COMBOS = [
    ("prompt_injection", "information_gathering", "DuckDuckGo_Search_Server"),
    ("prompt_injection", "it_development_management", "Terminal_Controller"),
    ("out_of_scope_parameter", "information_gathering", "DuckDuckGo_Search_Server"),
    ("out_of_scope_parameter", "it_development_management", "Terminal_Controller"),
    ("false_error", "information_gathering", "DuckDuckGo_Search_Server"),
    ("false_error", "it_development_management", "Terminal_Controller"),
]

LLM = "ollama/llama3.1:8b"


async def main():
    os.chdir(BASELINE_DIR)
    parser = build_argparser()
    start = time.time()
    total = len(COMBOS) * 2
    done = 0
    for mode in ["baseline", "defended"]:
        for attack_type, agent, tool in COMBOS:
            done += 1
            print(f"\n=== [{done}/{total}] {mode} | {attack_type} | {agent}/{tool} "
                  f"(elapsed {time.time()-start:.0f}s) ===", flush=True)
            args = parser.parse_args([
                "--mode", mode,
                "--llm", LLM,
                "--attack_type", attack_type,
                "--attack_task", "all",
                "--agent", agent,
                "--tool", tool,
            ])
            try:
                await run_mode(args, mode)
            except Exception as e:  # noqa: BLE001 — one bad combo must not kill the batch
                print(f"!!! combo failed: {e}")
    print(f"\nBatch finished in {time.time()-start:.0f}s")


if __name__ == "__main__":
    asyncio.run(main())
