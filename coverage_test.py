"""
coverage_test.py — empirically verifies, for each of MSB's 12 attack types,
whether our implementation can actually execute a scenario end-to-end (not
whether the attack succeeds). This is the evidence base for the Phase 5
attack-coverage matrix: it runs ONE scenario per attack type in both
baseline and defended mode, using the fastest available model, and records
whether the run completed, errored, or crashed outright.

This is deliberately not a statistical batch (see run_batch.py for that) --
it exists to answer "Present / Executable / Scored / Defended", not "what
is the ASR".
"""
import asyncio
import time

from cli_runner import BASELINE_DIR, build_argparser, run_mode
import os

LLM = "ollama/llama3.2:3b"

# (attack_type, agent, tool) -- one representative combo per attack type.
# Terminal_Controller is used for every attack type that needs an actual
# attack-tool server (it has full name_overlap/preference_manipulation/
# tool_transfer/out_of_scope_parameter variants implemented), and also for
# the attack types that only need the normal tool (prompt_injection,
# false_error, simulated_user, and their PI-* combinations).
# search_term_deception is structurally restricted to information_retrieval
# + Filesystem_MCP_Server -- no other combo is valid for it.
# NOTE: prompt_injection, false_error, and out_of_scope_parameter are
# deliberately excluded here -- they already have full 75-scenario
# statistical runs in results/{baseline,defended}_results.csv (see
# run_batch.py), and reusing the same (attack_task=obtain_agent_interaction_data,
# agent, tool) key here would dedup-collide with and silently overwrite
# that finalized data. This script only covers the 9 attack types that
# have never been executed before.
COMBOS = [
    ("name_overlap", "it_development_management", "Terminal_Controller"),
    ("preference_manipulation", "it_development_management", "Terminal_Controller"),
    ("simulated_user", "it_development_management", "Terminal_Controller"),
    ("search_term_deception", "information_retrieval", "Filesystem_MCP_Server"),
    ("tool_transfer", "it_development_management", "Terminal_Controller"),
    ("preference_manipulation-out_of_scope_parameter", "it_development_management", "Terminal_Controller"),
    ("preference_manipulation-simulated_user", "it_development_management", "Terminal_Controller"),
    ("prompt_injection-simulated_user", "it_development_management", "Terminal_Controller"),
    ("prompt_injection-false_error", "it_development_management", "Terminal_Controller"),
]


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
                "--attack_task", "obtain_agent_interaction_data",
                "--agent", agent,
                "--tool", tool,
                "--limit", "1",
            ])
            try:
                await run_mode(args, mode)
            except Exception as e:  # noqa: BLE001 -- a hard crash IS the data point here
                print(f"!!! CRASHED: {type(e).__name__}: {e}")
    print(f"\nCoverage test finished in {time.time()-start:.0f}s")


if __name__ == "__main__":
    asyncio.run(main())
