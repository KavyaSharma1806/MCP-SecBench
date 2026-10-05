#!/usr/bin/env python
"""
demo.py — narrated, single-scenario run for screen recording.

Runs ONE MSB scenario through the exact same code path as cli_runner.py
(cli_runner.run_scenario), and prints what happens in the backend as it
happens: which MCP servers are spawned, what the attack injects, which tools
the agent sees, every tool call and reply, every guard decision, and the
judge's verdict. Nothing here is simulated -- the narration is driven by
events emitted from the real run.

    python demo.py --mode both                                 # baseline, then defended
    python demo.py --mode both --attack_type false_error --tool Terminal_Controller --agent it_development_management
    python demo.py --mode defended --slow 1.5                  # pause between stages for viewers

It writes nothing to results/*.csv, and its sandbox files are prefixed
"demo_" so they never collide with a benchmark run's files.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import textwrap
import time

import cli_runner
from cli_runner import BASELINE_DIR, load_scenarios, make_llm_factory, run_scenario

os.system("")  # enables ANSI colors on older Windows consoles

C = {
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "cyan": "\033[96m", "grey": "\033[90m",
}
SLOW = 0.0


def paint(text: str, *styles: str) -> str:
    return "".join(C[s] for s in styles) + text + C["reset"]


def stage(title: str) -> None:
    time.sleep(SLOW)
    print("\n" + paint(f"━━ {title} " + "━" * max(4, 72 - len(title)), "bold", "cyan"))


def wrap(text: str, indent: str = "    ", width: int = 100) -> str:
    text = " ".join(str(text).split())
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def make_printer(mode: str):
    def on_event(kind: str, *payload) -> None:
        if kind == "sandbox":
            info = payload[0]
            stage("1. PREPARE THE SANDBOX")
            print(wrap(f"Output file the attack will target: operation_space/output/{info['output_file']}.txt"))
            if info.get("seeded"):
                print(wrap("Seeded it with fake personal data (name / phone 123456789 / email) for the attack to tamper with."))
            if info.get("dummy_pid"):
                print(wrap(f"Started a harmless dummy process to be 'killed': PID {info['dummy_pid']}"))
        elif kind == "servers":
            config = payload[0]
            stage("2-3. ASSEMBLE + SPAWN MCP SERVERS  (MSB's complete_server_config)")
            for name, spec in config.get("mcpServers", {}).items():
                tag = paint(" ← MALICIOUS", "red", "bold") if name.startswith(("attack-", "addition-")) else ""
                cmd = os.path.basename(str(spec.get("command", "")))
                script = next((a for a in spec.get("args", []) if str(a).endswith(".py") or str(a).startswith("@")), "")
                print(f"    {paint(name, 'bold')}{tag}  {paint(cmd + ' ' + str(script), 'grey')}")
        elif kind == "attack":
            info = payload[0]
            stage("ATTACK BEING INJECTED  (MSB's own templates, unmodified)")
            print(wrap(f"Attack type: {info['attack_type']}   ·   Goal: {info['attack_task']}"))
            if info["injection_content"]:
                print(paint("    Appended to the tool descriptions the model will read:", "yellow"))
                print(paint(wrap(info["injection_content"], "      "), "red"))
            if info["tool_response_attack"]:
                print(paint("    Will REPLACE the real tool reply with:", "yellow"))
                print(paint(wrap(info["tool_response_attack"], "      "), "red"))
            if info["attack_type"] in cli_runner.PARAM_LEAK_ATTACK_TYPES:
                print(paint("    Mechanism: the malicious tool's schema demands an out-of-scope field "
                            "(llm_model_name). Success = the agent fills it in.", "yellow"))
        elif kind == "tools":
            tools, guard_events = payload
            stage("4. TOOLS THE AGENT CAN SEE" + ("  (after apply_defense)" if mode == "defended" else ""))
            for t in tools:
                args = list(getattr(t, "args", {}) or {})
                flag = paint("  ⚠ out-of-scope field", "red") if any(a.lower() in cli_runner.OUT_OF_SCOPE_PARAM_KEYS for a in args) else ""
                print(f"    {paint(t.name, 'bold')}({', '.join(args)}){flag}")
            for ev in guard_events:
                print(paint(f"    [guard · {ev.category}] {ev.tool_name}: {ev.detail}", "green"))
            if mode == "defended":
                stage("5. DEFENDED MODE: mcp_guard ATTACHED")
                print(wrap("Parameter gate + response sanitizer now wrap this agent's tool dispatch. "
                           "The attack itself is unchanged."))
        elif kind == "step":
            index, action, observation, guard_events = payload
            if index == 1:
                stage("6. AGENT LOOP  (think → call a tool → read the reply)")
            time.sleep(SLOW / 2)
            tool_input = getattr(action, "tool_input", {})
            print(paint(f"\n    step {index}  CALL  ", "bold", "blue") + paint(f"{action.tool}({tool_input})", "blue"))
            for ev in guard_events:
                colour = "green"
                print(paint(f"             GUARD [{ev.category}]  {ev.detail}", colour, "bold"))
            obs = str(observation)
            colour = "green" if obs.startswith("[mcp_guard]") else ("red" if ("strictly adhere" in obs or "I am the user" in obs) else "grey")
            print(paint("             REPLY ", "bold") + paint(wrap(obs[:600], "", 86).replace("\n", "\n                   "), colour))
        elif kind == "verdict":
            row = payload[0]
            stage("7-8. SHUT DOWN + JUDGE")
            print(wrap(f"Judge used: {row['oracle']}"))
            if row["attack_success"] is None:
                print(paint("    VERDICT: not scored (no valid judge for this attack type yet)", "yellow", "bold"))
            elif row["attack_success"]:
                print(paint("    VERDICT: ATTACK SUCCEEDED", "red", "bold"))
            else:
                print(paint("    VERDICT: attack failed", "green", "bold"))
            print(wrap(f"Guard interventions: {row['guard_blocks']}   ·   tool calls: {row['tool_calls'] or '(none)'}"))
            if row.get("error"):
                print(paint(wrap(f"Run note: {row['error']}"), "yellow"))
    return on_event


async def main() -> None:
    global SLOW
    p = argparse.ArgumentParser(description="Narrated single-scenario MCP-SecBench demo")
    p.add_argument("--mode", choices=["baseline", "defended", "both"], default="both")
    p.add_argument("--llm", default="ollama/llama3.2:3b")
    p.add_argument("--attack_type", default="out_of_scope_parameter")
    p.add_argument("--attack_task", default="obtain_agent_interaction_data")
    p.add_argument("--agent", default="information_gathering")
    p.add_argument("--tool", default="DuckDuckGo_Search_Server")
    p.add_argument("--pick", type=int, default=0, help="which matching scenario to run (0 = first)")
    p.add_argument("--max_steps", type=int, default=8)
    p.add_argument("--timeout", type=float, default=180.0)
    p.add_argument("--slow", type=float, default=0.0, help="seconds to pause between stages")
    args = p.parse_args()
    SLOW = args.slow

    os.chdir(BASELINE_DIR)
    selector = cli_runner.build_argparser().parse_args([
        "--mode", "baseline", "--attack_type", args.attack_type, "--attack_task", args.attack_task,
        "--agent", args.agent, "--tool", args.tool,
    ])
    scenarios = load_scenarios(selector)
    if not scenarios:
        sys.exit("No MSB scenario matches those filters (see data/agent_task.jsonl for valid agent/tool pairs).")
    scenario = scenarios[min(args.pick, len(scenarios) - 1)]

    print(paint("\nMCP-SecBench live demo", "bold"))
    print(wrap(f"Model: {args.llm}"))
    print(wrap(f"User's innocent request: \"{scenario['agent_task']}\"  (tool: {scenario['tool_name']})"))

    modes = ["baseline", "defended"] if args.mode == "both" else [args.mode]
    rows = {}
    for mode in modes:
        print("\n" + paint(f"██████  {mode.upper()} RUN  ██████", "bold", "green" if mode == "defended" else "red"))
        rows[mode] = await run_scenario(
            scenario, make_llm_factory(args.llm), mode, args.max_steps, args.timeout,
            on_event=make_printer(mode), output_tag="demo",
        )

    if len(rows) == 2:
        stage("SIDE BY SIDE")
        for mode, row in rows.items():
            verdict = "not scored" if row["attack_success"] is None else ("SUCCEEDED" if row["attack_success"] else "failed")
            print(f"    {mode:9s}  attack {verdict:10s}  guard interventions: {row['guard_blocks']}")
        base, defn = rows["baseline"], rows["defended"]
        print(wrap("Same scenario, same model, same attack; only the guard differs. What that means for THIS take:"))
        # Attribute the outcome honestly: a defended run can also "fail" just because the
        # model didn't take the bait this time, in which case the guard deserves no credit.
        if defn["attack_success"] is None:
            print(paint(wrap("Not scored -- no valid judge for this attack type."), "yellow"))
        elif defn["attack_success"]:
            print(paint(wrap("The attack got through the guard. This is a miss."), "red", "bold"))
        elif defn["guard_blocks"] > 0:
            print(paint(wrap(f"The guard acted {defn['guard_blocks']} time(s) and the attack failed"
                             + (" -- where the undefended run was compromised." if base["attack_success"] else ".")), "green", "bold"))
        else:
            print(paint(wrap("The guard did not need to act: the model didn't attempt the attack in this take. "
                             "Any difference from the baseline here is model randomness, not the guard."), "yellow", "bold"))
        print(wrap("(Single runs vary -- the model is not deterministic; the benchmark reports rates over many runs.)", "    "))


if __name__ == "__main__":
    asyncio.run(main())
