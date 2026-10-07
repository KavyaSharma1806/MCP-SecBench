"""
Run MSB scenarios with mcp_shield (v2) instead of mcp_guard (v1).

Reuses cli_runner.py unchanged — same scenario grid, same LLM factory, same
success oracles — and swaps only the defence hook, so a shield run is an
apples-to-apples comparison with the existing baseline and v1 results:

    python implementation/run_shielded.py --llm ollama/llama3.2:3b --attack_type out_of_scope_parameter
    python implementation/run_shielded.py --llm ollama/llama3.1:8b --prompt_mode native --limit 5
    python implementation/compare_versions.py --llm ollama/llama3.2:3b

Results go to results/shield/ (never mixed with the v1 CSVs); the tamper-evident
audit log of every guard decision goes to results/shield/audit/.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import cli_runner  # noqa: E402  (sets up baseline/ on sys.path exactly as the benchmark does)
from mcp_shield import BLOCK_PREFIX, apply_shield  # noqa: E402

DETAIL_TO_LEGACY = {
    "tool_signature": "tool_signature", "system_prompt": "tool_signature",
    "parameter": "parameter", "policy": "parameter", "flow": "parameter", "integrity": "parameter",
    "response": "response",
}
_counter = {"n": 0}


def _legacy_summary(shield) -> dict[str, int]:
    """Map shield categories onto the CSV columns cli_runner already writes."""
    out = {"tool_signature": 0, "parameter": 0, "response": 0}
    for ev in shield.events:
        if ev.blocked:
            out[DETAIL_TO_LEGACY.get(ev.category, "parameter")] += 1
    out["total"] = sum(out.values())
    return out


def install(results_dir: Path) -> None:
    audit_dir = results_dir / "audit"

    async def shield_hook(agent):
        _counter["n"] += 1
        shield = await apply_shield(agent, audit_path=audit_dir / f"run_{os.getpid()}_{_counter['n']:04d}.jsonl")
        shield.summary = lambda: _legacy_summary(shield)      # CSV-compatible counts
        return shield

    cli_runner.apply_defense = shield_hook                    # the one line that differs from v1
    cli_runner.GUARD_BLOCK_PREFIX = BLOCK_PREFIX              # so the param-leak oracle sees refusals


def main() -> None:
    parser = cli_runner.build_argparser()
    parser.description = "MSB scenarios defended by mcp_shield (v2)"
    for action in parser._actions:
        if action.dest == "mode":
            action.required = False
            action.default = "defended"
            action.choices = ["defended"]
            action.help = "always 'defended' (shield); run baselines with cli_runner.py"
        if action.dest == "results_dir":
            action.default = str(ROOT / "results" / "shield")
    args = parser.parse_args()
    results_dir = cli_runner.resolve_results_dir(args)
    install(results_dir)
    os.chdir(cli_runner.BASELINE_DIR)
    asyncio.run(cli_runner.run_mode(args, "defended"))


if __name__ == "__main__":
    main()
