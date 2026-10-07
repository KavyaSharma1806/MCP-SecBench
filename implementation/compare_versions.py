"""
Three-way comparison: MSB baseline vs mcp_guard (v1) vs mcp_shield (v2).

    python implementation/compare_versions.py --llm ollama/llama3.2:3b [--prompt_mode native]

Reads only measured CSVs:
    results/baseline_results.csv          (cli_runner.py --mode baseline)
    results/defended_results.csv          (cli_runner.py --mode defended, v1)
    results/shield/defended_results.csv   (implementation/run_shielded.py, v2)
For --prompt_mode native the first two come from results/native_prompt/.
Attack types without a valid oracle (search_term_deception) are excluded,
exactly as cli_runner does. Nothing is reported for a version with no runs.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
KEYS = ["attack_type", "attack_task", "agent_name", "tool_name", "agent_task"]


def _load(path: Path, llm: str, prompt_mode: str) -> pd.DataFrame | None:
    if not path.exists():
        return None
    df = pd.read_csv(path)
    # Rows written before --prompt_mode existed were all MSB's exact prompt.
    df["prompt_mode"] = df["prompt_mode"].fillna("msb") if "prompt_mode" in df else "msb"
    df = df[(df["llm"] == llm) & (df["prompt_mode"] == prompt_mode)]
    if "oracle" in df:
        df = df[df["oracle"].fillna("operation_file") != "none"]
    df = df[df["attack_success"].notna()]
    if df.empty:
        return None
    df = df.copy()
    df["attack_success"] = df["attack_success"].astype(str).str.lower().isin({"true", "1", "1.0"}).astype(float)
    return df


def _rate(df: pd.DataFrame | None, attack_type: str) -> tuple[str, int, int]:
    if df is None:
        return "—", 0, 0
    sub = df[df["attack_type"] == attack_type]
    if sub.empty:
        return "—", 0, 0
    s, n = int(sub["attack_success"].sum()), len(sub)
    return f"{100 * s / n:.0f}% ({s}/{n})", s, n


def _mr(base_s: int, s: int, n: int) -> str:
    if not n:
        return "—"
    if base_s == 0:
        return "n/a"
    return f"{100 * (base_s - s) / base_s:.0f}%"


def main() -> None:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--llm", required=True)
    p.add_argument("--prompt_mode", choices=["msb", "native"], default="msb")
    args = p.parse_args()

    legacy_dir = ROOT / "results" / ("native_prompt" if args.prompt_mode == "native" else "")
    base = _load(legacy_dir / "baseline_results.csv", args.llm, args.prompt_mode)
    v1 = _load(legacy_dir / "defended_results.csv", args.llm, args.prompt_mode)
    v2 = _load(ROOT / "results" / "shield" / "defended_results.csv", args.llm, args.prompt_mode)

    types = sorted(set().union(*[set(d["attack_type"]) for d in (base, v1, v2) if d is not None]))
    lines = [
        f"# Baseline vs mcp_guard (v1) vs mcp_shield (v2) — {args.llm}, prompt={args.prompt_mode}",
        "",
        "| Attack type | Baseline ASR | v1 ASR | v1 MR | v2 ASR | v2 MR | v2 interventions |",
        "|---|---|---|---|---|---|---|",
    ]
    for t in types:
        b, bs, _ = _rate(base, t)
        r1, s1, n1 = _rate(v1, t)
        r2, s2, n2 = _rate(v2, t)
        inter = int(v2[v2["attack_type"] == t]["guard_blocks"].sum()) if v2 is not None and n2 else 0
        lines.append(f"| {t} | {b} | {r1} | {_mr(bs, s1, n1)} | {r2} | {_mr(bs, s2, n2)} | {inter if n2 else '—'} |")
    if v2 is None:
        lines += ["", "_No mcp_shield runs yet for this model/prompt — run implementation/run_shielded.py first._"]
    lines += ["", "ASR = successful attacks / scored runs. MR = (baseline successes − defended successes) / baseline "
              "successes; n/a when the baseline had no successes. Unscored attack types are excluded."]
    out = ROOT / "results" / "shield" / f"comparison__{args.llm.replace('/', '_').replace(':', '_').replace('.', '_')}__{args.prompt_mode}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
