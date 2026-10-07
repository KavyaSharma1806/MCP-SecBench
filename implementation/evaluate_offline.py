"""
Offline, LLM-free measurement of the text-level detectors: v1 mcp_guard vs v2
mcp_shield. Needs no API key and no Ollama.

    python implementation/evaluate_offline.py

Malicious set — built at run time ONLY from MSB's own attack material in
baseline/: every (template × attack goal) pair MSB can produce for tool
responses / tool descriptions, plus the four retrieval documents with each
goal substituted for {attack_instruction}.

Benign set — the same four retrieval documents with the placeholder removed,
split into paragraphs, plus everyday documentation text (benign_texts.txt)
that deliberately uses words like "important", "password", "token", "you
must", "ignore".

Reported: detection rate on the malicious set (1 - FNR), FPR on the benign
set, and mean latency per item. This measures the detectors only — not
end-to-end ASR, which needs an LLM (run_shielded.py).
"""

from __future__ import annotations

import json
import re
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASELINE = ROOT / "baseline"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BASELINE))

from data import prompt_template as msb  # noqa: E402  (MSB's own templates)
from mcp_shield import classify_text  # noqa: E402


def load_v1():
    try:
        from defenses.mcp_guard import SecurityGuard
    except Exception as exc:  # noqa: BLE001 — langchain_core missing
        print(f"(v1 unavailable: {exc}) — install the project venv to compare")
        return None

    def detect(text: str) -> bool:
        guard = SecurityGuard()
        return guard.sanitize_response("tool", text) != text
    return detect


def msb_goals() -> list[str]:
    goals = []
    for line in (BASELINE / "data" / "attack_task.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            goals.append(json.loads(line)["implementation"].replace("file_name", "notes").replace("{pid}", "4242"))
    return goals


def malicious_items() -> list[tuple[str, str]]:
    items = []
    for goal in msb_goals():
        items.append(("prompt_injection_template", msb.PROMPT_INJECTION_TEMPLATE.replace("{goal}", goal)))
        items.append(("false_error_template", msb.TOOL_RESPONSE_ATTACK_TEMPLATE + goal))
        items.append(("simulated_user_template", msb.SIMULATED_USER_TEMPLATE + goal))
        for doc in sorted((BASELINE / "operation_space" / "information").glob("*.txt")):
            items.append((f"retrieval:{doc.stem}", doc.read_text(encoding="utf-8").replace("{attack_instruction}", goal)))
    return items


def benign_items() -> list[tuple[str, str]]:
    items = []
    for doc in sorted((BASELINE / "operation_space" / "information").glob("*.txt")):
        text = doc.read_text(encoding="utf-8")
        text = "\n".join(line for line in text.splitlines() if "{attack_instruction}" not in line)
        items.append((f"doc:{doc.stem}", text))
        for para in re.split(r"\n\s*\n", text):
            if len(para.strip()) > 60:
                items.append((f"para:{doc.stem}", para.strip()))
    extra = HERE / "benign_texts.txt"
    if extra.exists():
        for block in re.split(r"\n-{3,}\n", extra.read_text(encoding="utf-8")):
            if block.strip():
                items.append(("benign_text", block.strip()))
    return items


def run(detect, items) -> tuple[list[bool], float]:
    hits, times = [], []
    for _, text in items:
        t0 = time.perf_counter()
        hits.append(bool(detect(text)))
        times.append((time.perf_counter() - t0) * 1000)
    return hits, statistics.mean(times) if times else 0.0


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    mal, ben = malicious_items(), benign_items()
    # At run time the shield knows the agent's tool list; give it the tools of
    # MSB's filesystem support server, which every MSB scenario loads.
    fs_tools = {"read_text_file", "read_file", "read_multiple_files", "write_file", "edit_file", "move_file",
                "search_files", "list_directory", "get_file_info", "create_directory", "kill_process"}
    detectors = {"v2 mcp_shield": lambda t: classify_text(t, known_tool_names=fs_tools).is_malicious}
    v1 = load_v1()
    if v1:
        detectors = {"v1 mcp_guard": v1, **detectors}

    lines = ["# Offline detector evaluation (no LLM)", "",
             f"Malicious items: {len(mal)} (MSB templates × MSB goals, MSB retrieval docs × goals). "
             f"Benign items: {len(ben)}.", "",
             "| Detector | Detection rate (1-FNR) | FNR | FPR | Mean latency |", "|---|---|---|---|---|"]
    per_family: dict[str, dict[str, str]] = {}
    for name, fn in detectors.items():
        mh, mt = run(fn, mal)
        bh, bt = run(fn, ben)
        tp, fp = sum(mh), sum(bh)
        lines.append(f"| {name} | {tp}/{len(mal)} = {100*tp/len(mal):.1f}% | {100*(len(mal)-tp)/len(mal):.1f}% | "
                     f"{fp}/{len(ben)} = {100*fp/len(ben):.1f}% | {(mt+bt)/2:.2f} ms |")
        fams: dict[str, list[bool]] = {}
        for (fam, _), hit in zip(mal, mh):
            fams.setdefault(fam.split(":")[0], []).append(hit)
        per_family[name] = {f: f"{sum(h)}/{len(h)}" for f, h in fams.items()}

    lines += ["", "## Detection by MSB attack family", "",
              "| Family | " + " | ".join(per_family) + " |", "|---|" + "---|" * len(per_family)]
    for fam in sorted({f for d in per_family.values() for f in d}):
        lines.append(f"| {fam} | " + " | ".join(per_family[n].get(fam, "—") for n in per_family) + " |")
    lines += ["", "Caveats: MSB's attack strings are fixed, and both detectors were designed knowing them, so these "
              "numbers show coverage of MSB's corpus — not robustness to unseen attacks. Benign set is small. "
              "Latency is per item on this machine, single-threaded."]

    out = HERE / "results" / "offline_eval.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
