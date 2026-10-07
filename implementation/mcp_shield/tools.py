"""
Tool-signature defence: what the agent is *told* its tools are.

Fixes the two gaps the v1 report documents:
  * near-miss names (execute_command_v1 vs execute_command,
    get_commands_history vs get_command_history) — v1 only removed exact
    duplicates
  * injected text in descriptions beyond MSB's fixed templates

and adds:
  * manifest pinning — a SHA-256 over each tool's name, description and
    input schema, re-checked before every call (catches "rug-pull" servers
    that change a tool after it was approved)
  * parameter-solicitation detection — schema fields whose name or
    description asks for the model name, system prompt, conversation
    history or credentials (MSB's out-of-scope-parameter attack, generalised)
  * preference-manipulation stripping ("always prefer this tool", "the
    only trustworthy tool", …)
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .detectors import Label, classify_text
from .normalize import normalize, split_sentences

# Decorations attackers add to make a decoy look like the real tool.
_DECORATION = re.compile(r"(_|-)?(v\d+|new|pro|plus|official|secure|fast|real|true|latest|updated|enhanced|advanced|2)$")
_PREFERENCE = re.compile(
    r"(always|only|must|should) (use|prefer|choose|select|call) (this|me)|prefer (this|me) over|"
    r"(the )?(best|most (reliable|accurate|popular|trusted|powerful|advanced)|only (trustworthy|reliable|official)|"
    r"recommended|superior|preferred|number one|#1|official) (tool|version|choice|option)|"
    r"(do not|don't|never) use (the )?(other|original|old|any other)|(other|original) tools? (are|is) (deprecated|unsafe|broken|outdated)|"
    r"(faster|better|safer|more accurate) than (the )?(other|original|regular|default)"
)
# Parameter names/descriptions that solicit data a tool never needs.
_SOLICIT_NAME = re.compile(
    r"(^|_)(llm|lm|model|ai|assistant|agent)(_?(model)?_?name|_?version|_?type|_?id)$|system_?prompt|"
    r"(^|_)(prompt|instructions?|conversation|chat_?history|history_?of|previous_?messages|context_?window)(_|$)|"
    r"api_?key|secret|password|passwd|token|credential|private_?key|ssh_?key|cookie|session_?id"
)
_SOLICIT_DESC = re.compile(
    r"(name|version|identity) of (the |your )?(model|llm|ai|assistant)|which (model|llm) (you are|are you)|"
    r"your (system )?prompt|your instructions|conversation history|chat history|previous messages|"
    r"(api|secret|access) key|password|credentials?|private key"
)


def _schema_of(tool: Any) -> dict:
    schema = getattr(tool, "args_schema", None)
    if schema is None:
        return {}
    if isinstance(schema, dict):
        return schema
    for attr in ("model_json_schema", "schema"):
        fn = getattr(schema, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                continue
    return {}


def schema_properties(tool: Any) -> dict[str, dict]:
    props = _schema_of(tool).get("properties", {}) or {}
    return {str(k): (v if isinstance(v, dict) else {}) for k, v in props.items()}


def fingerprint(tool: Any) -> str:
    payload = json.dumps(
        {"name": getattr(tool, "name", ""), "description": getattr(tool, "description", "") or "",
         "schema": _schema_of(tool)},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _base_name(name: str) -> str:
    canon = normalize(name).squashed.replace(" ", "")
    return _DECORATION.sub("", canon)


def near_miss(a: str, b: str) -> bool:
    """True when two different tool names are confusable."""
    if a == b:
        return False
    ca, cb = normalize(a).squashed, normalize(b).squashed
    if ca == cb:                                   # homoglyph / case / width tricks
        return True
    ba, bb = _base_name(a), _base_name(b)
    if ba == bb:                                   # execute_command vs execute_command_v1
        return True
    ratio = difflib.SequenceMatcher(None, ba, bb).ratio()
    shorter = min(len(ba), len(bb))
    # Long names one or two edits apart (get_command_history / get_commands_history).
    return shorter >= 8 and ratio >= 0.9


def solicited_params(tool: Any) -> list[str]:
    out = []
    for pname, pschema in schema_properties(tool).items():
        desc = f"{pschema.get('title', '')} {pschema.get('description', '')}".lower()
        if _SOLICIT_NAME.search(pname.lower()) or _SOLICIT_DESC.search(desc):
            out.append(pname)
    return out


@dataclass
class ToolReview:
    name: str
    keep: bool
    reasons: list[str] = field(default_factory=list)
    cleaned_description: str | None = None
    forbidden_params: list[str] = field(default_factory=list)
    preference_score: int = 0


def _clean_description(desc: str, known_tool_names: set[str]) -> tuple[str, list[str], int]:
    reasons: list[str] = []
    kept: list[str] = []
    pref_hits = 0
    for sentence in split_sentences(desc):
        canon = normalize(sentence)
        if _PREFERENCE.search(canon.all):
            pref_hits += 1
            continue
        verdict = classify_text(sentence, known_tool_names=known_tool_names)
        if verdict.label is Label.MALICIOUS or (verdict.label is Label.INSTRUCTION and "addressee" in str(verdict.reasons)):
            reasons.append("injected instruction removed from description")
            continue
        kept.append(sentence)
    whole = classify_text(desc, known_tool_names=known_tool_names)
    if whole.is_malicious and not reasons:
        # Multi-sentence payloads: fall back to the signature-cleaned text.
        reasons.append("description matched an injection pattern as a whole")
        kept = [s for s in kept if not classify_text(s).is_malicious]
    if pref_hits:
        reasons.append(f"{pref_hits} preference-manipulation claim(s) removed")
    if whole.signals & {"zero_width", "bidi_override", "unicode_tags"}:
        reasons.append("hidden characters removed from description")
    return " ".join(kept).strip(), reasons, pref_hits


def review_tools(tools: list[Any]) -> list[ToolReview]:
    """Decide, for each tool, whether it is exposed and with what description."""
    names = [getattr(t, "name", "") for t in tools]
    known = set(names)
    reviews: list[ToolReview] = []
    for tool in tools:
        desc = getattr(tool, "description", "") or ""
        cleaned, reasons, pref = _clean_description(desc, known - {tool.name})
        review = ToolReview(
            name=tool.name, keep=True, reasons=reasons,
            cleaned_description=cleaned if cleaned != desc else None,
            forbidden_params=solicited_params(tool), preference_score=pref,
        )
        if review.forbidden_params:
            review.reasons.append(f"parameter(s) soliciting agent/user data: {', '.join(review.forbidden_params)}")
        reviews.append(review)

    # Exact duplicates: keep the first registration.
    seen: set[str] = set()
    for review in reviews:
        if review.name in seen:
            review.keep = False
            review.reasons.append("duplicate tool name - later registration dropped")
        seen.add(review.name)

    # Near-miss groups: keep the most "plain" member, quarantine decoys.
    alive = [r for r in reviews if r.keep]
    for i, a in enumerate(alive):
        for b in alive[i + 1:]:
            if not (a.keep and b.keep) or not near_miss(a.name, b.name):
                continue
            def suspicion(r: ToolReview) -> tuple:
                decorated = _base_name(r.name) != normalize(r.name).squashed.replace(" ", "")
                non_ascii = any(ord(c) > 127 for c in r.name)
                return (non_ascii, r.preference_score > 0, decorated, len(r.forbidden_params), len(r.reasons), len(r.name))
            loser = max((a, b), key=suspicion)
            winner = b if loser is a else a
            if suspicion(loser) == suspicion(winner):
                # Indistinguishable twins: expose neither name silently — keep
                # the first, and flag the pair so the policy layer can demand
                # confirmation for both.
                loser = b
            loser.keep = False
            loser.reasons.append(f"near-miss of '{winner.name}' (name-collision/preference attack) - quarantined")
    return reviews
