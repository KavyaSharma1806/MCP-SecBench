"""
Runtime behaviour monitoring (instructions.txt Level 4).

Two complementary ideas:

1. Taint tracking (information-flow control, in the spirit of CaMeL /
   "dual-LLM" designs, but cheap and model-free).
   Everything a tool returns is *untrusted*. We remember the concrete
   artefacts it contained — file paths, URLs, e-mail addresses, PIDs, long
   tokens, quoted strings. When the agent later calls a WRITE / EXEC /
   NETWORK / DESTRUCTIVE tool, any argument that carries one of those
   artefacts *and* does not appear in the user's own request is data that
   flowed from an attacker-controllable source into a dangerous sink → block.
   This catches tool-response attacks even when the wording of the
   injection is completely novel, because it reasons about where the
   *values* came from, not about how the text was phrased.

2. Sequence rules over the action trace, e.g.
       read something sensitive  →  write / send / exec   = exfiltration
       same call repeated N times                           = loop / DoS
       total calls above budget                             = runaway agent
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .normalize import normalize
from .policy import SENSITIVE_PATHS, Capability, capability_of, find_secrets

_ARTEFACTS = [
    re.compile(r"(?:[a-zA-Z]:)?(?:[\\/][\w.\-~ ]+){1,}\.[a-z0-9]{1,6}\b", re.I),     # paths with extension
    re.compile(r"(?:~|\.{1,2})?[\\/](?:[\w.\-]+[\\/])*[\w.\-]+", re.I),              # unix-ish paths
    re.compile(r"\b[\w\-]+\.(txt|json|md|csv|py|sh|ps1|bat|exe|log|key|pem|docx?|xlsx?|env|yml|yaml|conf|ini)\b", re.I),
    re.compile(r"https?://[^\s\"'<>)]+", re.I),
    re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    re.compile(r"\bpid\s*[:=]?\s*(\d{2,7})\b", re.I),
    re.compile(r"\b(?:ssh-(?:rsa|ed25519|dss|ecdsa)\s+)?[A-Za-z0-9+/=]{40,}"),
]
_QUOTED = re.compile(r"[\"'`]([^\"'`\n]{6,200})[\"'`]")
_STOP_ARTEFACTS = {"/", "./", "../", "http://", "https://", "/n", "/s"}

# Strong indicators that a *response* actually contained sensitive material
# (mentioning the word "password" in a search result is not enough).
_SENSITIVE_CONTENT = re.compile(
    r"(authorized_keys|id_(rsa|ed25519|ecdsa)|personal_information|-----begin [a-z ]*private key-----|"
    r"\"(phone|ssn|passport|address|date_of_birth|credit_card)\"\s*:)", re.I)

SINK_CAPABILITIES = {Capability.WRITE, Capability.EXEC, Capability.NETWORK, Capability.DESTRUCTIVE}


def extract_artefacts(text: str) -> set[str]:
    found: set[str] = set()
    for pat in _ARTEFACTS:
        for m in pat.finditer(text):
            val = (m.group(1) if pat.groups and m.group(1) and pat.pattern.startswith(r"\bpid") else m.group(0)).strip(" .,;:")
            if len(val) >= 4 and val.lower() not in _STOP_ARTEFACTS:
                found.add(val.lower())
    for m in _QUOTED.finditer(text):
        val = m.group(1).strip()
        if len(val.split()) <= 12:
            found.add(val.lower())
    return found


def _arg_strings(tool_input: Any) -> list[str]:
    if isinstance(tool_input, dict):
        return [json.dumps(v, default=str) if not isinstance(v, str) else v for v in tool_input.values()]
    return [str(tool_input)] if tool_input is not None else []


@dataclass
class FlowVerdict:
    allowed: bool
    reason: str | None = None


@dataclass
class FlowMonitor:
    user_request: str = ""
    max_tool_calls: int = 25
    max_identical_calls: int = 3
    tainted: dict[str, str] = field(default_factory=dict)        # artefact -> source tool
    trace: list[tuple[str, Capability]] = field(default_factory=list)
    call_counts: dict[str, int] = field(default_factory=dict)
    sensitive_read: str | None = None

    def set_user_request(self, text: str) -> None:
        self.user_request = text or ""
        self._user_canon = normalize(self.user_request).canonical
        self._user_artefacts = extract_artefacts(self.user_request)

    def _from_user(self, artefact: str) -> bool:
        canon = getattr(self, "_user_canon", "")
        return artefact in canon or artefact in getattr(self, "_user_artefacts", set())

    # -- before a call ---------------------------------------------------
    def check_call(self, tool_name: str, tool_input: Any) -> FlowVerdict:
        cap = capability_of(tool_name)
        key = f"{tool_name}:{json.dumps(tool_input, sort_keys=True, default=str)}"
        self.call_counts[key] = self.call_counts.get(key, 0) + 1
        if len(self.trace) >= self.max_tool_calls:
            return FlowVerdict(False, f"tool-call budget exhausted ({self.max_tool_calls})")
        if self.call_counts[key] > self.max_identical_calls:
            return FlowVerdict(False, "the same call was repeated too many times (loop guard)")

        if cap in SINK_CAPABILITIES:
            args = " ".join(_arg_strings(tool_input)).lower()
            for artefact, source in self.tainted.items():
                if artefact in args and not self._from_user(artefact):
                    return FlowVerdict(
                        False,
                        f"argument '{artefact[:60]}' came from untrusted output of '{source}', "
                        f"not from the user's request (untrusted data -> {cap.value} sink)",
                    )
            if self.sensitive_read and cap in {Capability.NETWORK, Capability.WRITE, Capability.EXEC}:
                if not SENSITIVE_PATHS.search(getattr(self, "_user_canon", "")):
                    return FlowVerdict(
                        False,
                        f"{cap.value} after reading sensitive data via '{self.sensitive_read}' (possible exfiltration)",
                    )
        return FlowVerdict(True)

    def record_call(self, tool_name: str, tool_input: Any) -> None:
        cap = capability_of(tool_name)
        self.trace.append((tool_name, cap))
        if cap is Capability.READ and SENSITIVE_PATHS.search(" ".join(_arg_strings(tool_input))):
            self.sensitive_read = tool_name

    # -- after a call ----------------------------------------------------
    def observe_response(self, tool_name: str, observation: str) -> None:
        for artefact in extract_artefacts(observation):
            if not self._from_user(artefact):
                self.tainted.setdefault(artefact, tool_name)
        if find_secrets(observation) or _SENSITIVE_CONTENT.search(observation[:50_000]):
            self.sensitive_read = self.sensitive_read or tool_name
