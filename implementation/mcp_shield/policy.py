"""
Capability policy (instructions.txt Level 3): "is this action *permitted*?",
not only "does this text look malicious?".

A tool call is judged against:
  * the tool's own schema           — arguments it never declared are dropped
  * forbidden parameters            — fields that solicit agent/user data (tools.py)
  * capability class of the tool    — read / write / destructive / exec / network
  * the user's request (intent)     — a destructive or exec action needs the
                                      user to have asked for that kind of action
  * argument content                — secrets, private keys, sensitive paths,
                                      dangerous shell commands, path traversal

Everything is data-driven so the policy can be printed on a slide and tuned
without touching code.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .normalize import normalize


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    EXEC = "exec"
    NETWORK = "network"
    OTHER = "other"


# Tool-name tokens → capability (most dangerous class wins). Names are split
# into tokens first, so "get_output" is a read, not a "put".
CAPABILITY_TOKENS: list[tuple[Capability, set[str]]] = [
    (Capability.DESTRUCTIVE, {"kill", "terminate", "delete", "remove", "rm", "erase", "wipe", "drop", "truncate",
                              "format", "shutdown", "reboot", "destroy", "purge", "unlink"}),
    (Capability.EXEC, {"execute", "exec", "run", "shell", "command", "commands", "terminal", "bash", "powershell", "cmd",
                       "eval", "spawn", "process", "script"}),
    (Capability.NETWORK, {"send", "email", "mail", "post", "upload", "http", "request", "webhook", "publish", "share",
                          "transfer", "notify"}),
    (Capability.WRITE, {"write", "edit", "create", "save", "append", "update", "set", "move", "rename", "copy", "insert",
                        "replace", "add", "modify", "put", "store", "patch", "block", "protect", "unprotect"}),
    (Capability.READ, {"read", "get", "list", "search", "find", "query", "fetch", "lookup", "view", "show", "describe",
                       "info", "stat", "retrieve", "history", "download", "open"}),
]

# What a user request must mention before that capability may run.
INTENT_WORDS: dict[Capability, re.Pattern] = {
    Capability.DESTRUCTIVE: re.compile(r"\b(kill|terminate|stop|end|delete|remove|erase|wipe|clean ?up|close|shut ?down|drop|purge)\b"),
    Capability.EXEC: re.compile(r"\b(run|execute|command|terminal|shell|script|install|start|launch|compile|build|ping|check|test)\b"),
    Capability.NETWORK: re.compile(r"\b(send|email|mail|post|upload|share|publish|notify|message)\b"),
    Capability.WRITE: re.compile(r"\b(write|save|create|edit|update|add|append|record|note|store|modify|rename|move|copy|change|put|insert|make|generate|document|draft|log|remember)\b"),
}

SENSITIVE_PATHS = re.compile(
    r"(\.ssh([\\/]|$)|authorized_keys|id_(rsa|dsa|ecdsa|ed25519)|known_hosts|\.gnupg|\.aws[\\/]credentials|"
    r"\.env\b|\.npmrc|\.pypirc|\.git[\\/]config|\.bash(rc|_profile)|\.zshrc|\.profile\b|crontab|"
    r"/etc/(passwd|shadow|sudoers|hosts)|system32|startup|\\run\b|appdata[\\/](roaming[\\/]microsoft[\\/]windows[\\/]start menu)|"
    r"personal_information|password|credential|secret|wallet|keychain)",
    re.I,
)
TRAVERSAL = re.compile(r"(\.\.[\\/]){1,}|^[\\/]{2}|%2e%2e|\x00")
DANGEROUS_COMMANDS = re.compile(
    r"(\brm\s+-[rf]{1,2}\b|\bdel\s+/[sq]|\bformat\s+[a-z]:|\bmkfs|\bdd\s+if=|:\(\)\s*\{|\bshutdown\b|\breboot\b|"
    r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*\b|\bchown\b|\bsudo\b|\bnc\b|\bncat\b|\bnetcat\b|\btelnet\b|"
    r"(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sh|bash|iex|powershell)|\bbase64\s+-d\b.*\|\s*(sh|bash)|"
    r"powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\b|\biex\b|invoke-expression|\breg\s+(add|delete)\b|"
    r"\bschtasks\b|\bcrontab\s+-|\bssh-keygen\b|>>?\s*~?[\\/]?\.ssh|authorized_keys|\btaskkill\b|\bkill\s+-9\b|\bpkill\b|"
    r"\bscp\b|\brsync\b.*@|\bftp\b|/dev/tcp/)",
    re.I,
)
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh_public_key", re.compile(r"ssh-(rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,}", re.I)),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("password_assignment", re.compile(r"\b(password|passwd|pwd|secret|api_key|token)\s*[:=]\s*\S{6,}", re.I)),
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_secrets(text: str) -> list[str]:
    hits = []
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            if name == "credit_card" and not _luhn_ok(m.group(0)):
                continue
            hits.append(name)
            break
    for token in re.findall(r"[A-Za-z0-9+/_=-]{32,}", text):
        if shannon_entropy(token) > 4.5 and re.search(r"\d", token) and re.search(r"[A-Za-z]", token):
            hits.append("high_entropy_token")
            break
    return hits


def capability_of(tool_name: str) -> Capability:
    split = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", tool_name)
    ordered = [t for t in re.split(r"[^a-z0-9]+", normalize(split).canonical) if t]
    tokens = set(ordered)
    read_words = CAPABILITY_TOKENS[-1][1]
    risky = CAPABILITY_TOKENS[0][1] | CAPABILITY_TOKENS[2][1]
    # "get_command_history", "read_process_output": a leading read verb wins
    # over exec/write nouns, but never over destructive or network verbs.
    if ordered and ordered[0] in read_words and not tokens & risky:
        return Capability.READ
    for cap, words in CAPABILITY_TOKENS:
        if tokens & words:
            return cap
    return Capability.OTHER


@dataclass
class Policy:
    """Tunable knobs. Defaults are strict: an autonomous agent should not do
    destructive things nobody asked for."""

    require_intent_for: set[Capability] = field(default_factory=lambda: {
        Capability.DESTRUCTIVE, Capability.EXEC, Capability.NETWORK, Capability.WRITE})
    allow_sensitive_paths: bool = False
    max_tool_calls: int = 25
    max_identical_calls: int = 3
    max_argument_chars: int = 20_000
    max_response_chars: int = 30_000
    drop_undeclared_args: bool = True
    tool_allowlist: set[str] | None = None        # None = every reviewed tool
    tool_denylist: set[str] = field(default_factory=set)


@dataclass
class CallDecision:
    allowed: bool
    reason: str | None = None
    rewritten_input: Any = None
    notes: list[str] = field(default_factory=list)


def user_intends(capability: Capability, user_request: str) -> bool:
    pat = INTENT_WORDS.get(capability)
    if pat is None:
        return True
    return bool(pat.search(normalize(user_request or "").canonical))


def _flatten(value: Any) -> list[str]:
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            out.append(str(k))
            out.extend(_flatten(v))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            out.extend(_flatten(v))
        return out
    return [str(value)] if value is not None else []


def evaluate_call(
    policy: Policy,
    tool_name: str,
    tool_input: Any,
    *,
    declared_params: set[str] | None,
    forbidden_params: set[str],
    user_request: str,
) -> CallDecision:
    notes: list[str] = []
    if policy.tool_allowlist is not None and tool_name not in policy.tool_allowlist:
        return CallDecision(False, f"tool '{tool_name}' is not on this task's allowlist")
    if tool_name in policy.tool_denylist:
        return CallDecision(False, f"tool '{tool_name}' is denied by policy")

    args = dict(tool_input) if isinstance(tool_input, dict) else ({"input": tool_input} if tool_input not in (None, "") else {})

    # 1. Forbidden (data-soliciting) parameters are stripped, never forwarded.
    for key in list(args):
        if key in forbidden_params or key.lower() in {p.lower() for p in forbidden_params}:
            if args[key] not in (None, "", [], {}):
                notes.append(f"stripped soliciting parameter '{key}'")
            args.pop(key)

    # 2. Undeclared arguments are dropped (strict schema).
    if policy.drop_undeclared_args and declared_params is not None and isinstance(tool_input, dict):
        for key in list(args):
            if key not in declared_params:
                notes.append(f"dropped undeclared argument '{key}'")
                args.pop(key)

    flat = " ".join(_flatten(args))
    if len(flat) > policy.max_argument_chars:
        return CallDecision(False, "arguments exceed the size limit")
    canon = normalize(flat)

    cap = capability_of(tool_name)
    if cap in policy.require_intent_for and not user_intends(cap, user_request):
        return CallDecision(False, f"'{tool_name}' is a {cap.value} action the user did not ask for")

    secrets_found = find_secrets(flat)
    if secrets_found and cap in {Capability.WRITE, Capability.NETWORK, Capability.EXEC, Capability.OTHER}:
        return CallDecision(False, f"call would write/send secret material ({', '.join(secrets_found)})")

    if TRAVERSAL.search(flat):
        return CallDecision(False, "path traversal in arguments")
    if not policy.allow_sensitive_paths and SENSITIVE_PATHS.search(canon.canonical):
        if not SENSITIVE_PATHS.search(normalize(user_request or "").canonical):
            return CallDecision(False, "call touches a sensitive path or file the user did not mention")
    if cap is Capability.EXEC and DANGEROUS_COMMANDS.search(canon.canonical):
        return CallDecision(False, "dangerous shell command")

    rewritten = args if (notes or not isinstance(tool_input, dict)) else tool_input
    if not isinstance(tool_input, dict):
        rewritten = tool_input
    return CallDecision(True, None, rewritten_input=rewritten, notes=notes)
