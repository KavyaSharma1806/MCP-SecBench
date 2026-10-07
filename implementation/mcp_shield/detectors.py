"""
Injection detection: is this text DATA, an INSTRUCTION, or a MALICIOUS
INSTRUCTION aimed at the agent?

v1 (defenses/mcp_guard.py) asked "does this text contain one of MSB's template
strings?". That misses paraphrases and obfuscation and says nothing about
intent. mcp_shield scores every sentence on independent feature families:

  addressee   — is the text talking *to the model*? ("you must", "assistant",
                "as an AI", "your instructions", fake role headers)
  override    — does it try to replace the task? (ignore / disregard /
                forget / new task / instead / before you answer …, in many
                phrasings, after canonicalisation)
  action      — does it ask for a tool call or a side effect? (call/run/use
                <tool>, write/save/delete/send/kill/upload …)
  sensitive   — does it reach for something valuable? (keys, credentials,
                personal data, system prompt, conversation history)
  authority   — impersonation of the user/system/admin/developer, urgency,
                secrecy ("do not tell the user")
  exfil       — URLs with query data, markdown images, email addresses as a
                destination
  structural  — MSB template markers, hidden characters, encoded payloads

A sentence is malicious only when several families co-occur (e.g. addressee
+ override, or action + sensitive + authority). A recipe step ("Stir for 5
minutes") is imperative but has no addressee, no override, no tool and no
sensitive target, so it stays DATA — that is what keeps false positives low.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .normalize import TextViews, normalize, split_sentences


class Label(str, Enum):
    DATA = "data"
    INSTRUCTION = "instruction"
    MALICIOUS = "malicious_instruction"


# ── Known high-precision signatures (MSB templates + common jailbreak forms) ──
SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("msb_information_tag", re.compile(r"<\s*/?\s*information\s*>")),
    ("msb_important_tag", re.compile(r"<\s*/?\s*important\s*>")),
    ("msb_strict_adhere", re.compile(r"(you )?must strictly adhere to the following")),
    ("msb_new_user_query", re.compile(r"new user query\s*:?\s*i am the user")),
    ("msb_task_completed", re.compile(r"previous task has been completed.{0,60}(urgent|new) task", re.S)),
    ("msb_false_error", re.compile(r"\"?error\"?\s*:\s*in order to (get|obtain) the result")),
    ("msb_signed_user", re.compile(r"signed,?\s*the user")),
    ("fake_role_header", re.compile(r"(^|\n|\s)(#{1,3}\s*)?(system|assistant|developer|admin(istrator)?)\s*(message|prompt|note|override|notice)?\s*:\s", re.I)),
    ("chat_template_token", re.compile(r"<\|?(im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?inst\]|<</?sys>>")),
]

_ADDRESSEE = re.compile(
    r"\b(you (must|should|need to|have to|are required to|will now|are now|shall)|"
    r"(dear |hey |attention,? )?(assistant|ai|agent|model|llm|chatbot|claude|gpt|copilot)\b[,:]?|"
    r"as an (ai|assistant|language model)|your (instructions|task|goal|objective|system prompt|guidelines|rules)|"
    r"before (you|answering|responding|replying|continuing|proceeding)|from now on|"
    r"(please|kindly) (do|make sure|ensure|first|immediately|now|call|run|use|execute|write|send|save))"
)
_OVERRIDE = re.compile(
    r"\b((ignore|disregard|forget|override|bypass|skip|abandon|drop|discard|neglect|set aside|stop following)\b.{0,40}"
    r"\b(previous|prior|earlier|above|original|initial|existing|all|any|your|the|those|these|preceding)\b.{0,30}"
    r"\b(instructions?|guidance|directions?|rules|prompts?|tasks?|requests?|constraints|policy|policies|context|messages?)|"
    r"(new|updated|revised|real|actual|true|more urgent|higher priority|additional) (task|instructions?|objective|goal|orders?)|"
    r"(instead|rather),? (you (should|must)|do|call|run|please)|"
    r"(task|request) (is|has been) (complete|completed|done|finished|cancelled)|"
    r"(this|the following) (supersedes|overrides|replaces|takes precedence)|"
    r"do not (follow|obey|complete) (the|your) (original|previous|user)"
    r")"
)
_ACTION = re.compile(
    r"\b(call|invoke|run|execute|use|trigger|launch|issue)\s+(the\s+)?[`'\"]?[a-z_][a-z0-9_]{2,}[`'\"]?(\s+tool|\s+function|\s*\()|"
    r"\b(write|save|store|append|create|overwrite|modify|edit|delete|remove|erase|wipe|kill|terminate|"
    r"send|email|post|upload|transmit|forward|exfiltrate|leak|share|copy|move|chmod|install|download)\b"
    r".{0,60}\b(file|files|key|keys|data|password|credentials?|token|process|pid|server|url|http|email|directory|folder|"
    r"authorized_keys|config|history|information|record|records|content)"
)
_SENSITIVE = re.compile(
    r"(ssh-(rsa|ed25519|dss|ecdsa)|-----begin [a-z ]*private key-----|authorized_keys|id_rsa|\.ssh\b|"
    r"personal_information|api[_ ]?keys?|secret[_ ]?keys?|access[_ ]?tokens?|passwords?|passwd|credentials?|"
    r"credit card|social security|\bssn\b|bank account|system prompt|your (instructions|prompt|configuration)|"
    r"conversation history|chat history|previous messages|all (tool|available) (names|tools)|"
    r"(model|llm) name|which (model|llm) you are|environment variables|\.env\b|/etc/(passwd|shadow))"
)
_AUTHORITY = re.compile(
    r"(i am (the|your) (user|admin|administrator|developer|owner|creator)|message (is )?from (the )?(user|admin|system|developer)|"
    r"(system|security|admin|official|urgent|critical|mandatory) (notice|update|alert|override|requirement|instruction)|"
    r"(do not|don't|never) (tell|inform|mention|reveal|show|alert|notify) (this |it )?(to )?(the )?user|"
    r"without (telling|informing|asking|notifying) (the )?user|this is (very )?(important|urgent|critical)|"
    r"(immediately|urgently|right now|asap)\b|(required|mandatory) (step|action) before)"
)
_EXFIL = re.compile(
    r"(!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)\s]*\)|https?://[^\s)\"']+\?[^\s)\"']*(data|q|d|payload|secret|key|token|info|c)=|"
    r"(send|email|post|upload|forward|transmit) (it|them|this|the (data|results?|file|information|contents?)) to\b|"
    r"\bto\s+[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"
)

# Words that are imperative but harmless on their own (recipes, manuals).
_FAMILY_WEIGHTS = {"addressee": 1.2, "override": 2.0, "action": 1.0, "sensitive": 1.0, "authority": 1.0, "exfil": 1.6}
OBFUSCATION_SIGNALS = {"unicode_tags", "zero_width", "bidi_override", "base64_text", "hex_text", "letter_spacing", "leetspeak"}


@dataclass
class SentenceVerdict:
    text: str
    families: set[str]
    score: float
    label: Label


@dataclass
class Finding:
    label: Label
    score: float
    reasons: list[str] = field(default_factory=list)
    malicious_sentences: list[str] = field(default_factory=list)
    signals: set[str] = field(default_factory=set)

    @property
    def is_malicious(self) -> bool:
        return self.label is Label.MALICIOUS


def _families(sentence: str) -> set[str]:
    fam = set()
    if _ADDRESSEE.search(sentence):
        fam.add("addressee")
    if _OVERRIDE.search(sentence):
        fam.add("override")
    if _ACTION.search(sentence):
        fam.add("action")
    if _SENSITIVE.search(sentence):
        fam.add("sensitive")
    if _AUTHORITY.search(sentence):
        fam.add("authority")
    if _EXFIL.search(sentence):
        fam.add("exfil")
    return fam


def _sentence_label(fam: set[str]) -> tuple[float, Label]:
    score = sum(_FAMILY_WEIGHTS[f] for f in fam)
    malicious = (
        "override" in fam and len(fam) >= 2
        or {"addressee", "action"} <= fam and ({"sensitive", "authority", "exfil"} & fam)
        or {"action", "sensitive"} <= fam and ({"authority", "exfil"} & fam)
        or "exfil" in fam and ({"sensitive", "action", "addressee"} & fam)
        or {"authority", "addressee"} <= fam and "action" in fam
    )
    if malicious:
        return score, Label.MALICIOUS
    if {"addressee", "action"} <= fam or "override" in fam or ("authority" in fam and "addressee" in fam):
        return score, Label.INSTRUCTION
    return score, Label.DATA


def classify_text(text: str, *, known_tool_names: set[str] | None = None) -> Finding:
    """Heuristic semantic classifier over canonicalised text."""
    views: TextViews = normalize(text)
    reasons: list[str] = []
    malicious: list[str] = []
    best = Label.DATA
    total = 0.0

    scan = views.all
    sig_hits = [name for name, pat in SIGNATURES if pat.search(scan)]
    if sig_hits:
        reasons.append("signature:" + ",".join(sig_hits))

    obfuscation = views.signals & OBFUSCATION_SIGNALS
    if obfuscation:
        reasons.append("obfuscation:" + ",".join(sorted(obfuscation)))

    # Sentence-level scoring on every view (canonical, de-obfuscated, decoded).
    seen: set[str] = set()
    for view in (views.canonical, views.squashed, views.decoded):
        for sentence in split_sentences(view):
            if sentence in seen or len(sentence) < 8:
                continue
            seen.add(sentence)
            fam = _families(sentence)
            steers_tool = bool(known_tool_names) and "action" in fam and any(
                re.search(rf"\b{re.escape(t.lower())}\b", sentence) for t in known_tool_names)
            score, label = _sentence_label(fam)
            if steers_tool:
                # Untrusted text telling the agent to use one of ITS OWN tools is
                # steering the agent, not informing a reader.
                label = Label.MALICIOUS
            total += score
            if label is Label.MALICIOUS:
                malicious.append(sentence)
                best = Label.MALICIOUS
            elif label is Label.INSTRUCTION and best is Label.DATA:
                best = Label.INSTRUCTION

    if sig_hits and best is not Label.MALICIOUS:
        # A known attack template is malicious even when its payload sentence
        # was paraphrased away from our families.
        best = Label.MALICIOUS
    if obfuscation and best is Label.INSTRUCTION:
        best = Label.MALICIOUS          # hidden + imperative = smuggling
    if {"unicode_tags", "bidi_override"} & obfuscation and best is Label.DATA and views.decoded:
        best = Label.INSTRUCTION        # invisible text is never legitimate data

    if malicious:
        reasons.append(f"{len(malicious)} malicious sentence(s)")
    return Finding(label=best, score=round(total, 2), reasons=reasons, malicious_sentences=malicious, signals=views.signals)


def redact_sentences(text: str, finding: Finding) -> tuple[str, int]:
    """
    Remove only the offending sentences from the *raw* text, keeping the rest
    of a legitimate document usable (v1 withheld the whole observation).
    Matching is done on canonical forms so obfuscated sentences are found.
    """
    if not finding.malicious_sentences:
        return text, 0
    bad = set(finding.malicious_sentences)
    kept, removed = [], 0
    for raw_sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        canon = normalize(raw_sentence)
        if canon.canonical in bad or canon.squashed in bad or any(b in canon.all for b in bad if len(b) > 20):
            removed += 1
            kept.append("[removed by mcp_shield: instruction aimed at the agent]")
        else:
            kept.append(raw_sentence)
    return "\n".join(s for s in kept if s.strip()), removed
