"""
Text canonicalisation — defeat the cheap obfuscations that walk straight past
a keyword list.

Every detector in mcp_shield runs on *views* of the text produced here, not on
the raw string:

  raw        the original text (for span reporting)
  canonical  NFKC, invisible/bidi characters removed, homoglyphs folded,
             whitespace collapsed, lower-cased
  squashed   canonical with letter-spacing undone ("i g n o r e" -> "ignore")
             and leetspeak folded ("1gn0r3" -> "ignore")
  decoded    plain text recovered from base64 / hex / Unicode-tag smuggling,
             appended so hidden payloads are scanned too

The function also reports *which* obfuscations were present: hidden
characters in a tool description or tool output are themselves a strong
signal, regardless of what they spell.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width, joiners, word-joiner, BOM, soft hyphen, Mongolian vowel sep.
_INVISIBLE = dict.fromkeys(
    [0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF], None
)
# Bidirectional overrides / isolates ("Trojan Source").
_BIDI = dict.fromkeys([0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069], None)
# Unicode "tag" block U+E0000–U+E007F mirrors ASCII and renders invisibly —
# a known channel for smuggling instructions to LLMs.
_TAG_START, _TAG_END = 0xE0000, 0xE007F

# Cross-script look-alikes (Cyrillic/Greek → Latin) not folded by NFKC.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "Ι": "I", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "ν": "v",
    "α": "a", "ι": "i", "ρ": "p", "τ": "t", "υ": "u",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_SPACED = re.compile(r"\b(?:[a-z][\s._\-*]){3,}[a-z]\b")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
_WS = re.compile(r"\s+")


@dataclass
class TextViews:
    raw: str
    canonical: str
    squashed: str
    decoded: str
    signals: set[str] = field(default_factory=set)

    @property
    def all(self) -> str:
        """Every view joined — what the pattern detectors scan."""
        return "\n".join(v for v in (self.canonical, self.squashed, self.decoded) if v)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return ok / len(text)


def _try_decode_blobs(text: str, signals: set[str]) -> list[str]:
    out: list[str] = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", decoded):
            out.append(decoded)
            signals.add("base64_text")
    for m in _HEX.finditer(text):
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", decoded):
            out.append(decoded)
            signals.add("hex_text")
    return out


def normalize(text: str, *, max_len: int = 200_000) -> TextViews:
    if not isinstance(text, str):
        text = str(text)
    text = text[:max_len]
    signals: set[str] = set()

    # Recover Unicode-tag smuggled ASCII before stripping it.
    tag_chars = [chr(ord(c) - _TAG_START) for c in text if _TAG_START <= ord(c) <= _TAG_END]
    smuggled = "".join(tag_chars).strip()
    if tag_chars:
        signals.add("unicode_tags")
    stripped = "".join(c for c in text if not (_TAG_START <= ord(c) <= _TAG_END))

    if any(ord(c) in _INVISIBLE for c in stripped):
        signals.add("zero_width")
    if any(ord(c) in _BIDI for c in stripped):
        signals.add("bidi_override")
    stripped = stripped.translate(_INVISIBLE).translate(_BIDI)

    nfkc = unicodedata.normalize("NFKC", stripped)
    folded = nfkc.translate(_HOMOGLYPHS)
    if folded != nfkc:
        signals.add("homoglyphs")
    # Drop remaining combining marks (zalgo-style noise) after decomposition.
    folded = "".join(c for c in unicodedata.normalize("NFKD", folded) if not unicodedata.combining(c))
    canonical = _WS.sub(" ", folded).strip().lower()

    squashed = _SPACED.sub(lambda m: re.sub(r"[\s._\-*]", "", m.group(0)), canonical)
    if squashed != canonical:
        signals.add("letter_spacing")
    leet = squashed.translate(_LEET)
    if leet != squashed and re.search(r"[a-z][0-9@$][a-z]", squashed):
        signals.add("leetspeak")
    squashed = leet

    decoded_parts = _try_decode_blobs(stripped, signals)
    if smuggled:
        decoded_parts.append(smuggled)
    decoded = _WS.sub(" ", " \n".join(decoded_parts)).strip().lower()

    return TextViews(raw=text, canonical=canonical, squashed=squashed, decoded=decoded, signals=signals)


def split_sentences(text: str) -> list[str]:
    """Rough sentence/line splitter that keeps delimiters attached."""
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p for p in (s.strip() for s in parts) if p]
