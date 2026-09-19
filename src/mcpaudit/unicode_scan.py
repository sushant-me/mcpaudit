"""Invisible and confusable characters in text that a model will read.

Tool descriptions are not documentation. They are injected into the model's context, so
a description is executable in the only sense that matters: it can carry instructions.
Two ways to hide those instructions from the human reviewing the server:

* **Invisible characters.** Unicode has code points that render as nothing — the tag
  block (U+E0000..U+E007F, which mirrors ASCII one-for-one), zero-width spaces and
  joiners, bidirectional overrides (the *trojan source* trick), and variation selectors.
  A reviewer sees a clean sentence; a tokenizer sees the payload.
* **Confusable characters.** `раypal` with a Cyrillic `а` is a different string that
  looks identical. In a tool name it defeats an allowlist; in a description it can
  defeat a keyword search.

The tag block is the sharpest of these: each code point maps to a printable ASCII
character, so a whole instruction can be encoded into text that occupies no visible
width. `decode_tag_block` does that mapping, which turns "suspicious invisible
characters" into the actual string an attacker was hiding — far more useful in a report
than a list of code points.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

#: Unicode ranges that render as nothing (or as something other than what they carry).
INVISIBLE_RANGES: tuple[tuple[int, int, str], ...] = (
    (0xE0000, 0xE007F, "unicode tag block (invisible ASCII channel)"),
    (0x200B, 0x200F, "zero-width and directional marks"),
    (0x202A, 0x202E, "bidirectional embedding/override (trojan source)"),
    (0x2060, 0x2064, "word joiner and invisible operators"),
    (0x2066, 0x2069, "bidirectional isolate controls"),
    (0xFE00, 0xFE0F, "variation selectors"),
    (0xFEFF, 0xFEFF, "zero-width no-break space (BOM)"),
    (0x00AD, 0x00AD, "soft hyphen"),
    (0x180E, 0x180E, "Mongolian vowel separator"),
    (0x3164, 0x3164, "Hangul filler"),
    (0xFFA0, 0xFFA0, "halfwidth Hangul filler"),
)

#: A deliberately small confusables map: the characters that most often appear in
#: look-alike tool names. This is a partial check and the finding says so — a complete
#: confusables table is thousands of entries and belongs in a dependency, not here.
CONFUSABLES: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s",
    "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ⅰ": "i", "ⅼ": "l",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ѡ": "w", "ӏ": "l",
    "ⅽ": "c", "ⅾ": "d", "ⅿ": "m", "⁰": "0", "¹": "1", "²": "2", "³": "3",
    "‐": "-", "–": "-", "—": "-", "’": "'", "“": '"', "”": '"',
}


@dataclass(frozen=True)
class InvisibleFinding:
    """An invisible or confusable run inside a string."""

    kind: str
    detail: str
    decoded: str = ""
    position: int = 0


def decode_tag_block(text: str) -> str:
    """Recover the ASCII that tag characters (U+E0000..U+E007F) encode.

    Each tag code point maps to the printable ASCII character 0x20 higher, so
    ``U+E0069`` is ``i``. Returns the decoded string, empty if there is no tag block.
    """
    decoded = "".join(chr(cp - 0xE0000) for cp in map(ord, text) if 0xE0000 <= cp <= 0xE007F)
    return decoded


def find_invisible(text: str) -> list[InvisibleFinding]:
    """Report every invisible-character run, with the tag block decoded."""
    findings: list[InvisibleFinding] = []
    for index, char in enumerate(text):
        codepoint = ord(char)
        for low, high, label in INVISIBLE_RANGES:
            if low <= codepoint <= high:
                decoded = decode_tag_block(text) if label.startswith("unicode tag") else ""
                findings.append(
                    InvisibleFinding(
                        kind="invisible",
                        detail=f"{label}: U+{codepoint:04X}",
                        decoded=decoded,
                        position=index,
                    )
                )
                break
    # Collapse the tag-block entries into one, since every tag character decodes into
    # the same recovered string and ten findings for one hidden sentence is noise.
    collapsed: list[InvisibleFinding] = []
    seen_tags = False
    for finding in findings:
        if finding.detail.startswith("unicode tag"):
            if seen_tags:
                continue
            seen_tags = True
        collapsed.append(finding)
    return collapsed


def find_confusables(text: str) -> list[InvisibleFinding]:
    """Report characters that look like ASCII but are not.

    The finding carries the normalised form, so a reviewer can see whether
    ``раypal`` was standing in for ``paypal``.
    """
    findings: list[InvisibleFinding] = []
    for index, char in enumerate(text):
        if char in CONFUSABLES and ord(char) > 0x7F:
            findings.append(
                InvisibleFinding(
                    kind="confusable",
                    detail=f"U+{ord(char):04X} {unicodedata.name(char, '?')} looks like {CONFUSABLES[char]!r}",
                    decoded=CONFUSABLES[char],
                    position=index,
                )
            )
    return findings


def skeleton(text: str) -> str:
    """Fold confusables to ASCII, for comparing a name against an allowlist."""
    return "".join(CONFUSABLES.get(c, c) for c in text)


def strip_invisible(text: str) -> str:
    """Remove every invisible character, for showing what a human would see."""
    out = []
    for char in text:
        codepoint = ord(char)
        if any(low <= codepoint <= high for low, high, _ in INVISIBLE_RANGES):
            continue
        out.append(char)
    return "".join(out)


def summarise(text: str, limit: int = 120) -> str:
    """A readable rendering: invisible characters made visible as their code points."""
    rendered = []
    for char in text:
        codepoint = ord(char)
        if any(low <= codepoint <= high for low, high, _ in INVISIBLE_RANGES):
            rendered.append(f"<U+{codepoint:04X}>")
        else:
            rendered.append(char)
    joined = "".join(rendered)
    return joined[:limit] + ("…" if len(joined) > limit else "")
