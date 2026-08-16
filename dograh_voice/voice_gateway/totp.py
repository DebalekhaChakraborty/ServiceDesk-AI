"""RFC 6238 TOTP and deterministic parsing of a SPOKEN six-digit code.

Two jobs, both deliberately dependency-free and deterministic:

  1. TOTP generation/verification (RFC 6238 over RFC 4226 HMAC-OTP). No TOTP
     library is installed in this venv, and the venv is shared with the running
     ServiceDesk process, so adding one is not worth the blast radius. The
     algorithm is short and fully specified.

  2. Turning what a person said into six digits. This is done by exact lookup,
     never by a model: the LLM transcribes speech and nothing more. Asking a
     model to "repair" a half-heard code is how a wrong code becomes an
     accepted one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional

DIGITS = 6
PERIOD_SECONDS = 30

# Voice adds real latency: the caller hears the prompt, opens an app, reads six
# digits aloud, Gemini transcribes, the gateway parses. One step either side
# (±30s) covers that. Wider windows multiply the number of codes valid at once,
# which is exactly what an attacker wants.
DRIFT_STEPS = 1


def generate_seed() -> str:
    """A fresh base32 TOTP seed. 160 bits, the RFC 4226 recommended length."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_seed(seed_b32: str) -> bytes:
    padded = seed_b32.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_at(seed_b32: str, timestep: int) -> str:
    """The code for one specific timestep."""
    digest = hmac.new(_decode_seed(seed_b32), struct.pack(">Q", timestep), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def current_timestep(now: Optional[float] = None) -> int:
    return int((now if now is not None else time.time()) // PERIOD_SECONDS)


def find_matching_timestep(
    seed_b32: str, code: str, now: Optional[float] = None, drift: int = DRIFT_STEPS
) -> Optional[int]:
    """Return the timestep a code belongs to, or None.

    Returning the timestep rather than a bool is what makes one-time use
    enforceable: the caller records which step was consumed.

    Every candidate is compared in constant time and the loop is NOT
    short-circuited, so the time taken does not reveal which step matched.
    """
    if not isinstance(code, str) or len(code) != DIGITS or not code.isdigit():
        return None

    step = current_timestep(now)
    matched: Optional[int] = None
    for candidate in range(step - drift, step + drift + 1):
        if hmac.compare_digest(totp_at(seed_b32, candidate), code):
            matched = candidate
    return matched


def provisioning_uri(seed_b32: str, account: str, issuer: str = "ServiceDesk Recovery") -> str:
    """otpauth:// URI for authenticator apps (QR content, or manual entry)."""
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={seed_b32}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    )


# --------------------------------------------------------------------------
# Spoken code parsing
# --------------------------------------------------------------------------

# EXACT digit words only. No "oh" for zero, no "for"/"to"/"ate" homophones:
# a homophone table turns a misheard word into a confidently wrong digit, and
# the caller repeating themselves is far cheaper than a wrong acceptance.
_DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}

_SEPARATORS = str.maketrans({c: " " for c in ",.;:-–—_/\\|()[]{}!?'\"“”‘’"})


class SpokenCodeError(Exception):
    """The utterance did not yield exactly six digits."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        # A coarse category only. Never carries the utterance or partial digits.
        self.category = category


def parse_spoken_code(utterance: str) -> str:
    """Turn a spoken utterance into exactly six digits, or raise.

    Handles the forms people actually use:
        "482169"                      -> 482169
        "4 8 2 1 6 9"                 -> 482169
        "four eight two one six nine" -> 482169
        "four, eight, two, one, six, nine"
        "my code is 482169"           -> 482169

    Mixed digits and words are accepted because people do it ("four eight 2 1
    six nine"). Anything that does not resolve to exactly six digits is
    rejected outright rather than guessed at.
    """
    if not isinstance(utterance, str) or not utterance.strip():
        raise SpokenCodeError("empty")

    tokens = utterance.lower().translate(_SEPARATORS).split()

    digits: list[str] = []
    for token in tokens:
        if token in _DIGIT_WORDS:
            digits.append(_DIGIT_WORDS[token])
        elif token.isdigit():
            # "482169" or "48 21 69" - both are unambiguous digit runs.
            digits.extend(token)
        # Any other word (filler, "my code is", "um") is ignored: it carries
        # no digit and cannot change the result.

    if len(digits) != DIGITS:
        # Deliberately one category for both too-few and too-many. Telling the
        # caller "you gave five digits" is a partial-match oracle.
        raise SpokenCodeError("not_six_digits")

    return "".join(digits)
