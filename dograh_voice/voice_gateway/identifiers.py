"""Deterministic extraction of a LOOKUP IDENTIFIER from a spoken utterance.

Nothing in this module authenticates anybody. Everything here does one job:
turn what a caller said into a normalised key that selects at most one candidate
record. Duo performs the actual authentication.

Two rules drive the whole design.

**A spoken NAME is never an identifier.** Names collide, transcribe badly, and
are trivially known to an attacker. "My name is John Smith" yields nothing here
and never reaches a lookup.

**No fuzzy matching, ever.** No Levenshtein, no nearest-neighbour, no model
deciding between candidates. A misheard identifier must produce a miss, not a
confident match on somebody else's record. Everything below is exact lookup on
a normalised value; when normalisation is ambiguous we emit explicit *candidate*
forms and let the store fail closed if more than one record matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

# Employee IDs are digits-only for this PoC. Bounds exist so a stray digit run
# ("I've been waiting 20 minutes") cannot become a lookup key.
EMPLOYEE_ID_MIN_DIGITS = 4
EMPLOYEE_ID_MAX_DIGITS = 12

# E.164 allows at most 15 digits; below 8 is not a routable mobile number.
MOBILE_MIN_DIGITS = 8
MOBILE_MAX_DIGITS = 15

EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}")

_DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}

# Cue words that name which KIND of identifier the caller is giving. Matching is
# exact-token, so "identity" never counts as "id".
_UPN_CUES = {"email", "e-mail", "mail", "upn", "address"}
_MOBILE_CUES = {"mobile", "phone", "cell", "cellphone", "telephone", "handset"}
_EMPLOYEE_CUES = {"employee", "employe", "staff", "badge", "payroll", "personnel", "emp", "id"}

# Cues that a caller is offering a NAME. Recognised only so the miss can be
# logged accurately; the caller-visible reply is the same generic one.
_NAME_CUES = {"name", "called"}

# Stop words used when rebuilding a spoken email. Walking outward from "at"
# halts here so "my work email is alice at example dot com" does not absorb
# "work" or "email" into the local part.
_EMAIL_STOP_WORDS = {
    "is", "my", "work", "working", "email", "e-mail", "mail", "address", "upn",
    "the", "its", "it's", "corporate", "company", "account", "that's", "thats",
    "please", "sure", "okay", "ok", "yes", "and", "so", "um", "uh",
}

# Stripped before digit extraction. "@" and "." survive because an email token
# needs them; they are removed separately on the digit path.
_PUNCT = ",;:-–—_/\\|()[]{}!?'\"“”‘’"
_DIGIT_SEPARATORS = str.maketrans({c: " " for c in _PUNCT + ".@"})
_WORD_SEPARATORS = str.maketrans({c: " " for c in _PUNCT})


class IdentifierKind(str, Enum):
    EMPLOYEE_ID = "employee_id"
    UPN = "upn"
    MOBILE = "mobile"
    # A digit run with no cue word. Could be either an employee ID or a mobile
    # number, so the store checks both and fails closed if both match.
    UNSPECIFIED_DIGITS = "unspecified_digits"


class IdentifierError(Exception):
    """No usable identifier in the utterance.

    `category` is coarse and for local logs only. Every caller-visible reply is
    identical, so nothing here can become an enumeration oracle.
    """

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class SpokenIdentifier:
    kind: IdentifierKind
    value: str

    def redacted(self) -> str:
        """Log-safe rendering. The identifier value itself is never logged."""
        return f"{self.kind.value}:len{len(self.value)}"


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

def normalize_employee_id(raw: str) -> str:
    """Digits only, exact match. Separators and spacing are discarded."""
    digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
    if not (EMPLOYEE_ID_MIN_DIGITS <= len(digits) <= EMPLOYEE_ID_MAX_DIGITS):
        raise IdentifierError("employee_id_bad_length")
    return digits


def normalize_upn(raw: str) -> str:
    """Trim and lowercase. UPNs are case-insensitive; nothing else is changed."""
    value = str(raw or "").strip().lower()
    if not EMAIL_RE.fullmatch(value):
        raise IdentifierError("upn_malformed")
    return value


def normalize_mobile(raw: str, default_calling_code: Optional[str] = None) -> str:
    """Strict E.164 for STORAGE. Refuses to guess a country.

    A stored number that silently acquired the wrong country code would point at
    the wrong person forever, so the write path demands either a leading "+" or
    an explicitly configured default calling code.
    """
    text = str(raw or "").strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        raise IdentifierError("mobile_missing")

    if not text.startswith("+"):
        if not default_calling_code:
            raise IdentifierError("mobile_requires_country_code")
        digits = str(default_calling_code).lstrip("+") + digits

    if not (MOBILE_MIN_DIGITS <= len(digits) <= MOBILE_MAX_DIGITS):
        raise IdentifierError("mobile_bad_length")
    return "+" + digits


def mobile_candidates(digits: str, default_calling_code: Optional[str] = None,
                      spoken_plus: bool = False) -> list[str]:
    """Exact E.164 forms a spoken digit run could be, for LOOKUP only.

    A caller who says ten digits may mean the national form; one who says the
    country code may not say "plus". Both are enumerated exactly rather than
    guessed at, and the store fails closed if more than one record matches.
    """
    digits = "".join(ch for ch in str(digits or "") if ch.isdigit())
    if not digits:
        return []
    forms: list[str] = []

    def add(value: str) -> None:
        if MOBILE_MIN_DIGITS <= len(value) <= MOBILE_MAX_DIGITS and value not in forms:
            forms.append(value)

    add(digits)
    if not spoken_plus and default_calling_code:
        add(str(default_calling_code).lstrip("+") + digits)
    return ["+" + f for f in forms]


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def _digit_run(utterance: str) -> tuple[str, bool]:
    """All digits in the utterance, in order, plus whether "+" was spoken.

    Digit words and digit runs are both accepted because people mix them
    ("one seven nine 8 2 8 3"). Unknown words carry no digit and are ignored.
    """
    text = utterance.lower()
    spoken_plus = "+" in text or " plus " in f" {text} "
    tokens = text.translate(_DIGIT_SEPARATORS).split()
    digits: list[str] = []
    for token in tokens:
        if token in _DIGIT_WORDS:
            digits.append(_DIGIT_WORDS[token])
        elif token.isdigit():
            digits.extend(token)
    return "".join(digits), spoken_plus


def _reconstruct_email(utterance: str) -> Optional[str]:
    """Rebuild an address spoken as "alice dot test at example dot com".

    Strictly mechanical: exactly one "at", contiguous word/"dot" tokens on each
    side, and the result must still satisfy EMAIL_RE. Anything else returns
    None rather than a best guess.
    """
    tokens = utterance.lower().translate(_WORD_SEPARATORS).split()
    at_positions = [i for i, t in enumerate(tokens) if t == "at"]
    if len(at_positions) != 1:
        return None
    at = at_positions[0]

    def walk(indices) -> list[str]:
        parts: list[str] = []
        for i in indices:
            token = tokens[i]
            if token == "dot":
                parts.append(".")
            elif token.isalnum() and token not in _EMAIL_STOP_WORDS:
                parts.append(token)
            else:
                break
        return parts

    local = list(reversed(walk(range(at - 1, -1, -1))))
    domain = walk(range(at + 1, len(tokens)))
    if not local or not domain or "." not in domain:
        return None

    candidate = "".join(local) + "@" + "".join(domain)
    return candidate if EMAIL_RE.fullmatch(candidate) else None


def extract_identifier(
    utterance: str, default_calling_code: Optional[str] = None
) -> SpokenIdentifier:
    """Turn an utterance into exactly one normalised lookup identifier.

    Precedence is fixed and deterministic:

        1. a literal or reconstructed email address  -> UPN
        2. a mobile cue, or a spoken "plus"          -> MOBILE
        3. an employee cue                           -> EMPLOYEE_ID
        4. a bare digit run                          -> UNSPECIFIED_DIGITS

    Raises IdentifierError when the utterance yields nothing usable - which is
    what a spoken name does.
    """
    if not isinstance(utterance, str) or not utterance.strip():
        raise IdentifierError("empty")

    lowered = utterance.lower()
    words = set(lowered.translate(_WORD_SEPARATORS).split())

    # 1. UPN, literal first, then the spoken "at ... dot ..." form.
    match = EMAIL_RE.search(lowered)
    address = match.group(0) if match else _reconstruct_email(utterance)
    if address:
        return SpokenIdentifier(IdentifierKind.UPN, normalize_upn(address))

    digits, spoken_plus = _digit_run(utterance)

    if not digits:
        # No digits and no address. A name lands here, and goes no further.
        if words & _NAME_CUES:
            raise IdentifierError("name_not_accepted")
        raise IdentifierError("no_identifier")

    # 2. Mobile.
    if spoken_plus or (words & _MOBILE_CUES):
        if not (MOBILE_MIN_DIGITS <= len(digits) <= MOBILE_MAX_DIGITS):
            raise IdentifierError("mobile_bad_length")
        return SpokenIdentifier(IdentifierKind.MOBILE, digits)

    # 3. Employee ID.
    if words & _EMPLOYEE_CUES:
        return SpokenIdentifier(IdentifierKind.EMPLOYEE_ID, normalize_employee_id(digits))

    # 4. Digits with no cue: could be either. The store decides, and fails
    #    closed if the run matches more than one person.
    if EMPLOYEE_ID_MIN_DIGITS <= len(digits) <= MOBILE_MAX_DIGITS:
        return SpokenIdentifier(IdentifierKind.UNSPECIFIED_DIGITS, digits)
    raise IdentifierError("digits_out_of_range")


# --------------------------------------------------------------------------
# Factor choice
# --------------------------------------------------------------------------

_PUSH_WORDS = {"push", "notification", "notify", "approve", "app", "prompt"}
_PASSCODE_WORDS = {"passcode", "code", "otp", "number", "digits", "type", "read"}


def parse_factor_choice(utterance: str) -> Optional[str]:
    """"push" or "passcode" from a caller's answer, or None if unclear.

    Exact word matching, and an utterance mentioning both is deliberately
    unclear rather than resolved by precedence: an LLM must never invent a Duo
    factor, and neither should a guess here.
    """
    if not isinstance(utterance, str) or not utterance.strip():
        return None
    words = set(utterance.lower().translate(_WORD_SEPARATORS).split())
    push = bool(words & _PUSH_WORDS)
    passcode = bool(words & _PASSCODE_WORDS)
    if push == passcode:
        return None
    return "push" if push else "passcode"
