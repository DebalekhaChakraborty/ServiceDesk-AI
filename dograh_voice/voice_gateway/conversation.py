"""Deterministic reading of an EXTERNAL caller's opening turn.

Nothing here authenticates anybody, and nothing here is a model. It answers one
narrow, mechanical question about words the caller has already said:

    is this a ServiceDesk request, an identifier they volunteered before being
    asked, or neither?

That question exists because the external line is now **ServiceDesk Voice AI**,
not an account-recovery bot. The caller states what they need first; Duo is the
identity check that follows, not the personality of the line. So the gateway has
to tell "my VPN keeps disconnecting" from "hello" without ever asking an LLM —
an LLM answer here would put a trust transition behind a generated token.

Three rules drive the design.

**A greeting is not a request.** "hello" must not start a Duo Push. The caller
is greeted back and the line stays where it is.

**An identifier is not a problem statement.** A caller who opens with "my
employee ID is 1999" — which earlier test scripts taught them to do — has told
us nothing about what they need. The identifier is retained as an untrusted
lookup candidate so they are not made to repeat it, and they are asked what they
need.

**No intent classification.** There is no taxonomy of VPN/printer/password here
and there must not be one. Anything that is neither a greeting nor bare
identifier material is a request, stored verbatim, and sd_chat is the only thing
that ever decides what it means.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .identifiers import (
    EMAIL_RE,
    IdentifierError,
    IdentifierKind,
    SpokenIdentifier,
    _DIGIT_SEPARATORS,
    _DIGIT_WORDS,
    _EMPLOYEE_CUES,
    _MOBILE_CUES,
    _NAME_CUES,
    _UPN_CUES,
    extract_identifier,
)

# Words that carry no ServiceDesk meaning on their own. A caller whose whole
# utterance reduces to these has not stated a problem.
#
# Deliberately conservative: every word that could plausibly BE the request
# ("password", "account", "locked", "printer", "help", "reset", "vpn") is
# absent, because a false "that was only small talk" leaves a real caller
# looping on the welcome prompt. A false "that was a request" merely sends them
# to identity verification a turn early, which is harmless.
_FILLER = {
    "a", "an", "the", "and", "or", "so", "to", "of", "for", "with", "from",
    "is", "are", "was", "be", "been", "am", "im", "i", "me", "my", "mine",
    "you", "your", "yours", "we", "us", "our", "it", "its", "this", "that",
    "these", "those", "here", "there", "just", "well", "actually", "really",
    "very", "quite", "now", "then", "please", "sure", "sorry", "excuse",
    "um", "uh", "er", "erm", "hmm", "mm", "like", "know", "mean", "say",
    "said", "tell", "telling", "give", "giving", "got", "get", "have", "has",
    "had", "do", "does", "did", "don", "doesn", "didn", "can", "cant",
    "could", "would", "should", "will", "shall", "may", "might", "must",
    "on", "in", "at", "by", "as", "if", "but", "one", "again", "wanted",
    "want", "need", "needed", "calling", "call", "called", "speaking",
    "number", "digits", "digit", "dot", "plus", "sir", "maam", "madam",
}
# Contractions are split by the tokenizer ("can't" -> "can", "t"), and a single
# letter is never a ServiceDesk request.
_FILLER |= {chr(c) for c in range(ord("a"), ord("z") + 1)}
_FILLER |= {"re", "ve", "ll", "nt", "isn", "arent", "wasn", "won", "wouldn",
            "couldn", "shouldn", "haven", "hasn", "hadn"}

# Openers that deserve a natural answer rather than a Duo Push.
_GREETING = {
    "hello", "hallo", "helo", "hi", "hiya", "hey", "heya", "yo", "greetings",
    "good", "morning", "afternoon", "evening", "day", "welcome",
    "hear", "hearing", "listening", "listen", "read", "receiving",
    "anyone", "anybody", "someone", "somebody", "operator", "agent", "human",
    "yes", "yeah", "yep", "yup", "ok", "okay", "alright", "right",
    "thanks", "thank", "cheers", "bye", "goodbye", "hold",
}

# Identifier machinery: cue words that merely LABEL an identifier, never a
# problem. Imported from identifiers.py so the two modules cannot drift.
_IDENTIFIER_CUES = _EMPLOYEE_CUES | _MOBILE_CUES | _UPN_CUES | _NAME_CUES

# Words that qualify WHICH identifier ("my *work* email", "my *registered*
# mobile"). Dropped only when an identifier was actually found, because outside
# that role they carry real meaning — "it doesn't work" is a problem statement,
# and adding "work" to the unconditional set would silently swallow it.
_IDENTIFIER_MODIFIERS = {
    "work", "working", "corporate", "company", "office", "business",
    "personal", "registered", "primary", "official", "main",
}

_NON_REQUEST_WORDS = _FILLER | _GREETING | _IDENTIFIER_CUES

_UPN_PART_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class OpeningTurn:
    """What the caller's opening words were, mechanically.

    `request` is the caller's EXACT text, unmodified, or None. It is a problem
    statement and nothing else: it is never an identity claim, never an
    instruction to this module, and never consulted by any authentication step.
    """

    small_talk: bool = False
    identifier: Optional[SpokenIdentifier] = None
    request: Optional[str] = None

    def redacted(self) -> str:
        """Log-safe rendering. The caller's words are never logged."""
        kind = self.identifier.kind.value if self.identifier else "none"
        return (f"request={'yes' if self.request else 'no'} "
                f"identifier={kind} small_talk={self.small_talk}")


def _residual_words(utterance: str, identifier: Optional[SpokenIdentifier]) -> list[str]:
    """Words left once identifier material and conversational filler are gone.

    Removal is by VALUE, not by guessing at a span: a literal address is deleted
    by the same regex that recognised it, a reconstructed one is deleted by the
    parts of the address that was actually built, and digits are deleted
    whether they were spoken as words or as figures.
    """
    text = EMAIL_RE.sub(" ", utterance.lower())
    tokens = text.translate(_DIGIT_SEPARATORS).split()

    drop = set(_NON_REQUEST_WORDS)
    if identifier is not None:
        drop |= _IDENTIFIER_MODIFIERS
        if identifier.kind is IdentifierKind.UPN:
            # A spoken address arrives as ordinary words ("alice dot test at
            # example dot invalid"). Its components are exactly the parts of
            # the address that was reconstructed.
            drop |= {p for p in _UPN_PART_RE.split(identifier.value) if p}

    return [t for t in tokens
            if t not in drop and t not in _DIGIT_WORDS and not t.isdigit()]


def classify_opening(
    utterance: str, default_calling_code: Optional[str] = None
) -> OpeningTurn:
    """Read one opening utterance. Never raises; an unusable turn is empty.

    Precedence is fixed:

        1. anything meaningful beyond identifier material  -> request
           (any identifier found alongside it is kept too)
        2. identifier material only                        -> identifier, no request
        3. recognised greeting or acknowledgement          -> small talk
        4. anything else                                   -> nothing usable
    """
    if not isinstance(utterance, str) or not utterance.strip():
        return OpeningTurn()

    try:
        identifier = extract_identifier(utterance, default_calling_code)
    except IdentifierError:
        # No usable identifier is the normal case for a problem statement, and
        # for a name — which is never an identifier. Neither is an error here.
        identifier = None

    if _residual_words(utterance, identifier):
        return OpeningTurn(identifier=identifier, request=utterance.strip())

    if identifier is not None:
        return OpeningTurn(identifier=identifier)

    words = set(utterance.lower().translate(_DIGIT_SEPARATORS).split())
    return OpeningTurn(small_talk=bool(words & _GREETING))
