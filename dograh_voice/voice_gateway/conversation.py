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

# CLOSED-CLASS FUNCTION WORDS ONLY.
#
# This list is finished, and that is the point. It holds English's grammatical
# glue — determiners, pronouns, copulas, prepositions, auxiliaries — a set that
# linguists call closed because it does not accept new members. It cannot grow
# when the company buys a new VPN product or renames the printer fleet.
#
# An earlier version of this file also carried content words ("want", "need",
# "calling", "tell", "give", "number") to make particular sentences come out
# right. That was the beginning of a second NLP subsystem inside the gateway,
# and every one of those words was a judgement about meaning that belongs to
# sd_chat. They are gone. If a word carries information about the caller's
# problem, it is not glue, and it stays in the residual where it makes the
# utterance a request.
_FUNCTION_WORDS = {
    # determiners and quantifiers
    "a", "an", "the", "this", "that", "these", "those", "some", "any", "my",
    "your", "our", "its", "their", "his", "her",
    # pronouns
    "i", "me", "we", "us", "you", "it", "they", "them", "he", "she", "who",
    # copulas and auxiliaries
    "is", "am", "are", "was", "were", "be", "been", "being", "do", "does",
    "did", "have", "has", "had", "will", "would", "shall", "should", "can",
    "could", "may", "might", "must",
    # prepositions and conjunctions
    "of", "to", "for", "with", "from", "in", "on", "at", "by", "as", "and",
    "or", "but", "if", "so", "then", "there", "here",
    # discourse particles
    "please", "just", "well", "um", "uh", "er", "erm", "hmm", "like", "okay",
    "ok", "sorry", "actually",
    # glue used when SPEAKING an identifier aloud
    "dot", "plus",
}
# Contractions split on the apostrophe ("can't" -> "can", "t"); a bare letter
# is never a ServiceDesk problem.
_FUNCTION_WORDS |= {chr(c) for c in range(ord("a"), ord("z") + 1)}
_FUNCTION_WORDS |= {"re", "ve", "ll", "nt", "don", "doesn", "didn", "isn",
                    "aren", "wasn", "won", "couldn", "shouldn", "wouldn",
                    "haven", "hasn", "hadn", "can", "cant"}

# Openers that deserve an answer rather than an authentication attempt. Also
# closed, and for the same reason: this is the phatic vocabulary of English, not
# a taxonomy of what people want.
# Deliberately overlaps _FUNCTION_WORDS: "okay" is both grammatical filler
# mid-sentence and a complete phatic turn on its own, and it needs to be in both
# sets to be dropped from a residual AND to make a bare "okay" small talk rather
# than noise.
_GREETING = {
    "hello", "hallo", "hi", "hiya", "hey", "heya", "yo", "greetings",
    "morning", "afternoon", "evening", "good", "welcome",
    "hear", "hearing", "listening", "there", "anyone", "anybody", "someone",
    "yes", "yeah", "yep", "yup", "thanks", "thank", "cheers", "hello?",
    "okay", "ok", "alright", "sure", "right",
}

# Cue words that merely LABEL an identifier, never a problem. Imported from
# identifiers.py so the two modules cannot drift.
_IDENTIFIER_CUES = _EMPLOYEE_CUES | _MOBILE_CUES | _UPN_CUES | _NAME_CUES

# Words that qualify WHICH identifier ("my *work* email", "my *registered*
# mobile"). Dropped only when an identifier was actually found, because outside
# that role they carry real meaning — "it doesn't work" is a problem statement,
# and dropping "work" unconditionally would silently swallow it.
_IDENTIFIER_MODIFIERS = {
    "work", "working", "corporate", "company", "office", "business",
    "personal", "registered", "primary", "official", "main", "number",
}

_NON_REQUEST_WORDS = _FUNCTION_WORDS | _GREETING | _IDENTIFIER_CUES

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
