"""Dialogue acts: what the caller MEANT, separated from what the server may DO.

Before this module, understanding a reply and authorising a state transition
were the same function. `parse_factor_choice` looked for the literal word
"push", so a caller who said "okay, sure" got nothing — the security machine had
been handed the job of understanding English, and it was bad at it.

The split:

    caller utterance
        -> DIALOGUE INTERPRETATION      (this module)
        -> DialogueAct                  (a bounded enum, nothing else)
        -> SECURITY STATE VALIDATION    (duo_recovery, deterministic)
        -> allowed transition

The enum is the whole contract, and its membership is the security property.
There is deliberately no `VERIFIED`, no `AUTHENTICATED`, no `TRUSTED`, no
identity, no account, no Duo user id, no transaction id and no token. A dialogue
act cannot express "this person is who they say they are", so no amount of
cleverness in the layer above — deterministic or model-driven — can say it
either. The strongest thing an interpretation can mean is *"the caller agreed to
be sent a Duo notification"*, and the server still decides whether agreeing is a
legal move right now, whether a push-capable device was advertised by live Duo
preauth, and what Duo itself says afterwards.

That is why `interpret()` is safe to make model-assisted. Its output is not
trust; it is one of seven words.

Two layers, in order:

1. **Deterministic.** Affirmation and negation are a genuinely CLOSED class in
   English — roughly forty words, fixed, and they do not grow when the
   enterprise adds a new kind of ticket. That is categorically different from
   an intent taxonomy, which is why a small fixed table is the right tool here
   and the wrong tool for "what is the caller's problem".

2. **Semantic, optional.** Only for what layer 1 could not read. Off unless
   configured. Its answer is parsed as an exact enum member out of a supplied
   option list; anything else, any error, and any timeout become UNCLEAR, which
   re-prompts. Fail-closed is therefore the default behaviour of the fallback
   rather than a special case in it.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Optional, Protocol, Sequence

logger = logging.getLogger("voice_gateway")


class DialogueAct(str, Enum):
    """Everything a caller can be understood to have MEANT, in full.

    Adding a member here widens what the dialogue layer can express, so a member
    that names a trust state would be a security change and not a feature. There
    is no such member and there must never be one.
    """

    AFFIRM = "AFFIRM"        # "yes", "go ahead", "sure"
    DECLINE = "DECLINE"      # "no", "don't send it", "cancel"
    PUSH = "PUSH"            # names the push factor specifically
    PASSCODE = "PASSCODE"    # names the passcode factor specifically
    WAIT = "WAIT"            # "not yet", "hold on", "give me a second"
    DONE = "DONE"            # "approved it", "done" — a CLAIM, never a proof
    UNCLEAR = "UNCLEAR"      # understood nothing; re-prompt


# Multi-word forms whose meaning is not the sum of their tokens. Checked before
# tokenisation because several inverT a token that appears in them: "why not" is
# agreement containing a negation, "not yet" is a pause rather than a refusal.
_PHRASES: tuple[tuple[str, DialogueAct], ...] = (
    ("not yet", DialogueAct.WAIT),
    ("not right now", DialogueAct.WAIT),
    ("not now", DialogueAct.WAIT),
    ("hold on", DialogueAct.WAIT),
    ("hang on", DialogueAct.WAIT),
    ("give me a", DialogueAct.WAIT),
    ("one moment", DialogueAct.WAIT),
    ("just a", DialogueAct.WAIT),
    ("why not", DialogueAct.AFFIRM),
    ("go ahead", DialogueAct.AFFIRM),
    ("go for it", DialogueAct.AFFIRM),
    ("sounds good", DialogueAct.AFFIRM),
    ("sounds fine", DialogueAct.AFFIRM),
    ("that works", DialogueAct.AFFIRM),
    ("that's fine", DialogueAct.AFFIRM),
    ("thats fine", DialogueAct.AFFIRM),
    ("that's great", DialogueAct.AFFIRM),
    ("fire away", DialogueAct.AFFIRM),
    ("lets do it", DialogueAct.AFFIRM),
    ("let's do it", DialogueAct.AFFIRM),
    ("please do", DialogueAct.AFFIRM),
    ("yes please", DialogueAct.AFFIRM),
    ("i'm ready", DialogueAct.AFFIRM),
    ("im ready", DialogueAct.AFFIRM),
)

# Single tokens. Closed-class: these are the words English uses to agree and
# refuse, and the list is finished rather than in progress.
_AFFIRM = {
    "yes", "yeah", "yea", "yep", "yup", "ya", "yah", "aye", "ok", "okay",
    "okey", "kay", "sure", "please", "absolutely", "definitely", "certainly",
    "alright", "allright", "fine", "good", "great", "ready", "affirmative",
    "correct", "right", "indeed", "send", "proceed", "continue", "confirm",
}
_DECLINE = {
    "no", "not", "nope", "nah", "naw", "negative", "cancel", "stop", "abort",
    "never", "dont", "don't", "doesnt", "won't", "wont",
}
_WAIT = {"wait", "hold", "later", "moment", "second", "minute", "pause"}
_DONE = {"done", "approved", "accepted", "approve", "accept", "did", "finished"}

# Factor NAMES. These stay literal on purpose: naming a factor is a choice
# between offered options, and the server checks the choice against live Duo
# capability regardless of how confidently it was expressed.
#
# "phone", "app" and "mobile" are in here because callers say "use my phone"
# rather than "push". They are also the words that appear in *questions* about
# the factor ("which phone?"), which is why the interrogative guard below runs
# first — otherwise a caller asking for clarification would be read as choosing.
_PUSH = {"push", "notification", "notify", "prompt", "phone", "app", "mobile"}
_PASSCODE = {"passcode", "code", "otp", "digits", "number", "pin"}

# A reply containing one of these is a question, not an answer. Confusion must
# never be read as consent, so this outranks every content word below it.
_INTERROGATIVE = {
    "which", "what", "whats", "what's", "who", "whose", "how", "when",
    "where", "huh", "pardon", "repeat", "sorry", "mean", "means",
}

_PUNCT = re.compile(r"[^a-z0-9' ]+")
_APOSTROPHE = re.compile(r"[‘’]")


class SemanticDialogueInterpreter(Protocol):
    """A model that reads one short reply and returns one of `options`.

    Everything it is given is in the signature: the caller's words, and the
    labels it may choose between. It receives no identity, no call id, no Duo
    transaction id, no token, and no session — not by convention but because
    there is no parameter through which any of those could be passed.

    Returning None means "no confident answer", which becomes UNCLEAR.
    """

    def classify(self, utterance: str,
                 options: Sequence[DialogueAct]) -> Optional[DialogueAct]:
        ...


class NullSemanticInterpreter:
    """The default. Deterministic layer only; unreadable replies re-prompt."""

    def classify(self, utterance: str,
                 options: Sequence[DialogueAct]) -> Optional[DialogueAct]:
        return None


def _normalise(utterance: str) -> str:
    text = _APOSTROPHE.sub("'", str(utterance or "").lower())
    return _PUNCT.sub(" ", text).strip()


def interpret_deterministic(utterance: str) -> DialogueAct:
    """Layer 1. Fast, offline, and the only layer most replies ever reach.

    Negation scopes over the rest of a short reply, so "no, don't send it"
    is a refusal even though it contains "send". The phrase table runs first
    because it holds the forms where that rule would give the wrong answer.
    """
    text = _normalise(utterance)
    if not text:
        return DialogueAct.UNCLEAR

    for phrase, act in _PHRASES:
        if phrase in text:
            return act

    words = set(text.split())

    # 1. A question is not an answer. "which phone?" names a factor word and
    #    means the opposite of choosing it, so this outranks everything.
    if words & _INTERROGATIVE:
        return DialogueAct.UNCLEAR

    # 2. Negation scopes over the whole of a short reply, so it outranks both
    #    the factor names and the agreement words that may sit inside it:
    #    "stop, no notification" and "don't send it" are refusals, not choices.
    if words & _DECLINE:
        return DialogueAct.DECLINE
    if words & _WAIT:
        return DialogueAct.WAIT

    # 3. A named factor is a specific choice and outranks a bare yes: "I'd
    #    rather use the code" agrees AND chooses, and the choice is the
    #    informative half. Both named at once is a genuine ambiguity, not a
    #    precedence puzzle, so it falls through to UNCLEAR.
    push, passcode = bool(words & _PUSH), bool(words & _PASSCODE)
    if push != passcode:
        return DialogueAct.PUSH if push else DialogueAct.PASSCODE
    if push and passcode:
        return DialogueAct.UNCLEAR

    if words & _DONE:
        return DialogueAct.DONE
    if words & _AFFIRM:
        return DialogueAct.AFFIRM
    return DialogueAct.UNCLEAR


def interpret(
    utterance: str,
    options: Sequence[DialogueAct],
    semantic: Optional[SemanticDialogueInterpreter] = None,
) -> DialogueAct:
    """Read one reply as a dialogue act, constrained to `options`.

    `options` is what the CURRENT state can act on, supplied by the state
    machine. It is applied twice over: the semantic layer is told it may only
    choose between these labels, and any act — from either layer — outside them
    is discarded here as UNCLEAR. The state machine then validates the result
    again on its own terms. None of those three checks trusts the other two.
    """
    allowed = set(options)

    act = interpret_deterministic(utterance)
    if act is not DialogueAct.UNCLEAR:
        return act if act in allowed else DialogueAct.UNCLEAR

    if semantic is None:
        return DialogueAct.UNCLEAR

    try:
        proposed = semantic.classify(utterance, tuple(options))
    except Exception as exc:
        # A classifier that fails is a classifier that said nothing. It must
        # never fail OPEN into an affirmation, so the type of failure is
        # deliberately not inspected.
        logger.info("dialogue semantic_error=%s", type(exc).__name__)
        return DialogueAct.UNCLEAR

    if proposed is None:
        return DialogueAct.UNCLEAR
    if not isinstance(proposed, DialogueAct) or proposed not in allowed:
        # Covers a hallucinated label, a stringly-typed answer, and an act that
        # is real but not on offer in this state.
        logger.warning("dialogue semantic_rejected=%r", str(proposed)[:32])
        return DialogueAct.UNCLEAR

    logger.info("dialogue semantic_act=%s", proposed.value)
    return proposed
