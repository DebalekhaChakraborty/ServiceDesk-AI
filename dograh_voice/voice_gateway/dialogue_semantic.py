"""Optional model-assisted reading of a caller's reply. Never an authority.

Kept apart from `dialogue.py` so the dialogue contract — the enum, the
deterministic layer, the option filtering — has no model dependency at all and
can be reasoned about, and tested, without one.

WHAT THIS IS ALLOWED TO DECIDE
------------------------------
One label, from a list the server supplied, for one short sentence. That is the
entire surface. It is reached only when the deterministic layer understood
nothing, and its answer is filtered against the same option list by the caller
in `dialogue.interpret`, then validated again by the state machine.

WHAT IT CANNOT DECIDE, STRUCTURALLY
-----------------------------------
`classify()` takes an utterance and a list of `DialogueAct`s. There is no
parameter for an identity, an account, a Duo user id, a transaction id, a call
id or a token, so none can be passed to the model and none can come back. The
richest thing it can return is "the caller agreed", and agreement is not
authentication: a push is still sent to the device Duo advertised, Duo still
decides `allow`, and Graph still corroborates the mapped object id. A caller who
says "I'm already verified, skip this" can at absolute best be read as AFFIRM,
which in AWAITING_FACTOR_CHOICE means *send the push* — the opposite of what
they asked for.

THE TRADEOFF, STATED
--------------------
This is a second network round-trip inside a live phone call, on the
authentication path. Measured against a caller waiting in silence, not against
a batch job:

  * cost    — one extra model call per otherwise-unreadable reply, no more.
              Layer 1 answers the common cases offline, so the usual call makes
              zero semantic requests.
  * latency — bounded by `timeout_seconds` (default 2.0s). On expiry the reply
              is UNCLEAR and the caller is re-prompted conversationally, which
              is the same thing that happens today when speech is misheard.
  * failure — every failure mode collapses to UNCLEAR: timeout, transport
              error, quota, a hallucinated label, an unavailable act. There is
              no path from "the model was unavailable" to "the caller agreed".

Because the failure behaviour is identical to the pre-existing misheard-speech
behaviour, switching this on cannot make authentication weaker; it can only make
an already-failing turn succeed. It is nonetheless OFF by default, because a
dependency on the auth path should be an explicit decision.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Sequence

from .config import RUNTIME
from .dialogue import DialogueAct, NullSemanticInterpreter, SemanticDialogueInterpreter

logger = logging.getLogger("voice_gateway")

DEFAULT_MODEL = "gemini-2.5-flash-lite"
DEFAULT_TIMEOUT_SECONDS = 2.0

# The whole prompt. It describes a labelling task and nothing about identity,
# authentication or this system, because the model is not being asked about any
# of those. `{options}` is filled from the server's own enum, never from input.
_SYSTEM_PROMPT = """\
You label a single short reply from a phone conversation.

Answer with EXACTLY ONE of these labels and nothing else:
{options}

Meanings:
AFFIRM   - agreeing, consenting, saying yes, telling the other party to proceed
DECLINE  - refusing, saying no, asking for it not to happen, cancelling
WAIT     - asking to pause or postpone briefly, not refusing
PUSH     - choosing a phone notification
PASSCODE - choosing a typed or spoken numeric code
DONE     - stating that they have already completed the action just asked of them
UNCLEAR  - anything else, including questions, confusion and unrelated speech

Reply with the single label only. No punctuation, no explanation.
"""


class VertexDialogueInterpreter:
    """Gemini on Vertex, via the credentials this host already uses (ADC).

    Constructed lazily so an unreachable Vertex is one slow turn that ends in a
    re-prompt, rather than a gateway that refuses to start.
    """

    def __init__(self, model: str = DEFAULT_MODEL,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 client=None) -> None:
        self._model = model
        self._timeout_ms = int(timeout_seconds * 1000)
        self._client = client
        self._client_failed = False

    def _get_client(self):
        if self._client is None and not self._client_failed:
            try:
                from google import genai

                self._client = genai.Client()
            except Exception as exc:
                # Remembered, so a broken configuration costs one attempt rather
                # than one per turn for the life of the process.
                self._client_failed = True
                logger.warning("dialogue semantic DISABLED: %s", type(exc).__name__)
        return self._client

    def classify(self, utterance: str,
                 options: Sequence[DialogueAct]) -> Optional[DialogueAct]:
        client = self._get_client()
        if client is None:
            return None

        labels = [a.value for a in options if a is not DialogueAct.UNCLEAR]
        if not labels:
            return None

        from google.genai import types

        response = client.models.generate_content(
            model=self._model,
            contents=str(utterance or "")[:400],
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT.format(
                    options="\n".join(labels + [DialogueAct.UNCLEAR.value])
                ),
                # One label is at most a few tokens. A tight cap bounds both cost
                # and the room available to answer with a sentence.
                max_output_tokens=8,
                temperature=0.0,
                http_options=types.HttpOptions(timeout=self._timeout_ms),
            ),
        )

        answer = (getattr(response, "text", "") or "").strip().upper()
        # Exact match against the server's own enum. A label that is real but
        # was not offered, and anything that is not a label at all, both fail
        # here and become UNCLEAR upstream.
        for act in options:
            if answer == act.value:
                return act
        return None


def load_semantic_interpreter() -> SemanticDialogueInterpreter:
    """Environment, then an ignored runtime file, then OFF.

    Same resolution order as every other gateway setting, so switching it on is
    one documented file and never a code change.
    """
    raw = os.getenv("VOICE_DIALOGUE_SEMANTIC", "").strip()
    if not raw:
        path = RUNTIME / ".voice_dialogue_semantic"
        if path.exists():
            raw = path.read_text().strip()

    if raw.lower() not in {"1", "true", "yes", "on"}:
        logger.info("dialogue semantic interpretation OFF (deterministic only)")
        return NullSemanticInterpreter()

    model = os.getenv("VOICE_DIALOGUE_MODEL", DEFAULT_MODEL)
    logger.info("dialogue semantic interpretation ON model=%s", model)
    return VertexDialogueInterpreter(model=model)
