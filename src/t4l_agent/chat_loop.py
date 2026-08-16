from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .config import LoopConfig
from .owner_connect import PreModelHandler
from .runtime_coach import ChatMessage, RuntimeCoach, dumps_compact
from .t4l_client import T4LError, T4LMcpClient
from .video_verification import ExerciseVideoVerifier, YouTubeOEmbedVerifier

ORCHESTRATOR_SYSTEM_PROMPT = """You are the configured T4L Gym Bro coach.
Follow the installed T4L instruction bundle below. It is authoritative.

Your scope is training and recovery only. Never provide meal, calorie, macro,
fluid, electrolyte, supplement, weight, or body-composition advice,
calculations, targets, or recommendations. Never infer a nutrition deficiency,
dehydration, or diagnosis from athlete data. Refer individualized nutrition,
hydration, supplement, weight, and body-composition questions to a registered
dietitian or clinician. This boundary overrides every other instruction and
applies during onboarding, planning, normal chat, and background work.

Return one compact JSON object only. Never use a code fence. Every response may
also include one optional durable coaching-note patch:
{"reply":"short athlete-facing reply","write":null,"notes":null}
or
{"reply":"...","write":{"tool":"write_athlete_setup_draft",
"payload":{...}},"notes":null}
or
{"reply":"...","write":{"tool":"write_training_block_plan",
"payload":{...}},"notes":null}
or
{"reply":"...","write":{"tool":"write_daily_workout_plan",
"payload":{...}},"notes":null}

Use `notes` only for durable, plan-relevant intent from the latest athlete
turn: explicit training requests, schedule/equipment/injury/recovery
constraints, or unresolved coaching questions. Its shape is
{"capture":true,"athleteRequests":["..."],"openQuestions":["..."],
"summary":"..."}. Otherwise use null. Never capture nutrition, hydration,
supplement, weight, or body-composition content.

The host, not you, executes writes and enforces phone ownership. Never claim a
draft or proposal is accepted, synced, scheduled, or applied. For onboarding,
ask one useful missing question at a time. Once every required setup field is
known, show a concise summary containing the literal label `SETUP SUMMARY:` and
ask the athlete to confirm it. Emit write_athlete_setup_draft only when the
latest visible athlete turn explicitly confirms that exact prior summary.

After phone acceptance, use only a fresh phone-owned context revision and its
current training-block request. Full plans are review-only proposals. A plan
write must echo that requestId. Prefer exercise videos from the trusted current
catalog supplied in accepted context. When the host exposes domain-limited web
search, you may search YouTube for the exact exercise variation. Every selected
Short must still pass the host's live URL and title verification. If host
verification fails, do not write the plan and state what is missing.

For a new four-week block, write explicit weeks 1 through 4. Every workout
must include short, standard, and extended prebuilt variants with increasing
estimatedMinutes. Validate every variant with the same exercise/grouping/video
rules as the standard prescription.

A daily-workout request is narrower: select exactly one offered unfinished
sourceWorkoutId + variantId pair, or rest. Never rewrite exercises, add a
workout, modify the accepted block, or use health/nutrition history outside the
one current-day recovery payload. Honor excluded pairs exactly.

For pain, injury, dizziness, illness, or unsafe push-through questions, be
conservative. Missing data is unknown, not zero. Keep replies direct. No tables.
"""

_INSTRUCTION_FILES_BY_PURPOSE = {
    # Queueing, writes, validation, and safety are enforced by the host. The
    # model only needs the contract slice for its current job.
    "onboarding": ("skills/t4l-onboard-athlete/SKILL.md",),
    "chat": ("skills/t4l-answer-chat/SKILL.md",),
    "planning": (
        "skills/t4l-write-results/SKILL.md",
        "skills/t4l-write-results/reference/payload-shapes.md",
    ),
}
_MAX_INSTRUCTION_BYTES = 1_000_000
_CHAT_MAX_TOKENS = 1_800
_PLAN_MAX_TOKENS = 12_000
_PLAN_RETRY_BASE_SECONDS = 15.0
_PLAN_RETRY_MAX_SECONDS = 300.0
_YOUTUBE_SHORT_RE = re.compile(r"^https://www\.youtube\.com/shorts/[A-Za-z0-9_-]{11}$")
_EXPLICIT_CONFIRM_RE = re.compile(
    r"^\s*(?:yes(?:,?\s+(?:confirm|confirmed|that(?:'s| is) correct))?|"
    r"confirm(?:ed)?|looks good|correct|go ahead|ja(?:,?\s+(?:bestätigt|passt))?|"
    r"bestätigt|ich bestätige|passt|stimmt|genau)\s*[.!]?\s*$",
    re.IGNORECASE,
)
_CANONICAL_EQUIPMENT = (
    "bodyweight",
    "dumbbells",
    "barbell",
    "curlBar",
    "kettlebells",
    "bands",
    "bosu",
    "fullGym",
    "machines",
    "cableMachine",
    "pullUpBar",
    "bench",
    "squatRack",
)

SAFETY_RE = re.compile(
    r"\b(pain|hurt|hurts|injur|dizzy|dizziness|ill|sick|fever|"
    r"push through|unsafe|knee|back|hip|chest pain)\b",
    re.IGNORECASE,
)

NUTRITION_GUIDANCE_BOUNDARY_REPLY = (
    "I can help with training and recovery, but I can't provide individualized "
    "nutrition, hydration, supplement, weight, or body-composition guidance. "
    "Please take those questions to a registered dietitian or clinician."
)

_NUTRITION_TOPIC_RE = re.compile(
    r"\b(?:nutrition|diet(?:ary)?|food|meal|snack|breakfast|lunch|dinner|"
    r"eat(?:ing)?|calori(?:e|es|c)|kcal|macro(?:s|nutrients?)?|protein|"
    r"carb(?:s|ohydrates?)?|dietary fat|fiber|fibre|glycogen|hydrat(?:e|ion)|"
    r"drink|water|fluid|electrolytes?|sodium|potassium|magnesium|"
    r"supplements?|creatine|caffeine|vitamins?|minerals?|nutrients?|iron|"
    r"bmi|body mass index|body[ -]?fat|body[ -]?composition|bottle|plate|"
    r"oats?|oatmeal|banana|rice|chicken|yogurt|eggs?|shake|"
    r"ern[äa]hrung|essen|mahlzeit|kalorien|makros?|eiwei[ßs]|protein|"
    r"kohlenhydrate|fett|trinken|wasser|fl[üu]ssigkeit|elektrolyte|"
    r"nahrungserg[äa]nzung|kreatin|koffein|vitamine?|mineralstoffe|"
    r"nutrici[oó]n|comida|comer|calor[ií]as|macros?|prote[ií]na|"
    r"carbohidratos?|grasa|beber|agua|l[ií]quidos?|electrolitos?|"
    r"suplementos?)\b",
    re.IGNORECASE,
)
_ADVICE_REQUEST_RE = re.compile(
    r"\b(?:what should|should (?:i|we)|how much|how many|recommend|suggest|"
    r"advise|tell me|give me|make me|build me|help me|plan|target|calculate|"
    r"what do i need|what goes|was soll|soll ich|wie viel|empfiehl|"
    r"gib mir|hilf mir|berechne|qu[eé] debo|cu[aá]nt[oa]s?|recomienda|"
    r"sugi[eé]reme|dame|ay[uú]dame|calcula)\b",
    re.IGNORECASE,
)
_BODY_CHANGE_RE = re.compile(
    r"\b(?:lose|gain|drop|cut|bulk|change|target|reduce|increase)\b"
    r"[^.!?\n]{0,50}\b(?:body[ -]?fat|body[ -]?composition|weight)\b|"
    r"\b(?:body[ -]?fat|body[ -]?composition|weight)\b"
    r"[^.!?\n]{0,50}\b(?:goal|target|loss|gain|cut|bulk|percent(?:age)?)\b|"
    r"\b(?:abnehmen|zunehmen|k[öo]rperfett|k[öo]rperzusammensetzung|"
    r"gewichts?ziel|perder peso|ganar peso|grasa corporal|"
    r"composici[oó]n corporal)\b",
    re.IGNORECASE,
)
_OBLIQUE_NUTRITION_REQUEST_RE = re.compile(
    r"\b(?:refill|replenish|restore|top up|auff[üu]llen|reponer)\b"
    r"[^.!?\n]{0,45}\b(?:glycogen|electrolytes?|fuel stores?|glykogen|"
    r"elektrolyte|gluc[oó]geno|electrolitos?)\b|"
    r"\b(?:what|was|qu[eé])\b[^.!?\n]{0,35}\b(?:in|into|en)\b"
    r"[^.!?\n]{0,20}\b(?:my |meine[rn]? |mi )?"
    r"(?:bottle|plate|flasche|teller|botella|plato)\b|"
    r"\b(?:what|was|qu[eé])\b[^.!?\n]{0,35}\b(?:put|goes?|kommt|poner)\b"
    r"[^.!?\n]{0,25}\b(?:on|in|auf|en)\b[^.!?\n]{0,10}"
    r"\b(?:my |meine[rn]? |mi )?(?:bottle|plate|flasche|teller|botella|plato)\b|"
    r"\b(?:fuel me|underfueled|under-fueled|unterversorgt|infraalimentad[oa])\b",
    re.IGNORECASE,
)
_NUTRITION_INFERENCE_RE = re.compile(
    r"\b(?:you(?:'re| are| seem| look)?|du bist|pareces|est[aá]s)\b"
    r"[^.!?\n]{0,45}\b(?:dehydrated|underfueled|under-fueled|deficient|"
    r"low in (?:protein|carbs?|electrolytes?|sodium)|"
    r"dehydriert|unterversorgt|mangel|deshidratad[oa]|deficiente)\b|"
    r"\b(?:dehydrated|underfueled|under-fueled|deficien(?:t|cy)|dehydration|"
    r"electrolyte imbalance|protein deficiency|nutrition deficiency|"
    r"low glycogen|dehydriert|unterversorgt|mangel|deshidratad[oa]|"
    r"deficiente)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LoopStats:
    checked: int = 0
    answered: int = 0
    notes_written: int = 0
    setup_drafts_written: int = 0
    training_plans_written: int = 0


@dataclass(frozen=True)
class CoachDecision:
    reply: str
    tool: str | None = None
    payload: dict[str, Any] | None = None
    note_capture: dict[str, Any] | None = None


@dataclass(frozen=True)
class DecisionOutcome:
    reply: str
    setup_draft_written: bool = False
    training_plan_written: bool = False


@dataclass
class TrainingRequestRetryState:
    """Bounded retry state for the one current phone-authored plan request."""

    clock: Callable[[], float] = time.monotonic
    completed_request_id: str | None = None
    failed_request_id: str | None = None
    failure_count: int = 0
    retry_after: float = 0.0
    blocker_sent: bool = False
    revision_blocked_request_id: str | None = None

    def should_attempt(self, request_id: str) -> bool:
        if request_id == self.completed_request_id:
            return False
        if request_id == self.revision_blocked_request_id:
            return False
        if self.revision_blocked_request_id is not None:
            self.revision_blocked_request_id = None
        self._select(request_id)
        return self.clock() >= self.retry_after

    def record_failure(self, request_id: str) -> bool:
        self._select(request_id)
        self.failure_count += 1
        exponent = min(self.failure_count - 1, 8)
        delay = min(
            _PLAN_RETRY_BASE_SECONDS * (2**exponent),
            _PLAN_RETRY_MAX_SECONDS,
        )
        self.retry_after = self.clock() + delay
        should_send_blocker = not self.blocker_sent
        self.blocker_sent = True
        return should_send_blocker

    def record_success(self, request_id: str) -> None:
        self.completed_request_id = request_id
        self.failed_request_id = None
        self.failure_count = 0
        self.retry_after = 0.0
        self.blocker_sent = False
        self.revision_blocked_request_id = None

    def block_until_fresh_request(self, request_id: str) -> bool:
        already_blocked = request_id == self.revision_blocked_request_id
        self.revision_blocked_request_id = request_id
        self.failed_request_id = request_id
        self.failure_count = 0
        self.retry_after = 0.0
        self.blocker_sent = True
        return not already_blocked

    def _select(self, request_id: str) -> None:
        if request_id == self.failed_request_id:
            return
        self.failed_request_id = request_id
        self.failure_count = 0
        self.retry_after = 0.0
        self.blocker_sent = False


def run_chat_loop(
    *,
    client: T4LMcpClient,
    model: RuntimeCoach,
    config: LoopConfig,
    pre_model_handler: PreModelHandler | None = None,
) -> LoopStats:
    total = LoopStats()
    request_retry_state = TrainingRequestRetryState()
    while True:
        current = answer_pending_messages(
            client=client,
            model=model,
            recent_chat_limit=config.recent_chat_limit,
            pre_model_handler=pre_model_handler,
            instruction_bundle_dir=config.instruction_bundle_dir,
        )
        background = process_current_training_request(
            client=client,
            model=model,
            recent_chat_limit=config.recent_chat_limit,
            instruction_bundle_dir=config.instruction_bundle_dir,
            retry_state=request_retry_state,
        )
        total = LoopStats(
            checked=total.checked + current.checked,
            answered=total.answered + current.answered,
            notes_written=total.notes_written + current.notes_written,
            setup_drafts_written=(
                total.setup_drafts_written + current.setup_drafts_written
            ),
            training_plans_written=(
                total.training_plans_written
                + current.training_plans_written
                + background.training_plans_written
            ),
        )
        if config.once:
            return total
        time.sleep(config.poll_seconds)


def answer_pending_messages(
    *,
    client: T4LMcpClient,
    model: RuntimeCoach,
    recent_chat_limit: int,
    pre_model_handler: PreModelHandler | None = None,
    instruction_bundle_dir: Path | None = None,
    video_verifier: ExerciseVideoVerifier | None = None,
) -> LoopStats:
    messages = client.pending_messages()
    stats = LoopStats(checked=len(messages))
    answered = 0
    notes_written = 0
    setup_drafts_written = 0
    training_plans_written = 0
    instructions: dict[str, str] = {}
    descriptor: dict[str, Any] | None = None
    for message in messages:
        seq = _coerce_int(message.get("seq"))
        content = str(message.get("content") or "").strip()
        if not content:
            continue
        if pre_model_handler is not None:
            pre_model = pre_model_handler.handle(message)
            if pre_model.handled:
                _write_safe_chat_reply(client, pre_model.reply, seq)
                answered += 1
                continue
        if is_nutrition_guidance_request(content):
            _write_safe_chat_reply(client, NUTRITION_GUIDANCE_BOUNDARY_REPLY, seq)
            answered += 1
            continue
        planning_context = client.get_planning_context(recent_chat_limit)
        purpose = _prompt_purpose(planning_context)
        if purpose not in instructions:
            instructions[purpose] = load_instruction_bundle(
                instruction_bundle_dir, purpose=purpose
            )
        if descriptor is None:
            descriptor = client.get_agent_descriptor()
        decision = build_decision(
            model=model,
            message=message,
            planning_context=planning_context,
            descriptor=descriptor,
            instructions=instructions[purpose],
        )
        outcome = execute_decision(
            client=client,
            message=message,
            planning_context=planning_context,
            descriptor=descriptor,
            decision=decision,
            video_verifier=video_verifier or YouTubeOEmbedVerifier(),
        )
        safe_outcome_reply = safe_coach_reply(outcome.reply)
        _write_safe_chat_reply(client, safe_outcome_reply, seq)
        answered += 1
        setup_drafts_written += int(outcome.setup_draft_written)
        training_plans_written += int(outcome.training_plan_written)
        if message.get("visibility") != "control" and update_coaching_notes(
            client=client,
            seq=seq,
            capture=decision.note_capture,
        ):
            notes_written += 1
    return LoopStats(
        checked=stats.checked,
        answered=answered,
        notes_written=notes_written,
        setup_drafts_written=setup_drafts_written,
        training_plans_written=training_plans_written,
    )


def build_reply(
    *,
    model: RuntimeCoach,
    message: dict[str, Any],
    planning_context: dict[str, Any],
) -> str:
    """Compatibility wrapper for callers that only need an athlete reply."""
    return build_decision(
        model=model,
        message=message,
        planning_context=planning_context,
        descriptor={
            "agentId": "unverified",
            "displayName": "T4L Gym Bro",
            "runtime": "unverified",
        },
        instructions="",
    ).reply


def build_decision(
    *,
    model: RuntimeCoach,
    message: dict[str, Any],
    planning_context: dict[str, Any],
    descriptor: dict[str, Any],
    instructions: str,
) -> CoachDecision:
    user_content = str(message.get("content") or "")
    if is_nutrition_guidance_request(user_content):
        return CoachDecision(reply=NUTRITION_GUIDANCE_BOUNDARY_REPLY)
    safety_suffix = (
        "\nThis message includes a possible safety or pain signal. "
        "Be extra conservative."
        if SAFETY_RE.search(user_content)
        else ""
    )
    prompt = {
        "verifiedAgentDescriptor": descriptor,
        "phase": _phase(planning_context),
        "latestMessage": {
            "seq": message.get("seq"),
            "conversationId": message.get("conversationId"),
            "visibility": message.get("visibility"),
            "createdAt": message.get("createdAt"),
            "content": user_content,
        },
        "trustedExerciseMediaCatalog": _trusted_media_catalog(planning_context),
        "planningContext": _model_planning_context(planning_context),
    }
    raw = model.chat(
        [
            ChatMessage(
                role="system",
                content=(
                    ORCHESTRATOR_SYSTEM_PROMPT
                    + safety_suffix
                    + (
                        "\n\n--- RELEVANT INSTALLED T4L INSTRUCTIONS ---\n"
                        + instructions
                        if instructions
                        else ""
                    )
                ),
            ),
            ChatMessage(role="user", content=dumps_compact(prompt)),
        ],
        temperature=0.0,
        max_tokens=(
            _PLAN_MAX_TOKENS
            if _current_training_request(planning_context) is not None
            and _has_accepted_setup(planning_context)
            else _CHAT_MAX_TOKENS
        ),
        web_search=(
            _current_training_request(planning_context) is not None
            and _has_accepted_setup(planning_context)
            and not _trusted_media_catalog(planning_context)
        ),
    )
    parsed = parse_json_object(raw)
    if parsed is None:
        return CoachDecision(reply=safe_coach_reply(raw))
    reply = parsed.get("reply")
    safe_reply = safe_coach_reply(reply) if isinstance(reply, str) else ""
    note_capture = _sanitize_note_capture(parsed.get("notes"))
    write = parsed.get("write")
    if not isinstance(write, dict):
        return CoachDecision(
            reply=safe_reply or "I need one more detail.",
            note_capture=note_capture,
        )
    tool = write.get("tool")
    payload = write.get("payload")
    if not isinstance(tool, str) or not isinstance(payload, dict):
        return CoachDecision(
            reply=safe_reply or "I could not prepare that yet.",
            note_capture=note_capture,
        )
    return CoachDecision(
        reply=safe_reply or "I prepared a proposal for phone review.",
        tool=tool,
        payload=cast(dict[str, Any], payload),
        note_capture=note_capture,
    )


def execute_decision(
    *,
    client: T4LMcpClient,
    message: dict[str, Any],
    planning_context: dict[str, Any],
    descriptor: dict[str, Any],
    decision: CoachDecision,
    video_verifier: ExerciseVideoVerifier | None = None,
) -> DecisionOutcome:
    reply = _with_verified_intro(
        decision.reply,
        message=message,
        planning_context=planning_context,
        descriptor=descriptor,
    )
    if decision.tool is None:
        return DecisionOutcome(reply=reply)
    if decision.tool == "write_athlete_setup_draft":
        error, payload = _prepare_setup_draft(
            decision.payload,
            message=message,
            planning_context=planning_context,
        )
        if error is not None or payload is None:
            return DecisionOutcome(reply=f"I did not send a setup draft. {error}")
        client.write_athlete_setup_draft(payload)
        return DecisionOutcome(
            reply=(
                "I sent the confirmed setup draft to your phone for review. "
                "It is not accepted or applied yet. Review it on the phone."
            ),
            setup_draft_written=True,
        )
    if decision.tool == "write_training_block_plan":
        error, payload = _prepare_training_block_plan(
            decision.payload,
            planning_context=planning_context,
            video_verifier=video_verifier,
        )
        if error is not None or payload is None:
            return DecisionOutcome(reply=f"I did not store a training plan. {error}")
        try:
            client.write_training_block_plan(payload)
        except T4LError as mcp_error:
            if not mcp_error.refresh_context_required:
                raise
            return DecisionOutcome(
                reply=(
                    "I did not store that training plan because the phone context "
                    "changed while I was planning. Send a fresh training-block "
                    "request from the latest phone state. Nothing was stored or "
                    "accepted."
                )
            )
        return DecisionOutcome(
            reply=_accepted_handoff_reply(planning_context),
            training_plan_written=True,
        )
    return DecisionOutcome(
        reply="I did not run that write. The requested T4L tool is not allowed here."
    )


def process_current_training_request(
    *,
    client: T4LMcpClient,
    model: RuntimeCoach,
    recent_chat_limit: int,
    instruction_bundle_dir: Path | None,
    retry_state: TrainingRequestRetryState,
    video_verifier: ExerciseVideoVerifier | None = None,
) -> LoopStats:
    """Process a phone-authored daily or block request without a chat turn."""
    planning_context = client.get_planning_context(recent_chat_limit)
    daily_request = _pending_daily_workout_request(planning_context)
    if daily_request is not None:
        return _process_daily_workout_request(
            client=client,
            planning_context=planning_context,
            request=daily_request,
            retry_state=retry_state,
        )
    request = _pending_training_request(planning_context)
    if request is None or not _has_accepted_setup(planning_context):
        return LoopStats()
    request_id = str(request["requestId"])
    if _plan_already_stored_for_request(planning_context, request_id):
        retry_state.record_success(request_id)
        return LoopStats()
    if not retry_state.should_attempt(request_id):
        return LoopStats()
    revision_error = _training_request_revision_error(request, planning_context)
    if revision_error is not None:
        if retry_state.block_until_fresh_request(request_id):
            _write_safe_chat_reply(
                client,
                "I did not plan from that phone request. "
                f"{revision_error} Nothing was stored or accepted.",
                0,
            )
        return LoopStats()
    descriptor = client.get_agent_descriptor()
    decision = build_decision(
        model=model,
        message={
            "content": "Process the current phone-authored training-block request.",
            "visibility": "control",
        },
        planning_context=planning_context,
        descriptor=descriptor,
        instructions=load_instruction_bundle(
            instruction_bundle_dir, purpose="planning"
        ),
    )
    if decision.tool != "write_training_block_plan":
        if retry_state.record_failure(request_id):
            _write_safe_chat_reply(
                client,
                decision.reply
                or (
                    "I could not create the requested plan because verified "
                    "exercise videos are unavailable. Nothing was stored."
                ),
                0,
            )
        return LoopStats()
    preparation_error, payload = _prepare_training_block_plan(
        decision.payload,
        planning_context=planning_context,
        video_verifier=video_verifier or YouTubeOEmbedVerifier(),
    )
    if preparation_error is not None or payload is None:
        if retry_state.record_failure(request_id):
            _write_safe_chat_reply(
                client,
                "I could not store the requested training block. "
                f"{preparation_error} Nothing was accepted or applied.",
                0,
            )
        return LoopStats()
    try:
        client.write_training_block_plan(payload)
    except T4LError as mcp_error:
        if not mcp_error.refresh_context_required:
            raise
        if retry_state.block_until_fresh_request(request_id):
            _write_safe_chat_reply(
                client,
                "I did not store that training block because the phone context "
                "changed while I was planning. Send a fresh training-block "
                "request from the latest phone state. Nothing was stored or accepted.",
                0,
            )
        return LoopStats()
    retry_state.record_success(request_id)
    _write_safe_chat_reply(client, _accepted_handoff_reply(planning_context), 0)
    return LoopStats(training_plans_written=1)


def _process_daily_workout_request(
    *,
    client: T4LMcpClient,
    planning_context: dict[str, Any],
    request: dict[str, Any],
    retry_state: TrainingRequestRetryState,
) -> LoopStats:
    """Create one review-only daily recommendation from phone-approved choices."""
    request_id = str(request.get("requestId") or "")
    if not request_id:
        return LoopStats()
    if _daily_plan_already_stored_for_request(planning_context, request_id):
        retry_state.record_success(request_id)
        return LoopStats()
    if not retry_state.should_attempt(request_id):
        return LoopStats()
    error, payload = _prepare_daily_workout_plan(request, planning_context)
    if error is not None or payload is None:
        retry_state.record_failure(request_id)
        return LoopStats()
    try:
        client.write_daily_workout_plan(payload)
    except T4LError as mcp_error:
        if not mcp_error.refresh_context_required:
            raise
        retry_state.block_until_fresh_request(request_id)
        return LoopStats()
    retry_state.record_success(request_id)
    return LoopStats(training_plans_written=1)


def is_nutrition_guidance_request(text: str) -> bool:
    """Return true only for requests asking the coach to prescribe nutrition."""
    normalized = " ".join(text.split())
    if not normalized:
        return False
    if _BODY_CHANGE_RE.search(normalized) or _OBLIQUE_NUTRITION_REQUEST_RE.search(
        normalized
    ):
        return True
    if _NUTRITION_TOPIC_RE.search(normalized) is None:
        return False
    if _ADVICE_REQUEST_RE.search(normalized) is not None:
        return True
    # A question about a scoped topic is itself a request for the coach to
    # answer inside that prohibited domain (for example, "Is creatine safe?").
    return "?" in normalized


def contains_prohibited_nutrition_guidance(text: str) -> bool:
    """Deterministic last-mile gate for athlete-visible coach output."""
    normalized = " ".join(text.split())
    if not normalized or normalized == NUTRITION_GUIDANCE_BOUNDARY_REPLY:
        return False
    # Fail closed on scoped topics. A prose classifier that only looks for
    # imperative verbs misses declarative prescriptions such as "a shake works
    # best after training" and body-composition calculations such as BMI.
    if _NUTRITION_TOPIC_RE.search(normalized) is not None:
        return True
    return any(
        pattern.search(normalized) is not None
        for pattern in (
            _NUTRITION_INFERENCE_RE,
            _BODY_CHANGE_RE,
        )
    )


def safe_coach_reply(text: str) -> str:
    """Replace prohibited guidance with the fixed product boundary."""
    stripped = text.strip()
    if contains_prohibited_nutrition_guidance(stripped):
        return NUTRITION_GUIDANCE_BOUNDARY_REPLY
    return stripped


def _write_safe_chat_reply(client: T4LMcpClient, content: str, seq: int | None) -> None:
    client.write_chat_reply(safe_coach_reply(content), seq)


def load_instruction_bundle(bundle_dir: Path | None, *, purpose: str) -> str:
    if bundle_dir is None:
        raise ValueError("An installed T4L instruction bundle is required.")
    files = _INSTRUCTION_FILES_BY_PURPOSE.get(purpose)
    if files is None:
        raise ValueError(f"Unknown T4L instruction purpose: {purpose}")
    root = bundle_dir.expanduser().resolve()
    chunks: list[str] = []
    total = 0
    for relative in files:
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError("Instruction path escaped the bundle root.") from error
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Instruction bundle file is missing: {relative}")
        content = path.read_text(encoding="utf-8")
        total += len(content.encode("utf-8"))
        if total > _MAX_INSTRUCTION_BYTES:
            raise ValueError("Instruction bundle is too large.")
        chunks.append(f"\n### {relative}\n{content.strip()}\n")
    return "".join(chunks)


def _prompt_purpose(planning_context: dict[str, Any]) -> str:
    if not _has_accepted_setup(planning_context):
        return "onboarding"
    if _current_training_request(planning_context) is not None:
        return "planning"
    return "chat"


def _model_planning_context(
    planning_context: dict[str, Any],
) -> dict[str, Any]:
    """Keep authoritative context and drop broker compatibility copies."""

    result: dict[str, Any] = {
        key: deepcopy(planning_context[key])
        for key in ("schema", "planningContractVersion", "generatedAt")
        if key in planning_context
    }
    accepted = planning_context.get("acceptedState")
    if isinstance(accepted, dict):
        accepted_copy = deepcopy(accepted)
        contexts = accepted_copy.get("contexts")
        if isinstance(contexts, dict):
            app_snapshot = contexts.get("app_snapshot")
            if isinstance(app_snapshot, dict):
                if app_snapshot.get("dayContext") == contexts.get("day_context"):
                    app_snapshot.pop("dayContext", None)
                if app_snapshot.get("dailySnapshot") == contexts.get("daily_snapshot"):
                    app_snapshot.pop("dailySnapshot", None)
                profile_artifact = contexts.get("athlete_profile")
                profile = (
                    profile_artifact.get("profile")
                    if isinstance(profile_artifact, dict)
                    else None
                )
                fitness_data = app_snapshot.get("fitnessData")
                if (
                    isinstance(fitness_data, dict)
                    and profile is not None
                    and fitness_data.get("profile") == profile
                ):
                    fitness_data.pop("profile", None)
                # This catalog is supplied once beside planningContext as a
                # compact exercise-id -> verified URL map.
                app_snapshot.pop("verifiedExerciseMediaCatalog", None)
            accepted_copy["contexts"] = _drop_prompt_duplicates(contexts)
        result["acceptedState"] = accepted_copy
    requests = planning_context.get("currentRequests")
    if isinstance(requests, list):
        result["currentRequests"] = [
            deepcopy(item)
            for item in requests
            if isinstance(item, dict)
            and item.get("status") == "pending"
            and item.get("kind") in {"training_block_request", "daily_workout_request"}
        ]
    notes = planning_context.get("coachingNotes")
    if isinstance(notes, dict):
        result["coachingNotes"] = _drop_prompt_duplicates(deepcopy(notes))
    chat = planning_context.get("recentChat")
    if isinstance(chat, list):
        result["recentChat"] = [
            {
                key: deepcopy(item[key])
                for key in ("seq", "role", "content", "createdAt")
                if key in item
            }
            for item in chat
            if isinstance(item, dict)
        ]
    # Legacy installs have no atomic accepted bundle. Keep only the few old
    # fallbacks they need; v2 agents never receive these duplicated rows.
    if _accepted_revision(planning_context) is None:
        for key in ("dayContext", "recentLogs", "profile", "activeBlock"):
            value = planning_context.get(key)
            if value is not None:
                result[key] = _drop_prompt_duplicates(deepcopy(value))
    return result


def _drop_prompt_duplicates(value: Any) -> Any:
    if isinstance(value, list):
        return [_drop_prompt_duplicates(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: _drop_prompt_duplicates(item)
        for key, item in value.items()
        if not (value.get("schema") == "memory_wiki.v1" and key == "byCategory")
    }


def _phase(planning_context: dict[str, Any]) -> dict[str, Any]:
    revision = _accepted_revision(planning_context)
    request = _current_training_request(planning_context)
    return {
        "name": "coaching" if _has_accepted_setup(planning_context) else "onboarding",
        "acceptedContextRevision": revision,
        "phoneControlsAcceptedState": True,
        "currentTrainingBlockRequestId": (
            request.get("requestId") if request is not None else None
        ),
    }


def _with_verified_intro(
    reply: str,
    *,
    message: dict[str, Any],
    planning_context: dict[str, Any],
    descriptor: dict[str, Any],
) -> str:
    if message.get("visibility") != "control" or _has_accepted_setup(planning_context):
        return reply
    name = descriptor.get("displayName")
    runtime = descriptor.get("runtime")
    if not isinstance(name, str) or not name.strip():
        return reply
    lines = [f"I'm {name.strip()}, your T4L Gym Bro."]
    metadata: list[str] = []
    if isinstance(runtime, str) and runtime.strip():
        metadata.append(f"runtime {runtime.strip()}")
    provider = descriptor.get("provider")
    model = descriptor.get("model")
    reasoning = descriptor.get("reasoning")
    if isinstance(provider, str) and provider.strip():
        metadata.append(f"provider {provider.strip()}")
    if isinstance(model, str) and model.strip():
        metadata.append(f"model {model.strip()}")
    if isinstance(reasoning, str) and reasoning.strip():
        metadata.append(f"reasoning {reasoning.strip()}")
    if metadata:
        lines.append("Verified: " + ", ".join(metadata) + ".")
    lines.append("Your phone controls accepted training state.")
    if reply.strip():
        lines.append(reply.strip())
    return "\n".join(lines)


def _prepare_setup_draft(
    raw_payload: dict[str, Any] | None,
    *,
    message: dict[str, Any],
    planning_context: dict[str, Any],
    video_verifier: ExerciseVideoVerifier | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    if _has_accepted_setup(planning_context):
        return "The phone already has accepted setup state.", None
    content = str(message.get("content") or "")
    if _EXPLICIT_CONFIRM_RE.fullmatch(content) is None:
        return "The latest athlete turn was not an explicit confirmation.", None
    if raw_payload is None:
        return "The model did not provide the setup fields.", None
    sequence = _coerce_int(message.get("seq"))
    created_at = message.get("createdAt")
    if sequence is None or sequence < 1:
        return "The confirmed chat sequence is missing.", None
    if not isinstance(created_at, str) or not _is_iso_datetime(created_at):
        return "The confirmed chat timestamp is missing.", None
    confirmation = raw_payload.get("confirmation")
    summary = confirmation.get("summary") if isinstance(confirmation, dict) else None
    if not isinstance(summary, str) or not summary.strip():
        return "The confirmed setup summary is missing.", None
    if not _summary_was_presented(summary, planning_context):
        return "The setup summary does not match the prior coach turn.", None
    profile = raw_payload.get("profile")
    goals = raw_payload.get("goals")
    if not isinstance(profile, dict) or not isinstance(goals, dict):
        return "The setup profile or goals are incomplete.", None
    conversation = message.get("conversationId")
    conversation_id = (
        conversation.strip()
        if isinstance(conversation, str) and conversation.strip()
        else "default"
    )
    digest_input = dumps_compact(
        {
            "conversationId": conversation_id,
            "seq": sequence,
            "summary": summary.strip(),
        }
    ).encode("utf-8")
    profile_allowed = {
        "name",
        "goal",
        "heightCm",
        "weightKg",
        "age",
        "sex",
        "trainingDays",
        "sessionMinutes",
        "equipment",
        "constraints",
        "preferences",
    }
    goals_allowed = {
        "longTerm",
        "shortTerm",
        "blockWeeks",
        "successTest",
        "reviewDate",
    }
    equipment, equipment_error = _normalise_equipment(profile.get("equipment"))
    if equipment_error is not None:
        return equipment_error, None
    clean_profile = {
        key: value for key, value in profile.items() if key in profile_allowed
    }
    clean_profile["equipment"] = equipment
    payload: dict[str, Any] = {
        "schema": "athlete_setup_draft.v1",
        "draftId": "setup_" + hashlib.sha256(digest_input).hexdigest()[:24],
        "createdAt": created_at,
        "source": {
            "conversationId": conversation_id,
            "confirmedMessageSeq": sequence,
            "confirmedAt": created_at,
        },
        "profile": clean_profile,
        "goals": {key: value for key, value in goals.items() if key in goals_allowed},
        "hardLimits": raw_payload.get("hardLimits"),
        # Required only by the legacy phone wire schema. Nutrition is outside
        # coach scope, so the host never forwards model-authored values.
        "nutritionPreferences": [],
        "coachingStyle": raw_payload.get("coachingStyle"),
        "confirmation": {"summary": summary.strip(), "confirmed": True},
    }
    if _contains_prohibited_guidance_value(payload):
        return "The setup draft contains guidance outside coach scope.", None
    error = _validate_setup_draft(payload)
    return (error, None) if error is not None else (None, payload)


def _validate_setup_draft(payload: dict[str, Any]) -> str | None:
    required = {
        "schema",
        "draftId",
        "createdAt",
        "source",
        "profile",
        "goals",
        "hardLimits",
        "nutritionPreferences",
        "coachingStyle",
        "confirmation",
    }
    if set(payload) != required:
        return "The setup draft has the wrong top-level fields."
    profile = payload.get("profile")
    goals = payload.get("goals")
    if not isinstance(profile, dict) or not isinstance(goals, dict):
        return "The setup profile or goals are not objects."
    if not _nonempty_string(profile.get("goal")):
        return "The training goal is missing."
    training_days = profile.get("trainingDays")
    if not _bounded_int(training_days, 1, 7):
        return "Training days must be between 1 and 7."
    session_minutes = profile.get("sessionMinutes")
    if not _bounded_int(session_minutes, 10, 240):
        return "Session length must be between 10 and 240 minutes."
    for key in ("equipment", "constraints", "preferences"):
        if not _string_list_value(profile.get(key)):
            return f"profile.{key} must be an array of non-empty strings."
    for key in ("longTerm", "shortTerm", "successTest"):
        if not _nonempty_string(goals.get(key)):
            return f"goals.{key} is missing."
    if not _bounded_int(goals.get("blockWeeks"), 1, 4):
        return "Block length must be between 1 and 4 weeks."
    review_date = goals.get("reviewDate")
    if review_date is not None and not _is_iso_date(review_date):
        return "The review date must use YYYY-MM-DD."
    for key in ("hardLimits", "nutritionPreferences"):
        if not _string_list_value(payload.get(key)):
            return f"{key} must be an array of non-empty strings."
    if not _nonempty_string(payload.get("coachingStyle")):
        return "The coaching style is missing."
    for key in ("heightCm", "weightKg"):
        value = profile.get(key)
        if value is not None and (
            not isinstance(value, int | float) or isinstance(value, bool) or value <= 0
        ):
            return f"profile.{key} must be positive when present."
    age = profile.get("age")
    if age is not None and not _bounded_int(age, 13, 120):
        return "profile.age must be between 13 and 120 when present."
    for key in ("name", "sex"):
        if key in profile and not _nonempty_string(profile.get(key)):
            return f"profile.{key} must be non-empty when present."
    return None


def _prepare_training_block_plan(
    raw_payload: dict[str, Any] | None,
    *,
    planning_context: dict[str, Any],
    video_verifier: ExerciseVideoVerifier | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    if not _has_accepted_setup(planning_context):
        return "The phone has not accepted and synced athlete setup yet.", None
    request = _pending_training_request(planning_context)
    if request is None:
        return "There is no current phone-authored training-block request.", None
    revision_error = _training_request_revision_error(request, planning_context)
    if revision_error is not None:
        return revision_error, None
    request_id = str(request["requestId"])
    if _plan_already_stored_for_request(planning_context, request_id):
        return "A proposal for this request is already stored.", None
    if raw_payload is None:
        return "The model did not provide a training block.", None
    if _contains_prohibited_guidance_value(raw_payload):
        return "The training block contains guidance outside coach scope.", None
    payload = dict(raw_payload)
    payload["requestId"] = request_id
    revision = _accepted_revision(planning_context)
    if revision is not None:
        payload["contextRevision"] = revision
    error = _validate_training_block(
        payload,
        _trusted_media_catalog(planning_context),
        video_verifier,
    )
    return (error, None) if error is not None else (None, payload)


def _contains_prohibited_guidance_value(value: object) -> bool:
    if isinstance(value, str):
        return contains_prohibited_nutrition_guidance(value)
    if isinstance(value, dict):
        return any(
            _contains_prohibited_guidance_value(child) for child in value.values()
        )
    if isinstance(value, list):
        return any(_contains_prohibited_guidance_value(child) for child in value)
    return False


def _validate_training_block(
    payload: dict[str, Any],
    catalog: dict[str, str],
    video_verifier: ExerciseVideoVerifier | None,
) -> str | None:
    if not catalog and video_verifier is None:
        return "A trusted Shorts catalog or live verification tool is missing."
    candidate = payload.get("block")
    block = candidate if isinstance(candidate, dict) else payload
    required = (
        "id",
        "style",
        "title",
        "durationWeeks",
        "currentWeek",
        "weeklyFocus",
        "measurableTargets",
        "workouts",
        "createdBy",
        "createdAt",
    )
    if any(key not in block for key in required):
        return "The training block is missing required fields."
    duration = block.get("durationWeeks")
    current_week = block.get("currentWeek")
    if not _bounded_int(duration, 1, 52) or not _bounded_int(current_week, 1, 52):
        return "The training block has invalid week numbers."
    if not _string_list_value(block.get("weeklyFocus"), allow_empty=False):
        return "weeklyFocus must be a non-empty string array."
    if not _string_list_value(block.get("measurableTargets"), allow_empty=False):
        return "measurableTargets must be a non-empty string array."
    workouts = block.get("workouts")
    if not isinstance(workouts, list) or not workouts:
        return "The training block has no workouts."
    weeks: set[int] = set()
    for index, workout in enumerate(workouts):
        if not isinstance(workout, dict):
            return f"Workout {index + 1} is not an object."
        week = workout.get("week")
        if not isinstance(week, int) or isinstance(week, bool):
            return f"Workout {index + 1} has no valid week."
        weeks.add(week)
        error = _validate_workout(workout, catalog, video_verifier, index)
        if error is not None:
            return error
    if weeks != set(range(1, cast(int, duration) + 1)):
        return "The full block must include at least one workout in every week."
    return None


def _validate_workout(
    workout: dict[str, Any],
    catalog: dict[str, str],
    video_verifier: ExerciseVideoVerifier | None,
    workout_index: int,
) -> str | None:
    for key in ("id", "week", "day", "title", "focus", "rationale", "conditioning"):
        if key not in workout or workout[key] in (None, ""):
            return f"Workout {workout_index + 1} is missing {key}."
    items = workout.get("items")
    exercises = workout.get("exercises")
    if isinstance(items, list) and items:
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                return f"Workout item {index + 1} is not an object."
            item_type = str(item.get("type") or "exercise")
            if item_type in {"", "exercise"}:
                exercise = item.get("exercise")
                candidate = exercise if isinstance(exercise, dict) else item
                error = _validate_exercise(candidate, catalog, video_verifier)
            elif item_type in {"superset", "circuit"}:
                children = item.get("exercises")
                expected = 2 if item_type == "superset" else 3
                if not isinstance(children, list) or len(children) < expected:
                    return f"A {item_type} has the wrong number of exercises."
                if item_type == "superset" and len(children) != 2:
                    return "A superset must contain exactly two exercises."
                if not _bounded_int(item.get("rounds"), 1, 100):
                    return f"A {item_type} needs a positive rounds value."
                error = None
                for child in children:
                    if not isinstance(child, dict):
                        return f"A {item_type} child is not an exercise object."
                    child_sets = child.get("sets")
                    if child_sets not in (None, 1) or isinstance(child_sets, bool):
                        return f"A {item_type} child sets must be 1 or omitted."
                    error = _validate_exercise(child, catalog, video_verifier)
                    if error is not None:
                        break
            else:
                return "Workout item type must be exercise, superset, or circuit."
            if error is not None:
                return error
        return None
    if isinstance(exercises, list) and exercises:
        for exercise in exercises:
            if not isinstance(exercise, dict):
                return "A flat workout contains an invalid exercise."
            error = _validate_exercise(exercise, catalog, video_verifier)
            if error is not None:
                return error
        return None
    return "Each workout needs non-empty items or exercises."


def _validate_exercise(
    exercise: dict[str, Any],
    catalog: dict[str, str],
    video_verifier: ExerciseVideoVerifier | None,
) -> str | None:
    for key in (
        "exerciseId",
        "name",
        "sets",
        "reps",
        "targetLoad",
        "targetRpe",
        "restSeconds",
        "coachCue",
    ):
        if key not in exercise or exercise[key] in (None, ""):
            return f"Exercise is missing {key}."
    if isinstance(exercise.get("exercises"), list):
        return "Nested workout groups are not supported."
    media = exercise.get("media")
    if not isinstance(media, dict):
        return "Every exercise needs a media object."
    url = media.get("explainerUrl")
    if not isinstance(url, str) or _YOUTUBE_SHORT_RE.fullmatch(url) is None:
        return "Every exercise needs a canonical YouTube Shorts URL."
    if not _nonempty_string(media.get("setup")):
        return "Every exercise video needs setup guidance."
    for key in ("cues", "commonMistakes"):
        if not _string_list_value(media.get(key), allow_empty=False):
            return f"Every exercise video needs non-empty {key}."
    exercise_id = _catalog_key(exercise.get("exerciseId"))
    exercise_name = _catalog_key(exercise.get("name"))
    trusted = catalog.get(exercise_id) or catalog.get(exercise_name)
    if trusted == url:
        return None
    raw_id = exercise.get("exerciseId")
    raw_name = exercise.get("name")
    if (
        video_verifier is None
        or not isinstance(raw_id, str)
        or not isinstance(raw_name, str)
        or not video_verifier.verify(exercise_id=raw_id, name=raw_name, url=url)
    ):
        return "An exercise Short is not verified for that exact variation."
    return None


def _trusted_media_catalog(planning_context: dict[str, Any]) -> dict[str, str]:
    accepted = planning_context.get("acceptedState")
    contexts = accepted.get("contexts") if isinstance(accepted, dict) else None
    if not isinstance(contexts, dict):
        return {}
    catalog: dict[str, str] = {}
    for context in contexts.values():
        if not isinstance(context, dict):
            continue
        for key in (
            "verifiedExerciseMediaCatalog",
            "exerciseMediaCatalog",
            "verifiedExerciseMedia",
        ):
            _collect_catalog_entries(context.get(key), catalog)
        fitness_data = context.get("fitnessData")
        if isinstance(fitness_data, dict):
            for key in (
                "verifiedExerciseMediaCatalog",
                "exerciseMediaCatalog",
                "verifiedExerciseMedia",
            ):
                _collect_catalog_entries(fitness_data.get(key), catalog)
    return catalog


def _collect_catalog_entries(value: object, target: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and _YOUTUBE_SHORT_RE.fullmatch(item):
                target[_catalog_key(key)] = item
            elif isinstance(item, dict):
                _collect_catalog_item(item, target, fallback=key)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                _collect_catalog_item(item, target)


def _collect_catalog_item(
    item: dict[str, Any],
    target: dict[str, str],
    *,
    fallback: object = None,
) -> None:
    url = item.get("explainerUrl")
    if not isinstance(url, str) or _YOUTUBE_SHORT_RE.fullmatch(url) is None:
        return
    for raw_key in (item.get("exerciseId"), item.get("name"), fallback):
        key = _catalog_key(raw_key)
        if key:
            target[key] = url


def _current_training_request(
    planning_context: dict[str, Any],
) -> dict[str, Any] | None:
    request = _pending_training_request(planning_context)
    if request is None:
        return None
    if _training_request_revision_error(request, planning_context) is not None:
        return None
    return request


def _pending_daily_workout_request(
    planning_context: dict[str, Any],
) -> dict[str, Any] | None:
    requests = planning_context.get("currentRequests")
    if not isinstance(requests, list):
        return None
    for request in requests:
        if not isinstance(request, dict):
            continue
        request_id = request.get("requestId")
        if (
            request.get("kind") == "daily_workout_request"
            and request.get("status") == "pending"
            and isinstance(request_id, str)
            and request_id.strip()
        ):
            return cast(dict[str, Any], request)
    return None


def _daily_plan_already_stored_for_request(
    planning_context: dict[str, Any], request_id: str
) -> bool:
    plan = planning_context.get("dailyWorkoutPlan")
    if not isinstance(plan, dict):
        return False
    payload = plan.get("plan")
    candidate = payload if isinstance(payload, dict) else plan
    return candidate.get("requestId") == request_id


def _prepare_daily_workout_plan(
    request: dict[str, Any], planning_context: dict[str, Any]
) -> tuple[str | None, dict[str, Any] | None]:
    payload = request.get("payload")
    if not isinstance(payload, dict):
        return "The daily request payload is missing.", None
    revision = _accepted_revision(planning_context)
    if (
        revision is None
        or payload.get("contextRevision") != revision
        or not isinstance(payload.get("requestId"), str)
    ):
        return "The daily request is stale.", None
    target_date = payload.get("targetDate")
    if not isinstance(target_date, str) or not target_date:
        return "The daily request has no target date.", None
    excluded: set[tuple[str, str]] = set()
    for item in payload.get("excludedChoices", []):
        if not isinstance(item, dict):
            continue
        source = item.get("sourceWorkoutId")
        variant = item.get("variantId")
        if isinstance(source, str) and isinstance(variant, str):
            excluded.add((source, variant))
    check_in = payload.get("todayRecoveryCheckIn")
    recovery = check_in if isinstance(check_in, dict) else {}
    available_time = payload.get("availableTime")
    time_choice = available_time if isinstance(available_time, dict) else {}
    needs_short = (
        recovery.get("energy") == "lower"
        or recovery.get("soreness") == "moreSore"
        or recovery.get("sleepQuality") == "poor"
        or recovery.get("stress") == "higher"
    )
    supports_extension = (
        recovery.get("energy") == "higher"
        and recovery.get("soreness") == "fresh"
        and recovery.get("sleepQuality") == "good"
        and recovery.get("stress") == "lower"
        and bool(time_choice.get("openEnded"))
    )
    variant_order = (
        ("extended", "standard", "short")
        if supports_extension
        else ("short", "standard", "extended")
        if needs_short
        else ("standard", "short", "extended")
    )
    choices: list[tuple[str, str]] = []
    for workout in payload.get("eligibleChoices", []):
        if not isinstance(workout, dict):
            continue
        source = workout.get("workoutId")
        variants = workout.get("variants")
        if not isinstance(source, str) or not isinstance(variants, list):
            continue
        # The phone has already bounded these variants by the chosen time.
        # Transparent check-in signals select the smallest suitable version.
        for variant in variant_order:
            if variant in variants and (source, variant) not in excluded:
                choices.append((source, variant))
                break
    result: dict[str, Any] = {
        "schema": "daily_workout_plan.v1",
        "requestId": payload["requestId"],
        "contextRevision": revision,
        "targetDate": target_date,
    }
    if not choices:
        result.update(
            {
                "decision": "rest",
                "rationale": (
                    "No unfinished weekly session fits the time you selected. "
                    "Rest leaves every weekly session available."
                ),
            }
        )
        return None, result
    source, variant = choices[0]
    result.update(
        {
            "decision": "train",
            "sourceWorkoutId": source,
            "variantId": variant,
            "rationale": (
                "This unfinished session fits your time and today's recovery "
                "check-in. The accepted weekly plan stays unchanged."
            ),
        }
    )
    return None, result


def _pending_training_request(
    planning_context: dict[str, Any],
) -> dict[str, Any] | None:
    requests = planning_context.get("currentRequests")
    if not isinstance(requests, list):
        return None
    for request in requests:
        if not isinstance(request, dict):
            continue
        request_id = request.get("requestId")
        if (
            request.get("kind") == "training_block_request"
            and request.get("status") == "pending"
            and isinstance(request_id, str)
            and request_id.strip()
        ):
            return cast(dict[str, Any], request)
    return None


def _training_request_revision_error(
    request: dict[str, Any], planning_context: dict[str, Any]
) -> str | None:
    accepted_revision = _accepted_revision(planning_context)
    payload = request.get("payload")
    request_revision = (
        payload.get("contextRevision") if isinstance(payload, dict) else None
    )
    if (
        accepted_revision is None
        or not isinstance(request_revision, str)
        or request_revision.strip() != accepted_revision
    ):
        revision_label = accepted_revision or "the latest accepted revision"
        return (
            "The phone request is stale or missing its context revision. "
            f"Send a fresh request for {revision_label}."
        )
    return None


def _plan_already_stored_for_request(
    planning_context: dict[str, Any], request_id: str
) -> bool:
    active = planning_context.get("activeBlock")
    return isinstance(active, dict) and active.get("requestId") == request_id


def _accepted_revision(planning_context: dict[str, Any]) -> str | None:
    accepted = planning_context.get("acceptedState")
    revision = accepted.get("contextRevision") if isinstance(accepted, dict) else None
    return revision.strip() if isinstance(revision, str) and revision.strip() else None


def _accepted_handoff_reply(planning_context: dict[str, Any]) -> str:
    request = _current_training_request(planning_context) or {}
    request_payload = request.get("payload")
    payload = request_payload if isinstance(request_payload, dict) else {}
    goals = payload.get("goals")
    profile = payload.get("profile")
    goal = goals.get("shortTerm") if isinstance(goals, dict) else None
    if not _nonempty_string(goal) and isinstance(profile, dict):
        goal = profile.get("goal")
    constraints = profile.get("constraints") if isinstance(profile, dict) else None
    hard_limits = (
        "; ".join(str(item).strip() for item in constraints)
        if isinstance(constraints, list)
        and all(_nonempty_string(item) for item in constraints)
        and constraints
        else "none supplied in accepted phone context"
    )
    revision = _accepted_revision(planning_context) or "unknown"
    short_term = str(goal).strip() if _nonempty_string(goal) else "not supplied"
    return "\n".join(
        (
            f"Fresh phone context {revision} is synced.",
            f"Short-term goal: {short_term}.",
            f"Hard limits: {hard_limits}.",
            "The training-block proposal was stored for phone review. It is "
            "not accepted or applied yet.",
        )
    )


def _has_accepted_setup(planning_context: dict[str, Any]) -> bool:
    if _accepted_revision(planning_context) is None:
        return False
    accepted = planning_context.get("acceptedState")
    contexts = accepted.get("contexts") if isinstance(accepted, dict) else None
    artifact = contexts.get("athlete_profile") if isinstance(contexts, dict) else None
    if not isinstance(artifact, dict):
        return False
    profile = artifact.get("profile")
    candidate = profile if isinstance(profile, dict) else artifact
    return (
        _nonempty_string(candidate.get("goal"))
        and _bounded_int(candidate.get("trainingDays"), 1, 7)
        and _bounded_int(candidate.get("sessionMinutes"), 10, 240)
    )


def _summary_was_presented(summary: str, planning_context: dict[str, Any]) -> bool:
    chat = planning_context.get("recentChat")
    if not isinstance(chat, list):
        return False
    needle = " ".join(summary.split()).casefold()
    for turn in reversed(chat):
        if not isinstance(turn, dict) or turn.get("role") != "assistant":
            continue
        content = turn.get("content")
        if not isinstance(content, str):
            continue
        haystack = " ".join(content.split()).casefold()
        return "setup summary:" in haystack and needle in haystack
    return False


def _catalog_key(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _normalise_equipment(value: object) -> tuple[list[str], str | None]:
    if not isinstance(value, list):
        return [], "Equipment must be an array of supported equipment IDs."
    by_key = {_equipment_key(item): item for item in _CANONICAL_EQUIPMENT}
    result: list[str] = []
    for raw in value:
        key = _equipment_key(raw)
        canonical = by_key.get(key)
        if canonical is None:
            return (
                [],
                "Unknown equipment must be clarified. Use only canonical T4L "
                "equipment IDs.",
            )
        if canonical not in result:
            result.append(canonical)
    return result, None


def _equipment_key(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list_value(value: object, *, allow_empty: bool = True) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and all(_nonempty_string(item) for item in value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _is_iso_datetime(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _is_iso_date(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d") == value
    except ValueError:
        return False


def update_coaching_notes(
    *,
    client: T4LMcpClient,
    seq: int | None,
    capture: dict[str, Any] | None,
) -> bool:
    capture = _sanitize_note_capture(capture)
    if not capture.get("capture"):
        return False
    notes = client.get_coaching_notes()
    merged = merge_note_capture(notes, capture, seq=seq)
    client.write_coaching_notes(merged)
    return True


def merge_note_capture(
    notes: dict[str, Any],
    capture: dict[str, Any],
    *,
    seq: int | None,
) -> dict[str, Any]:
    capture = _sanitize_note_capture(capture)
    merged: dict[str, Any] = dict(notes)
    merged.setdefault("schema", "t4l.coaching_notes.v1")
    merged["updatedAt"] = datetime.now(UTC).isoformat()
    source = {"sourceSeq": seq, "status": "open"}
    _append_text_items(
        merged,
        "athleteRequests",
        _string_list(capture.get("athleteRequests")),
        source=source,
    )
    _append_text_items(
        merged,
        "openQuestions",
        _string_list(capture.get("openQuestions")),
        source=source,
    )
    summary = capture.get("summary")
    if isinstance(summary, str) and summary.strip():
        _append_text_items(
            merged, "summaries", [summary.strip()], source={"sourceSeq": seq}
        )
    return merged


def _sanitize_note_capture(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not value.get("capture"):
        return {"capture": False}
    sanitized: dict[str, Any] = {"capture": True}
    for key in ("athleteRequests", "openQuestions"):
        items = [
            item
            for item in _string_list(value.get(key))
            if not contains_prohibited_nutrition_guidance(item)
        ]
        if items:
            sanitized[key] = items
    summary = value.get("summary")
    if (
        isinstance(summary, str)
        and summary.strip()
        and not contains_prohibited_nutrition_guidance(summary)
    ):
        sanitized["summary"] = summary.strip()
    if len(sanitized) == 1:
        return {"capture": False}
    return sanitized


def parse_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else None


def _append_text_items(
    target: dict[str, Any],
    key: str,
    values: list[str],
    *,
    source: dict[str, Any],
) -> None:
    existing = target.get(key)
    items = existing if isinstance(existing, list) else []
    seen = {_item_text(item).casefold() for item in items if _item_text(item)}
    for value in values:
        text = value.strip()
        if not text or text.casefold() in seen:
            continue
        item = dict(source)
        item["text"] = text
        items.append(item)
        seen.add(text.casefold())
    target[key] = items


def _item_text(item: object) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and isinstance(item.get("text"), str):
        return str(item["text"])
    return ""


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _coerce_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None
