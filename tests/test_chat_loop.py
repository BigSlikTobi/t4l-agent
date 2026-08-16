from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from t4l_agent.chat_loop import (
    NUTRITION_GUIDANCE_BOUNDARY_REPLY,
    TrainingRequestRetryState,
    answer_pending_messages,
    contains_prohibited_nutrition_guidance,
    is_nutrition_guidance_request,
    merge_note_capture,
    parse_json_object,
    process_current_training_request,
    safe_coach_reply,
)
from t4l_agent.runtime_coach import ChatMessage
from t4l_agent.t4l_client import T4LError


class RecordingModel:
    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.messages: list[list[ChatMessage]] = []
        self.max_tokens: list[int | None] = []
        self.web_search: list[bool] = []

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        web_search: bool = False,
    ) -> str:
        self.messages.append(messages)
        self.max_tokens.append(max_tokens)
        self.web_search.append(web_search)
        return self.replies.pop(0)


class FakeClient:
    server_url = "http://127.0.0.1:8787"

    def __init__(
        self,
        *,
        pending: list[dict[str, Any]],
        planning_context: dict[str, Any],
        descriptor: dict[str, Any] | None = None,
    ) -> None:
        self._pending = pending
        self._planning_context = planning_context
        self._descriptor = descriptor or {
            "agentId": "agent-01",
            "displayName": "Atlas",
            "runtime": "openclaw",
            "provider": "customer-provider",
            "model": "customer-model",
            "reasoning": "runtime-default",
        }
        self.replies: list[tuple[str, int | None]] = []
        self.setup_drafts: list[dict[str, Any]] = []
        self.training_plans: list[dict[str, Any]] = []
        self.daily_workout_plans: list[dict[str, Any]] = []
        self.notes: dict[str, Any] = {}
        self.training_write_error: T4LError | None = None

    def pending_messages(self) -> list[dict[str, Any]]:
        return self._pending

    def get_planning_context(self, recent_chat_limit: int) -> dict[str, Any]:
        del recent_chat_limit
        return self._planning_context

    def get_agent_descriptor(self) -> dict[str, Any]:
        return self._descriptor

    def write_chat_reply(self, content: str, seq: int | None) -> None:
        self.replies.append((content, seq))

    def write_athlete_setup_draft(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.setup_drafts.append(payload)
        return {"stored": {"status": "pending"}}

    def write_training_block_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.training_write_error is not None:
            error = self.training_write_error
            self.training_write_error = None
            raise error
        self.training_plans.append(payload)
        return {"stored": {"status": "pending"}}

    def write_daily_workout_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.daily_workout_plans.append(payload)
        return {"stored": {"status": "pending"}}

    def get_coaching_notes(self) -> dict[str, Any]:
        return self.notes

    def write_coaching_notes(self, payload: dict[str, Any]) -> None:
        self.notes = payload


def _bundle(tmp_path: Path) -> Path:
    root = tmp_path / "instructions"
    for relative in (
        "docs/setup_instruction.md",
        "docs/coaching_setup.md",
        "skills/t4l-onboard-athlete/SKILL.md",
        "skills/t4l-answer-chat/SKILL.md",
        "skills/t4l-write-results/SKILL.md",
        "skills/t4l-write-results/reference/payload-shapes.md",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"instruction: {relative}", encoding="utf-8")
    return root


def _empty_context(
    *, recent_chat: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "acceptedState": {"contextRevision": None, "contexts": {}},
        "currentRequests": [],
        "recentChat": recent_chat or [],
    }


def _accepted_context(*, with_catalog: bool = True) -> dict[str, Any]:
    app_snapshot: dict[str, Any] = {}
    if with_catalog:
        app_snapshot["verifiedExerciseMediaCatalog"] = {
            "push_up": "https://www.youtube.com/shorts/qFFtrj0mdBQ",
            "row": "https://www.youtube.com/shorts/t7VDDNKBNx8",
        }
    return {
        "acceptedState": {
            "contextRevision": "ctx_12_abcdef123456",
            "contexts": {
                "athlete_profile": {
                    "profile": {
                        "goal": "Build strength",
                        "trainingDays": 4,
                        "sessionMinutes": 60,
                    }
                },
                "app_snapshot": app_snapshot,
            },
        },
        "currentRequests": [
            {
                "requestId": "onboarding_setup_123",
                "kind": "training_block_request",
                "status": "pending",
                "payload": {
                    "contextRevision": "ctx_12_abcdef123456",
                    "goals": {"shortTerm": "Complete four strong weeks"},
                    "profile": {
                        "goal": "Build strength",
                        "constraints": ["Stop on sharp pain"],
                    },
                    "requirements": {"reviewRequired": True},
                },
            }
        ],
        "recentChat": [],
        "activeBlock": None,
    }


def _daily_workout_context() -> dict[str, Any]:
    return {
        "acceptedState": {
            "contextRevision": "ctx_daily_123456",
            "contexts": {"app_snapshot": {}, "athlete_profile": {}},
        },
        "currentRequests": [
            {
                "requestId": "daily-1",
                "kind": "daily_workout_request",
                "status": "pending",
                "payload": {
                    "schema": "daily_workout_request.v1",
                    "requestId": "daily-1",
                    "contextRevision": "ctx_daily_123456",
                    "targetDate": "2026-08-15",
                    "targetTimezone": "Europe/Berlin",
                    "availableTime": {"minutes": 30, "openEnded": False},
                    "todayRecoveryCheckIn": {
                        "energy": "lower",
                        "soreness": "normal",
                        "sleepQuality": "good",
                        "stress": "normal",
                    },
                    "eligibleChoices": [
                        {
                            "workoutId": "weekly-lower",
                            "variants": ["short", "standard"],
                        }
                    ],
                    "excludedChoices": [],
                },
            }
        ],
        "dailyWorkoutPlan": None,
        "recentChat": [],
    }


def _setup_payload(summary: str) -> dict[str, Any]:
    return {
        "profile": {
            "name": "Tobi",
            "goal": "Build strength",
            "trainingDays": 4,
            "sessionMinutes": 60,
            "equipment": ["fullGym"],
            "constraints": [],
            "preferences": ["supersets"],
        },
        "goals": {
            "longTerm": "Build durable strength",
            "shortTerm": "Complete four consistent weeks",
            "blockWeeks": 4,
            "successTest": "Finish all sessions pain-free",
        },
        "hardLimits": ["Stop on sharp pain"],
        "nutritionPreferences": ["No fixed calories"],
        "coachingStyle": "Direct and concise",
        "confirmation": {"summary": summary, "confirmed": True},
    }


def _training_plan() -> dict[str, Any]:
    def exercise(exercise_id: str, name: str, url: str) -> dict[str, Any]:
        return {
            "exerciseId": exercise_id,
            "name": name,
            "sets": 1,
            "reps": "10",
            "targetLoad": "moderate",
            "targetRpe": 7,
            "restSeconds": 0,
            "coachCue": "Move cleanly.",
            "media": {
                "explainerUrl": url,
                "setup": "Set up with control.",
                "cues": ["Brace"],
                "commonMistakes": ["Rushing"],
            },
        }

    return {
        "schema": "training_block_plan.v1",
        "id": "block-1",
        "style": "strengthHypertrophy",
        "title": "Strength base",
        "durationWeeks": 1,
        "currentWeek": 1,
        "weeklyFocus": ["Clean repeatable reps"],
        "measurableTargets": ["Complete all sessions"],
        "workouts": [
            {
                "id": "w1",
                "week": 1,
                "day": 1,
                "title": "Upper body",
                "focus": "Strength",
                "rationale": "Build the base.",
                "conditioning": "None",
                "items": [
                    {
                        "type": "superset",
                        "groupId": "ss-1",
                        "title": "Push pull",
                        "rounds": 3,
                        "restSeconds": 90,
                        "exercises": [
                            exercise(
                                "push_up",
                                "Push-Up",
                                "https://www.youtube.com/shorts/qFFtrj0mdBQ",
                            ),
                            exercise(
                                "row",
                                "Row",
                                "https://www.youtube.com/shorts/t7VDDNKBNx8",
                            ),
                        ],
                    }
                ],
            }
        ],
        "createdBy": "Atlas",
        "createdAt": "2026-08-11T09:10:00+00:00",
    }


def test_parse_json_object_accepts_fenced_json() -> None:
    assert parse_json_object('```json\n{"capture": false}\n```') == {"capture": False}


def test_nutrition_request_gate_catches_direct_and_oblique_requests() -> None:
    blocked = (
        "What should I eat after lifting?",
        "How many calories and grams of protein should I target?",
        "Help me refill glycogen before tomorrow.",
        "What would you put in my training bottle?",
        "Is creatine safe?",
        "Build a plan to cut my body-fat percentage.",
        "Wie viel Wasser und Elektrolyte soll ich trinken?",
    )
    for message in blocked:
        assert is_nutrition_guidance_request(message), message


def test_nutrition_request_gate_keeps_training_and_recovery_questions() -> None:
    allowed = (
        "My sleep was six hours. Should I lower today's training load?",
        "My HRV is below baseline. Should I take a rest day?",
        "I ate late and slept badly. Should I deload the squat session?",
        "What RPE should I use for today's deadlifts?",
    )
    for message in allowed:
        assert not is_nutrition_guidance_request(message), message


def test_post_model_gate_replaces_prescriptions_calculations_and_inferences() -> None:
    blocked = (
        "Eat oatmeal and a banana before training.",
        "Aim for 30 g of protein after the session.",
        "Drink 500 ml water with electrolytes.",
        "You seem dehydrated and low in sodium.",
        "Set a body-fat target of 14 percent.",
        "A banana works best after training.",
        "Your BMI is 23.4.",
    )
    for reply in blocked:
        assert contains_prohibited_nutrition_guidance(reply), reply
        assert safe_coach_reply(reply) == NUTRITION_GUIDANCE_BOUNDARY_REPLY


def test_post_model_gate_allows_recovery_and_training_facts() -> None:
    allowed = (
        "Your sleep was 6 hours versus a 7.5-hour baseline.",
        "Your recent training load is 18 percent above baseline.",
        "Keep today's squat work at RPE 6 and stop if pain rises.",
        "The synced check-in says energy is lower than usual.",
    )
    for reply in allowed:
        assert not contains_prohibited_nutrition_guidance(reply), reply
        assert safe_coach_reply(reply) == reply


def test_clear_nutrition_request_is_short_circuited_before_model(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        pending=[
            {
                "seq": 4,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:00:00+00:00",
                "content": "Tell me what to put on my plate after training.",
            }
        ],
        planning_context=_empty_context(),
    )
    model = RecordingModel([])

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.answered == 1
    assert model.messages == []
    assert client.replies == [(NUTRITION_GUIDANCE_BOUNDARY_REPLY, 4)]


def test_generated_nutrition_guidance_is_replaced_before_visible_write(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        pending=[
            {
                "seq": 5,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:00:00+00:00",
                "content": "How can I recover better?",
            }
        ],
        planning_context=_empty_context(),
    )
    model = RecordingModel(
        [
            '{"reply":"Drink 500 ml water and take magnesium.",'
            '"write":null,"notes":null}',
        ]
    )

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.answered == 1
    assert client.replies == [(NUTRITION_GUIDANCE_BOUNDARY_REPLY, 5)]
    assert len(model.messages) == 1
    system_prompt = model.messages[0][0].content
    assert "Never capture nutrition, hydration" in system_prompt


def test_merge_note_capture_appends_new_items_without_duplicates() -> None:
    notes: dict[str, Any] = {
        "schema": "t4l.coaching_notes.v1",
        "athleteRequests": [{"text": "Move long run to Saturday"}],
    }
    merged = merge_note_capture(
        notes,
        {
            "capture": True,
            "athleteRequests": [
                "Move long run to Saturday",
                "Use hotel gym next week",
            ],
            "openQuestions": ["Check knee soreness before squats"],
            "summary": "Travel affects next week.",
        },
        seq=42,
    )

    requests = merged["athleteRequests"]
    assert len(requests) == 2
    assert requests[1]["text"] == "Use hotel gym next week"
    assert requests[1]["sourceSeq"] == 42
    assert merged["openQuestions"][0]["text"] == "Check knee soreness before squats"
    assert merged["summaries"][0]["text"] == "Travel affects next week."


def test_merge_note_capture_drops_nutrition_content() -> None:
    merged = merge_note_capture(
        {},
        {
            "capture": True,
            "athleteRequests": [
                "Move the long run to Saturday",
                "Give me a high-protein meal plan",
                "Set a goal to lose weight",
                "Athlete seems underfueled after training",
            ],
            "openQuestions": ["How much water should I drink?"],
            "summary": "Athlete wants calorie and macro targets.",
        },
        seq=43,
    )

    assert [item["text"] for item in merged["athleteRequests"]] == [
        "Move the long run to Saturday"
    ]
    assert merged["openQuestions"] == []
    assert "summaries" not in merged


def test_visible_turn_writes_note_patch_from_the_same_model_call(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        pending=[
            {
                "seq": 44,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:00:00+00:00",
                "content": "Use the hotel gym next week.",
            }
        ],
        planning_context=_empty_context(),
    )
    model = RecordingModel(
        [
            json.dumps(
                {
                    "reply": "Got it. What equipment does it have?",
                    "write": None,
                    "notes": {
                        "capture": True,
                        "athleteRequests": ["Use the hotel gym next week"],
                        "openQuestions": ["Which hotel-gym equipment is available?"],
                        "summary": "Travel changes next week's training location.",
                    },
                }
            )
        ]
    )

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.answered == 1
    assert stats.notes_written == 1
    assert len(model.messages) == 1
    assert client.notes["athleteRequests"][0]["text"] == ("Use the hotel gym next week")


def test_model_prompt_uses_purpose_instructions_and_deduplicated_v2_context(
    tmp_path: Path,
) -> None:
    context = _accepted_context()
    profile = context["acceptedState"]["contexts"]["athlete_profile"]["profile"]
    day_context = {"schema": "day_context.v1", "large": "d" * 2_000}
    daily_snapshot = {
        "schema": "daily_snapshot.v1",
        "memoryWiki": {
            "schema": "memory_wiki.v1",
            "entries": [{"text": "Train on Monday"}],
            "byCategory": {"schedule": [{"text": "Train on Monday"}]},
        },
        "large": "s" * 2_000,
    }
    app_snapshot = context["acceptedState"]["contexts"]["app_snapshot"]
    app_snapshot.update(
        {
            "dayContext": day_context,
            "dailySnapshot": daily_snapshot,
            "fitnessData": {"profile": profile, "other": True},
        }
    )
    context["acceptedState"]["contexts"].update(
        {"day_context": day_context, "daily_snapshot": daily_snapshot}
    )
    context.update(
        {
            "dayContext": day_context,
            "recentLogs": [day_context],
            "profile": profile,
            "requestHistory": [context["currentRequests"][0]] * 20,
            "pendingRequests": context["currentRequests"],
        }
    )
    client = FakeClient(
        pending=[
            {
                "seq": 45,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:00:00+00:00",
                "content": "Prepare the requested block.",
            }
        ],
        planning_context=context,
    )
    model = RecordingModel(
        [
            '{"reply":"I am preparing the review-only proposal.",'
            '"write":null,"notes":null}'
        ]
    )

    answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    system_prompt = model.messages[0][0].content
    assert "skills/t4l-write-results/SKILL.md" in system_prompt
    assert "skills/t4l-onboard-athlete/SKILL.md" not in system_prompt
    prompt = json.loads(model.messages[0][1].content)
    projected = prompt["planningContext"]
    assert "requestHistory" not in projected
    assert "pendingRequests" not in projected
    assert "dayContext" not in projected
    projected_app = projected["acceptedState"]["contexts"]["app_snapshot"]
    assert "dayContext" not in projected_app
    assert "dailySnapshot" not in projected_app
    assert "profile" not in projected_app["fitnessData"]
    projected_wiki = projected["acceptedState"]["contexts"]["daily_snapshot"][
        "memoryWiki"
    ]
    assert "byCategory" not in projected_wiki
    assert len(json.dumps(projected)) < len(json.dumps(context)) * 0.6


def test_control_turn_uses_verified_intro_and_installed_instructions(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        pending=[
            {
                "seq": 1,
                "conversationId": "default",
                "visibility": "control",
                "createdAt": "2026-08-11T09:00:00+00:00",
                "content": "Begin verified onboarding.",
            }
        ],
        planning_context=_empty_context(),
    )
    model = RecordingModel(
        ['{"reply":"What is your main long-term goal?","write":null}']
    )

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.answered == 1
    reply = client.replies[0][0]
    assert "I'm Atlas, your T4L Gym Bro." in reply
    assert "runtime openclaw" in reply
    assert "provider customer-provider" in reply
    assert "model customer-model" in reply
    assert "reasoning runtime-default" in reply
    assert "phone controls accepted training state" in reply
    system_prompt = model.messages[0][0].content
    assert "skills/t4l-onboard-athlete/SKILL.md" in system_prompt
    assert "skills/t4l-write-results/SKILL.md" not in system_prompt
    assert "scope is training and recovery only" in system_prompt
    assert "registered\ndietitian or clinician" in system_prompt


def test_explicit_confirmation_writes_strict_pending_setup_draft(
    tmp_path: Path,
) -> None:
    summary = "Four gym days, 60 minutes, strength focus, stop on sharp pain."
    context = _empty_context(
        recent_chat=[
            {
                "role": "assistant",
                "content": f"SETUP SUMMARY: {summary}\nConfirm this setup summary?",
            }
        ]
    )
    message = {
        "seq": 12,
        "conversationId": "default",
        "visibility": "visible",
        "createdAt": "2026-08-11T09:09:55+00:00",
        "content": "Yes, confirm.",
    }
    decision = {
        "reply": "Sending it.",
        "write": {
            "tool": "write_athlete_setup_draft",
            "payload": _setup_payload(summary),
        },
    }
    client = FakeClient(pending=[message], planning_context=context)
    model = RecordingModel([json.dumps(decision)])

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.setup_drafts_written == 1
    assert len(client.setup_drafts) == 1
    draft = client.setup_drafts[0]
    assert set(draft) == {
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
    assert draft["schema"] == "athlete_setup_draft.v1"
    assert draft["draftId"].startswith("setup_")
    assert draft["source"] == {
        "conversationId": "default",
        "confirmedMessageSeq": 12,
        "confirmedAt": "2026-08-11T09:09:55+00:00",
    }
    assert draft["confirmation"] == {"summary": summary, "confirmed": True}
    assert draft["nutritionPreferences"] == []
    assert "not accepted or applied" in client.replies[0][0]


def test_setup_write_is_rejected_without_exact_explicit_confirmation(
    tmp_path: Path,
) -> None:
    summary = "Four gym days and 60 minutes."
    context = _empty_context(
        recent_chat=[{"role": "assistant", "content": f"SETUP SUMMARY: {summary}"}]
    )
    decision = {
        "reply": "Sending it.",
        "write": {
            "tool": "write_athlete_setup_draft",
            "payload": _setup_payload(summary),
        },
    }
    client = FakeClient(
        pending=[
            {
                "seq": 12,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:09:55+00:00",
                "content": "Change it to five days.",
            }
        ],
        planning_context=context,
    )
    model = RecordingModel([json.dumps(decision)])

    answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert client.setup_drafts == []
    assert "not an explicit confirmation" in client.replies[0][0]


def test_setup_draft_cannot_smuggle_nutrition_guidance(tmp_path: Path) -> None:
    summary = "Four gym days and 60 minutes."
    context = _empty_context(
        recent_chat=[{"role": "assistant", "content": f"SETUP SUMMARY: {summary}"}]
    )
    payload = _setup_payload(summary)
    payload["profile"]["preferences"] = ["Eat 30 g protein after training"]
    client = FakeClient(
        pending=[
            {
                "seq": 13,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:10:00+00:00",
                "content": "Yes, confirm.",
            }
        ],
        planning_context=context,
    )
    decision = {
        "reply": "Sending it.",
        "write": {
            "tool": "write_athlete_setup_draft",
            "payload": payload,
        },
    }
    model = RecordingModel([json.dumps(decision)])

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.setup_drafts_written == 0
    assert client.setup_drafts == []
    assert "outside coach scope" in client.replies[0][0]


def test_setup_write_rejects_unknown_equipment_instead_of_inventing_id(
    tmp_path: Path,
) -> None:
    summary = "Four days with my custom home rack."
    context = _empty_context(
        recent_chat=[{"role": "assistant", "content": f"SETUP SUMMARY: {summary}"}]
    )
    payload = _setup_payload(summary)
    payload["profile"]["equipment"] = ["custom home rack"]
    decision = {
        "reply": "Sending it.",
        "write": {"tool": "write_athlete_setup_draft", "payload": payload},
    }
    client = FakeClient(
        pending=[
            {
                "seq": 14,
                "conversationId": "default",
                "visibility": "visible",
                "createdAt": "2026-08-11T09:12:00+00:00",
                "content": "Confirm",
            }
        ],
        planning_context=context,
    )
    model = RecordingModel([json.dumps(decision)])

    answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert client.setup_drafts == []
    assert "Unknown equipment must be clarified" in client.replies[0][0]


def test_phone_request_writes_review_only_plan_with_verified_videos(
    tmp_path: Path,
) -> None:
    context = _accepted_context()
    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": _training_plan()},
    }
    client = FakeClient(pending=[], planning_context=context)
    model = RecordingModel([json.dumps(decision)])

    stats = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
    )

    assert stats.training_plans_written == 1
    assert len(client.training_plans) == 1
    plan = client.training_plans[0]
    assert plan["requestId"] == "onboarding_setup_123"
    assert plan["contextRevision"] == "ctx_12_abcdef123456"
    assert plan["workouts"][0]["items"][0]["type"] == "superset"
    assert client.replies[0][1] == 0
    assert "Fresh phone context ctx_12_abcdef123456" in client.replies[0][0]
    assert "Short-term goal: Complete four strong weeks" in client.replies[0][0]
    assert "Hard limits: Stop on sharp pain" in client.replies[0][0]
    assert "not accepted or applied yet" in client.replies[0][0]
    assert model.max_tokens == [12_000]
    assert model.web_search == [False]


def test_daily_workout_request_writes_one_review_only_recovery_choice(
    tmp_path: Path,
) -> None:
    client = FakeClient(pending=[], planning_context=_daily_workout_context())
    model = RecordingModel([])

    stats = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
    )

    assert stats.training_plans_written == 1
    assert model.messages == []
    assert client.training_plans == []
    assert client.daily_workout_plans == [
        {
            "schema": "daily_workout_plan.v1",
            "requestId": "daily-1",
            "contextRevision": "ctx_daily_123456",
            "targetDate": "2026-08-15",
            "decision": "train",
            "sourceWorkoutId": "weekly-lower",
            "variantId": "short",
            "rationale": (
                "This unfinished session fits your time and today's recovery "
                "check-in. The accepted weekly plan stays unchanged."
            ),
        }
    ]


def test_daily_workout_request_never_plans_from_stale_phone_context(
    tmp_path: Path,
) -> None:
    context = _daily_workout_context()
    context["acceptedState"]["contextRevision"] = "ctx_newer_123456"
    client = FakeClient(pending=[], planning_context=context)
    model = RecordingModel([])

    stats = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
    )

    assert stats.training_plans_written == 0
    assert client.daily_workout_plans == []
    assert model.messages == []


def test_training_plan_payload_cannot_smuggle_nutrition_guidance(
    tmp_path: Path,
) -> None:
    plan = _training_plan()
    plan["workouts"][0]["rationale"] = (
        "Drink 500 ml water with electrolytes before this workout."
    )
    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": plan},
    }
    client = FakeClient(pending=[], planning_context=_accepted_context())
    model = RecordingModel([json.dumps(decision)])

    stats = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
    )

    assert stats.training_plans_written == 0
    assert client.training_plans == []
    assert "guidance outside coach scope" in client.replies[0][0]


def test_interactive_plan_revision_race_returns_safe_reply_and_keeps_loop_alive(
    tmp_path: Path,
) -> None:
    context = _accepted_context()
    message = {
        "seq": 42,
        "conversationId": "default",
        "visibility": "visible",
        "createdAt": "2026-08-11T09:20:00+00:00",
        "content": "Build the requested block now.",
    }
    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": _training_plan()},
    }
    client = FakeClient(pending=[message], planning_context=context)
    client.training_write_error = T4LError(
        "MCP error -32009: stale context",
        error_code=-32009,
    )
    model = RecordingModel([json.dumps(decision)])

    stats = answer_pending_messages(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
    )

    assert stats.checked == 1
    assert stats.answered == 1
    assert stats.training_plans_written == 0
    assert client.training_plans == []
    assert len(client.replies) == 1
    assert client.replies[0][1] == 42
    assert "phone context changed" in client.replies[0][0]
    assert "Nothing was stored or accepted" in client.replies[0][0]


def test_phone_request_uses_web_search_and_live_video_verifier_without_catalog(
    tmp_path: Path,
) -> None:
    class AcceptingVerifier:
        def verify(self, *, exercise_id: str, name: str, url: str) -> bool:
            return bool(exercise_id and name and url)

    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": _training_plan()},
    }
    client = FakeClient(
        pending=[], planning_context=_accepted_context(with_catalog=False)
    )
    model = RecordingModel([json.dumps(decision)])

    stats = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
        video_verifier=AcceptingVerifier(),
    )

    assert stats.training_plans_written == 1
    assert len(client.training_plans) == 1
    assert model.max_tokens == [12_000]
    assert model.web_search == [True]


def test_background_plan_blocker_uses_seq_zero_and_cannot_answer_user_turns(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        pending=[], planning_context=_accepted_context(with_catalog=False)
    )
    model = RecordingModel(
        [
            json.dumps(
                {
                    "reply": "Live YouTube Shorts verification failed. Nothing stored.",
                    "write": None,
                }
            )
        ]
    )

    process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=TrainingRequestRetryState(),
    )

    assert client.replies == [
        ("Live YouTube Shorts verification failed. Nothing stored.", 0)
    ]


def test_transient_plan_failure_retries_after_backoff_then_writes_once(
    tmp_path: Path,
) -> None:
    class Clock:
        now = 100.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    state = TrainingRequestRetryState(clock=clock)
    client = FakeClient(pending=[], planning_context=_accepted_context())
    model = RecordingModel(
        [
            json.dumps(
                {
                    "reply": "The live video check failed. Nothing was stored.",
                    "write": None,
                }
            ),
            json.dumps(
                {
                    "reply": "I prepared the block.",
                    "write": {
                        "tool": "write_training_block_plan",
                        "payload": _training_plan(),
                    },
                }
            ),
        ]
    )

    first = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )
    immediate = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )
    clock.now += 15.0
    retried = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )
    after_success = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )

    assert first.training_plans_written == 0
    assert immediate.training_plans_written == 0
    assert retried.training_plans_written == 1
    assert after_success.training_plans_written == 0
    assert len(model.messages) == 2
    assert len(client.training_plans) == 1
    assert len(client.replies) == 2
    assert client.replies[0] == (
        "The live video check failed. Nothing was stored.",
        0,
    )
    assert "not accepted or applied yet" in client.replies[1][0]


def test_stale_request_is_blocked_until_fresh_matching_request_arrives(
    tmp_path: Path,
) -> None:
    context = _accepted_context()
    stale_request = context["currentRequests"][0]
    stale_request["payload"]["contextRevision"] = "ctx_11_stale000000"
    client = FakeClient(pending=[], planning_context=context)
    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": _training_plan()},
    }
    model = RecordingModel([json.dumps(decision)])
    state = TrainingRequestRetryState()

    stale = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )
    repeated_stale = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )

    fresh_request = dict(stale_request)
    fresh_request["requestId"] = "onboarding_setup_124"
    fresh_request["payload"] = dict(stale_request["payload"])
    fresh_request["payload"]["contextRevision"] = "ctx_12_abcdef123456"
    context["currentRequests"] = [fresh_request]
    matching = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )

    assert stale.training_plans_written == 0
    assert repeated_stale.training_plans_written == 0
    assert matching.training_plans_written == 1
    assert len(model.messages) == 1
    assert len(client.training_plans) == 1
    assert client.training_plans[0]["requestId"] == "onboarding_setup_124"
    assert client.training_plans[0]["contextRevision"] == "ctx_12_abcdef123456"
    assert len(client.replies) == 2
    assert "stale or missing its context revision" in client.replies[0][0]
    assert client.replies[0][1] == 0


def test_plan_write_revision_race_waits_for_fresh_phone_request(
    tmp_path: Path,
) -> None:
    context = _accepted_context()
    client = FakeClient(pending=[], planning_context=context)
    client.training_write_error = T4LError(
        "MCP error -32009: stale context",
        error_code=-32009,
    )
    decision = {
        "reply": "I prepared the block.",
        "write": {"tool": "write_training_block_plan", "payload": _training_plan()},
    }
    model = RecordingModel([json.dumps(decision), json.dumps(decision)])
    state = TrainingRequestRetryState()

    raced = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )
    suppressed = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )

    fresh_request = dict(context["currentRequests"][0])
    fresh_request["requestId"] = "onboarding_setup_125"
    fresh_request["payload"] = dict(fresh_request["payload"])
    context["currentRequests"] = [fresh_request]
    fresh = process_current_training_request(
        client=client,  # type: ignore[arg-type]
        model=model,
        recent_chat_limit=20,
        instruction_bundle_dir=_bundle(tmp_path),
        retry_state=state,
    )

    assert raced.training_plans_written == 0
    assert suppressed.training_plans_written == 0
    assert fresh.training_plans_written == 1
    assert len(model.messages) == 2
    assert len(client.training_plans) == 1
    assert client.training_plans[0]["requestId"] == "onboarding_setup_125"
    assert len(client.replies) == 2
    assert "phone context changed" in client.replies[0][0]
    assert client.replies[0][1] == 0
