from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any, cast
from urllib.request import Request

import pytest

from t4l_agent.pairing import HttpChannelConfirmationClient, VerifiedOwnerIdentity


class FakeResponse:
    status = 200

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            {
                "status": "confirmed",
                "requestId": "req-1",
                "pairingRequestId": "pair-1",
            }
        ).encode()


def _owner(*, verified: bool = True) -> VerifiedOwnerIdentity:
    return VerifiedOwnerIdentity(
        runtime="hermes",
        agent_id="agent-01",
        channel="slack",
        account_id="workspace-01",
        sender_id="owner-id",
        owner_verified=verified,
    )


def test_http_confirmation_posts_only_verified_identity_and_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setenv("T4L_CONNECTOR_RUNTIME_TOKEN", "runtime-test-secret")

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(cast(bytes, request.data or b"").decode())
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = HttpChannelConfirmationClient("http://127.0.0.1:8787")

    result = client.confirm(code="ABCD-1234", owner=_owner(), request_id="req-1")

    assert result.ok
    assert captured["url"].endswith("/v1/pairing/channel-confirmation")
    assert captured["body"] == {
        "code": "ABCD-1234",
        "channel": "slack",
        "verifiedAccountId": "workspace-01",
        "verifiedSenderId": "owner-id",
        "requestId": "req-1",
    }
    assert "isAdmin" not in captured["body"]
    assert captured["headers"]["X-t4l-runtime-token"] == "runtime-test-secret"


def test_http_confirmation_rejects_unverified_owner_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unverified owner reached network")
        ),
    )

    result = HttpChannelConfirmationClient("http://127.0.0.1:8787").confirm(
        code="ABCD-1234", owner=_owner(verified=False)
    )

    assert not result.ok
    assert result.code == "invalid_confirmation"


def test_http_confirmation_propagates_structured_connector_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("T4L_CONNECTOR_RUNTIME_TOKEN", "runtime-test-secret")

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        del request, timeout
        raise urllib.error.HTTPError(
            "http://127.0.0.1:8787/v1/pairing/channel-confirmation",
            403,
            "Forbidden",
            Message(),
            io.BytesIO(
                json.dumps(
                    {
                        "error": {
                            "code": "owner_not_allowed",
                            "message": "Sender is not allowlisted.",
                        }
                    }
                ).encode()
            ),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = HttpChannelConfirmationClient("http://127.0.0.1:8787").confirm(
        code="ABCD-1234", owner=_owner()
    )

    assert not result.ok
    assert result.status_code == 403
    assert result.code == "owner_not_allowed"
    assert result.message == "Sender is not allowlisted."
