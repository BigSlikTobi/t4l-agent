from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlparse

_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,256}$")
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")


@dataclass(frozen=True)
class VerifiedOwnerIdentity:
    """Identity asserted by a trusted gateway adapter, never by chat text."""

    runtime: str
    agent_id: str
    channel: str
    account_id: str
    sender_id: str
    owner_verified: bool


@dataclass(frozen=True)
class PairingConfirmation:
    ok: bool
    status_code: int
    code: str
    message: str
    request_id: str | None = None
    pairing_request_id: str | None = None


class ChannelConfirmationClient(Protocol):
    def confirm(
        self,
        *,
        code: str,
        owner: VerifiedOwnerIdentity,
        request_id: str | None = None,
    ) -> PairingConfirmation: ...


@dataclass(frozen=True)
class HttpChannelConfirmationClient:
    connector_base_url: str
    runtime_token_env: str = "T4L_CONNECTOR_RUNTIME_TOKEN"
    timeout_seconds: float = 10.0

    def confirm(
        self,
        *,
        code: str,
        owner: VerifiedOwnerIdentity,
        request_id: str | None = None,
    ) -> PairingConfirmation:
        validation_error = self._validation_error(code, owner, request_id)
        if validation_error is not None:
            return PairingConfirmation(
                False, 400, "invalid_confirmation", validation_error
            )
        token = os.environ.get(self.runtime_token_env, "")
        if not token:
            return PairingConfirmation(
                False,
                503,
                "runtime_credential_missing",
                "Runtime credential environment variable "
                f"{self.runtime_token_env} is missing.",
            )
        payload: dict[str, Any] = {
            "code": code,
            "channel": owner.channel.strip().lower(),
            "verifiedAccountId": owner.account_id,
            "verifiedSenderId": owner.sender_id,
        }
        if request_id is not None:
            payload["requestId"] = request_id
        request = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "content-type": "application/json",
                "x-t4l-runtime-token": token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                status = int(response.status)
                decoded = _json_object(response.read())
        except urllib.error.HTTPError as error:
            decoded = _json_object(error.read())
            return _error_confirmation(error.code, decoded)
        except (OSError, ValueError, json.JSONDecodeError):
            return PairingConfirmation(
                False,
                503,
                "connector_unavailable",
                "The local T4L connector could not be reached.",
            )
        if status != 200 or decoded.get("status") != "confirmed":
            return _error_confirmation(status, decoded)
        return PairingConfirmation(
            True,
            status,
            "confirmed",
            "Phone pairing was confirmed. Finish the connection in the app.",
            request_id=_optional_text(decoded.get("requestId")),
            pairing_request_id=_optional_text(decoded.get("pairingRequestId")),
        )

    def _endpoint(self) -> str:
        return f"{self.connector_base_url.rstrip('/')}/v1/pairing/channel-confirmation"

    def _validation_error(
        self,
        code: str,
        owner: VerifiedOwnerIdentity,
        request_id: str | None,
    ) -> str | None:
        parsed = urlparse(self.connector_base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            return "Channel confirmation accepts only a loopback connector URL."
        if parsed.username is not None or parsed.password is not None:
            return "Connector URLs must not contain credentials."
        if parsed.query or parsed.fragment or parsed.path.rstrip("/"):
            return "Connector base URL must not contain a path, query, or fragment."
        if not _ENV_RE.fullmatch(self.runtime_token_env):
            return "Runtime credential environment variable name is invalid."
        if not owner.owner_verified:
            return "The gateway did not verify this sender as the owner."
        if (
            not _ID_RE.fullmatch(owner.channel)
            or not _ID_RE.fullmatch(owner.account_id)
            or not _ID_RE.fullmatch(owner.sender_id)
        ):
            return "Verified channel identity is invalid."
        if not _CODE_RE.fullmatch(code):
            return "The pairing code format is invalid."
        if request_id is not None and not _ID_RE.fullmatch(request_id):
            return "Request ID is invalid."
        return None


def _json_object(body: bytes) -> dict[str, Any]:
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("JSON response is not an object")
    return cast(dict[str, Any], parsed)


def _error_confirmation(status: int, decoded: dict[str, Any]) -> PairingConfirmation:
    error = decoded.get("error")
    if isinstance(error, dict):
        code = _optional_text(error.get("code")) or "confirmation_failed"
        message = (
            _optional_text(error.get("message")) or "Phone pairing was not confirmed."
        )
    else:
        code = "confirmation_failed"
        message = "Phone pairing was not confirmed."
    return PairingConfirmation(False, int(status), code, message)


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
