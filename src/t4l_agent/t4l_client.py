from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, cast


class T4LError(RuntimeError):
    """Raised when the T4L server or MCP endpoint returns an unusable result."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: int | str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code

    @property
    def refresh_context_required(self) -> bool:
        return self.error_code == -32009


class T4LMcpClient:
    def __init__(self, server_url: str, api_key: str) -> None:
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key

    @property
    def server_url(self) -> str:
        return self._server_url

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        response = self._post_json(f"{self._server_url}/mcp", payload)
        error = response.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            safe_message = message if isinstance(message, str) else "Request failed."
            raise T4LError(
                f"MCP error {code}: {safe_message}",
                error_code=code if isinstance(code, int | str) else None,
            )
        result = response.get("result")
        if not isinstance(result, dict):
            return None
        return result.get("structuredContent")

    def pending_messages(self) -> list[dict[str, Any]]:
        result = self.call_tool("get_pending_chat_messages")
        messages = result.get("messages") if isinstance(result, dict) else None
        return [
            cast(dict[str, Any], item)
            for item in messages or []
            if isinstance(item, dict)
        ]

    def get_planning_context(self, recent_chat_limit: int) -> dict[str, Any]:
        result = self.call_tool(
            "get_planning_context", {"recentChatLimit": recent_chat_limit}
        )
        return cast(dict[str, Any], result) if isinstance(result, dict) else {}

    def get_agent_descriptor(self) -> dict[str, Any]:
        """Read identity metadata from the connector's public manifest."""
        manifest = self._get_json(f"{self._server_url}/.well-known/t4l-agent")
        descriptor = manifest.get("agent")
        if not isinstance(descriptor, dict):
            raise T4LError("T4L connector manifest has no agent descriptor.")
        required = ("agentId", "displayName", "runtime")
        if any(
            not isinstance(descriptor.get(name), str)
            or not str(descriptor[name]).strip()
            for name in required
        ):
            raise T4LError("T4L connector agent descriptor is incomplete.")
        return cast(dict[str, Any], descriptor)

    def get_coaching_notes(self) -> dict[str, Any]:
        result = self.call_tool("get_coaching_notes")
        if isinstance(result, dict):
            payload = result.get("payload")
            if isinstance(payload, dict):
                return cast(dict[str, Any], payload)
            return result
        return {}

    def write_coaching_notes(self, payload: dict[str, Any]) -> None:
        self.call_tool("write_coaching_notes", {"payload": payload})

    def write_athlete_setup_draft(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.call_tool("write_athlete_setup_draft", {"payload": payload})
        return cast(dict[str, Any], result) if isinstance(result, dict) else {}

    def write_training_block_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.call_tool("write_training_block_plan", {"payload": payload})
        return cast(dict[str, Any], result) if isinstance(result, dict) else {}

    def write_daily_workout_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.call_tool("write_daily_workout_plan", {"payload": payload})
        return cast(dict[str, Any], result) if isinstance(result, dict) else {}

    def write_chat_reply(self, content: str, in_reply_to_seq: int | None) -> None:
        args: dict[str, Any] = {"content": content}
        if in_reply_to_seq is not None:
            args["inReplyToSeq"] = in_reply_to_seq
        self.call_tool("write_chat_reply", args)

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
                "x-t4l-token": self._api_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            error_code: int | str | None = None
            error_message = "Request failed."
            try:
                decoded_error = json.loads(detail)
            except json.JSONDecodeError:
                decoded_error = None
            if isinstance(decoded_error, dict):
                error_payload = decoded_error.get("error")
                if isinstance(error_payload, dict):
                    raw_code = error_payload.get("code")
                    raw_message = error_payload.get("message")
                    if isinstance(raw_code, int | str):
                        error_code = raw_code
                    if isinstance(raw_message, str) and raw_message.strip():
                        error_message = raw_message.strip()
            raise T4LError(
                f"T4L server HTTP {error.code}: {error_message}",
                status_code=error.code,
                error_code=error_code,
            ) from error
        except (OSError, json.JSONDecodeError) as error:
            raise T4LError(f"T4L server request failed: {error}") from error
        if not isinstance(decoded, dict):
            raise T4LError("T4L server response was not a JSON object.")
        return cast(dict[str, Any], decoded)

    def _get_json(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise T4LError(
                f"T4L connector manifest returned HTTP {error.code}."
            ) from error
        except (OSError, json.JSONDecodeError) as error:
            raise T4LError("T4L connector manifest request failed.") from error
        if not isinstance(decoded, dict):
            raise T4LError("T4L connector manifest was not a JSON object.")
        return cast(dict[str, Any], decoded)
