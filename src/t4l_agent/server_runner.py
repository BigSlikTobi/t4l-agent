from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from types import TracebackType

from t4l_server.connector import ReleaseDescriptor, SetupAdapter
from t4l_server.server import ServerConfig, create_server


@dataclass(frozen=True)
class RunningServer:
    host: str
    port: int
    display_host: str
    data_dir: Path
    api_key: str

    @property
    def server_url(self) -> str:
        return f"http://{self.display_host}:{self.port}"

    @property
    def mcp_url(self) -> str:
        return f"{self.server_url}/mcp"


class EmbeddedT4LServer:
    def __init__(
        self,
        *,
        data_dir: Path,
        host: str,
        port: int,
        api_key: str,
        agent_id: str,
        agent_name: str,
        agent_runtime: str,
        agent_provider: str | None,
        agent_model: str | None,
        agent_reasoning: str | None,
        connector_runtime_token: str,
        connector_setup_adapter: SetupAdapter,
        connector_release: ReleaseDescriptor | None = None,
    ) -> None:
        self._config = ServerConfig(
            data_dir=data_dir.expanduser().resolve(),
            host=host,
            port=port,
            token=api_key,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_runtime=agent_runtime,
            agent_provider=agent_provider,
            agent_model=agent_model,
            agent_reasoning=agent_reasoning,
            connector_runtime_token=connector_runtime_token,
            connector_setup_adapter=connector_setup_adapter,
            connector_release=connector_release,
            allow_legacy_app_token=False,
            require_https=not _loopback_host(host),
        )
        self._server = create_server(self._config)
        self._thread: threading.Thread | None = None

    def __enter__(self) -> RunningServer:
        self.start()
        raw_host, port = self._server.server_address[:2]
        host = str(raw_host)
        display_host = _lan_ip() if self._config.host in {"0.0.0.0", "::"} else host
        return RunningServer(
            host=str(host),
            port=int(port),
            display_host=display_host,
            data_dir=self._config.data_dir,
            api_key=self._config.token,
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._thread = None


def _loopback_host(host: str) -> bool:
    normalized = host.strip().casefold()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _lan_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
        except OSError:
            return "127.0.0.1"
