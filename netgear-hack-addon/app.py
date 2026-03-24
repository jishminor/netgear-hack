from __future__ import annotations

import json
import os
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from netgear_hack.router import AuthenticationError, ConfigError, NetgearClient, ProtocolError, RequestError, RouterConfig, load_profile


OPTIONS_PATH = Path("/data/options.json")
PROFILE_PATH = Path("/opt/netgear-hack/router_profile.example.json")


def load_options() -> dict[str, Any]:
    with OPTIONS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def build_config(options: dict[str, Any]) -> RouterConfig:
    return RouterConfig(
        host=options["host"],
        username=options["username"],
        password=options["password"],
        timeout=float(options.get("timeout", 30)),
        verify_tls=bool(options.get("verify_tls", True)),
    )


def build_profile(options: dict[str, Any]) -> dict[str, Any]:
    profile = load_profile(PROFILE_PATH)
    profile["host"] = options["host"]
    profile["username"] = options["username"]
    profile["password"] = options["password"]
    return profile


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "NetgearHack/0.1"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self._send_json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path not in {"/block", "/unblock"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        options = self.server.options  # type: ignore[attr-defined]
        token = options.get("api_token") or ""
        if token:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {token}":
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid bearer token"})
                return

        started = time.monotonic()
        try:
            body = self._read_json()
            mac = body["mac"]
            print(f"request start path={self.path} mac={mac} timeout={options.get('timeout', 30)}")
            config = build_config(options)
            profile = build_profile(options)
            client = NetgearClient(config, profile)
            result = client.unblock_mac(mac) if self.path == "/unblock" else client.block_mac(mac)
        except KeyError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request body must include mac"})
            return
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
            return
        except AuthenticationError as exc:
            print(f"request auth_error path={self.path} error={exc}")
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            return
        except (ConfigError, RequestError, ProtocolError) as exc:
            print(f"request failure path={self.path} error={exc}")
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return

        elapsed = time.monotonic() - started
        print(f"request success path={self.path} mac={result.mac} status={result.status} elapsed={elapsed:.2f}s")
        self._send_json(HTTPStatus.OK, {"status": result.status, "mac": result.mac})

    def log_message(self, format: str, *args: object) -> None:
        print(format % args)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except BrokenPipeError:
            print(f"client disconnected before response was written status={status.value} payload={payload}")


def main() -> None:
    options = load_options()
    port = int(os.getenv("PORT", "8099"))
    server = ThreadingHTTPServer(("0.0.0.0", port), RequestHandler)
    server.options = options  # type: ignore[attr-defined]
    print(f"starting netgear-hack addon on port {port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
