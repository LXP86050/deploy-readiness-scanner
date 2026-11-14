from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LIMIT = 60


class Handler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    requests = 0

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path in {"/health", "/vector/health"}:
            self._json(200, {"status": "ok", "path": self.path})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        if length:
            self.rfile.read(length)
        if self.path != "/v1/chat/completions":
            self._json(404, {"error": "not found"})
            return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth.strip()) < 16:
            self._json(401, {"error": {"message": "missing bearer token"}})
            return
        with Handler.lock:
            Handler.requests += 1
            count = Handler.requests
        time.sleep(0.01 + (count % 5) * 0.015)
        remaining = max(0, LIMIT - count)
        headers = {
            "x-ratelimit-limit-requests": str(LIMIT),
            "x-ratelimit-remaining-requests": str(remaining),
        }
        if remaining == 0:
            headers["retry-after"] = "1"
            self._json(429, {"error": {"message": "rate limit"}}, headers)
            return
        self._json(
            200,
            {
                "id": f"chatcmpl-demo-{count}",
                "object": "chat.completion",
                "model": "mock-small",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            },
            headers,
        )

    def _json(self, status: int, body: dict[str, object], headers: dict[str, str] | None = None) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


def serve(host: str = "127.0.0.1", port: int = 8089) -> ThreadingHTTPServer:
    Handler.requests = 0
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    serve("0.0.0.0", 8089).serve_forever()
