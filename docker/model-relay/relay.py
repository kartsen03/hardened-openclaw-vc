"""Fixed-destination HTTP relay: listen on :11434 and forward to one upstream (the host's Ollama).

It is not a proxy: clients cannot pick the destination, only the path, and only Ollama API
paths are forwarded. It rewrites the Host header to the upstream's own address, because
Ollama answers 403 to unfamiliar Host values (its DNS-rebinding protection). Responses are
streamed through as they arrive. Upstream comes from RELAY_UPSTREAM
(default host.docker.internal:11435). Stdlib only.
"""
from __future__ import annotations

import http.client
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = os.environ.get("RELAY_UPSTREAM", "host.docker.internal:11435").rsplit(":", 1)
# Only inference and read-only metadata. /api/pull, /api/push, /api/delete, /api/create and
# /api/copy are refused, so even a hijacked agent cannot change the host's model store.
ALLOWED = {("GET", "/api/tags"), ("GET", "/api/version"), ("GET", "/api/ps"), ("POST", "/api/chat"),
           ("POST", "/api/generate"), ("POST", "/api/show"), ("POST", "/api/embed")}
HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "host"}


class Relay(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "model-relay/1"

    def log_message(self, *args):
        pass

    def _forward(self) -> None:
        if (self.command if self.command != "HEAD" else "GET", self.path.split("?", 1)[0]) not in ALLOWED:
            self.send_error(403, "endpoint not allowed by the model relay")
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["Host"] = "127.0.0.1"
        up = http.client.HTTPConnection(HOST, int(PORT), timeout=900)
        try:
            up.request(self.command, self.path, body=body, headers=headers)
            resp = up.getresponse()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while chunk := resp.read1(65536):
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError:
            self.close_connection = True
        finally:
            up.close()

    do_GET = do_POST = do_HEAD = _forward


if __name__ == "__main__":
    print(f"model relay :11434 -> {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 11434), Relay).serve_forever()
