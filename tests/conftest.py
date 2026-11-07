"""Shared pytest fixtures: a tiny local HTTP server for check modules to hit,
so tests never touch the real network.
"""

import http.server
import threading

import pytest


@pytest.fixture
def make_server():
    servers = []

    def _make(routes: dict):
        """routes: {path: callable(handler) -> None}. Each callable is
        responsible for calling send_response/send_header/end_headers/wfile.write."""

        class Handler(http.server.BaseHTTPRequestHandler):
            # HTTP/1.0: the server closes the connection after every response,
            # so test handlers don't need to compute Content-Length to avoid
            # httpx hanging on a keep-alive connection waiting for more bytes.
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def _dispatch(self):
                path = self.path.split("?", 1)[0]
                route = routes.get(path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                route(self)

            def do_GET(self):
                self._dispatch()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self._dispatch()

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        port = server.server_address[1]
        return f"http://127.0.0.1:{port}"

    yield _make

    for server in servers:
        server.shutdown()
        server.server_close()
