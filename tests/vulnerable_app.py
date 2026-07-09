from __future__ import annotations
"""
tests/vulnerable_app.py
------------------------
A small, self-contained web application with KNOWN vulnerabilities *and* known
safe endpoints. It is the ground truth for the accuracy test suite
(tests/test_accuracy.py): the scanner should flag every vulnerable endpoint
(recall) and flag none of the safe ones (precision).

Deliberately vulnerable — DO NOT deploy. Runs on 127.0.0.1 only.

Endpoints
  /                     home page linking to everything below (so the crawler
                        discovers each parameter)
  /sqli?id=             error-based SQL injection (emits a SQL error on quote)
  /sqli_blind?id=       boolean-based blind SQLi (full vs empty result set)
  /xss?q=               reflected XSS (input echoed unescaped)   [VULN]
  /xss_safe?q=          reflected but HTML-escaped               [SAFE]
  /redirect?next=       open redirect (Location: <input>)        [VULN]
  /redirect_safe?next=  redirect only to same-site paths         [SAFE]
  /dom                  DOM XSS via location.hash -> innerHTML    [VULN, needs render]
  /static               static page, no user input               [SAFE]

  REST/JSON API surface (Phase D — API-first injection)
  /api/search?q=        GET  JSON, error-based SQLi in query param [VULN]
  /api/login            POST JSON body, error-based SQLi (username) [VULN]
  /api/report           POST JSON body, boolean-based blind SQLi    [VULN]
  /api/echo             POST JSON body, reflects input verbatim     [SAFE]
"""

import html
import http.server
import json as _json_mod
import socketserver
import threading
import urllib.parse

# A chunk of filler so "full" vs "empty" boolean responses differ by >15% / >50B.
_FILLER = "<li>record " + "x" * 40 + "</li>\n"
_FULL_LIST = "<ul>\n" + (_FILLER * 30) + "</ul>"
_EMPTY_LIST = "<ul>\n</ul>"

_NAV = """
<a href="/sqli?id=1">sqli</a>
<a href="/sqli_blind?id=1">sqli_blind</a>
<a href="/xss?q=hello">xss</a>
<a href="/xss_safe?q=hello">xss_safe</a>
<a href="/redirect?next=/home">redirect</a>
<a href="/redirect_safe?next=/home">redirect_safe</a>
<a href="/api/search?q=hello">api-search</a>
<a href="/static">static</a>
"""

# JSON list bodies for the boolean-based API endpoint (full vs empty must differ
# by >15% / >50B so the detector's gates fire).
_API_FULL = [{"id": i, "name": "record " + "x" * 40} for i in range(30)]
_API_EMPTY: list = []


def _page(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body><h1>{title}</h1>{body}</body></html>"
    ).encode()


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, status: int = 200):
        body = _json_mod.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            data = _json_mod.loads(raw or b"{}")
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send(_page("Vulnerable Test App", _NAV))

        elif path == "/sqli":
            raw = params.get("id", [""])[0]
            if "'" in raw or '"' in raw:
                # Error-based: leak a recognisable DB error string
                self._send(_page(
                    "DB Error",
                    "You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version near "
                    f"'{html.escape(raw)}'",
                ))
            else:
                self._send(_page("User", f"<p>User id {html.escape(raw)}</p>"))

        elif path == "/sqli_blind":
            raw = params.get("id", [""])[0]
            # FALSE conditions return an empty result set; everything else
            # (baseline + TRUE conditions) returns the full list.
            if "1'='2" in raw or "1=2" in raw:
                self._send(_page("Search", _EMPTY_LIST))
            else:
                self._send(_page("Search", _FULL_LIST))

        elif path == "/xss":
            raw = params.get("q", [""])[0]
            self._send(_page("Search", f"<p>Results for: {raw}</p>"))  # UNSAFE

        elif path == "/xss_safe":
            raw = params.get("q", [""])[0]
            self._send(_page("Search", f"<p>Results for: {html.escape(raw)}</p>"))  # SAFE

        elif path == "/redirect":
            nxt = params.get("next", ["/"])[0]
            # Open redirect: blindly 302 to any absolute/external target. Internal
            # values render a 200 page (so the crawler keeps the ?next param).
            if nxt.startswith(("http://", "https://", "//")):
                self._send(b"", status=302, headers={"Location": nxt})
            else:
                self._send(_page("Redirect", f"<p>next={html.escape(nxt)}</p>"))

        elif path == "/redirect_safe":
            nxt = params.get("next", ["/"])[0]
            # Safe: reject absolute/external targets outright.
            if nxt.startswith(("http://", "https://", "//")):
                self._send(_page("Blocked", "Invalid redirect target"), status=400)
            else:
                self._send(_page("Redirect", f"<p>next={html.escape(nxt)}</p>"))

        elif path == "/dom":
            self._send(_page(
                "DOM",
                '<div id="out"></div>'
                '<script>document.getElementById("out").innerHTML='
                'decodeURIComponent(location.hash.slice(1));</script>',
            ))

        elif path == "/static":
            self._send(_page("Static", "<p>Nothing user-controlled here.</p>"))

        elif path == "/api/search":
            # GET JSON API — error-based SQLi in the `q` query parameter. Returns
            # a JSON body (Content-Type: application/json), so a classic HTML
            # crawler never records it; the Phase D API pass does.
            raw = params.get("q", [""])[0]
            if "'" in raw or '"' in raw:
                self._json(
                    {"error": "You have an error in your SQL syntax; check the "
                              f"manual near '{raw}'"},
                    status=500,
                )
            else:
                self._json({"results": [{"id": 1, "name": "widget"}]})

        else:
            self._send(_page("Not Found", "no such page"), status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/login":
            # JSON-body error-based SQLi in `username`. A quote breaks the query.
            username = str(body.get("username", ""))
            if "'" in username or '"' in username:
                self._json({"error": "SQLITE_ERROR: unrecognized token near "
                                     f"'{username}'"}, status=500)
            else:
                self._json({"status": "ok", "token": "abc123"})

        elif path == "/api/report":
            # JSON-body boolean-based blind SQLi in `category`: FALSE conditions
            # return an empty result set, everything else the full one.
            category = str(body.get("category", ""))
            if "1'='2" in category or "1=2" in category:
                self._json({"items": _API_EMPTY})
            else:
                self._json({"items": _API_FULL})

        elif path == "/api/echo":
            # SAFE: reflects the JSON input verbatim but never builds a query from
            # it. Must NOT be flagged — reflection alone is not injection.
            self._json({"echo": body.get("msg", "")})

        else:
            self._json({"error": "no such endpoint"}, status=404)


class VulnerableApp:
    """Start/stop helper for the vulnerable app in a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self._server = socketserver.ThreadingTCPServer((host, port), _Handler)
        self.host, self.port = self._server.server_address[:2]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "VulnerableApp":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()


if __name__ == "__main__":
    # Manual run: python -m tests.vulnerable_app
    with VulnerableApp(port=8090) as app:
        print(f"Vulnerable app on {app.url} (Ctrl-C to stop)")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
