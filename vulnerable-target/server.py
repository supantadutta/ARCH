"""Intentionally *misconfigured* local demo target — DISABLED BY DEFAULT.

This tiny server exists solely to give AutoBugHunter a safe, self-contained
asset to scan during demos. It is **not** an exploit lab and contains **no**
exploitable vulnerabilities, payloads, or sensitive data:

* It only serves a static HTML page over HTTP.
* The "weaknesses" are passive *misconfigurations* a baseline scan can flag —
  e.g. missing security headers (Content-Security-Policy, X-Frame-Options) and
  a verbose ``Server`` banner. These are detectable but not exploitable.

Run it only inside an isolated lab, only against your own machine, and only
when you have explicitly enabled it (compose ``vuln`` profile). Never expose it
to a network you do not fully control.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9000

_PAGE = b"""<!DOCTYPE html>
<html>
  <head><title>AutoBugHunter Demo Target</title></head>
  <body>
    <h1>Authorized demo target</h1>
    <p>This page is served only as a safe scan target for AutoBugHunter.</p>
    <p>It intentionally omits common security headers so a baseline scan has
       something benign to report. There is nothing exploitable here.</p>
  </body>
</html>
"""


class DemoHandler(BaseHTTPRequestHandler):
    # Verbose banner is itself a (benign) misconfiguration to detect.
    server_version = "DemoServer"
    sys_version = "1.0-insecure-headers-demo"

    def _respond(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PAGE)))
        # NOTE: deliberately NOT sending CSP / X-Frame-Options / HSTS so the
        # scanner can flag their absence. No exploitable behaviour is added.
        self.end_headers()
        self.wfile.write(_PAGE)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        self._respond()

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def log_message(self, fmt, *args):  # quieter logs
        print("[vulnerable-target]", fmt % args)


if __name__ == "__main__":
    print(f"[vulnerable-target] listening on 0.0.0.0:{PORT} (authorized demo use only)")
    ThreadingHTTPServer(("0.0.0.0", PORT), DemoHandler).serve_forever()
