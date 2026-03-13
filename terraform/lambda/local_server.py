"""
Thin HTTP wrapper around the Lambda handler for local Docker testing.

Translates HTTP requests into API Gateway v2 event format and calls lambda_handler.

Usage:
    python local_server.py
    # Listens on LISTEN_ADDR (default :8080)
"""

import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import handler
from handler import lambda_handler

# Pre-seed the HMAC secret from env var so handler.get_hmac_secret()
# returns it directly without calling Secrets Manager.
_secret = os.environ.get("HMAC_SECRET")
if not _secret:
    raise SystemExit("HMAC_SECRET env var is required for local mode")
handler._hmac_secret = _secret


class LambdaHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        raw_qs = parse_qs(parsed.query)
        # API Gateway v2 format: single values (not lists)
        qs = {k: v[0] for k, v in raw_qs.items()} if raw_qs else None

        event = {
            "rawPath": parsed.path,
            "queryStringParameters": qs,
        }

        result = lambda_handler(event, None)

        status = result.get("statusCode", 200)
        headers = result.get("headers", {})
        body = result.get("body", "")

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if "Content-Type" not in headers:
            self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def log_message(self, format, *args):
        print(f"[lambda] {args[0]}")


def main():
    addr = os.environ.get("LISTEN_ADDR", ":8080")
    host, _, port = addr.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port)

    server = HTTPServer((host, port), LambdaHTTPHandler)
    print(f"Lambda local server listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
