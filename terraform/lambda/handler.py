"""
Lambda handler for OpenVPN OAuth2 auth flow.

Routes:
  GET /auth?state=...     — verify HMAC on state blob, redirect to Cognito hosted UI
  GET /callback?code=...  — receive auth code from Cognito, POST to daemon /callback
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cached across invocations
_hmac_secret = None
_secrets_client = None


def get_hmac_secret():
    """Fetch HMAC secret from Secrets Manager (cached)."""
    global _hmac_secret, _secrets_client
    if _hmac_secret is not None:
        return _hmac_secret
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager")
    resp = _secrets_client.get_secret_value(SecretId=os.environ["HMAC_SECRET_ARN"])
    _hmac_secret = resp["SecretString"]
    return _hmac_secret


def sign(secret, data):
    """HMAC-SHA256 sign data, return base64url-encoded (no padding)."""
    mac = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def verify_hmac(secret, data, expected_mac):
    """Verify HMAC signature."""
    return hmac.compare_digest(sign(secret, data), expected_mac)


def lambda_handler(event, context):
    """API Gateway v2 (HTTP API) handler."""
    path = event.get("rawPath", "")
    qs = event.get("queryStringParameters") or {}

    if path == "/auth":
        return handle_auth(qs)
    elif path == "/callback":
        return handle_callback(qs)
    else:
        return {"statusCode": 404, "body": "not found"}


def handle_auth(qs):
    """Verify state blob HMAC and redirect to Cognito hosted UI."""
    state_blob = qs.get("state", "")
    if not state_blob:
        return {"statusCode": 400, "body": "missing state"}

    secret = get_hmac_secret()

    # State format: base64payload.mac
    parts = state_blob.split(".", 1)
    if len(parts) != 2:
        return {"statusCode": 400, "body": "invalid state format"}

    encoded, mac = parts
    if not verify_hmac(secret, encoded, mac):
        logger.warning("invalid HMAC for state")
        return {"statusCode": 403, "body": "invalid signature"}

    # Decode and validate expiry
    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=="))
    except Exception:
        return {"statusCode": 400, "body": "decode state failed"}

    if time.time() > payload.get("exp", 0):
        return {"statusCode": 400, "body": "state expired"}

    logger.info("state OK, sid=%s, agent=%s", payload.get("sid"), payload.get("ip"))

    # Build Cognito authorize URL
    cognito_domain = os.environ["COGNITO_DOMAIN"]
    client_id = os.environ["COGNITO_CLIENT_ID"]
    redirect_uri = os.environ["COGNITO_REDIRECT_URI"]

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email",
        "state": state_blob,
    }

    # PKCE: include code_challenge if passed as query parameter
    code_challenge = qs.get("cc", "")
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    authorize_url = f"{cognito_domain}/oauth2/authorize?" + urllib.parse.urlencode(params)

    return {
        "statusCode": 302,
        "headers": {"Location": authorize_url},
        "body": "",
    }


def handle_callback(qs):
    """Receive auth code from Cognito, POST to daemon callback."""
    code = qs.get("code", "")
    state_blob = qs.get("state", "")

    if not code or not state_blob:
        return {
            "statusCode": 400,
            "body": html_page("Error", "Missing code or state parameter."),
            "headers": {"Content-Type": "text/html"},
        }

    secret = get_hmac_secret()

    # Re-verify state HMAC
    parts = state_blob.split(".", 1)
    if len(parts) != 2 or not verify_hmac(secret, parts[0], parts[1]):
        return {
            "statusCode": 403,
            "body": html_page("Error", "Invalid state signature."),
            "headers": {"Content-Type": "text/html"},
        }

    # Extract daemon IP from state
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    except Exception:
        return {
            "statusCode": 400,
            "body": html_page("Error", "Cannot decode state."),
            "headers": {"Content-Type": "text/html"},
        }

    agent_addr = payload.get("ip", "")
    session_id = payload.get("sid", "")

    # Build callback payload
    callback_body = json.dumps({
        "code": code,
        "session_id": session_id,
        "ts": int(time.time()),
    }).encode()

    body_mac = sign(secret, callback_body.decode())

    # POST to daemon /callback
    agent_url = f"http://{agent_addr}/callback"
    req = urllib.request.Request(
        agent_url,
        data=callback_body,
        headers={
            "Content-Type": "application/json",
            "X-Internal-Token": body_mac,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        logger.warning("agent returned %d: %s", status, e.read().decode(errors="replace"))
    except Exception as e:
        logger.error("callback POST failed: %s", e)
        return {
            "statusCode": 502,
            "body": html_page("Authentication failed", "Please close this window and reconnect."),
            "headers": {"Content-Type": "text/html"},
        }

    if status == 200:
        logger.info("callback accepted for sid=%s", session_id)
        return {
            "statusCode": 200,
            "body": html_page("Authentication successful", "You can close this window and return to your VPN client."),
            "headers": {"Content-Type": "text/html"},
        }
    elif status in (404, 409):
        return {
            "statusCode": 200,
            "body": html_page("Link no longer valid", "This link has already been used or has expired. If you need to connect, please reconnect your VPN client."),
            "headers": {"Content-Type": "text/html"},
        }
    else:
        return {
            "statusCode": 502,
            "body": html_page("Authentication failed", "Please close this window and reconnect."),
            "headers": {"Content-Type": "text/html"},
        }


def html_page(title, message):
    return f"<!DOCTYPE html><html><body><h1>{title}</h1><p>{message}</p></body></html>"
