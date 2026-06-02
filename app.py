import base64
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional

import config

STATE_TTL_SECONDS = 600


def _resp(status_code, headers=None, body=""):
    h = {"content-type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return {"statusCode": status_code, "headers": h, "body": body}


def _redirect(url, cookies=None):
    headers = {"location": url}
    if cookies:
        headers["set-cookie"] = cookies
    return _resp(302, headers=headers, body="")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _sign_state(payload: dict) -> str:
    secret = config.STATE_SECRET
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if secret:
        import hmac
        import hashlib

        sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
        return _b64url(msg) + "." + _b64url(sig)
    return _b64url(msg) + "." + _b64url(secrets.token_bytes(32))


def _verify_state(state: str) -> Optional[dict]:
    try:
        part_msg, part_sig = state.split(".", 1)
        msg = base64.urlsafe_b64decode(part_msg + "==")
        sig = base64.urlsafe_b64decode(part_sig + "==")
        payload = json.loads(msg.decode("utf-8"))
    except Exception:
        return None

    secret = config.STATE_SECRET
    if secret:
        import hmac
        import hashlib

        expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return None

    ts = payload.get("ts")
    if not isinstance(ts, int):
        return None
    if int(time.time()) - ts > STATE_TTL_SECONDS:
        return None

    return payload


def _qs(event):
    q = event.get("queryStringParameters")
    if isinstance(q, dict) and q:
        return q

    raw = event.get("rawQueryString")
    if raw:
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in parsed.items()}

    return {}


def _path(event):
    return (event.get("rawPath") or event.get("path") or "/").strip("/")


def _cookie(event, name):
    headers = event.get("headers") or {}
    cookie = headers.get("cookie") or headers.get("Cookie")
    if not cookie:
        return None
    parts = [p.strip() for p in cookie.split(";")]
    for p in parts:
        if p.startswith(name + "="):
            return urllib.parse.unquote(p.split("=", 1)[1])
    return None


def _http(method, url, headers=None, data=None):
    req = urllib.request.Request(url, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if data is not None:
        req.data = data
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _http_json(method, url, headers=None, data=None):
    status, text = _http(method, url, headers=headers, data=data)
    try:
        return status, json.loads(text) if text else {}
    except Exception:
        return status, {"raw": text}


def login_page(base_url: str):
    go_url = base_url.rstrip("/") + "/go"
    html = """<!doctype html>
<html>
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Login</title>
</head>
<body>
<div style=\"font-family: -apple-system, system-ui, Segoe UI, Roboto, Helvetica, Arial; max-width: 720px; margin: 40px auto;\">
<h1>Login</h1>
<a href=\"{go}\" style=\"display: inline-block; padding: 12px 16px; background: #24292f; color: white; text-decoration: none; border-radius: 8px;\">Login with GitHub SSO</a>
</div>
</body>
</html>""".format(go=_escape(go_url))
    return _resp(200, body=html)


def go(event, base_url: str):
    client_id = config.GITHUB_CLIENT_ID
    callback_url = base_url.rstrip("/") + "/callback"

    state = _sign_state({"ts": int(time.time())})

    params = {
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": "read:user",
        "state": state,
        "allow_signup": "true",
    }
    url = "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)
    return _redirect(url)


def login(event, base_url: str):
    return login_page(base_url)


def callback(event, base_url: str):
    q = _qs(event)
    code = q.get("code")
    state = q.get("state")
    if not code or not state:
        return _resp(400, body="Missing code or state")

    if not _verify_state(state):
        return _resp(400, body="Invalid state")

    client_id = config.GITHUB_CLIENT_ID
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET") or config.GITHUB_CLIENT_SECRET
    if not client_secret:
        return _resp(500, body="Missing GITHUB_CLIENT_SECRET")

    token_url = "https://github.com/login/oauth/access_token"
    data = urllib.parse.urlencode(
        {"client_id": client_id, "client_secret": client_secret, "code": code}
    ).encode("utf-8")

    status, token_payload = _http_json(
        "POST",
        token_url,
        headers={"accept": "application/json"},
        data=data,
    )
    if status != 200:
        return _resp(400, body=f"Token exchange failed ({status})")

    access_token = token_payload.get("access_token")
    if not access_token:
        return _resp(400, body="Token exchange failed")

    status, user = _http_json(
        "GET",
        "https://api.github.com/user",
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {access_token}",
            "user-agent": "oauth-demo",
        },
    )
    if status != 200:
        return _resp(400, body=f"Failed to fetch user ({status})")

    name = user.get("name") or ""
    login_name = user.get("login") or ""
    avatar = user.get("avatar_url") or ""

    html = """<!doctype html>
<html>
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Hello</title>
</head>
<body>
<div style=\"font-family: -apple-system, system-ui, Segoe UI, Roboto, Helvetica, Arial; max-width: 720px; margin: 40px auto;\">
<h1>Hello</h1>
<p><strong>{name}</strong> ({login})</p>
<img src=\"{avatar}\" alt=\"avatar\" width=\"120\" height=\"120\" style=\"border-radius: 60px;\">
</div>
</body>
</html>""".format(
        name=_escape(name), login=_escape(login_name), avatar=_escape(avatar)
    )

    return _resp(200, body=html)


def _escape(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _action(event):
    pp = event.get("pathParameters") or {}
    if isinstance(pp, dict):
        a = pp.get("action") or pp.get("proxy")
        if a:
            return str(a).strip("/")

    p = event.get("rawPath") or event.get("path") or "/"
    p = str(p)
    if "/Production/" in p:
        p = p.split("/Production/", 1)[1]
    return p.strip("/")


def lambda_handler(event, context):
    try:
        base_url = config.BASE_URL

        action = _action(event)
        if action == "debug":
            return {
                "statusCode": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps(event, indent=2, default=str),
            }

        if action == "login":
            return login(event, base_url)
        if action == "go":
            return go(event, base_url)
        if action == "callback":
            return callback(event, base_url)

        return _resp(404, body="Not found")
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"content-type": "text/plain; charset=utf-8"},
            "body": f"Server error: {type(e).__name__}: {e}",
        }
