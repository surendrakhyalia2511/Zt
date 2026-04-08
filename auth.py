#!/usr/bin/env python3
"""
auth.py
Zero Trust IoT Gateway — API Authentication

Supports three modes (set AUTH_MODE in config):
  "apikey"   : Single API key in X-API-Key header or ?key= param
  "password" : Username + password → session cookie
  "jwt"      : Username + password → JWT bearer token (industry standard)

Default mode: "password" — best for homeowner dashboard login screen.

Configuration via environment variables or auth_config.json:
  ZT_AUTH_MODE     : apikey | password | jwt
  ZT_USERNAME      : dashboard username (default: admin)
  ZT_PASSWORD      : dashboard password (CHANGE THIS)
  ZT_API_KEY       : API key for apikey mode
  ZT_JWT_SECRET    : JWT signing secret (auto-generated if missing)
"""

import os
import json
import time
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

# ── Config ─────────────────────────────────────────────────────
AUTH_CONFIG_FILE = os.path.join(os.environ.get("SK_HOME", "/home/sk"), "auth_config.json")

def _load_config():
    defaults = {
        "mode":       "jwt",
        "username":   "admin",
        "password":   "changeMe123",
        "api_key":    secrets.token_urlsafe(32),
        "jwt_secret": secrets.token_urlsafe(64),
    }
    try:
        if os.path.exists(AUTH_CONFIG_FILE):
            with open(AUTH_CONFIG_FILE) as f:
                saved = json.load(f)
                defaults.update(saved)
        else:
            # First run — save generated secrets
            with open(AUTH_CONFIG_FILE, 'w') as f:
                json.dump(defaults, f, indent=2)
            os.chmod(AUTH_CONFIG_FILE, 0o600)
            print(f"[AUTH] Created auth config at {AUTH_CONFIG_FILE}")
            print(f"[AUTH] Default login: admin / changeMe123")
            print(f"[AUTH] API Key: {defaults['api_key']}")
    except Exception as e:
        print(f"[AUTH] Config error: {e}")
    return defaults

CONFIG = _load_config()
AUTH_MODE  = os.getenv("ZT_AUTH_MODE",   CONFIG.get("mode",       "password"))
USERNAME   = os.getenv("ZT_USERNAME",    CONFIG.get("username",   "admin"))
PASSWORD   = os.getenv("ZT_PASSWORD",    CONFIG.get("password",   "changeMe123"))
API_KEY    = os.getenv("ZT_API_KEY",     CONFIG.get("api_key",    ""))
JWT_SECRET = os.getenv("ZT_JWT_SECRET",  CONFIG.get("jwt_secret", ""))

# In-memory session store (sufficient for single-gateway use)
# { session_token: { username, expires_at } }
_sessions: dict = {}
SESSION_TTL = 24 * 3600   # 24 hours


# ── Helpers ────────────────────────────────────────────────────

def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

def _make_session_token() -> str:
    return secrets.token_urlsafe(32)

def _make_jwt(username: str) -> str:
    """Minimal JWT — header.payload.signature (HS256)."""
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    header  = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_TTL,
    }).encode())
    sig = b64(hmac.new(
        JWT_SECRET.encode(),
        f"{header}.{payload}".encode(),
        hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def _verify_jwt(token: str) -> Optional[str]:
    """Returns username if valid, None if invalid/expired."""
    try:
        def b64(data: str) -> bytes:
            pad = 4 - len(data) % 4
            return base64.urlsafe_b64decode(data + "=" * pad)

        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected_sig = hmac.new(
            JWT_SECRET.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256
        ).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()
        if not hmac.compare_digest(sig, expected_b64):
            return None
        data = json.loads(b64(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("sub")
    except Exception:
        return None


# ── Login endpoint helper (call from dashboard_api.py) ────────

async def login(request: Request) -> JSONResponse:
    """
    Handle POST /auth/login.
    Accepts JSON: { "username": "...", "password": "..." }
    Returns token or session cookie depending on AUTH_MODE.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    user = body.get("username", "")
    pw   = body.get("password", "")

    if not (_safe_compare(user, USERNAME) and _safe_compare(pw, PASSWORD)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if AUTH_MODE == "jwt":
        token = _make_jwt(user)
        return JSONResponse({"token": token, "type": "Bearer", "expires_in": SESSION_TTL})

    elif AUTH_MODE in ("password", "session"):
        token = _make_session_token()
        _sessions[token] = {
            "username":   user,
            "expires_at": time.time() + SESSION_TTL,
        }
        resp = JSONResponse({"message": "Login successful"})
        resp.set_cookie(
            key="zt_session",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_TTL,
        )
        return resp

    elif AUTH_MODE == "apikey":
        # In API key mode, just validate and return the key
        return JSONResponse({"api_key": API_KEY, "message": "Use X-API-Key header"})

    raise HTTPException(status_code=500, detail="Unknown auth mode")


async def logout(request: Request) -> JSONResponse:
    """Handle POST /auth/logout — invalidate session."""
    cookie = request.cookies.get("zt_session")
    if cookie and cookie in _sessions:
        del _sessions[cookie]
    resp = JSONResponse({"message": "Logged out"})
    resp.delete_cookie("zt_session")
    return resp


# ── FastAPI dependency — use with Depends(require_auth) ────────

async def require_auth(request: Request):
    """
    FastAPI dependency that enforces authentication.
    Add to any route: async def my_route(..., _=Depends(require_auth))

    Checks (in order):
      1. Skip auth for dashboard HTML and static files
      2. API key in X-API-Key header or ?key= param
      3. JWT Bearer token in Authorization header
      4. Session cookie
    """
    path = request.url.path

    # Exact match for root and specific files
    public_exact = {"/", "/manifest.json", "/sw.js", "/favicon.ico"}
    # Prefix match only for auth and static routes
    public_prefix = ("/auth/", "/static/")

    if path in public_exact or path.startswith(public_prefix):
        return True

    # ── API Key mode ──────────────────────────────────────────
    if AUTH_MODE == "apikey":
        key = (request.headers.get("X-API-Key") or
               request.query_params.get("key") or "")
        if _safe_compare(key, API_KEY):
            return True
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # ── JWT mode ──────────────────────────────────────────────
    if AUTH_MODE == "jwt":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            username = _verify_jwt(token)
            if username:
                return username
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # ── Password / session mode ───────────────────────────────
    cookie = request.cookies.get("zt_session")
    if cookie and cookie in _sessions:
        session = _sessions[cookie]
        if session["expires_at"] > time.time():
            return session["username"]
        else:
            del _sessions[cookie]

    # Not authenticated — for API calls return 401
    # For browser requests return 401 (frontend handles redirect to login)
    raise HTTPException(status_code=401, detail="Authentication required")


def cleanup_sessions():
    """Remove expired sessions — call periodically."""
    now = time.time()
    expired = [k for k, v in _sessions.items() if v["expires_at"] < now]
    for k in expired:
        del _sessions[k]
