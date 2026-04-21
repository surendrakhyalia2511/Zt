#!/usr/bin/env python3
import os
import json
import time
import hmac
import hashlib
import base64
import secrets
import bcrypt
from typing import Optional

from fastapi import HTTPException, Request, Depends
from fastapi.responses import JSONResponse

AUTH_CONFIG_FILE = os.path.join(os.environ.get("SK_HOME", "/home/sk"), "auth_config.json")

def _load_config():
    defaults = {
        "mode": "jwt", "username": "admin", "password": "changeMe123",
        "api_key": secrets.token_urlsafe(32), "jwt_secret": secrets.token_urlsafe(64),
    }
    try:
        if os.path.exists(AUTH_CONFIG_FILE):
            with open(AUTH_CONFIG_FILE) as f:
                defaults.update(json.load(f))
        else:
            with open(AUTH_CONFIG_FILE, 'w') as f:
                json.dump(defaults, f, indent=2)
            os.chmod(AUTH_CONFIG_FILE, 0o600)
    except Exception as e:
        print(f"[AUTH] Config error: {e}")
    return defaults

CONFIG     = _load_config()
AUTH_MODE  = os.getenv("ZT_AUTH_MODE",  CONFIG.get("mode",       "password"))
USERNAME   = os.getenv("ZT_USERNAME",   CONFIG.get("username",   "admin"))
PASSWORD   = os.getenv("ZT_PASSWORD",   CONFIG.get("password",   "changeMe123"))
API_KEY    = os.getenv("ZT_API_KEY",    CONFIG.get("api_key",    ""))
JWT_SECRET = os.getenv("ZT_JWT_SECRET", CONFIG.get("jwt_secret", ""))

_sessions: dict = {}
SESSION_TTL = 24 * 3600


def _safe_compare(a: str, b: str) -> bool:
    """Compare plain or bcrypt-hashed passwords safely."""
    if b.startswith('$2b$') or b.startswith('$2a$'):
        try:
            return bcrypt.checkpw(a.encode(), b.encode())
        except Exception:
            return False
    return hmac.compare_digest(a.encode(), b.encode())

def _make_jwt(username: str, role: str = "admin") -> str:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    header  = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({
        "sub": username, "role": role,
        "iat": int(time.time()), "exp": int(time.time()) + SESSION_TTL,
    }).encode())
    sig = b64(hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _verify_jwt(token: str) -> Optional[tuple]:
    try:
        def b64(data: str) -> bytes:
            return base64.urlsafe_b64decode(data + "=" * (4 - len(data) % 4))
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected = base64.urlsafe_b64encode(
            hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(b64(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("sub"), data.get("role", "viewer")
    except Exception:
        return None


async def login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    user = body.get("username", "")
    pw   = body.get("password", "")

    admin_ok    = _safe_compare(user, USERNAME) and _safe_compare(pw, PASSWORD)
    viewer_ok   = False
    viewer_role = None
    for u in CONFIG.get("users", []):
        if _safe_compare(user, u.get("username", "")) and _safe_compare(pw, u.get("password", "")):
            viewer_ok   = True
            viewer_role = u.get("role", "viewer")
            break

    if not (admin_ok or viewer_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    _user_role = CONFIG.get("role", "admin") if admin_ok else (viewer_role or "viewer")

    if AUTH_MODE == "jwt":
        token = _make_jwt(user, _user_role)
        return JSONResponse({"token": token, "type": "Bearer", "expires_in": SESSION_TTL})

    if AUTH_MODE in ("password", "session"):
        token = secrets.token_urlsafe(32)
        _sessions[token] = {"username": user, "expires_at": time.time() + SESSION_TTL}
        resp = JSONResponse({"message": "Login successful"})
        resp.set_cookie(key="zt_session", value=token, httponly=True,
                        samesite="lax", max_age=SESSION_TTL)
        return resp

    if AUTH_MODE == "apikey":
        return JSONResponse({"api_key": API_KEY, "message": "Use X-API-Key header"})

    raise HTTPException(status_code=500, detail="Unknown auth mode")


async def logout(request: Request) -> JSONResponse:
    cookie = request.cookies.get("zt_session")
    if cookie and cookie in _sessions:
        del _sessions[cookie]
    resp = JSONResponse({"message": "Logged out"})
    resp.delete_cookie("zt_session")
    return resp


async def require_auth(request: Request):
    path           = request.url.path
    public_exact   = {"/", "/manifest.json", "/sw.js", "/favicon.ico"}
    public_prefix  = ("/auth/", "/static/")

    if path in public_exact or path.startswith(public_prefix):
        return True

    if AUTH_MODE == "apikey":
        key = (request.headers.get("X-API-Key") or request.query_params.get("key") or "")
        if _safe_compare(key, API_KEY):
            return True
        raise HTTPException(status_code=401, detail="Invalid API key",
                            headers={"WWW-Authenticate": "ApiKey"})

    if AUTH_MODE == "jwt":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            result = _verify_jwt(auth_header[7:])
            if result:
                username, role = result if isinstance(result, tuple) else (result, "admin")
                return username
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})

    cookie = request.cookies.get("zt_session")
    if cookie and cookie in _sessions:
        session = _sessions[cookie]
        if session["expires_at"] > time.time():
            return session["username"]
        del _sessions[cookie]

    raise HTTPException(status_code=401, detail="Authentication required")


async def change_password(request: Request) -> JSONResponse:
    """
    Handle POST /auth/change-password
    Body: { "current_password": "...", "new_password": "...", "confirm_password": "..." }
    Requires valid JWT — changes password for the authenticated user only.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    current_pw  = body.get("current_password", "")
    new_pw      = body.get("new_password", "")
    confirm_pw  = body.get("confirm_password", "")

    # Validate new password
    if new_pw != confirm_pw:
        raise HTTPException(status_code=400, detail="New passwords do not match")
    if len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in new_pw):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in new_pw):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")

    # Get username from JWT
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    result = _verify_jwt(auth_header[7:])
    if not result:
        raise HTTPException(status_code=401, detail="Invalid token")
    username, role = result if isinstance(result, tuple) else (result, "viewer")

    import json as _j, os as _os
    with open(AUTH_CONFIG_FILE) as f:
        cfg = _j.load(f)

    # Check current password and update
    if username == cfg.get("username"):
        if not _safe_compare(current_pw, cfg.get("password", "")):
            raise HTTPException(status_code=403, detail="Current password is incorrect")
        cfg["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    else:
        # Viewer user
        found = False
        for u in cfg.get("users", []):
            if u.get("username") == username:
                if not _safe_compare(current_pw, u.get("password", "")):
                    raise HTTPException(status_code=403, detail="Current password is incorrect")
                u["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
                found = True
                break
        if not found:
            raise HTTPException(status_code=404, detail="User not found")

    with open(AUTH_CONFIG_FILE, "w") as f:
        _j.dump(cfg, f, indent=2)
    _os.chmod(AUTH_CONFIG_FILE, 0o600)

    return JSONResponse({"message": "Password changed successfully"})
