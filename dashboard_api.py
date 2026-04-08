from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

import aiofiles
import asyncio
import json
import os
import subprocess
from datetime import datetime

from auth import require_auth, login, logout
import sys
sys.path.insert(0, os.environ.get('SK_HOME', '/home/sk'))
from env_loader import env

app = FastAPI(title="ZeroTrust Gateway Dashboard API", version="1.0.0")

# ── Middleware first ─────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://192.168.35.136", "https://localhost", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files (secure dir — web assets only) ───────────────
app.mount("/static", StaticFiles(directory=env("STATIC_DIR", "/home/sk/static_web")), name="static")

# ── File Paths ───────────────────────────────────────────────
DEVICE_HISTORY = env("DEVICE_HISTORY", os.path.expanduser("~/device_history.json"))
ALERTS_LOG     = env("ALERT_LOG",     "/var/log/zt-alerts.log")
RATELIMIT_LOG  = env("RATELIMIT_LOG", "/var/log/zt-ratelimit.log")
QUARANTINE_SH  = os.path.expanduser("~/quarantine_device.sh")
RESTORE_SH     = os.path.expanduser("~/restore_device.sh")
HEARTBEAT_FILE = env("HEARTBEAT_FILE", "/var/run/zt-heartbeat")

# ── Helpers ──────────────────────────────────────────────────
async def read_json(path: str):
    try:
        async with aiofiles.open(path, "r") as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail=f"Invalid JSON: {path}")

async def read_log_lines(path: str, tail: int = 200):
    try:
        async with aiofiles.open(path, "r") as f:
            lines = (await f.read()).strip().splitlines()
            return lines[-tail:]
    except FileNotFoundError:
        return []

def derive_lan(ip: str, quarantined: bool) -> str:
    if quarantined:
        return "quarantine-lan"
    if ip.startswith(env("IOT_NET", "192.168.20") + "."):
        return "iot-lan"
    if ip.startswith(env("QUARANTINE_NET", "192.168.30") + "."):
        return "quarantine-lan"
    if ip.startswith(env("TRUSTED_NET", "192.168.10") + "."):
        return "c-devices"
    return "iot-lan"

def derive_status(info: dict) -> str:
    if info.get("quarantined"):
        return "quarantined"
    if info.get("under_attack"):
        return "under_attack"
    if info.get("scanning"):
        return "scanning"
    return "active"

def normalize_device(name: str, info: dict) -> dict:
    ip          = info.get("last_ip", "unknown")
    quarantined = info.get("quarantined", False)

    # ✅ FIX: force gateway into c-devices
    if name == "gateway":
        lan = "c-devices"
    else:
        lan = derive_lan(ip, quarantined)

    return {
        "name":               name,
        "ip":                 ip,
        "mac":                info.get("mac", "unknown"),
        "vendor":             info.get("vendor", "unknown"),
        "type":               info.get("device_type", "unknown"),
        "lan":                lan,
        "trust_score":        info.get("trust_score", info.get("score", None)),
        "status":             derive_status(info),
        "ports":              info.get("open_ports", []),
        "last_seen":          info.get("last_seen", "unknown"),
        "violations":         info.get("quarantine_count", 0),
        "quarantined":        quarantined,
        "quarantined_before": info.get("quarantined_before", False),
        "scanning":           info.get("scanning", False),
        "under_attack":       info.get("under_attack", False),
        "east_west":          info.get("east_west", False),
        "rl_applied":         info.get("rl_applied", False),
        "rl_penalty":         info.get("rl_penalty", 0),
        "connections":        info.get("connections", 0),
        "score_reasons":      info.get("score_reasons", []),
        "score_trend":        info.get("score_trend", "stable"),
        "score_avg":          info.get("score_avg", None),
        "score_history":      info.get("score_history", []),
    }

# ── Auth routes (public — no require_auth) ────────────────────
@app.post("/auth/login")
async def do_login(request: Request):
    return await login(request)

@app.post("/auth/logout")
async def do_logout(request: Request):
    return await logout(request)

# ── Dashboard (public — serves HTML) ─────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    async with aiofiles.open(env("DASHBOARD_HTML", "/home/sk/dashboard.html"), "r") as f:
        return await f.read()

# ── PWA routes (public) ───────────────────────────────────────
@app.get("/manifest.json")
async def manifest():
    return FileResponse(
        os.path.join(env("STATIC_DIR", "/home/sk/static_web"), "manifest.json"),
        media_type="application/manifest+json"
    )

@app.get("/sw.js")
async def service_worker():
    return FileResponse(
        os.path.join(env("STATIC_DIR", "/home/sk/static_web"), "sw.js"),
        media_type="application/javascript"
    )

# ── GET /api/devices (protected) ─────────────────────────────
@app.get("/api/devices")
async def get_devices(_=Depends(require_auth)):
    data    = await read_json(DEVICE_HISTORY)
    devices = [normalize_device(name, info) for name, info in data.items()]
    return {"total": len(devices), "devices": devices}

# ── GET /api/lans (protected) ─────────────────────────────────
@app.get("/api/lans")
async def get_lans(_=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    lans = {}
    for name, info in data.items():
        device = normalize_device(name, info)
        lan    = device["lan"]
        if lan not in lans:
            lans[lan] = {"name": lan, "device_count": 0, "devices": [], "avg_trust": 0}
        lans[lan]["device_count"] += 1
        lans[lan]["devices"].append({
            "name":        device["name"],
            "ip":          device["ip"],
            "type":        device["type"],
            "trust_score": device["trust_score"],
            "status":      device["status"],
        })
    for lan in lans.values():
        scores = [d["trust_score"] for d in lan["devices"]
                  if isinstance(d["trust_score"], (int, float))]
        lan["avg_trust"] = round(sum(scores) / len(scores), 1) if scores else None
    return {"lans": list(lans.values())}

# ── GET /api/alerts (protected) ───────────────────────────────
@app.get("/api/alerts")
async def get_alerts(tail: int = 100, _=Depends(require_auth)):
    lines  = await read_log_lines(ALERTS_LOG, tail)
    alerts = []
    for line in lines:
        parts = line.split(" ", 2)
        alerts.append({
            "raw":       line,
            "timestamp": f"{parts[0]} {parts[1]}" if len(parts) >= 2 else "",
            "message":   parts[2] if len(parts) >= 3 else line,
        })
    return {"total": len(alerts), "alerts": list(reversed(alerts))}

# ── GET /api/traffic (protected) ──────────────────────────────
@app.get("/api/traffic")
async def get_traffic(tail: int = 200, _=Depends(require_auth)):
    lines   = await read_log_lines(RATELIMIT_LOG, tail)
    entries = []
    for line in lines:
        parts = line.split(" ", 2)
        ip    = "unknown"
        msg   = parts[2] if len(parts) >= 3 else line
        for segment in msg.split():
            if segment.startswith(env("IOT_NET", "192.168.20") + ".") or segment.startswith(env("TRUSTED_NET", "192.168.10") + "."):
                ip = segment
                break
        entries.append({
            "raw":       line,
            "timestamp": f"{parts[0]} {parts[1]}" if len(parts) >= 2 else "",
            "message":   msg,
            "ip":        ip,
        })
    return {"total": len(entries), "traffic": list(reversed(entries))}

# ── POST /api/quarantine/{name} (protected) ───────────────────
@app.post("/api/quarantine/{name}")
async def quarantine_device(name: str, _=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    if name not in data:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    ip = data[name].get("last_ip", "")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")
    try:
        result = subprocess.run(
            ["bash", QUARANTINE_SH, name, ip],
            capture_output=True, text=True, timeout=15
        )
        return {
            "action":  "quarantine",
            "device":  name,
            "ip":      ip,
            "success": result.returncode == 0,
            "output":  result.stdout.strip(),
            "error":   result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Script timed out")

# ── POST /api/restore/{name} (protected) ──────────────────────
@app.post("/api/restore/{name}")
async def restore_device(name: str, _=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    if name not in data:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    ip = data[name].get("last_ip", "")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")
    try:
        result = subprocess.run(
            ["bash", RESTORE_SH, name, ip],
            capture_output=True, text=True, timeout=15
        )
        return {
            "action":  "restore",
            "device":  name,
            "ip":      ip,
            "success": result.returncode == 0,
            "output":  result.stdout.strip(),
            "error":   result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Script timed out")

def _read_heartbeat():
    """Read last controller cycle timestamp from heartbeat file."""
    try:
        HEARTBEAT_FILE = env("HEARTBEAT_FILE", "/var/run/zt-heartbeat")
        if os.path.exists(HEARTBEAT_FILE):
            with open(HEARTBEAT_FILE) as f:
                return f.read().strip()
    except Exception:
        pass
    return None

# ── GET /api/status (protected — quick health check) ──────────
@app.get("/api/status")
async def get_status(_=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    total     = len(data)
    quarantined = sum(1 for d in data.values() if d.get("quarantined"))
    alerts_today = 0
    try:
        lines = await read_log_lines(ALERTS_LOG, 500)
        today = datetime.now().strftime("%Y-%m-%d")
        alerts_today = sum(1 for l in lines if l.startswith(today))
    except Exception:
        pass
    return {
        "total_devices":   total,
        "quarantined":     quarantined,
        "trusted":         total - quarantined,
        "alerts_today":    alerts_today,
        "controller_time": datetime.now().isoformat(),
        "last_cycle_at":   _read_heartbeat(),
    }

# ── WebSocket /ws/live (auth via token param) ─────────────────
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket, token: str = ""):
    # Validate JWT token passed as query param for WebSocket
    from auth import _verify_jwt, AUTH_MODE, API_KEY, _safe_compare
    authenticated = False

    if AUTH_MODE == "jwt" and token:
        if _verify_jwt(token):
            authenticated = True
    elif AUTH_MODE == "apikey" and token:
        if _safe_compare(token, API_KEY):
            authenticated = True
    else:
        # Allow in password/session mode — dashboard handles auth
        authenticated = True

    if not authenticated:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    try:
        last_size = 0
        while True:
            try:
                if os.path.exists(ALERTS_LOG):
                    size = os.path.getsize(ALERTS_LOG)
                    if size != last_size:
                        last_size = size
                        lines = await read_log_lines(ALERTS_LOG, 5)
                        for line in lines:
                            await websocket.send_json({
                                "type":      "alert",
                                "timestamp": datetime.now().isoformat(),
                                "message":   line,
                            })
            except Exception:
                pass
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
