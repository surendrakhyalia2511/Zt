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

from auth import require_auth, login, logout, change_password, _verify_jwt, AUTH_MODE, API_KEY, _safe_compare, USERNAME
import alert_manager as am
import sys
sys.path.insert(0, os.environ.get('SK_HOME', '/home/sk'))
from env_loader import env

app = FastAPI(title="ZeroTrust Gateway Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://192.168.35.136", "https://localhost", "http://localhost"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=env("STATIC_DIR", "/home/sk/static_web")), name="static")

DEVICE_HISTORY = env("DEVICE_HISTORY", os.path.expanduser("~/device_history.json"))
ALERTS_LOG     = env("ALERT_LOG",      "/var/log/zt-alerts.log")
RATELIMIT_LOG  = env("RATELIMIT_LOG",  "/var/log/zt-ratelimit.log")
QUARANTINE_SH  = os.path.expanduser("~/quarantine_device.sh")
RESTORE_SH     = os.path.expanduser("~/restore_device.sh")
HEARTBEAT_FILE = env("HEARTBEAT_FILE", "/var/run/zt-heartbeat")
WHITELIST_FILE = os.path.expanduser("~/iot_whitelist.json")


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


def derive_lan(ip: str, quarantined: bool, stored_lan: str = "") -> str:
    if quarantined:              return "quarantine-lan"
    if stored_lan == "c-devices": return "c-devices"
    if ip.startswith(env("IOT_NET",        "192.168.20") + "."): return "iot-lan"
    if ip.startswith(env("QUARANTINE_NET", "192.168.30") + "."): return "quarantine-lan"
    if ip.startswith(env("TRUSTED_NET",    "192.168.10") + "."): return "c-devices"
    return "iot-lan"


def derive_status(info: dict) -> str:
    if info.get("quarantined"):   return "quarantined"
    if info.get("under_attack"):  return "under_attack"
    if info.get("scanning"):      return "scanning"
    return "active"


def normalize_device(name: str, info: dict) -> dict:
    ip          = info.get("last_ip", "unknown")
    quarantined = info.get("quarantined", False)
    lan = "c-devices" if name == "gateway" else derive_lan(ip, quarantined, info.get("lan", ""))
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
        "active":             info.get("active", True),
        "last_seen":          info.get("last_seen", ""),
        "date_joined":        info.get("date_joined", ""),
        "quarantine_reason":  info.get("quarantine_reason", ""),
    }


def _load_whitelist():
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _save_whitelist(rules):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def _require_admin(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if AUTH_MODE == "jwt" and auth_header.startswith("Bearer "):
        result   = _verify_jwt(auth_header[7:])
        username = result[0] if isinstance(result, tuple) else result
        role     = result[1] if isinstance(result, tuple) else "viewer"
        if username == USERNAME and role == "admin":
            return username
    raise HTTPException(status_code=403, detail="Admin role required")


def _name_to_ip(name):
    try:
        r = subprocess.run(
            ["docker", "inspect", name, "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
            capture_output=True, text=True)
        ips = [i for i in r.stdout.strip().split() if i.startswith("192.168.20")]
        return ips[0] if ips else None
    except Exception:
        return None


@app.post("/auth/login")
async def do_login(request: Request):
    return await login(request)

@app.post("/auth/logout")
async def do_logout(request: Request):
    return await logout(request)

@app.post("/auth/change-password")
async def do_change_password(request: Request):
    return await change_password(request)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    async with aiofiles.open(env("DASHBOARD_HTML", "/home/sk/dashboard.html"), "r") as f:
        return await f.read()

@app.get("/manifest.json")
async def manifest():
    return FileResponse(os.path.join(env("STATIC_DIR", "/home/sk/static_web"), "manifest.json"),
                        media_type="application/manifest+json")

@app.get("/sw.js")
async def service_worker():
    return FileResponse(os.path.join(env("STATIC_DIR", "/home/sk/static_web"), "sw.js"),
                        media_type="application/javascript")

@app.get("/api/devices")
async def get_devices(_=Depends(require_auth)):
    data    = await read_json(DEVICE_HISTORY)
    devices = [normalize_device(name, info) for name, info in data.items()]
    return {"total": len(devices), "devices": devices}

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
            "name": device["name"], "ip": device["ip"],
            "type": device["type"], "trust_score": device["trust_score"], "status": device["status"],
        })
    for lan in lans.values():
        scores = [d["trust_score"] for d in lan["devices"] if isinstance(d["trust_score"], (int, float))]
        lan["avg_trust"] = round(sum(scores) / len(scores), 1) if scores else None
    return {"lans": list(lans.values())}

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

@app.get("/api/traffic")
async def get_traffic(tail: int = 200, _=Depends(require_auth)):
    lines   = await read_log_lines(RATELIMIT_LOG, tail)
    iot_pfx = env("IOT_NET", "192.168.20") + "."
    tru_pfx = env("TRUSTED_NET", "192.168.10") + "."
    entries = []
    for line in lines:
        parts = line.split(" ", 2)
        ip    = "unknown"
        msg   = parts[2] if len(parts) >= 3 else line
        for segment in msg.split():
            if segment.startswith(iot_pfx) or segment.startswith(tru_pfx):
                ip = segment; break
        entries.append({
            "raw": line, "timestamp": f"{parts[0]} {parts[1]}" if len(parts) >= 2 else "",
            "message": msg, "ip": ip,
        })
    return {"total": len(entries), "traffic": list(reversed(entries))}

@app.post("/api/quarantine/{name}")
async def quarantine_device(name: str, _=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    if name not in data:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    ip = data[name].get("last_ip", "")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")
    try:
        result  = subprocess.run(["bash", QUARANTINE_SH, name, ip],
                                 capture_output=True, text=True, timeout=15)
        success = result.returncode == 0
        if success:
            am.send_alert(am.ALERT_QUARANTINE, {"device": name, "ip": ip,
                                                 "reason": "Manually isolated via dashboard"})
            try:
                import json as _jj
                _dh = _jj.load(open(DEVICE_HISTORY))
                if name in _dh:
                    _dh[name]["quarantine_reason"] = "Manually isolated via dashboard"
                    _jj.dump(_dh, open(DEVICE_HISTORY, "w"), indent=2)
            except Exception:
                pass
        return {"action": "quarantine", "device": name, "ip": ip, "success": success,
                "output": result.stdout.strip(), "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Script timed out")

@app.post("/api/restore/{name}")
async def restore_device(name: str, _=Depends(require_auth)):
    data = await read_json(DEVICE_HISTORY)
    if name not in data:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    ip = data[name].get("last_ip", "")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")
    try:
        result  = subprocess.run(["bash", RESTORE_SH, name, ip],
                                 capture_output=True, text=True, timeout=15)
        success = result.returncode == 0
        if success:
            am.send_alert(am.ALERT_RESTORED, {"device": name, "ip": ip})
        return {"action": "restore", "device": name, "ip": ip, "success": success,
                "output": result.stdout.strip(), "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Script timed out")

@app.get("/api/status")
async def get_status(_=Depends(require_auth)):
    data         = await read_json(DEVICE_HISTORY)
    total        = len(data)
    quarantined  = sum(1 for d in data.values() if d.get("quarantined"))
    alerts_today = 0
    try:
        lines        = await read_log_lines(ALERTS_LOG, 500)
        today        = datetime.now().strftime("%Y-%m-%d")
        alerts_today = sum(1 for l in lines if l.startswith(today))
    except Exception:
        pass
    last_cycle = None
    try:
        if os.path.exists(HEARTBEAT_FILE):
            with open(HEARTBEAT_FILE) as f:
                last_cycle = f.read().strip()
    except Exception:
        pass
    return {
        "total_devices":   total,
        "quarantined":     quarantined,
        "trusted":         total - quarantined,
        "alerts_today":    alerts_today,
        "controller_time": datetime.now().isoformat(),
        "last_cycle_at":   last_cycle,
    }

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket, token: str = ""):
    authenticated = False
    if AUTH_MODE == "jwt" and token:
        authenticated = bool(_verify_jwt(token))
    elif AUTH_MODE == "apikey" and token:
        authenticated = _safe_compare(token, API_KEY)
    else:
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
                                "type": "alert",
                                "timestamp": datetime.now().isoformat(),
                                "message": line,
                            })
            except Exception:
                pass
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass

@app.get("/api/whitelist")
async def get_whitelist(_=Depends(require_auth)):
    return {"rules": _load_whitelist()}

@app.post("/api/whitelist")
async def add_whitelist_rule(request: Request, _=Depends(require_auth)):
    _require_admin(request)
    body = await request.json()
    src  = body.get("src", "").strip()
    dst  = body.get("dst", "").strip()
    note = body.get("note", "").strip()
    if not src or not dst:
        raise HTTPException(status_code=400, detail="src and dst required")
    rules = _load_whitelist()
    if any(r["src"] == src and r["dst"] == dst for r in rules):
        raise HTTPException(status_code=409, detail="Rule already exists")
    rule = {"src": src, "dst": dst, "note": note,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    rules.append(rule)
    _save_whitelist(rules)
    src_ip, dst_ip = _name_to_ip(src), _name_to_ip(dst)
    if src_ip and dst_ip:
        subprocess.run(["iptables-nft", "-I", "FORWARD", "1",
                        "-i", "docker-iot", "-o", "docker-iot",
                        "-s", src_ip, "-d", dst_ip, "-j", "ACCEPT"],
                       capture_output=True)
    am.send_alert("WHITELIST_ADDED", {"src": src, "dst": dst, "note": note})
    return {"success": True, "rule": rule}

@app.delete("/api/whitelist")
async def delete_whitelist_rule(request: Request, _=Depends(require_auth)):
    _require_admin(request)
    body      = await request.json()
    src       = body.get("src", "").strip()
    dst       = body.get("dst", "").strip()
    rules     = _load_whitelist()
    new_rules = [r for r in rules if not (r["src"] == src and r["dst"] == dst)]
    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail="Rule not found")
    _save_whitelist(new_rules)
    si, di = _name_to_ip(src), _name_to_ip(dst)
    if si and di:
        subprocess.run(["iptables-nft", "-D", "FORWARD",
                        "-i", "docker-iot", "-o", "docker-iot",
                        "-s", si, "-d", di, "-j", "ACCEPT"],
                       capture_output=True)
    return {"success": True}
