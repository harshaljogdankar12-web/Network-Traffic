import asyncio
import json
import random
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from notifier import notify_critical, clear_buzzer

app = FastAPI(title="Network Traffic Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REGIONS: Dict[str, Dict] = {
    "US": {"name": "United States", "lat": 37.09, "lng": -95.71},
    "GB": {"name": "United Kingdom", "lat": 55.37, "lng": -3.43},
    "DE": {"name": "Germany", "lat": 51.16, "lng": 10.45},
    "FR": {"name": "France", "lat": 46.22, "lng": 2.21},
    "IN": {"name": "India", "lat": 20.59, "lng": 78.96},
    "CN": {"name": "China", "lat": 35.86, "lng": 104.19},
    "JP": {"name": "Japan", "lat": 36.20, "lng": 138.25},
    "BR": {"name": "Brazil", "lat": -14.23, "lng": -51.92},
    "AU": {"name": "Australia", "lat": -25.27, "lng": 133.77},
    "CA": {"name": "Canada", "lat": 56.13, "lng": -106.34},
    "RU": {"name": "Russia", "lat": 61.52, "lng": 105.31},
    "KR": {"name": "South Korea", "lat": 35.90, "lng": 127.76},
    "SG": {"name": "Singapore", "lat": 1.35, "lng": 103.82},
    "ZA": {"name": "South Africa", "lat": -30.55, "lng": 22.93},
    "NG": {"name": "Nigeria", "lat": 9.08, "lng": 8.67},
    "MX": {"name": "Mexico", "lat": 23.63, "lng": -102.55},
    "ID": {"name": "Indonesia", "lat": -0.78, "lng": 113.92},
    "SA": {"name": "Saudi Arabia", "lat": 23.88, "lng": 45.07},
    "TR": {"name": "Turkey", "lat": 38.96, "lng": 35.24},
    "PK": {"name": "Pakistan", "lat": 30.37, "lng": 69.34},
    "UA": {"name": "Ukraine", "lat": 48.37, "lng": 31.16},
    "NL": {"name": "Netherlands", "lat": 52.13, "lng": 5.29},
    "IT": {"name": "Italy", "lat": 41.87, "lng": 12.56},
    "ES": {"name": "Spain", "lat": 40.46, "lng": -3.74},
    "PL": {"name": "Poland", "lat": 51.91, "lng": 19.14},
}

TRAFFIC_WEIGHTS = {
    "US": 25, "GB": 12, "DE": 8, "IN": 10, "CN": 8,
    "BR": 5, "CA": 5, "AU": 4, "FR": 5, "JP": 7,
    "RU": 3, "KR": 4, "SG": 2, "ZA": 1, "NG": 1,
    "MX": 2, "ID": 2, "SA": 1, "TR": 2, "PK": 1,
    "UA": 1, "NL": 2, "IT": 2, "ES": 2, "PL": 1,
}


class AppState:
    def __init__(self):
        self.total_requests = 0
        self.requests_this_second = 0
        self.active_sessions = random.randint(80, 200)
        self.response_time_ms = 45
        self.blocked_regions: Set[str] = set()
        self.region_traffic: Dict = {
            code: {
                "name": info["name"],
                "lat": info["lat"],
                "lng": info["lng"],
                "count": 0,
                "blocked": False,
                "status": "safe",
            }
            for code, info in REGIONS.items()
        }
        self.audit_logs: List[Dict] = []
        self.alerts: List[Dict] = []
        self.simulation_active = False
        self.simulation_users = 0
        self.simulation_mode = "flood"
        self.simulation_region: Optional[str] = None
        self.rps_history: List[int] = [0] * 60
        self.threat_level = "safe"
        self.websocket_clients: List[WebSocket] = []
        self.sim_requests_sent = 0
        self.allowed_regions: Set[str] = set()  # allow list â€” always overrides block list

    def add_audit_log(self, event_type: str, details: str, actor: str = "system"):
        log = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "event_type": event_type,
            "details": details,
            "actor": actor,
        }
        self.audit_logs.insert(0, log)
        if len(self.audit_logs) > 150:
            self.audit_logs.pop()

    def add_alert(self, alert_type: str, message: str, severity: str = "warn") -> Dict:
        for a in self.alerts:
            if a["type"] == alert_type and not a.get("resolved", False):
                return a
        alert = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": alert_type,
            "message": message,
            "severity": severity,
            "resolved": False,
        }
        self.alerts.insert(0, alert)
        if len(self.alerts) > 50:
            self.alerts.pop()
        return alert


state = AppState()


class BlockRequest(BaseModel):
    actor: str = "admin"


class SimulationConfig(BaseModel):
    users: int = 10
    mode: str = "flood"
    region: Optional[str] = None


def weighted_region() -> str:
    regions = list(TRAFFIC_WEIGHTS.keys())
    weights = list(TRAFFIC_WEIGHTS.values())
    return random.choices(regions, weights=weights, k=1)[0]


def detect_anomalies():
    total = sum(r["count"] for r in state.region_traffic.values())

    for code, region in state.region_traffic.items():
        if code in state.blocked_regions and code not in state.allowed_regions:
            region["status"] = "blocked"
            continue
        pct = region["count"] / total if total else 0
        if pct > 0.40:
            region["status"] = "critical"
            state.add_alert(
                f"spike_{code}",
                f"Spike: {region['name']} â†’ {region['count']} req ({round(pct*100)}% of total)",
                "critical",
            )
            if not any(
                l["event_type"] == "SPIKE_DETECTED" and region["name"] in l["details"]
                for l in state.audit_logs[:5]
            ):
                state.add_audit_log("SPIKE_DETECTED", f"Region spike: {region['name']}", "system")
        elif pct > 0.25:
            region["status"] = "warn"
        else:
            region["status"] = "safe"

    rps = state.requests_this_second
    if rps > 80:
        state.threat_level = "critical"
        state.add_alert("burst", f"Request burst: {rps} req/s (critical threshold exceeded)", "critical")
        if not any(l["event_type"] == "BURST_DETECTED" for l in state.audit_logs[:3]):
            state.add_audit_log("BURST_DETECTED", f"Request burst: {rps} req/s", "system")
    elif rps > 40:
        state.threat_level = "warn"
        for a in state.alerts:
            if a["type"] == "burst" and not a.get("resolved"):
                a["resolved"] = True
    else:
        state.threat_level = "safe"
        for a in state.alerts:
            if a["type"] == "burst" and not a.get("resolved"):
                a["resolved"] = True

    if state.simulation_users > 50:
        state.add_alert(
            "sim_overload",
            f"Simulation overload: {state.simulation_users} dummy users active",
            "critical",
        )
        if not any(l["event_type"] == "SIM_OVERLOAD" for l in state.audit_logs[:3]):
            state.add_audit_log("SIM_OVERLOAD", f"Too many simulation users: {state.simulation_users}", "system")


async def broadcast(data: dict):
    if not state.websocket_clients:
        return
    message = json.dumps(data)
    dead: List[WebSocket] = []
    for ws in state.websocket_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in state.websocket_clients:
            state.websocket_clients.remove(ws)


async def traffic_generator():
    while True:
        await asyncio.sleep(1)

        normal_req = random.randint(5, 20)
        sim_req = 0

        if state.simulation_active and state.simulation_users > 0:
            multi = {"flood": random.randint(3, 8), "spike": random.randint(12, 25), "gradual": 3}.get(
                state.simulation_mode, 5
            )
            sim_req = state.simulation_users * multi
            state.sim_requests_sent += sim_req

        state.requests_this_second = normal_req + sim_req
        state.total_requests += state.requests_this_second
        state.active_sessions = max(10, state.active_sessions + random.randint(-3, 6))

        if state.requests_this_second > 60:
            state.response_time_ms = random.randint(250, 900)
        elif state.requests_this_second > 30:
            state.response_time_ms = random.randint(80, 250)
        else:
            state.response_time_ms = random.randint(18, 70)

        for _ in range(normal_req):
            r = weighted_region()
            state.region_traffic[r]["count"] += 1

        if state.simulation_active and sim_req > 0:
            if state.simulation_mode == "spike" and state.simulation_region:
                state.region_traffic[state.simulation_region]["count"] += sim_req
            else:
                for _ in range(sim_req):
                    r = weighted_region()
                    state.region_traffic[r]["count"] += 1

        for r in state.region_traffic.values():
            r["count"] = max(0, int(r["count"] * 0.92))

        state.rps_history.pop(0)
        state.rps_history.append(state.requests_this_second)

        detect_anomalies()

        # â”€â”€ Critical notifications (Telegram + Firebase) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        rps  = state.requests_this_second
        sims = state.simulation_users

        if state.simulation_active and sims > 50:
            # Simulation overload â†’ notify immediately (cooldown prevents spam)
            asyncio.create_task(notify_critical(
                "SIM_OVERLOAD",
                f"{sims} dummy users active â€” simulation overload detected",
                rps=rps, sim_users=sims,
            ))
        elif not state.simulation_active or sims <= 50:
            # External alerts stay quiet unless simulation users are above 50.
            asyncio.create_task(clear_buzzer())
        # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        uptime = 99.8 if state.threat_level != "critical" else round(random.uniform(97.2, 99.0), 2)

        payload = {
            "type": "traffic_update",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "stats": {
                "total_requests": state.total_requests,
                "rps": state.requests_this_second,
                "active_sessions": state.active_sessions,
                "uptime": uptime,
                "response_time_ms": state.response_time_ms,
                "threat_level": state.threat_level,
            },
            "regions": {
                code: {
                    **region,
                    "blocked": code in state.blocked_regions and code not in state.allowed_regions,
                    "allowed": code in state.allowed_regions,
                }
                for code, region in state.region_traffic.items()
            },
            "rps_history": state.rps_history,
            "alerts": [a for a in state.alerts if not a.get("resolved")][:10],
            "audit_logs": state.audit_logs[:25],
            "blocked_regions": [c for c in state.blocked_regions if c not in state.allowed_regions],
            "allowed_regions": list(state.allowed_regions),
            "simulation": {
                "active": state.simulation_active,
                "users": state.simulation_users,
                "mode": state.simulation_mode,
                "requests_sent": state.sim_requests_sent,
                "region": state.simulation_region,
            },
        }
        await broadcast(payload)


@app.on_event("startup")
async def startup():
    asyncio.create_task(traffic_generator())


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.websocket_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.websocket_clients:
            state.websocket_clients.remove(websocket)


@app.post("/api/block/{code}")
async def block_region(code: str, req: BlockRequest):
    if code not in REGIONS:
        raise HTTPException(404, "Region not found")
    state.blocked_regions.add(code)
    state.region_traffic[code]["blocked"] = True
    state.region_traffic[code]["status"] = "blocked"
    state.add_audit_log("REGION_BLOCKED", f"{REGIONS[code]['name']} ({code}) blocked", req.actor)
    for a in state.alerts:
        if f"spike_{code}" in a["type"]:
            a["resolved"] = True
    return {"status": "blocked", "region": code}


@app.delete("/api/block/{code}")
async def unblock_region(code: str, actor: str = "admin"):
    if code not in REGIONS:
        raise HTTPException(404, "Region not found")
    state.blocked_regions.discard(code)
    state.region_traffic[code]["blocked"] = False
    state.region_traffic[code]["status"] = "safe"
    state.add_audit_log("REGION_UNBLOCKED", f"{REGIONS[code]['name']} ({code}) unblocked", actor)
    return {"status": "unblocked", "region": code}


@app.get("/api/blocked")
async def get_blocked():
    return {"blocked": list(state.blocked_regions)}


@app.post("/api/simulate/start")
async def start_simulation(config: SimulationConfig):
    if config.mode not in ["flood", "spike", "gradual"]:
        raise HTTPException(400, "Invalid mode. Use: flood, spike, gradual")
    if config.mode == "spike" and config.region and config.region not in REGIONS:
        raise HTTPException(404, "Region not found")
    state.simulation_active = True
    state.simulation_users = max(1, min(config.users, 500))
    state.simulation_mode = config.mode
    state.simulation_region = config.region
    state.sim_requests_sent = 0
    state.add_audit_log(
        "SIMULATION_STARTED",
        f"{state.simulation_users} dummy users | mode={config.mode} | target={config.region or 'random'}",
        "demo_user",
    )
    return {"status": "started", "users": state.simulation_users, "mode": config.mode}


@app.post("/api/simulate/stop")
async def stop_simulation():
    prev = state.simulation_users
    state.simulation_active = False
    state.simulation_users = 0
    state.simulation_region = None
    for a in state.alerts:
        if a["type"] in ["sim_overload", "burst"]:
            a["resolved"] = True
    state.add_audit_log("SIMULATION_STOPPED", f"Simulation ({prev} users) stopped", "demo_user")
    return {"status": "stopped"}


@app.post("/api/allow/{code}")
async def allow_region(code: str, req: BlockRequest):
    if code not in REGIONS:
        raise HTTPException(404, "Region not found")
    state.allowed_regions.add(code)
    state.add_audit_log("REGION_ALLOWED", f"{REGIONS[code]['name']} ({code}) added to allow list (overrides block)", req.actor)
    return {"status": "allowlisted", "region": code}


@app.delete("/api/allow/{code}")
async def remove_allow(code: str, actor: str = "admin"):
    if code not in REGIONS:
        raise HTTPException(404, "Region not found")
    state.allowed_regions.discard(code)
    state.add_audit_log("REGION_ALLOW_REMOVED", f"{REGIONS[code]['name']} ({code}) removed from allow list", actor)
    return {"status": "allow_removed", "region": code}


@app.get("/api/access/{code}")
async def check_access(code: str):
    if code not in REGIONS:
        raise HTTPException(404, "Region not found")
    # Allow list always takes priority over block list
    if code in state.allowed_regions:
        return {
            "access": "allowed",
            "region": code,
            "region_name": REGIONS[code]["name"],
            "message": "Access granted (allow list override)",
            "allowlisted": True,
        }
    blocked = code in state.blocked_regions
    return {
        "access": "blocked" if blocked else "allowed",
        "region": code,
        "region_name": REGIONS[code]["name"],
        "message": "Access blocked by security policy" if blocked else "Access granted",
        "allowlisted": False,
    }


@app.post("/api/alert/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    for a in state.alerts:
        if a["id"] == alert_id:
            a["resolved"] = True
            state.add_audit_log("ALERT_RESOLVED", f"Alert {alert_id} manually resolved", "admin")
            return {"status": "resolved"}
    raise HTTPException(404, "Alert not found")


@app.get("/api/regions")
async def get_regions():
    return {"regions": REGIONS}


@app.get("/api/stats")
async def get_stats():
    return {
        "total_requests": state.total_requests,
        "rps": state.requests_this_second,
        "active_sessions": state.active_sessions,
        "response_time_ms": state.response_time_ms,
        "threat_level": state.threat_level,
        "blocked_regions": list(state.blocked_regions),
    }


# Serve built React app
app.mount("/", StaticFiles(directory="../dist", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
