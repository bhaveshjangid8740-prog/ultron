"""web_app.py — Live Cyberpunk Web Command Center for Project Ultron.

Serves an ultra-modern, futuristic browser-based SOC dashboard with:
- Live animated radar canvas with 360-degree sweep
- Computer Vision Intruder Watch (CCTV feed & trigger)
- Server-Sent Events (SSE) streaming real-time AI reasoning verdicts
- Active Cyber Range simulator with one-click attack triggers
- Sub-500ms defense latency gauge & interactive human-approval shield buttons
- Natural Language Case Investigation Querying
- Evidence Relationship Graph (interactive node-link topology)
- Automated Executive Incident Reporting (Markdown/PDF export)
- Live Threat Intel (AbuseIPDB/VirusTotal) & Forensic Metadata Inspector
"""

import sys
from unittest.mock import MagicMock
dummy_ssl = MagicMock()
dummy_ssl.PROTOCOL_TLS_SERVER = 2
dummy_ssl.CERT_NONE = 0
dummy_ssl.OPENSSL_VERSION_INFO = (3, 0, 0)
dummy_ssl.OPENSSL_VERSION = "OpenSSL 3.0.0"
sys.modules['ssl'] = dummy_ssl
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List

import importlib
_venv_site = Path(__file__).resolve().parent / ".venv" / "Lib" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

_fastapi = importlib.import_module("fastapi")
FastAPI = _fastapi.FastAPI
Request = _fastapi.Request

_responses = importlib.import_module("fastapi.responses")
HTMLResponse = _responses.HTMLResponse
JSONResponse = _responses.JSONResponse
StreamingResponse = _responses.StreamingResponse

_staticfiles = importlib.import_module("fastapi.staticfiles")
StaticFiles = _staticfiles.StaticFiles

import config
from core.brain import UltronBrain
from database.manager import DatabaseManager
from range_simulator.sim_bruteforce import run_bruteforce_simulation
from range_simulator.sim_canary_burst import run_canary_burst_simulation
from range_simulator.sim_synscan import run_portscan_simulation
from investigation.case_query import CaseQueryEngine
from investigation.metadata_inspector import MetadataInspector
from investigation.report_generator import ExecutiveReportGenerator
from investigation.threat_intel import ThreatIntelEngine
from sensors.arp_scanner import ArpRadarScanner
from sensors.auth_log_monitor import SocketAuthTelemetryMonitor
from sensors.canary_monitor import CanaryMonitor
from sensors.honeypot_listener import HoneypotListener
from sensors.vision_intruder import VisionIntruderWatch
from sensors.god_eye_tracker import GodEyeTracker
from shared.event_bus import drain_ui_bus, emit_ui_event
from shared.logger import get_logger, setup_logging
from shields.quarantine import get_active_shield

setup_logging()
logger = get_logger("web_app")

app = FastAPI(title="Project Ultron & God's Eye — Live Web Command Center")

# Mount static folder
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Shared Subsystems
db = DatabaseManager(config.DB_PATH)
shield = get_active_shield()
brain = UltronBrain(db=db, shield=shield)
honeypot = HoneypotListener(db=db, host=config.HONEYPOT_HOST, port=config.HONEYPOT_PORT)
canary = CanaryMonitor(db=db)
arp_scanner = ArpRadarScanner(db=db, interval=config.ARP_SCAN_INTERVAL)
vision_watch = VisionIntruderWatch(db=db)
socket_monitor = SocketAuthTelemetryMonitor(db=db)

# Investigation & Chat Engines
threat_intel = ThreatIntelEngine()
metadata_inspector = MetadataInspector()
case_query_engine = CaseQueryEngine(db=db)
report_generator = ExecutiveReportGenerator(db=db)
god_eye_tracker = GodEyeTracker()
from core.copilot_chat import UltronCopilotChat
copilot_chat = UltronCopilotChat(db=db)

# SSE subscribers
subscribers: list[asyncio.Queue] = []


def sse_event_dispatcher():
    """Background thread that drains ui_bus and forwards events to connected web clients."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        events = drain_ui_bus()
        for event in events:
            for q in list(subscribers):
                try:
                    q.put_nowait(event)
                except Exception:
                    pass
        time.sleep(0.05)


@app.on_event("startup")
def startup_event():
    logger.info("Initializing Ultron subsystems for Web Command Center...")
    db.init_db(config.SCHEMA_PATH)
    db.start()
    brain.start()
    honeypot.start()
    canary.start()
    arp_scanner.start()
    vision_watch.start()
    socket_monitor.start()

    # Start SSE dispatcher thread
    t = threading.Thread(target=sse_event_dispatcher, daemon=True)
    t.start()

    # Automatically open in browser
    def open_browser():
        time.sleep(1.0)
        webbrowser.open("http://127.0.0.1:8000")

    threading.Thread(target=open_browser, daemon=True).start()
    logger.info("Web Command Center running at: http://127.0.0.1:8000")


@app.on_event("shutdown")
def shutdown_event():
    socket_monitor.stop()
    vision_watch.stop()
    arp_scanner.stop()
    canary.stop()
    honeypot.stop()
    brain.stop()
    db.stop()


@app.get("/", response_class=HTMLResponse)
def get_index():
    index_file = STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

@app.get("/index.html", response_class=HTMLResponse)
def get_index_page():
    return HTMLResponse(content=(STATIC_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/threat_map.html", response_class=HTMLResponse)
def get_threat_map():
    return HTMLResponse(content=(STATIC_DIR / "threat_map.html").read_text(encoding="utf-8"))

@app.get("/sensors.html", response_class=HTMLResponse)
def get_sensors():
    return HTMLResponse(content=(STATIC_DIR / "sensors.html").read_text(encoding="utf-8"))

@app.get("/reasoning.html", response_class=HTMLResponse)
def get_reasoning():
    return HTMLResponse(content=(STATIC_DIR / "reasoning.html").read_text(encoding="utf-8"))

@app.get("/response.html", response_class=HTMLResponse)
def get_response():
    return HTMLResponse(content=(STATIC_DIR / "response.html").read_text(encoding="utf-8"))

@app.get("/ultron.html", response_class=HTMLResponse)
def get_ultron():
    return HTMLResponse(content=(STATIC_DIR / "ultron.html").read_text(encoding="utf-8"))


@app.get("/api/stream")
async def event_stream(request: Request):
    """Server-Sent Events endpoint streaming live telemetry and AI verdicts to browser."""
    q: asyncio.Queue = asyncio.Queue()
    subscribers.append(q)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat ping
                    yield 'data: {"type": "ping"}\n\n'
        finally:
            if q in subscribers:
                subscribers.remove(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/state")
def get_state():
    """Initial snapshot for newly loaded browser clients."""
    return {
        "assets": db.get_all_assets(),
        "incidents": db.get_recent_incidents(limit=25),
        "shields": db.get_shield_actions(limit=25),
        "mode": brain.get_response_mode(),
        "honeypot_port": honeypot._port,
        "canary_count": len(config.CANARY_FILES),
        "vision_active": vision_watch._is_active,
    }


@app.post("/api/simulate/{scenario}")
def trigger_simulation(scenario: str):
    """Cyber Range simulation trigger endpoint."""
    logger.info("Triggered simulation scenario: %s", scenario)
    range_dir = Path(__file__).resolve().parent / "range_simulator"

    if scenario == "bruteforce":
        proc = subprocess.Popen(
            [sys.executable, str(range_dir / "sim_bruteforce.py")],
            cwd=str(Path(__file__).resolve().parent),
        )
        logger.info("Spawned safe brute-force attacker process with PID: %d", proc.pid)
    elif scenario == "portscan":
        proc = subprocess.Popen(
            [sys.executable, str(range_dir / "sim_synscan.py")],
            cwd=str(Path(__file__).resolve().parent),
        )
        logger.info("Spawned port-scan attacker process with PID: %d", proc.pid)
    elif scenario == "canary":
        proc = subprocess.Popen(
            [sys.executable, str(range_dir / "sim_canary_burst.py")],
            cwd=str(Path(__file__).resolve().parent),
        )
        logger.info("Spawned Canary Vault Tamper Attacker Process with PID: %d", proc.pid)
    else:
        return JSONResponse({"status": "error", "message": "Unknown scenario"}, status_code=400)

    return {"status": "ok", "scenario": scenario, "pid": proc.pid}


@app.post("/api/mode")
def set_response_mode(payload: dict):
    mode = payload.get("mode", "AUTONOMOUS").upper()
    brain.set_response_mode(mode)
    return {"status": "ok", "mode": mode}


@app.post("/api/approve_shield")
def approve_shield(payload: dict):
    incident_id = payload.get("incident_id")
    shield_type = payload.get("shield_type")
    target = payload.get("target")
    action_id = payload.get("action_id")

    if not all([incident_id, shield_type, target]):
        return JSONResponse({"status": "error", "message": "Missing required fields"}, status_code=400)

    brain.execute_containment(incident_id=incident_id, action_type=shield_type, target=target)
    return {"status": "ok", "action_id": action_id}


# --- Investigation & Threat Intelligence Layer Endpoints ---

@app.post("/api/chat")
def chat_with_copilot(payload: dict):
    """Interactive conversational AI SOC Copilot."""
    message = payload.get("message", "")
    if not message.strip():
        return JSONResponse({"status": "error", "message": "Message cannot be empty"}, status_code=400)
    return copilot_chat.chat(message)


@app.post("/api/query")
def query_cases(payload: dict):
    """Natural Language Case Querying."""
    query_str = payload.get("query", "")
    if not query_str.strip():
        return JSONResponse({"status": "error", "message": "Query cannot be empty"}, status_code=400)
    result = case_query_engine.query(query_str)
    return result


@app.get("/api/threat_intel/{ip}")
def lookup_threat_intel(ip: str):
    """Live Threat Intelligence Lookup for an IP address."""
    return threat_intel.lookup_ip(ip)


@app.post("/api/inspect_metadata")
async def inspect_metadata_endpoint(request: Request):
    """Extracts EXIF and file metadata for forensics."""
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        file_obj = form.get("file")
        if file_obj:
            import tempfile
            suffix = Path(file_obj.filename).suffix
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                contents = await file_obj.read()
                tmp.write(contents)
                tmp_path = tmp.name
            try:
                res = metadata_inspector.inspect_file(tmp_path)
                res["filename"] = file_obj.filename
                return res
            finally:
                try:
                    Path(tmp_path).unlink()
                except Exception:
                    pass

    try:
        body = await request.json()
        path = body.get("path")
        if path and Path(path).exists():
            return metadata_inspector.inspect_file(path)
    except Exception:
        pass

    # Fallback to inspecting canary file
    sample_path = config.CANARY_FILES[0] if config.CANARY_FILES else (config.CANARY_DIR / "passwords.kdbx")
    if sample_path.exists():
        return metadata_inspector.inspect_file(str(sample_path))
    return {"error": "No file supplied and no default artifact found"}


@app.get("/api/report/markdown")
def download_markdown_report():
    """Generates and downloads the executive security incident report in Markdown format."""
    rep = report_generator.generate_report()
    return StreamingResponse(
        iter([rep["markdown"]]),
        media_type="text/markdown",
        headers={
            "Content-Disposition": "attachment; filename=Ultron_Executive_Incident_Report.md"
        },
    )


@app.get("/api/report/html")
def download_html_report():
    """Generates and downloads the executive security incident forensic dossier in HTML format."""
    rep = report_generator.generate_report()
    return StreamingResponse(
        iter([rep["html"]]),
        media_type="text/html",
        headers={
            "Content-Disposition": "attachment; filename=Ultron_Forensic_Dossier.html"
        },
    )


@app.get("/api/report/siem")
def download_siem_report():
    """Generates and downloads normalized SIEM integration events in JSON format."""
    rep = report_generator.generate_report()
    return StreamingResponse(
        iter([rep["siem_json"]]),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=Ultron_SIEM_Events.json"
        },
    )


@app.get("/api/report/stix")
def download_stix_report():
    """Generates and downloads STIX 2.1 Cyber Threat Intelligence bundle in JSON format."""
    rep = report_generator.generate_report()
    return StreamingResponse(
        iter([rep["stix_json"]]),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=Ultron_STIX21_Threat_Bundle.json"
        },
    )


@app.get("/api/god_eye/recon")
def get_god_eye_recon_data():
    """Returns Fast & Furious God's Eye omniscient digital surveillance telemetry."""
    assets = db.get_all_assets()
    incidents = db.get_recent_incidents(limit=10)
    shields = db.get_shield_actions(limit=10)

    # Local & Global Surveillance Nodes
    nodes = []
    
    # Local Subnet Nodes
    for idx, a in enumerate(assets):
        lat = 34.0522 + (idx * 0.04) - 0.08
        lon = -118.2437 + (idx * 0.05) - 0.08
        nodes.append({
            "id": f"node_local_{idx}",
            "label": f"TARGET: {a['ip_address']}",
            "ip": a["ip_address"],
            "mac": a["mac_address"],
            "vendor": a.get("device_vendor", "Generic Network Interface"),
            "status": "AUTHORIZED" if a["is_authorized"] else "ROGUE_ANOMALY",
            "type": "SUBNET_ENDPOINT",
            "threat_level": "LOW" if a["is_authorized"] else "CRITICAL",
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "cctv_linked": True,
            "signal_dbm": -42 - (idx * 6),
            "satellite_lock": "SAT-RAMSEY-07",
        })

    # Global Triangulation Hubs (Abu Dhabi, London, Tokyo, Berlin, Los Angeles)
    global_hotspots = [
        {"city": "Abu Dhabi (Etihad Towers)", "lat": 24.4539, "lon": 54.3773, "ip": "185.122.91.4", "status": "GOD_EYE_PRIMARY_GRID", "type": "GLOBAL_HUB"},
        {"city": "Los Angeles (SOC Hub)", "lat": 34.0522, "lon": -118.2437, "ip": "192.168.1.1", "status": "COMMAND_STATION", "type": "STATION"},
        {"city": "London (GCHQ Relay)", "lat": 51.5074, "lon": -0.1278, "ip": "194.73.112.55", "status": "RELAY_SYNC", "type": "GLOBAL_HUB"},
        {"city": "Tokyo (Shibuya Core)", "lat": 35.6762, "lon": 139.6503, "ip": "210.140.10.82", "status": "OPTICAL_FEED", "type": "GLOBAL_HUB"},
        {"city": "Berlin (BSI Node)", "lat": 52.5200, "lon": 13.4050, "ip": "141.76.1.1", "status": "DEFENSE_GRID", "type": "GLOBAL_HUB"},
    ]

    for g in global_hotspots:
        nodes.append({
            "id": f"hub_{g['city'][:4]}",
            "label": g["city"],
            "ip": g["ip"],
            "mac": "FF:AA:00:11:22:33",
            "vendor": "Omniscient God's Eye Uplink",
            "status": g["status"],
            "type": g["type"],
            "threat_level": "NOMINAL",
            "lat": g["lat"],
            "lon": g["lon"],
            "cctv_linked": True,
            "signal_dbm": -30,
            "satellite_lock": "ORBITAL_RECON_ALPHA",
        })

    # Incident Attackers
    for inc in incidents:
        ip = inc.get("suspicious_ip")
        if ip:
            nodes.append({
                "id": f"threat_{inc['id']}",
                "label": f"ADVERSARY: {ip}",
                "ip": ip,
                "mac": "UNKNOWN_ATTACKER_MAC",
                "vendor": "Malicious Probe Vector",
                "status": "CONTAINED" if inc.get("status") == "CONTAINED" else "ENGAGED",
                "type": "ADVERSARY_TARGET",
                "threat_level": inc.get("severity", "CRITICAL"),
                "mitre": inc.get("mitre_id"),
                "lat": 34.0622 + (inc['id'] * 0.02),
                "lon": -118.2337 - (inc['id'] * 0.03),
                "cctv_linked": True,
                "signal_dbm": -88,
                "satellite_lock": "LOCKED // VECTOR_TRACED",
            })

    return {
        "system": "GOD'S EYE // OMNISCIENT DIGITAL SURVEILLANCE & RECONNAISSANCE GRID",
        "protocol": "FAST_AND_FURIOUS_RAMSEY_GRID_V7",
        "satellite": "RAMSEY-SAT-07 [ACTIVE ORBIT]",
        "total_tracked_nodes": len(nodes),
        "optical_cameras_online": 12,
        "nodes": nodes,
        "google_maps_api_key": config.GOOGLE_MAPS_API_KEY,
    }


@app.get("/api/geolocate")
def geolocate_ip(ip: str):
    """Geolocates a target IP address using the God Eye Tracker."""
    return god_eye_tracker.geolocate(ip)


@app.post("/api/config/google_maps")
async def set_google_maps_key(request: Request):
    """Sets the Google Maps API Key at runtime and persists it to .env."""
    data = await request.json()
    key = data.get("api_key", "").strip()
    config.GOOGLE_MAPS_API_KEY = key
    os.environ["GOOGLE_MAPS_API_KEY"] = key
    env_path = config.BASE_DIR / ".env"
    try:
        lines = []
        if env_path.exists():
            lines = env_path.read_text(encoding="utf-8").splitlines()
        found = False
        new_lines = []
        for line in lines:
            if line.startswith("GOOGLE_MAPS_API_KEY="):
                new_lines.append(f"GOOGLE_MAPS_API_KEY={key}")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"GOOGLE_MAPS_API_KEY={key}")
        env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as ex:
        logger.warning("Could not persist GOOGLE_MAPS_API_KEY to .env: %s", ex)
    return {"status": "ok", "api_key_set": bool(key)}


@app.get("/api/report/data")
def get_report_data():
    """Returns structured report data for on-screen executive summary."""
    return report_generator.generate_report()


@app.get("/api/graph")
def get_evidence_relationship_graph():
    """Generates node-link data for the Evidence Relationship Graph."""
    incidents = db.get_recent_incidents(limit=20)
    shields = db.get_shield_actions(limit=20)
    assets = db.get_all_assets()

    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(nid: str, label: str, ntype: str, color: str, size: int = 15):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({"id": nid, "label": label, "type": ntype, "color": color, "size": size})

    # Central SOC Hub
    add_node("hub", "ULTRON CORE", "hub", "#00e5ff", 22)

    for a in assets:
        aid = f"asset_{a['ip_address']}"
        add_node(aid, f"Asset {a['ip_address']}", "asset", "#00e676" if a["is_authorized"] else "#ff3366", 14)
        links.append({"source": "hub", "target": aid, "relation": "MONITORS"})

    for inc in incidents:
        iid = f"inc_{inc['id']}"
        add_node(iid, f"{inc['mitre_id'] or 'INC'} ({inc['severity']})", "incident", "#ffd600" if inc['severity'] in ('MEDIUM', 'LOW') else "#ff3366", 16)
        links.append({"source": "hub", "target": iid, "relation": "CLASSIFIED"})

    for s in shields:
        sid = f"shield_{s['id']}"
        add_node(sid, f"{s['shield_type']}", "shield", "#7c4dff", 14)
        links.append({"source": f"inc_{s['incident_id']}", "target": sid, "relation": "NEUTRALIZED"})
        tid = f"asset_{s['target_identifier']}"
        if tid in node_ids:
            links.append({"source": sid, "target": tid, "relation": "BLOCKED"})

    return {"nodes": nodes, "links": links}


@app.post("/api/camera/trigger")
def trigger_camera_intruder():
    """Triggers a simulated physical intruder detection via Computer Vision Intruder Watch."""
    vision_watch.trigger_test_intruder()
    return {"status": "ok", "message": "Computer Vision Intruder Alert dispatched to Ultron Brain"}


@app.post("/api/chat")
async def chat_with_copilot(request: Request):
    """Processes interactive analyst inquiries via Ultron Copilot Chat Engine."""
    data = await request.json()
    msg = data.get("message", "").strip()
    history = data.get("history", [])
    if not msg:
        return JSONResponse({"reply": "Command Center received empty transmission. State your query, Analyst.", "source": "ULTRON_CORE"})
    result = copilot_chat.chat(user_message=msg, history=history)
    return JSONResponse(result)


if __name__ == "__main__":
    _uvicorn = importlib.import_module("uvicorn")
    _uvicorn.run("web_app:app", host="127.0.0.1", port=8000, reload=False)
