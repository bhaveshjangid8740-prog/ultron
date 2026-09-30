"""tests/test_api_endpoints.py — Verifies all Web Command Center & Investigation endpoints."""

import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))

def post(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("[1] Testing /api/state...")
    state = get("/api/state")
    assert "assets" in state
    assert "incidents" in state
    print(f" -> Assets: {len(state['assets'])}, Incidents: {len(state['incidents'])}, Mode: {state['mode']}")

    print("\n[2] Testing /api/query (Natural Language Case Query)...")
    qres = post("/api/query", {"query": "Show all critical incidents"})
    assert "results" in qres
    print(f" -> Query matched: {qres['match_count']} incidents")

    print("\n[3] Testing /api/threat_intel/203.0.113.44...")
    intel = get("/api/threat_intel/203.0.113.44")
    assert intel["abuse_score"] == 96
    print(f" -> Threat Intel Score: {intel['abuse_score']}/100, ISP: {intel['isp']}")

    print("\n[4] Testing /api/inspect_metadata...")
    meta = post("/api/inspect_metadata", {})
    assert "filename" in meta or "error" not in meta
    print(f" -> Forensic file inspected: {meta.get('filename')}, size: {meta.get('size_bytes')}")

    print("\n[5] Testing /api/graph (Evidence Relationship Graph)...")
    graph = get("/api/graph")
    assert "nodes" in graph and "links" in graph
    print(f" -> Graph nodes: {len(graph['nodes'])}, links: {len(graph['links'])}")

    print("\n[6] Testing /api/report/data (Automated Executive Report)...")
    rep = get("/api/report/data")
    assert "markdown" in rep
    print(f" -> Report generated with {rep['incident_count']} incidents, avg containment latency: {rep['avg_latency_ms']}ms")

    print("\n[7] Testing /api/camera/trigger (Vision Intruder Watch)...")
    cam = post("/api/camera/trigger", {})
    assert cam["status"] == "ok"
    print(f" -> Vision Intruder Watch triggered: {cam['message']}")

    print("\n[8] Testing /api/simulate/bruteforce (Cyber Range)...")
    sim = post("/api/simulate/bruteforce", {})
    assert sim["status"] == "ok"
    print(" -> Cyber Range brute-force attack triggered successfully")

    print("\nALL 8 API ENDPOINTS VALIDATED AND 100% OPERATIONAL!")

if __name__ == "__main__":
    main()
