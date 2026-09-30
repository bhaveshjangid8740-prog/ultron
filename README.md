# Project Ultron & God's Eye — Autonomous SOC Agent

An offline-first, autonomous local Security Operations Center (SOC) agent fusing real-time telemetry ingestion (**God Eye**), AI reasoning powered by Google Gemini / Antigravity (**Ultron Core**), sub-second containment (**Autonomous Shields**), and a dark cyberpunk Command Center with an integrated **Cyber Range** simulator.

---

## Architecture Overview

```
                                ┌───────────────────────────────────────┐
                                │       COMMAND CENTER UI (ui/)         │
                                │   Radar · Terminal Feed · Shields     │
                                └───────────▲───────────────▲───────────┘
                                            │ ui_bus        │ triggers
                                ┌───────────┴────────┐  ┌───┴──────────┐
                                │ ULTRON CORE (core/)│  │ SHIELDS      │
                                │   AI Agent Loop    │  │ (shields/)   │
                                │   MITRE Tagging    │  │ Firewall/Kill│
                                └───────────▲────────┘  └───▲──────────┘
                                            │ sensor_queue  │ records
                                ┌───────────┴───────────────┴──────────┐
                                │           GOD EYE (sensors/)         │
                                │   ARP Radar · Canary · Honeypot      │
                                └───────────────────┬──────────────────┘
                                                    │
                                            ┌───────┴────────┐
                                            │  SQLite (WAL)  │
                                            └────────────────┘
```

---

## Directory Structure

```
ultron/
├── main.py                         # Application bootstrapper and UI launcher
├── config.py                       # Centralized settings, ports, and thresholds
├── requirements.txt                # Production dependencies
├── .gitignore                      # Git ignore rules
│
├── shared/                         # Thread-safe primitives
│   ├── event_bus.py                # Bounded sensor_queue & non-blocking ui_bus
│   └── logger.py                   # Structured per-subsystem logging
│
├── database/                       # Storage layer (WAL SQLite + Dedicated Writer)
│   ├── schema.sql                  # DDL schema with check constraints & indexes
│   ├── manager.py                  # Thread-safe DatabaseManager
│   └── models.py                   # Typed dataclasses
│
├── sensors/                        # Sensory Ingestion (God Eye)
│   ├── arp_scanner.py              # Subnet sweep with rogue MAC alerts
│   ├── canary_monitor.py           # Watchdog file tampering detector
│   └── honeypot_listener.py        # Raw socket deception listener (FTP:21)
│
├── core/                           # Cognition & Reasoning (Ultron Core)
│   ├── agent_client.py             # Gemini API client + offline deterministic engine
│   ├── mitre_lookup.py             # MITRE ATT&CK taxonomy mapper
│   ├── risk_scoring.py             # 0-100 heuristic scoring and severity band
│   ├── correlator.py               # Rolling-window event correlation
│   ├── schemas.py                  # Pydantic validation contracts
│   └── brain.py                    # Consumer event loop & shield dispatcher
│
├── shields/                        # Active Containment (Autonomous Shields)
│   ├── base.py                     # Strategy pattern protocol & ShieldResult
│   ├── windows_shield.py           # Windows netsh firewall & taskkill/psutil
│   ├── linux_shield.py             # Linux iptables & SIGKILL
│   ├── privilege_check.py          # Admin / root elevation verification
│   └── quarantine.py               # Factory and host isolation
│
├── range_simulator/                # Cyber Range (Loopback Attacks)
│   ├── sim_bruteforce.py           # Loopback FTP/SSH credential spray (T1110)
│   ├── sim_synscan.py              # Loopback port sweep (T1046)
│   └── sim_canary_burst.py         # Canary decoy tampering (T1486)
│
├── ui/                             # Presentation Layer (CustomTkinter)
│   ├── theme.py                    # Cyberpunk color tokens & fonts
│   ├── voice_alerts.py             # Dedicated non-blocking TTS audio thread
│   ├── main_window.py              # Root window & ui_bus event dispatcher
│   └── panels/
│       ├── header_frame.py         # System status & AUTO/HUMAN toggle
│       ├── radar_frame.py          # Discovered assets & trap indicators
│       ├── brain_feed_frame.py     # Live terminal feed of AI reasoning
│       ├── shield_log_frame.py     # Containment deployment log & approvals
│       └── range_frame.py          # Simulator attack buttons & latency
│
└── tests/                          # Integration Test Suites
    ├── test_database.py            # SQLite concurrency & DAO test
    ├── test_pipeline.py            # End-to-end detect-reason-contain test
    └── test_smoke.py               # Full multi-scenario integration suite
```

---

## Quickstart

### 1. Run the Command Center GUI
```bash
.venv\Scripts\python.exe main.py
```

### 2. Run Test Suites
```bash
# Database concurrency test
.venv\Scripts\python.exe tests/test_database.py

# End-to-end detection pipeline test
.venv\Scripts\python.exe tests/test_pipeline.py

# Full smoke test (all 3 attack simulations)
.venv\Scripts\python.exe tests/test_smoke.py
```

---

## Demo Script (Judges Presentation)

1. Launch `python main.py` to open the cyberpunk dashboard.
2. In the **Cyber Range** panel (bottom right), click:
   * **Simulate Brute Force**: Honeypot captures failed logins $\rightarrow$ Ultron reasons and tags MITRE `T1110` $\rightarrow$ Shield drops IP in under 50ms.
   * **Simulate Port Scan**: Port sweep detected $\rightarrow$ MITRE `T1046` $\rightarrow$ Containment triggered.
   * **Trigger Canary Tamper**: File integrity trip $\rightarrow$ PID resolved $\rightarrow$ MITRE `T1486` $\rightarrow$ Process neutralized.
3. Switch toggle to **HUMAN APPROVAL**: Watch actions queue with interactive **Deploy Shield Now** buttons!
