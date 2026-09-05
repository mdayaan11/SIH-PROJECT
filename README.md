<div align="center">

# 🔒 ENCLIVRA
### AI-Powered Threat Intelligence for Unidirectional Networks

**Smart India Hackathon (SIH) 2024 — Cybersecurity Track**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-cyphirsit.vercel.app-00c8ff?style=for-the-badge&logo=vercel)](https://cyphirsit.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Render.com-46E3B7?style=for-the-badge&logo=render)](https://sih-project-d3r8.onrender.com)
[![GitHub](https://img.shields.io/badge/GitHub-mdayaan11%2FSIH--PROJECT-181717?style=for-the-badge&logo=github)](https://github.com/mdayaan11/SIH-PROJECT)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi)

</div>

---

## 🎯 Problem Statement

Critical government networks (NTRO, defence, power-grid) use **hardware unidirectional data diodes** — traffic can only flow **inward**, never outward. This means:
- Standard IDS/SIEM tools that push telemetry to the cloud **cannot work** here
- Egress is hardware-blocked (0 bytes out), so no external SOC visibility
- Threats inside the sealed enclave go **undetected**

**ENCLIVRA** solves this by running a fully self-contained, air-gapped threat intelligence pipeline *inside* the sealed enclave that detects, chains, and cryptographically seals every threat — with a real-time dashboard for SOC operators.

---

## ✨ What We Built

### 🔴 Backend — Python Sealed Enclave Pipeline
A production-grade Python backend (`main.py` · FastAPI + Uvicorn) that runs entirely inside the sealed network enclave.

#### Real-Time Packet Ingestion
- **Live Scapy sniffer** (`pipeline/live_sniffer.py`) captures raw network packets off the wire
- **Zeek log watcher** (`pipeline/ingestion.py`) tails Zeek `conn.log` / `dns.log` / `ssl.log` files via `watchfiles`
- All events flow through a central `asyncio.Queue` (capacity 10,000) for backpressure-safe fan-out

#### 7 Threat Detectors
| Detector | Technique | MITRE ATT&CK |
|---|---|---|
| **C2 Beacon Detector** | Periodicity + JA3 fingerprinting of SSL intervals | T1071.001 |
| **DNS Tunnel Detector** | Shannon entropy analysis on subdomain strings | T1048 |
| **Port Scan Detector** | SYN/REJ ratio + sequential port sweep signature | T1046 |
| **Encrypted Malware Detector** | SPLT side-channel (TLS size + time distributions) | T1573 |
| **Exfiltration Detector** | EWMA baseline deviation with z-score threshold | T1048 |
| **DDoS Detector** | SYN flood rate with source diversity entropy | T1498 |
| **ML Detector** | Scikit-Learn IsolationForest anomaly detection on 8-feature vectors | T1071 |

#### Cryptographic Evidence Chain
- Every alert is **SHA-256 hash-chained** — each block contains the hash of the previous block, forming a tamper-evident linked list
- **Ed25519 digital signatures** sign each alert package — court-admissible evidence
- `EvidencePackager` bundles the alert, supporting network events, chain context, and signature into a sealed package
- **DuckDB** stores the append-only ledger — zero external DB dependency

#### Extras & Intelligence Modules
- **StoryStitcher** — correlates related alerts into multi-stage attack narratives
- **BaselineManager** — tracks per-host EWMA traffic baselines for anomaly detection
- **StormCollapser** — deduplicates alert storms (prevents noise from overwhelming SOC)
- **RetroHuntEngine** — DuckDB-powered retrospective IOC search across historical events
- **AttackGenerator** — synthetic attack scenario generator for demo / red team

#### REST API (FastAPI)
| Endpoint | Description |
|---|---|
| `GET /api/alerts` | Paginated threat alerts with filtering |
| `GET /api/alerts/{id}` | Single alert detail with full context |
| `GET /api/status` | Live system telemetry (EPS, uptime, chain length) |
| `GET /api/evidence/{id}` | Sealed evidence package with Ed25519 signature |
| `GET /api/chain` | Full hash-chain ledger |
| `POST /api/demo/trigger` | Trigger synthetic attack scenarios |
| `POST /api/retrohunt/search` | Retroactive IOC hunt |
| `WS /ws` | WebSocket — real-time event + alert stream |

---

### 🖥️ Frontend — React SOC Dashboard
A production React + Vite + TypeScript single-page application deployed on Vercel at **https://cyphirsit.vercel.app**.

#### Pages & Features

| Page | What it Does |
|---|---|
| **Overview** | KPI cards (events processed, EPS, uptime, alerts, verified chain blocks), Cryptographic Pipeline Visualizer, Live IP Ingress Stream |
| **Live Monitoring** | Real-time network event feed from WebSocket / synthetic stream, per-packet detail |
| **Threat Analytics** | MITRE ATT&CK heatmap, threat-type breakdown charts, severity distribution |
| **Dynamic Forensic Graph** | Interactive attack-graph visualization connecting source IPs → detectors → destinations |
| **Threat Alerts** | Full alert table with confidence scores, severity badges, MITRE mapping |
| **Alert Detail** | Per-alert deep dive: evidence chain, timeline, IOC extraction, analyst verdict feedback |
| **Evidence Verification** | Verify Ed25519 signatures and SHA-256 hash integrity; tamper simulation demo |
| **IP Connection History** | Per-IP historical traffic analysis and device profiling |
| **Detection Engines** | Status and configuration of all 7 active detector modules |
| **Network Topology** | Live network topology with baseline anomaly highlights |
| **Linux OS Kernel API** | Telemetry from kernel-level syscall and netfilter hooks |
| **Retro Hunt** | Query historical events by IP, rule, or threat type using DuckDB |
| **Detection Timeline** | Chronological view of multi-stage attack stories |
| **System Health** | Pipeline health, detector performance, queue depths |
| **Demo Mode** | Trigger 6 synthetic attack scenarios for demonstrations |
| **Updates** | Version and changelog viewer |

#### Key UI Components

- **`IpIngressStreamCard`** — Animated horizontal pill track + sequential row feed showing live IP ingress packets arriving in real-time. Includes 1×/2×/5× speed control, Pause/Resume, and instant threat injection.
- **`AiCopilot`** — Floating AI Security Copilot drawer with classic Copilot sparkle logo. Features:
  - Natural language Q&A about any detected threat
  - Quick-action chips: Evidence Chain, Block IP Rules, CISO Summary, C2 Beaconing, DNS Exfil
  - **⚡ Run 6 Demo Attacks** — instantly fires 6 distinct attack vectors into live telemetry, popping new IPs in the stream and spiking the event counter
  - Typing indicator and streaming response animation
- **`PipelineVisualizer`** — Visual flow diagram of the 6-stage cryptographic pipeline (Ingest → Metadata → Process → Detect → Alert → Verified)
- **`IntegrityLockdownModal`** — Full-screen emergency lockdown overlay triggered on chain tamper detection
- **`PoliceDossierModal`** — Court-ready evidence dossier export view
- **`NtroTrafficReplayPanel`** — Replay captured traffic sessions with packet-by-packet playback

#### Global State (Zustand)
- `events_processed` — monotonically increasing counter (never resets, starts at 148,520)
- `alerts` — seeded with 6 realistic demo alerts; grows as attacks are detected or injected
- `demoAttackSignal` — reactive integer that triggers instant IP burst in the stream card
- `tamperAlertActive` — triggers emergency lockdown modal on chain integrity breach

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 19, TypeScript, Vite, Zustand, React Router, Lucide Icons, shadcn/ui |
| **Styling** | Vanilla CSS + custom glassmorphism design system |
| **Backend** | Python 3.12, FastAPI, Uvicorn, asyncio |
| **Packet Capture** | Scapy (live sniffer), Zeek log ingestion via watchfiles |
| **Database** | DuckDB (embedded, zero-dependency analytical store) |
| **ML / Stats** | Scikit-Learn (IsolationForest), NumPy, SciPy |
| **Cryptography** | Python `cryptography` lib — Ed25519 (signatures), SHA-256 (chaining) |
| **Deployment** | Vercel (frontend), Render.com (backend) |
| **Real-time** | WebSocket (FastAPI native) |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.12+
- Node.js 20+
- (Optional) Zeek IDS for log ingestion

### Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Generate crypto keys and start the server
python main.py

# API available at: http://localhost:8000
# WebSocket at:     ws://localhost:8000/ws
```

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
# App available at: http://localhost:5173

# Build for production
npm run build
```

### Environment Variables
```env
# frontend/.env.local
VITE_API_URL=http://localhost:8000   # Point to your backend
```

---

## 🔐 Cryptographic Architecture

```
Network Packet
     │
     ▼
[LogIngester / LiveSniffer]
     │  NetworkEvent (src_ip, dst_ip, proto, bytes, ts)
     ▼
[Async Fan-Out Queue]
     │
     ├──▶ [C2BeaconDetector]   ─┐
     ├──▶ [DNSTunnelDetector]  ─┤
     ├──▶ [PortScanDetector]   ─┤── ThreatAlert
     ├──▶ [EncryptedMalware]   ─┤     │
     ├──▶ [ExfiltrationDet.]   ─┤     ▼
     ├──▶ [DDoSDetector]       ─┤  [AlertChain]
     └──▶ [MLDetector]         ─┘     │  SHA-256 hash(prev_hash + alert_json)
                                      ▼
                               [EvidencePackager]
                                      │  Ed25519 sign(canonical_json)
                                      ▼
                               [DuckDB Ledger]
                                      │
                                      ▼
                            [WebSocket Broadcast]
                                      │
                                      ▼
                            [React Dashboard / AI Copilot]
```

---

## 📸 Features Highlight

### Live IP Ingress Motion Stream
IPs arrive one-by-one in an animated horizontal pill track, each badge sliding in with a glowing keyframe animation. A separate motion-row list shows protocol, port, threat type, geolocation, and timestamp.

### AI Security Copilot
A floating assistant that answers cybersecurity questions about live threats — complete with iptables mitigation commands, JA3 hashes, DNS entropy analysis, CISO summaries, and chain integrity reports. The **⚡ Run 6 Demo Attacks** button immediately injects 6 real attack profiles (C2 beaconing, DNS exfiltration, SYN flood, JA3 malware, port sweep, data drop) with fresh IPs appearing in the stream in real-time.

### Evidence Chain Tamper Detection
A SHA-256 chain links every alert. Triggering a tamper test breaks the chain — the UI instantly shows an emergency **IntegrityLockdownModal** and generates a `CRITICAL` alert with egress lockdown status.

---

## 📁 Project Structure

```
SIH-PROJECT/
├── main.py                    # FastAPI app entry point
├── app.py                     # Alternative WSGI entry
├── requirements.txt           # Python dependencies
├── vercel.json                # Vercel SPA routing config
│
├── pipeline/                  # Core ingestion pipeline
│   ├── models.py              # Pydantic models (NetworkEvent, ThreatAlert, etc.)
│   ├── ingestion.py           # Zeek log file watcher & parser
│   └── live_sniffer.py        # Scapy real-time packet capture
│
├── detectors/                 # Threat detection modules
│   ├── base.py                # Abstract base detector
│   ├── c2_beacon.py           # Cobalt Strike / C2 beacon detection
│   ├── dns_tunnel.py          # DNS exfiltration / tunneling
│   ├── port_scan.py           # Port scan / reconnaissance
│   ├── encrypted_malware.py   # TLS side-channel (JA3 / SPLT)
│   ├── exfiltration.py        # Data exfiltration volume anomaly
│   ├── ddos.py                # SYN flood / volumetric DDoS
│   └── ml_detector.py         # Scikit-Learn IsolationForest
│
├── crypto/                    # Cryptographic modules
│   ├── keys.py                # Ed25519 key generation & management
│   ├── chain.py               # SHA-256 hash chain
│   └── evidence.py            # Evidence package signing
│
├── storage/                   # Persistence layer
│   ├── database.py            # DuckDB interface
│   └── retrohunt.py           # Retroactive IOC search engine
│
├── extras/                    # Intelligence extras
│   ├── attack_generator.py    # Synthetic attack scenario generator
│   ├── story_stitcher.py      # Multi-stage attack correlation
│   ├── baseline.py            # Per-host EWMA traffic baselines
│   ├── storm_collapse.py      # Alert deduplication / noise reduction
│   └── feedback.py            # Analyst verdict feedback store
│
└── frontend/                  # React dashboard
    └── src/
        ├── App.tsx             # Router + global AI Copilot
        ├── pages/             # 17 SOC dashboard pages
        ├── components/        # Reusable UI components
        │   ├── AiCopilot.tsx  # AI Security Copilot drawer
        │   └── IpIngressStreamCard.tsx  # Live IP motion stream
        ├── store/
        │   └── useStore.ts    # Zustand global state
        └── lib/
            └── api.ts         # REST API client with demo fallbacks
```

---

## 👥 Team

Built for **Smart India Hackathon (SIH) 2024** — Cybersecurity & National Security Track.

---

## 📄 License

This project was developed for the Smart India Hackathon. All rights reserved.

---

<div align="center">
<strong>ENCLIVRA</strong> — Sealed. Signed. Unbreachable.
</div>
