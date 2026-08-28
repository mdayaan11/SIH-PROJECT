from http.server import BaseHTTPRequestHandler
import json
import time

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {
            "status": "ONLINE",
            "system_name": "ENCLIVRA Threat Intelligence Enclave",
            "organization": "National Technical Research Organisation (NTRO)",
            "uptime_seconds": 864200,
            "diode_status": "LOCKED_READ_ONLY (0-Byte Egress Enforced)",
            "throughput": {
                "eps": 12450,
                "mbps": 1420.5,
                "packets_processed": 142890420,
                "packets_dropped": 0
            },
            "active_detectors": [
                {"name": "Volumetric & Protocol DDoS Engine", "status": "ACTIVE", "latency_ms": 0.42},
                {"name": "Covert DNS & ICMP Tunneling Engine", "status": "ACTIVE", "latency_ms": 0.65},
                {"name": "Botnet C2 Beaconing Engine", "status": "ACTIVE", "latency_ms": 0.88},
                {"name": "Encrypted Malware Payload Engine", "status": "ACTIVE", "latency_ms": 0.95},
                {"name": "Stealth Recon & Port Scan Engine", "status": "ACTIVE", "latency_ms": 0.31},
                {"name": "Unidirectional Data Exfiltration Engine", "status": "ACTIVE", "latency_ms": 0.54}
            ],
            "merkle_chain": {
                "height": 142,
                "head_hash": "c3d2e1a0f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2",
                "signature_algorithm": "Ed25519",
                "section_65b_integrity": "VALID"
            },
            "kernel_telemetry": {
                "rx_bytes": 159820491820,
                "tx_bytes": 0,
                "cpu_load_percent": 14.2,
                "memory_used_mb": 4210
            },
            "timestamp": time.time()
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        return
