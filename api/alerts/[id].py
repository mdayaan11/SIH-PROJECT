from http.server import BaseHTTPRequestHandler
import json
import time
from urllib.parse import parse_qs, urlparse

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        # Extract alert ID from URL path or query params
        parsed = urlparse(self.path)
        path_parts = [p for p in parsed.path.split('/') if p]
        alert_id = path_parts[-1] if path_parts else "NTRO-ALERT-C93F10A"
        
        qs = parse_qs(parsed.query)
        if 'id' in qs:
            alert_id = qs['id'][0]

        alert_data = {
            "alert_id": alert_id,
            "timestamp": time.time() - 120,
            "flow_identifier": f"FLOW-{abs(hash(alert_id)) % 900000 + 100000}",
            "threat_class": "c2_beacon",
            "threat_class_name": "Botnet C2 Beaconing Engine",
            "severity": "critical",
            "confidence": 0.98,
            "source_ips": ["192.168.1.75"],
            "dest_ips": ["45.33.32.156"],
            "dest_ports": [443],
            "features": {
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "ja4_fingerprint": "t13d1516h2_8daaf6152771_b177e01b3992",
                "iat_entropy": 0.94,
                "byte_ratio": "18.4:1"
            },
            "crypto_proof": {
                "block_index": 142,
                "previous_hash": "a8f5f167f44f4964e6c998dee827110c947291a0c8b211f4672e816a70a83151",
                "merkle_root": "c3d2e1a0f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2",
                "ed25519_signature": "30450221008f12a4b89012cdef0123456789abcdef0123456789abcdef0123456789"
            }
        }
        
        response = {
            "success": True,
            "alert": alert_data
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
