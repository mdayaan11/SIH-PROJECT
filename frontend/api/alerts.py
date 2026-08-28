from http.server import BaseHTTPRequestHandler
import json
import time

MOCK_ALERTS = [
    {
        "alert_id": "NTRO-ALERT-C93F10A",
        "timestamp": time.time() - 120,
        "flow_identifier": "FLOW-984210",
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
    },
    {
        "alert_id": "NTRO-ALERT-D82E91B",
        "timestamp": time.time() - 450,
        "flow_identifier": "FLOW-984188",
        "threat_class": "dns_tunnel",
        "threat_class_name": "Covert DNS Tunnel Exfiltration",
        "severity": "high",
        "confidence": 0.94,
        "source_ips": ["192.168.1.102"],
        "dest_ips": ["8.8.8.8"],
        "dest_ports": [53],
        "features": {
            "subdomain_entropy": 4.82,
            "txt_record_ratio": 0.89,
            "query_rate_eps": 142.5
        },
        "crypto_proof": {
            "block_index": 141,
            "previous_hash": "b7e4f056e33e3853d5b887cee716000b836180b0b7a100e3561d705b60972040",
            "merkle_root": "a8f5f167f44f4964e6c998dee827110c947291a0c8b211f4672e816a70a83151",
            "ed25519_signature": "304402207a112233445566778899aabbccddeeff00112233445566778899aabbcc"
        }
    },
    {
        "alert_id": "NTRO-ALERT-E71D80C",
        "timestamp": time.time() - 900,
        "flow_identifier": "FLOW-984105",
        "threat_class": "ddos",
        "threat_class_name": "Volumetric TCP SYN Flood",
        "severity": "critical",
        "confidence": 0.99,
        "source_ips": ["185.220.101.5", "185.220.101.9", "185.220.101.12"],
        "dest_ips": ["10.0.0.1"],
        "dest_ports": [80],
        "features": {
            "syn_ratio": 0.98,
            "packet_rate_pps": 14500,
            "source_ip_entropy": 7.92
        },
        "crypto_proof": {
            "block_index": 140,
            "previous_hash": "96f3e045d22d2742c4a776bdd605ef0a725070a0a6a00d24450c604a50861030",
            "merkle_root": "b7e4f056e33e3853d5b887cee716000b836180b0b7a100e3561d705b60972040",
            "ed25519_signature": "30450221006b554433221100ffeeddccbbaa99887766554433221100ffeeddcc"
        }
    }
]

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {
            "success": True,
            "count": len(MOCK_ALERTS),
            "alerts": MOCK_ALERTS
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
