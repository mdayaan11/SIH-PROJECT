from http.server import BaseHTTPRequestHandler
import json
import time
import uuid

VALID_TYPES = {
    "Port Scan",
    "Malware File",
    "DDoS",
    "DNS Tunneling",
    "C2 Beacon",
    "Data Exfiltration",
    "SQL Injection",
    "Brute Force",
    "SYN Flood",
    "ICMP Tunnel",
    "JA3 Malware",
    "c2_beacon",
    "dns_tunnel",
    "ddos",
    "port_scan",
    "malware"
}

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "low",
    "medium",
    "high",
    "critical"
}

# Global in-memory storage for real alerts in Vercel Serverless container
STORED_ALERTS = []

class handler(BaseHTTPRequestHandler):
    def send_cors_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        self.send_cors_headers(200)
        
        # Parse query params for filtering
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        filtered = STORED_ALERTS[:]

        if 'severity' in qs:
            target_sev = qs['severity'][0].upper()
            filtered = [a for a in filtered if str(a.get("severity", "")).upper() == target_sev]

        if 'type' in qs:
            target_type = qs['type'][0].lower()
            filtered = [a for a in filtered if str(a.get("type", "")).lower() == target_type]

        response = {
            "success": True,
            "count": len(filtered),
            "alerts": filtered
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
        return

    def do_DELETE(self):
        global STORED_ALERTS
        STORED_ALERTS.clear()
        self.send_cors_headers(200)
        response = {"message": "Alerts reset", "count": 0}
        self.wfile.write(json.dumps(response).encode('utf-8'))
        return

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_cors_headers(400)
                self.wfile.write(json.dumps({"error": "Missing JSON payload"}).encode('utf-8'))
                return

            post_data = self.rfile.read(content_length)
            payload = json.loads(post_data.decode('utf-8'))

            if not isinstance(payload, dict):
                self.send_cors_headers(400)
                self.wfile.write(json.dumps({"error": "Payload must be a JSON object"}).encode('utf-8'))
                return

            required_fields = ["type", "source_ip", "severity", "timestamp", "details"]
            for f in required_fields:
                if f not in payload or payload[f] is None:
                    self.send_cors_headers(400)
                    self.wfile.write(json.dumps({"error": f"Missing required field: {f}"}).encode('utf-8'))
                    return

            alert_type = payload.get("type")
            alert_severity = payload.get("severity")

            if alert_type not in VALID_TYPES:
                self.send_cors_headers(400)
                self.wfile.write(json.dumps({"error": f"Invalid threat type: {alert_type}"}).encode('utf-8'))
                return

            if str(alert_severity).upper() not in {s.upper() for s in VALID_SEVERITIES}:
                self.send_cors_headers(400)
                self.wfile.write(json.dumps({"error": f"Invalid severity level: {alert_severity}"}).encode('utf-8'))
                return

            alert_id = f"ALERT-{uuid.uuid4().hex[:8].upper()}"
            new_alert = {
                "id": alert_id,
                "alert_id": alert_id,
                "type": alert_type,
                "source_ip": payload.get("source_ip"),
                "severity": str(alert_severity).upper(),
                "timestamp": payload.get("timestamp"),
                "details": payload.get("details"),
                "created_at": time.time()
            }

            STORED_ALERTS.append(new_alert)

            self.send_cors_headers(201)
            self.wfile.write(json.dumps({
                "message": "Alert recorded",
                "alert": new_alert
            }).encode('utf-8'))
            return

        except Exception as e:
            self.send_cors_headers(400)
            self.wfile.write(json.dumps({"error": "Malformed JSON payload or request error"}).encode('utf-8'))
            return

    def do_OPTIONS(self):
        self.send_cors_headers(200)
        return
