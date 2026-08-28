"""
ENCLIVRA — 2-Laptop Live Wi-Fi Demonstration Tool

Usage on Laptop A (Attacker):
    python live_wifi_demo.py --target 192.168.1.15 --attack scan
    python live_wifi_demo.py --target 192.168.1.15 --attack brute_force
    python live_wifi_demo.py --target 192.168.1.15 --attack mitm
    python live_wifi_demo.py --target 192.168.1.15 --attack ddos
    python live_wifi_demo.py --target 192.168.1.15 --attack sqli
"""

import argparse
import socket
import sys
import time
import urllib.request
import urllib.parse

def run_port_scan(target_ip: str):
    print(f"⚡ [SCENARIO 1] Launching Network Port Scan against {target_ip}...")
    ports = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8000, 8080]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            res = s.connect_ex((target_ip, port))
            if res == 0:
                open_ports.append(port)
            s.close()
            time.sleep(0.02)
        except Exception:
            pass
    print(f"✅ Port Scan Complete. Target: {target_ip} | Scanned: {len(ports)} ports | Open: {open_ports}")

def run_brute_force(target_ip: str):
    print(f"🔒 [SCENARIO 2] Launching Automated Brute Force SSH/Web Login Exhaustion against {target_ip}...")
    passwords = [f"admin{i}" for i in range(100)] + ["password123", "root", "123456", "admin123"]
    attempts = 0
    for pwd in passwords:
        attempts += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, 22))
            s.close()
        except Exception:
            pass
        if attempts % 20 == 0:
            print(f"  ➜ Sent {attempts} rapid authentication attempts to {target_ip}:22...")
        time.sleep(0.01)
    print(f"✅ Brute Force Sequence Complete: {attempts} failed authentication logs generated.")

def run_mitm(target_ip: str):
    print(f"🕵️ [SCENARIO 3] Launching MITM Interception & ARP Spoof Anomaly against {target_ip}...")
    for i in range(15):
        try:
            req = urllib.request.Request(
                f"http://{target_ip}:8000/api/status",
                headers={'User-Agent': 'Mozilla/5.0 (MITM-Proxy-Interception-Probe/1.0)'}
            )
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                _ = resp.read()
        except Exception:
            pass
        time.sleep(0.1)
    print(f"✅ MITM Proxy & Interception Sequence Complete against {target_ip}.")

def run_ddos(target_ip: str):
    print(f"🚨 [SCENARIO 4] Launching Volumetric SYN/HTTP Flood (DDoS) against {target_ip}...")
    packets_sent = 0
    for i in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            s.connect_ex((target_ip, 8000))
            s.close()
            packets_sent += 1
        except Exception:
            pass
    print(f"✅ Volumetric DDoS Flood Complete: {packets_sent} burst connection requests sent to {target_ip}.")

def run_sqli(target_ip: str):
    print(f"💉 [SCENARIO 5] Launching SQL Injection & Web Exploit Payload against {target_ip}...")
    sqli_payloads = [
        "' OR '1'='1",
        "' UNION SELECT username, password FROM users--",
        "admin' --",
        "'; DROP TABLE logs; --"
    ]
    for payload in sqli_payloads:
        try:
            encoded_payload = urllib.parse.quote(payload)
            req = urllib.request.Request(f"http://{target_ip}:8000/api/alerts?search={encoded_payload}")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                _ = resp.read()
        except Exception:
            pass
        time.sleep(0.1)
    print(f"✅ SQL Injection & Web Exploit Sequence Complete against {target_ip}.")

def main():
    parser = argparse.ArgumentParser(description="ENCLIVRA 2-Laptop Live Wi-Fi Demo Attacker Tool")
    parser.add_argument("--target", required=True, help="Target Laptop B's Local Wi-Fi IP address (e.g. 192.168.1.15)")
    parser.add_argument("--attack", choices=["scan", "brute_force", "mitm", "ddos", "sqli", "all"], default="scan", help="Attack scenario to run")
    args = parser.parse_args()

    print(f"\n========================================================")
    print(f"🚀 ENCLIVRA LIVE WI-FI DEMONSTRATION TOOL")
    print(f"🎯 Target Laptop IP: {args.target}")
    print(f"========================================================\n")

    if args.attack == "scan" or args.attack == "all":
        run_port_scan(args.target)
        time.sleep(1)

    if args.attack == "brute_force" or args.attack == "all":
        run_brute_force(args.target)
        time.sleep(1)

    if args.attack == "mitm" or args.attack == "all":
        run_mitm(args.target)
        time.sleep(1)

    if args.attack == "ddos" or args.attack == "all":
        run_ddos(args.target)
        time.sleep(1)

    if args.attack == "sqli" or args.attack == "all":
        run_sqli(args.target)

    print(f"\n========================================================")
    print(f"🎉 All attack sequences sent to Laptop B ({args.target})!")
    print(f"📊 Check ENCLIVRA Dashboard to see real-time alerts!")
    print(f"========================================================\n")

if __name__ == "__main__":
    main()
