"""
test_backend.py
----------------
Pre-deployment sanity check for the CyphirSit backend.

Run this against your LOCAL server before pushing/deploying anywhere.
It exercises every endpoint, checks status codes, checks CORS headers,
checks validation, and checks that state behaves as expected.

Usage:
    1. In one terminal:  python app.py
    2. In another:        python test_backend.py

    Optionally point it at a different host (e.g. a staging deployment):
    python test_backend.py --url https://your-backend.onrender.com
"""

import sys
import argparse
import requests

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

results = []


def check(name, condition, extra=""):
    status = PASS if condition else FAIL
    print(f"[{status}] {name}" + (f" -- {extra}" if extra and not condition else ""))
    results.append(condition)


def run_tests(base_url):
    print(f"\nTesting backend at: {base_url}\n" + "-" * 50)

    # 1. Health check
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        check("GET /health returns 200", r.status_code == 200, f"got {r.status_code}")
        check("GET /health returns correct body", r.json() == {"status": "running"}, f"got {r.text}")
    except requests.exceptions.RequestException as e:
        print(f"[{FAIL}] Could not reach server at all: {e}")
        print("\nIs app.py running? Is the URL/port correct?")
        sys.exit(1)

    # 2. Reset state so the test is repeatable
    r = requests.delete(f"{base_url}/api/alerts", timeout=5)
    check("DELETE /api/alerts returns 200", r.status_code == 200, f"got {r.status_code}")

    r = requests.get(f"{base_url}/api/alerts", timeout=5)
    check("GET /api/alerts is empty after reset", r.json().get("count") == 0, f"got {r.json()}")

    # 3. Valid alert submission
    valid_alert = {
        "type": "Port Scan",
        "source_ip": "192.168.1.50",
        "severity": "MEDIUM",
        "timestamp": "2026-08-28 09:00:00",
        "details": "Automated test alert",
    }
    r = requests.post(f"{base_url}/api/alert", json=valid_alert, timeout=5)
    check("POST /api/alert (valid) returns 201", r.status_code == 201, f"got {r.status_code}: {r.text}")
    body = r.json() if r.status_code == 201 else {}
    check("Response includes stored alert with an id", "alert" in body and "id" in body.get("alert", {}))

    # 4. Alert now appears in GET
    r = requests.get(f"{base_url}/api/alerts", timeout=5)
    data = r.json()
    check("GET /api/alerts count == 1 after one POST", data.get("count") == 1, f"got {data}")

    # 5. Invalid alert: bad type
    r = requests.post(f"{base_url}/api/alert", json={**valid_alert, "type": "Ransomware"}, timeout=5)
    check("POST with invalid type returns 400", r.status_code == 400, f"got {r.status_code}")

    # 6. Invalid alert: bad severity
    r = requests.post(f"{base_url}/api/alert", json={**valid_alert, "severity": "EXTREME"}, timeout=5)
    check("POST with invalid severity returns 400", r.status_code == 400, f"got {r.status_code}")

    # 7. Invalid alert: missing fields
    r = requests.post(f"{base_url}/api/alert", json={"type": "Port Scan"}, timeout=5)
    check("POST with missing fields returns 400", r.status_code == 400, f"got {r.status_code}")

    # 8. Invalid alert: not JSON at all
    r = requests.post(f"{base_url}/api/alert", data="not json", timeout=5,
                       headers={"Content-Type": "application/json"})
    check("POST with malformed JSON returns 400 (not 500)", r.status_code == 400, f"got {r.status_code}")

    # 9. Filtering
    r = requests.post(f"{base_url}/api/alert", json={**valid_alert, "severity": "CRITICAL",
                                                       "type": "Malware File"}, timeout=5)
    r = requests.get(f"{base_url}/api/alerts?severity=CRITICAL", timeout=5)
    data = r.json()
    check("Filter by severity works", data.get("count") == 1 and
          data["alerts"][0]["severity"] == "CRITICAL", f"got {data}")

    # 10. CORS header present
    r = requests.get(f"{base_url}/api/alerts", timeout=5)
    cors_header = r.headers.get("Access-Control-Allow-Origin")
    check("CORS header present on /api/alerts", cors_header is not None, f"got headers: {dict(r.headers)}")

    # 11. Unknown route returns 404 JSON, not a crash/HTML error page
    r = requests.get(f"{base_url}/api/does-not-exist", timeout=5)
    check("Unknown route returns 404", r.status_code == 404, f"got {r.status_code}")

    # 12. Final cleanup
    r = requests.delete(f"{base_url}/api/alerts", timeout=5)
    check("Final DELETE cleanup returns 200", r.status_code == 200)

    # Summary
    print("-" * 50)
    total = len(results)
    passed = sum(results)
    print(f"\n{passed}/{total} checks passed.")
    if passed != total:
        print("Fix the failures above before deploying.")
        sys.exit(1)
    else:
        print("Backend looks good to deploy.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5000",
                         help="Base URL of the backend to test (default: local)")
    args = parser.parse_args()
    run_tests(args.url.rstrip("/"))
