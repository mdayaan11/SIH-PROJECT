"""
Async IP Threat Intelligence Enrichment for ENCLIVRA.

Uses ip-api.com (free, no API key needed, 45 req/min) to enrich
source and destination IPs in alerts with:
  - Country, city, ASN, ISP, org
  - Tor exit node flag
  - Private/reserved IP detection

All lookups are cached (TTL=1h) and run async.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# ---------------------------------------------------------------------------
# Known Tor exit node prefixes (small embedded list — update periodically)
# ---------------------------------------------------------------------------
_TOR_EXIT_PREFIXES = {
    "185.220.101.", "185.220.100.", "185.220.103.", "185.220.102.",
    "193.218.118.", "62.102.148.", "171.25.193.", "91.108.56.",
    "45.142.212.", "45.148.10.", "95.142.40.", "51.15.",
}

# ---------------------------------------------------------------------------
# Private / Reserved IP ranges (RFC 1918, loopback, link-local)
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# In-memory cache: ip → (result_dict, expire_ts)
_cache: dict[str, tuple[dict[str, Any], float]] = {}
_CACHE_TTL = 3600.0  # 1 hour


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_tor_exit(ip: str) -> bool:
    """Heuristic check against known Tor exit prefixes."""
    return any(ip.startswith(pfx) for pfx in _TOR_EXIT_PREFIXES)


async def enrich_ip(ip: str) -> dict[str, Any]:
    """Async enrich a single IP. Returns cached result if available."""
    if not ip or ip in ("", "0.0.0.0", "::"):
        return {"ip": ip, "private": False, "error": "empty_ip"}

    # Check cache
    cached = _cache.get(ip)
    if cached and time.time() < cached[1]:
        return cached[0]

    # Private IP shortcut — no external lookup needed
    if _is_private_ip(ip):
        result: dict[str, Any] = {
            "ip": ip,
            "private": True,
            "tor_exit": False,
            "country": "Private",
            "country_code": "XX",
            "city": "Internal",
            "asn": "AS0",
            "isp": "Private Network",
            "org": "Private Network",
            "lat": 0.0,
            "lon": 0.0,
        }
        _cache[ip] = (result, time.time() + _CACHE_TTL)
        return result

    base = {"ip": ip, "private": False, "tor_exit": _is_tor_exit(ip)}

    if not HTTPX_AVAILABLE:
        base["error"] = "httpx_not_installed"
        return base

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,isp,org,as,lat,lon,query"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "ip": ip,
                        "private": False,
                        "tor_exit": _is_tor_exit(ip),
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                    }
                    _cache[ip] = (result, time.time() + _CACHE_TTL)
                    return result
    except Exception as exc:
        base["error"] = str(exc)

    _cache[ip] = (base, time.time() + 60.0)  # short cache on failure
    return base


async def enrich_alert(alert_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich all source_ips and dest_ips in an alert dict.
    Adds 'geo_enrichment' key with per-IP results.
    """
    source_ips: list[str] = alert_dict.get("source_ips", [])
    dest_ips: list[str] = alert_dict.get("dest_ips", [])

    all_ips = list(set(source_ips + dest_ips))
    if not all_ips:
        return alert_dict

    tasks = [enrich_ip(ip) for ip in all_ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    geo_map: dict[str, Any] = {}
    for ip, res in zip(all_ips, results):
        if isinstance(res, Exception):
            geo_map[ip] = {"ip": ip, "error": str(res)}
        else:
            geo_map[ip] = res

    alert_dict["geo_enrichment"] = geo_map

    # Flag if any source IP is Tor exit
    if any(geo_map.get(ip, {}).get("tor_exit") for ip in source_ips):
        alert_dict["tor_exit_detected"] = True

    return alert_dict
