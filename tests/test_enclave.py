"""Comprehensive Test Suite for Sealed Enclave Watch.

Tests:
1. Crypto: KeyManager Ed25519 sign & verify
2. Crypto: AlertChain hash chaining & verification
3. Crypto: EvidencePackager SHA-256 & Ed25519 signature + tamper detection
4. Storage: DuckDB database operations (events, alerts, chain, graph, stats)
5. Detectors: 6 threat detection engines registry
6. API: FastAPI endpoints
"""

import asyncio
import os
import json
import time
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Core models
from pipeline.models import (
    NetworkEvent, ThreatAlert, ThreatType, Severity, LogType,
    AlertChainEntry, EvidencePackage
)

# Crypto
from crypto.keys import KeyManager
from crypto.chain import AlertChain
from crypto.evidence import EvidencePackager

# Storage
from storage.database import Database

# Detectors
from detectors import ALL_DETECTORS, DDoSDetector, C2BeaconDetector, DNSTunnelDetector, EncryptedMalwareDetector, PortScanDetector, ExfiltrationDetector

# FastAPI app
from main import app, state


def test_crypto_keys(tmp_path):
    """Test Ed25519 key generation, loading, signing, and verification."""
    km = KeyManager(keys_dir=str(tmp_path / "keys"))
    km.load_or_generate()
    
    assert km.private_key is not None
    assert km.public_key is not None
    
    data = b"Sealed Enclave Test Data"
    sig = km.sign(data)
    assert len(sig) == 64
    assert km.verify(data, sig) is True
    assert km.verify(b"Tampered Data", sig) is False


def test_alert_chain():
    """Test hash chain creation, entry linking, and integrity verification."""
    chain = AlertChain()
    
    # Run async add_alert
    async def _add():
        alert1 = ThreatAlert(
            threat_type=ThreatType.PORT_SCAN,
            detector_id="port_scan_detector",
            confidence=0.85,
            title="Port Scan Detected",
            source_ips=["192.168.1.100"],
            dest_ips=["10.0.0.1"]
        )
        entry1 = await chain.add_alert(alert1)
        
        alert2 = ThreatAlert(
            threat_type=ThreatType.C2_BEACON,
            detector_id="c2_beacon_detector",
            confidence=0.92,
            title="C2 Beaconing Detected",
            source_ips=["192.168.1.105"],
            dest_ips=["45.33.32.156"]
        )
        entry2 = await chain.add_alert(alert2)
        
        heartbeat = await chain.add_heartbeat()
        return entry1, entry2, heartbeat
        
    entry1, entry2, heartbeat = asyncio.run(_add())
    
    assert len(chain.chain) == 3
    valid, bad_idx = chain.verify_chain()
    assert valid is True
    assert bad_idx is None
    
    # Tamper test
    chain.chain[1].alert_hash = "f" * 64
    valid_tampered, bad_idx_tampered = chain.verify_chain()
    assert valid_tampered is False
    assert bad_idx_tampered == 1


def test_evidence_verification(tmp_path):
    """Test evidence package generation, valid verification, and tampered package rejection."""
    km = KeyManager(keys_dir=str(tmp_path / "keys"))
    km.load_or_generate()
    packager = EvidencePackager(km)
    chain = AlertChain()

    async def _setup():
        alert = ThreatAlert(
            threat_type=ThreatType.EXFILTRATION,
            detector_id="exfiltration_detector",
            confidence=0.95,
            title="Data Exfiltration Detected",
            source_ips=["192.168.1.90"],
            dest_ips=["203.0.113.50"]
        )
        chain_entry = await chain.add_alert(alert)
        event = NetworkEvent(
            ts=time.time(),
            log_type=LogType.CONN,
            src_ip="192.168.1.90",
            dst_ip="203.0.113.50",
            orig_bytes=10000000
        )
        return alert, chain_entry, event

    alert, chain_entry, event = asyncio.run(_setup())
    pkg = packager.create_package(alert, chain_entry, chain, [event])

    # Verify using FastAPI endpoint
    client = TestClient(app)
    resp = client.post("/api/evidence/verify", json=json.loads(pkg.model_dump_json()))
    assert resp.status_code == 200
    res = resp.json()
    assert res["hash_valid"] is True
    assert res["signature_valid"] is True
    assert res["overall_valid"] is True

    # Tamper test: modify alert title in evidence package
    pkg_dict = json.loads(pkg.model_dump_json())
    pkg_dict["alert"]["title"] = "MODIFIED TITLE BY ATTACKER"
    tampered_resp = client.post("/api/evidence/verify", json=pkg_dict)
    assert tampered_resp.status_code == 200
    tampered_res = tampered_resp.json()
    assert tampered_res["hash_valid"] is False
    assert tampered_res["overall_valid"] is False


def test_duckdb_storage(tmp_path):
    """Test DuckDB database store and query operations."""
    db_path = str(tmp_path / "test_enclave.duckdb")
    db = Database(db_path=db_path)

    async def _db_ops():
        await db.connect()
        await db.initialize()

        # Store event
        evt = NetworkEvent(
            ts=time.time(),
            log_type=LogType.CONN,
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            dst_port=80,
            proto="tcp"
        )
        await db.store_event(evt)

        # Store alert
        alert = ThreatAlert(
            threat_type=ThreatType.DDOS,
            detector_id="ddos_detector",
            confidence=0.99,
            title="SYN Flood Attack",
            source_ips=["192.168.1.50"],
            dest_ips=["10.0.0.1"]
        )
        await db.store_alert(alert)

        # Query back
        alerts = await db.get_alerts(limit=10)
        assert len(alerts) >= 1
        assert alerts[0]["threat_type"] == "ddos"

        stats = await db.get_alert_stats()
        assert stats["total_count"] >= 1
        assert "ddos" in stats["threat_type_counts"]

        graph = await db.get_network_graph_data()
        assert "nodes" in graph

        await db.close()

    asyncio.run(_db_ops())


def test_detectors_registry():
    """Verify all 6 detectors are correctly registered."""
    assert len(ALL_DETECTORS) == 6


def test_api_endpoints():
    """Test REST API endpoints."""
    with TestClient(app) as client:
        # Status endpoint
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert "uptime_seconds" in resp.json()

        # Alerts endpoint
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

        # Chain verify
        resp = client.get("/api/chain/verify")
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

        # Detectors
        resp = client.get("/api/detectors")
        assert resp.status_code == 200
        assert len(resp.json()) == 6

        # Public key
        resp = client.get("/api/public-key")
        assert resp.status_code == 200
        assert "public_key_pem" in resp.json()

        # Generate attack trigger
        resp = client.post("/api/generate/port_scan")
        assert resp.status_code == 200
        assert resp.json()["status"] == "generating"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
