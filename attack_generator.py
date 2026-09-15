"""
Realistic Attack Traffic Generator for ENCLIVRA.

Generates per-attack-type synthetic network events with accurate
feature distributions that trigger the ML model and rule-based detectors.

Attack types:
  - c2_beacon        : Periodic fixed-interval SSL/TLS beaconing
  - dns_tunnel       : High-entropy, long base64-encoded DNS queries
  - ddos             : SYN flood from many random source IPs
  - port_scan        : Sequential TCP SYN sweep (conn_state=S0)
  - exfiltration     : Large outbound HTTPS with anomalous byte ratio
  - encrypted_malware: Unusual cipher/JA3 fingerprint on rare ports
"""
from __future__ import annotations

import asyncio
import base64
import math
import os
import random
import string
import time
import uuid
from typing import Optional

from pipeline.models import NetworkEvent, LogType

# Known malicious C2 IPs (fictional but realistic)
_C2_IPS = [
    "45.33.32.156", "185.220.101.34", "198.98.54.105",
    "91.108.56.182", "62.102.148.69", "193.218.118.180",
]

# Known internal subnet for victim machines
_INTERNAL_SUBNETS = ["192.168.1", "192.168.2", "10.0.0", "172.16.0"]

# Known Cobalt Strike JA3 fingerprints
_CS_JA3 = [
    "e7d705a3286e19ea42f587b344ee6865",
    "a0e9f5d64349fb13191bc781f81f42e1",
    "8c4a0b2f7e3d6c1a9f5e2b8d4c7a3f1e",
]

# Malware cipher suites (unusual)
_MALWARE_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_NULL_WITH_NULL_NULL",
]


class AttackGenerator:
    """Synthetic Threat Traffic Generator — produces realistic network events."""

    def __init__(self, out_queue: asyncio.Queue):
        self.out_queue = out_queue
        self._base_time = time.time()

    def _ts(self, offset: float = 0.0) -> float:
        t = self._base_time + offset
        self._base_time += offset
        return t

    def _rand_internal_ip(self, subnet: Optional[str] = None) -> str:
        s = subnet or random.choice(_INTERNAL_SUBNETS)
        return f"{s}.{random.randint(1, 254)}"

    def _rand_port(self) -> int:
        return random.randint(1024, 65534)

    def _b64_entropy_string(self, length: int) -> str:
        """Generate base64-encoded random data (high entropy, like DNS tunnel payload)."""
        raw = os.urandom(length)
        return base64.urlsafe_b64encode(raw).decode().replace("=", "")[:length]

    def _random_string(self, length: int) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    # ------------------------------------------------------------------
    # C2 Beacon
    # ------------------------------------------------------------------
    async def generate_c2_beacon(
        self,
        src_ip: str = "192.168.1.50",
        dst_ip: Optional[str] = None,
        interval: float = 30.0,
        jitter: float = 0.15,
        count: int = 25,
    ) -> int:
        """
        Cobalt Strike / C2 beacon simulation.
        Periodic SSL connections with fixed interval + small jitter.
        """
        c2_ip = dst_ip or random.choice(_C2_IPS)
        ja3 = random.choice(_CS_JA3)
        total = 0
        for i in range(count):
            actual_interval = interval * (1.0 + random.uniform(-jitter, jitter))
            event = NetworkEvent(
                ts=time.time() - (count - i) * actual_interval,
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.SSL,
                src_ip=src_ip,
                src_port=self._rand_port(),
                dst_ip=c2_ip,
                dst_port=443,
                proto="tcp",
                conn_state="SF",
                orig_bytes=random.randint(128, 350),
                resp_bytes=random.randint(200, 600),
                orig_pkts=random.randint(3, 8),
                resp_pkts=random.randint(3, 8),
                duration=actual_interval * 0.01,
                history="ShADadfF",
                ja3=ja3,
                ja3s="b3ebe953c5aa7748c4628fa0b9f3e47e",
                server_name=f"{self._random_string(8)}.{random.choice(['io', 'cc', 'ru', 'to'])}",
                ssl_version="TLSv12",
                ssl_established=True,
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # DNS Tunnel
    # ------------------------------------------------------------------
    async def generate_dns_tunnel(
        self,
        src_ip: str = "192.168.1.75",
        tunnel_domain: str = "exfil.attacker.io",
        count: int = 60,
    ) -> int:
        """
        DNS exfiltration tunnel simulation.
        High-entropy, long base64 subdomain queries over UDP/53.
        """
        total = 0
        for _ in range(count):
            # Encode 'data' as high-entropy base64 subdomain
            payload_len = random.randint(40, 80)
            subdomain = self._b64_entropy_string(payload_len)
            query = f"{subdomain}.{tunnel_domain}"

            event = NetworkEvent(
                ts=time.time() - random.uniform(0, 300),
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.DNS,
                src_ip=src_ip,
                src_port=self._rand_port(),
                dst_ip="8.8.8.8",
                dst_port=53,
                proto="udp",
                conn_state="SF",
                orig_bytes=len(query) + 28,
                resp_bytes=random.randint(30, 120),
                orig_pkts=1,
                resp_pkts=1,
                duration=random.uniform(0.01, 0.1),
                query=query,
                qtype_name="TXT",
                rcode_name="NOERROR",
                answers=[f"{self._b64_entropy_string(20)}.attacker.io"],
                ttls=[random.uniform(0, 1)],  # Abnormally low TTL
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # DDoS
    # ------------------------------------------------------------------
    async def generate_ddos(
        self,
        target_ip: str = "10.0.0.100",
        target_port: int = 80,
        count: int = 500,
    ) -> int:
        """
        Distributed SYN flood from randomized source IPs.
        Very high packet rate, no response bytes (conn_state=S0).
        """
        total = 0
        for i in range(count):
            event = NetworkEvent(
                ts=time.time() - (count - i) * 0.002,
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.CONN,
                src_ip=self._rand_internal_ip(),
                src_port=random.randint(1024, 65534),
                dst_ip=target_ip,
                dst_port=target_port,
                proto="tcp",
                conn_state="S0",
                orig_bytes=random.randint(40, 80),
                resp_bytes=0,
                orig_pkts=random.randint(1, 3),
                resp_pkts=0,
                duration=0.0,
                history="S",
                missed_bytes=0,
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # Port Scan
    # ------------------------------------------------------------------
    async def generate_port_scan(
        self,
        src_ip: str = "192.168.1.100",
        target_ip: str = "10.0.0.1",
        start_port: int = 1,
        end_port: int = 1024,
    ) -> int:
        """
        Sequential TCP SYN port sweep.
        Single source → sequential ports, no responses (S0).
        """
        total = 0
        for port in range(start_port, end_port + 1):
            event = NetworkEvent(
                ts=time.time() - (end_port - port) * 0.001,
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.CONN,
                src_ip=src_ip,
                src_port=self._rand_port(),
                dst_ip=target_ip,
                dst_port=port,
                proto="tcp",
                conn_state="S0",
                orig_bytes=40,
                resp_bytes=0,
                orig_pkts=1,
                resp_pkts=0,
                duration=0.0,
                history="S",
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # Data Exfiltration
    # ------------------------------------------------------------------
    async def generate_exfiltration(
        self,
        src_ip: str = "192.168.1.80",
        dst_ip: Optional[str] = None,
        count: int = 30,
    ) -> int:
        """
        Large-volume outbound HTTPS transfer simulation.
        Very high orig_bytes, low resp_bytes, off-hours timing.
        """
        c2_ip = dst_ip or random.choice(_C2_IPS)
        total = 0
        for i in range(count):
            # Simulate off-hours (2-4 AM local time)
            ts = time.time() - (count - i) * 60.0

            chunk_size = random.randint(200_000, 800_000)
            event = NetworkEvent(
                ts=ts,
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.CONN,
                src_ip=src_ip,
                src_port=self._rand_port(),
                dst_ip=c2_ip,
                dst_port=443,
                proto="tcp",
                conn_state="SF",
                orig_bytes=chunk_size,
                resp_bytes=random.randint(200, 1024),
                orig_pkts=random.randint(200, 600),
                resp_pkts=random.randint(2, 10),
                duration=random.uniform(30.0, 90.0),
                history="ShADadfF",
                ssl_established=True,
                server_name=f"cdn-{self._random_string(6)}.exfil.io",
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # Encrypted Malware
    # ------------------------------------------------------------------
    async def generate_encrypted_malware(
        self,
        src_ip: str = "192.168.1.90",
        count: int = 20,
    ) -> int:
        """
        Encrypted malware C2 traffic simulation.
        Unusual cipher suites, non-standard ports, rare destinations, high-entropy SNI.
        """
        total = 0
        for _ in range(count):
            dst_port = random.choice([4444, 8443, 9001, 12345, 31337, 8080])
            event = NetworkEvent(
                ts=time.time() - random.uniform(0, 600),
                uid=f"C{uuid.uuid4().hex[:16]}",
                log_type=LogType.SSL,
                src_ip=src_ip,
                src_port=self._rand_port(),
                dst_ip=random.choice(_C2_IPS),
                dst_port=dst_port,
                proto="tcp",
                conn_state="SF",
                orig_bytes=random.randint(4096, 16384),
                resp_bytes=random.randint(2048, 8192),
                orig_pkts=random.randint(15, 50),
                resp_pkts=random.randint(10, 40),
                duration=random.uniform(5.0, 20.0),
                history="ShADadfF",
                ja3=random.choice(_CS_JA3),
                cipher=random.choice(_MALWARE_CIPHERS),
                ssl_version="TLSv10",  # Outdated TLS = suspicious
                server_name=self._b64_entropy_string(20)[:15] + ".cc",
                ssl_established=True,
            )
            await self.out_queue.put(event)
            total += 1
            await asyncio.sleep(0)
        return total

    # ------------------------------------------------------------------
    # Generate all attack types
    # ------------------------------------------------------------------
    async def generate_all(self) -> dict[str, int]:
        """Inject one complete scenario of all 6 attack types."""
        results = {}

        results["c2_beacon"] = await self.generate_c2_beacon(
            src_ip=self._rand_internal_ip("192.168.1"),
            count=20,
        )
        results["dns_tunnel"] = await self.generate_dns_tunnel(
            src_ip=self._rand_internal_ip("192.168.1"),
            count=40,
        )
        results["ddos"] = await self.generate_ddos(
            target_ip=self._rand_internal_ip("10.0.0"),
            count=200,
        )
        results["port_scan"] = await self.generate_port_scan(
            src_ip=self._rand_internal_ip("192.168.2"),
            target_ip=self._rand_internal_ip("10.0.0"),
            start_port=1,
            end_port=200,
        )
        results["exfiltration"] = await self.generate_exfiltration(
            src_ip=self._rand_internal_ip("192.168.1"),
            count=20,
        )
        results["encrypted_malware"] = await self.generate_encrypted_malware(
            src_ip=self._rand_internal_ip("192.168.1"),
            count=15,
        )

        return results
