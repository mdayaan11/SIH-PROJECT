import asyncio
import random
import time
import uuid
import string
from typing import Optional

from pipeline.models import NetworkEvent, LogType

class AttackGenerator:
    """Synthetic Threat Traffic Generator."""

    def __init__(self, out_queue: asyncio.Queue):
        self.out_queue = out_queue
        self._base_time = time.time()

    def _get_ts(self, increment: float = 0.0) -> float:
        self._base_time += increment
        return self._base_time

    def _random_ip(self, prefix: str = '192.168.1') -> str:
        """Helper to generate random IPs."""
        suffix = random.randint(1, 254)
        return f"{prefix}.{suffix}"

    def _random_string(self, length: int) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    async def generate_ddos(self, target_ip: str = '10.0.0.100', duration: int = 10, rate: int = 100) -> None:
        """SYN flood — many random source IPs → one target."""
        total_events = duration * rate
        for _ in range(total_events):
            event = NetworkEvent(
                ts=self._get_ts(1.0 / rate),
                log_type=LogType.CONN,
                src_ip=self._random_ip('192.168.2'),
                src_port=random.randint(1024, 65535),
                dst_ip=target_ip,
                dst_port=80,
                proto='tcp',
                conn_state='S0',
                orig_bytes=0,
                resp_bytes=0,
                history='S'
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)  # Yield to event loop

    async def generate_c2_beacon(self, src_ip: str = '192.168.1.50', dst_ip: str = '45.33.32.156', interval: float = 30.0, jitter: float = 0.15, count: int = 20) -> None:
        """Periodic connections with jitter."""
        for _ in range(count):
            actual_interval = interval * (1.0 + random.uniform(-jitter, jitter))
            event = NetworkEvent(
                ts=self._get_ts(actual_interval),
                log_type=LogType.SSL,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=dst_ip,
                dst_port=443,
                proto='tcp',
                conn_state='SF',
                orig_bytes=random.randint(50, 200),
                resp_bytes=random.randint(100, 500),
                ja3='e7d705a3286e19ea42f587b344ee6865',
                history='ShADadfF'
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def generate_dns_tunnel(self, src_ip: str = '192.168.1.75', tunnel_domain: str = 'data.evil.com', count: int = 50) -> None:
        """Long high-entropy subdomains."""
        for _ in range(count):
            subdomain = self._random_string(random.randint(30, 60))
            event = NetworkEvent(
                ts=self._get_ts(random.uniform(0.1, 1.5)),
                log_type=LogType.DNS,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip='8.8.8.8',
                dst_port=53,
                proto='udp',
                query=f"{subdomain}.{tunnel_domain}",
                qtype_name='TXT',
                answers=[self._random_string(100)]
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def generate_encrypted_malware(self, src_ip: str = '192.168.1.80', dst_ip: str = '185.220.101.1', count: int = 15) -> None:
        """SSL connections with self-signed certs."""
        for _ in range(count):
            now = self._get_ts(random.uniform(2.0, 10.0))
            event = NetworkEvent(
                ts=now,
                log_type=LogType.X509,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=dst_ip,
                dst_port=443,
                proto='tcp',
                cert_subject='CN=localhost',
                cert_issuer='CN=localhost',
                cert_not_valid_before=now - 3600,
                cert_not_valid_after=now + 86400,
                ja3='e7d705a3286e19ea42f587b344ee6865'
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def generate_port_scan(self, src_ip: str = '10.0.0.200', target_ip: str = '10.0.0.50', ports_count: int = 100) -> None:
        """Sequential port connections."""
        for port in range(1, ports_count + 1):
            state = 'S0' if random.random() < 0.9 else 'REJ'
            event = NetworkEvent(
                ts=self._get_ts(random.uniform(0.001, 0.01)),
                log_type=LogType.CONN,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=target_ip,
                dst_port=port,
                proto='tcp',
                conn_state=state,
                duration=random.uniform(0.001, 0.01)
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def generate_exfiltration(self, src_ip: str = '192.168.1.90', dst_ip: str = '203.0.113.50', total_bytes: int = 50_000_000) -> None:
        """Large uploads over multiple connections, off-hours timestamp."""
        # First: warm up baseline with normal-looking traffic from this source
        for _ in range(60):
            event = NetworkEvent(
                ts=self._get_ts(random.uniform(0.5, 2.0)),
                log_type=LogType.CONN,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=self._random_ip('10.0.0'),
                dst_port=random.choice([80, 443]),
                proto='tcp',
                conn_state='SF',
                orig_bytes=random.randint(100, 2000),
                resp_bytes=random.randint(500, 10000)
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

        # Then: large uploads (the actual exfiltration)
        bytes_sent = 0
        while bytes_sent < total_bytes:
            chunk = random.randint(100_000, 5_000_000)
            bytes_sent += chunk
            event = NetworkEvent(
                ts=self._get_ts(random.uniform(0.5, 5.0)),
                log_type=LogType.CONN,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=dst_ip,
                dst_port=443,
                proto='tcp',
                conn_state='SF',
                orig_bytes=chunk,
                resp_bytes=random.randint(100, 500)
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def generate_normal_traffic(self, count: int = 200) -> None:
        """Normal-looking connections."""
        ports = [80, 443, 53, 22]
        for _ in range(count):
            port = random.choice(ports)
            proto = 'udp' if port == 53 else 'tcp'
            log_type = LogType.DNS if port == 53 else LogType.CONN
            event = NetworkEvent(
                ts=self._get_ts(random.uniform(0.1, 5.0)),
                log_type=log_type,
                src_ip=self._random_ip(),
                src_port=random.randint(1024, 65535),
                dst_ip=self._random_ip('10.0.0'),
                dst_port=port,
                proto=proto,
                conn_state='SF',
                orig_bytes=random.randint(100, 5000),
                resp_bytes=random.randint(100, 50000)
            )
            await self.out_queue.put(event)
            await asyncio.sleep(0)

    async def run_all_attacks(self) -> None:
        """Runs all attack types plus normal traffic."""
        await self.generate_normal_traffic(50)
        await self.generate_port_scan()
        await self.generate_dns_tunnel()
        await self.generate_encrypted_malware()
        await self.generate_c2_beacon()
        await self.generate_exfiltration()
        await self.generate_ddos()
        await self.generate_normal_traffic(50)

