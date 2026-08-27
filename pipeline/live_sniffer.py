"""
Real-Time Live Network Packet Sniffer using Scapy & AsyncIO.
Captures real IP packets on active network interfaces without interrupting traffic.
"""

import asyncio
import logging
import time
from typing import Callable, Optional
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from pipeline.models import NetworkEvent, LogType

logger = logging.getLogger("enclave.sniffer")

class LivePacketSniffer:
    """Passively sniffs real network packets and converts them to NetworkEvents."""

    def __init__(self, on_event_callback: Callable[[NetworkEvent], None]):
        self.on_event_callback = on_event_callback
        self.running = False
        self.packet_count = 0
        self.active_interface = "all"
        self._thread = None

    def _process_packet(self, pkt):
        try:
            if not pkt.haslayer(IP):
                return

            self.packet_count += 1
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            src_port = 0
            dst_port = 0
            proto = "ip"
            log_type = LogType.CONN
            orig_bytes = len(pkt)
            query = None

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                proto = "tcp"
                log_type = LogType.SSL if (dst_port == 443 or src_port == 443) else LogType.CONN
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                proto = "udp"
                if pkt.haslayer(DNS):
                    log_type = LogType.DNS
                    if pkt.haslayer(DNSQR):
                        try:
                            query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                        except Exception:
                            pass

            event = NetworkEvent(
                ts=time.time(),
                log_type=log_type,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                orig_bytes=orig_bytes,
                resp_bytes=0,
                query=query,
                conn_state="SF"
            )

            # Pass real captured event to pipeline
            self.on_event_callback(event)

        except Exception as e:
            pass

    def start_sniffing(self):
        """Starts real packet sniffing in background thread."""
        import threading
        if self.running:
            return

        self.running = True
        logger.info("📡 Starting real-time passive network packet sniffer...")

        def _sniff_thread():
            try:
                sniff(
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self.running
                )
            except Exception as e:
                logger.error(f"Sniffer error (requires raw socket permissions): {e}")

        self._thread = threading.Thread(target=_sniff_thread, daemon=True)
        self._thread.start()

    def stop_sniffing(self):
        self.running = False
