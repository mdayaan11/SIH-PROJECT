"""Specialist threat detectors."""

from detectors.ddos import DDosDetector as DDoSDetector
from detectors.c2_beacon import C2BeaconDetector
from detectors.dns_tunnel import DnsTunnelDetector as DNSTunnelDetector
from detectors.encrypted_malware import EncryptedMalwareDetector
from detectors.port_scan import PortScanDetector
from detectors.exfiltration import ExfiltrationDetector
from detectors.ml_detector import RealMLDetector

ALL_DETECTORS = [
    DDoSDetector,
    C2BeaconDetector,
    DNSTunnelDetector,
    EncryptedMalwareDetector,
    PortScanDetector,
    ExfiltrationDetector,
    RealMLDetector,
]

__all__ = [
    "DDoSDetector",
    "C2BeaconDetector",
    "DNSTunnelDetector",
    "EncryptedMalwareDetector",
    "PortScanDetector",
    "ExfiltrationDetector",
    "RealMLDetector",
    "ALL_DETECTORS",
]
