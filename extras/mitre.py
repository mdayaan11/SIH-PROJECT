"""
MITRE ATT&CK Mapping for ENCLIVRA threat types.
Maps each ThreatType to tactics, techniques, and sub-techniques.
"""
from __future__ import annotations
from typing import Any

# Full MITRE ATT&CK mapping per threat type
MITRE_MAP: dict[str, dict[str, Any]] = {
    "c2_beacon": {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "techniques": [
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "sub_technique_id": "T1071.001",
                "sub_technique_name": "Web Protocols",
                "description": "Adversaries communicate via HTTP/HTTPS to blend with normal traffic.",
                "url": "https://attack.mitre.org/techniques/T1071/001/",
            },
            {
                "id": "T1573",
                "name": "Encrypted Channel",
                "sub_technique_id": "T1573.002",
                "sub_technique_name": "Asymmetric Cryptography",
                "description": "Uses SSL/TLS to encrypt C2 communications and evade detection.",
                "url": "https://attack.mitre.org/techniques/T1573/002/",
            },
            {
                "id": "T1102",
                "name": "Web Service",
                "description": "Uses legitimate web services as C2 to avoid suspicion.",
                "url": "https://attack.mitre.org/techniques/T1102/",
            },
        ],
        "kill_chain_phase": "command-and-control",
        "severity_note": "Active C2 beacon means adversary has established persistence.",
    },
    "dns_tunnel": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "techniques": [
            {
                "id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "sub_technique_id": "T1048.003",
                "sub_technique_name": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
                "description": "Data encoded in DNS query labels to bypass firewalls.",
                "url": "https://attack.mitre.org/techniques/T1048/003/",
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "sub_technique_id": "T1071.004",
                "sub_technique_name": "DNS",
                "description": "Uses DNS protocol as covert channel for data exfiltration.",
                "url": "https://attack.mitre.org/techniques/T1071/004/",
            },
        ],
        "kill_chain_phase": "exfiltration",
        "severity_note": "DNS tunneling can exfiltrate data from air-gapped or firewall-protected networks.",
    },
    "ddos": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "techniques": [
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "sub_technique_id": "T1498.001",
                "sub_technique_name": "Direct Network Flood",
                "description": "Floods network with SYN packets to exhaust server resources.",
                "url": "https://attack.mitre.org/techniques/T1498/001/",
            },
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "description": "Resource exhaustion targeting specific services.",
                "url": "https://attack.mitre.org/techniques/T1499/",
            },
        ],
        "kill_chain_phase": "actions-on-objectives",
        "severity_note": "DDoS causes availability impact and may be a distraction for other attacks.",
    },
    "port_scan": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "techniques": [
            {
                "id": "T1046",
                "name": "Network Service Scanning",
                "description": "Enumerates open ports and services on target hosts for lateral movement.",
                "url": "https://attack.mitre.org/techniques/T1046/",
            },
            {
                "id": "T1018",
                "name": "Remote System Discovery",
                "description": "Identifies live hosts on the network.",
                "url": "https://attack.mitre.org/techniques/T1018/",
            },
        ],
        "kill_chain_phase": "reconnaissance",
        "severity_note": "Port scanning typically precedes exploitation or lateral movement.",
    },
    "exfiltration": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "techniques": [
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "description": "Data sent over established C2 channel to adversary infrastructure.",
                "url": "https://attack.mitre.org/techniques/T1041/",
            },
            {
                "id": "T1030",
                "name": "Data Transfer Size Limits",
                "description": "Data transferred in chunks to avoid detection thresholds.",
                "url": "https://attack.mitre.org/techniques/T1030/",
            },
            {
                "id": "T1020",
                "name": "Automated Exfiltration",
                "description": "Automated tools used for continuous data transfer.",
                "url": "https://attack.mitre.org/techniques/T1020/",
            },
        ],
        "kill_chain_phase": "exfiltration",
        "severity_note": "Data exfiltration is a high-confidence indicator of active breach and data loss.",
    },
    "encrypted_malware": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "techniques": [
            {
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "sub_technique_id": "T1027.002",
                "sub_technique_name": "Software Packing",
                "description": "Malware uses encryption/packing to evade signature-based detection.",
                "url": "https://attack.mitre.org/techniques/T1027/002/",
            },
            {
                "id": "T1573",
                "name": "Encrypted Channel",
                "sub_technique_id": "T1573.001",
                "sub_technique_name": "Symmetric Cryptography",
                "description": "Uses custom cipher suites or non-standard TLS to avoid TLS inspection.",
                "url": "https://attack.mitre.org/techniques/T1573/001/",
            },
            {
                "id": "T1055",
                "name": "Process Injection",
                "description": "Injected code communicates via encrypted channel.",
                "url": "https://attack.mitre.org/techniques/T1055/",
            },
        ],
        "kill_chain_phase": "command-and-control",
        "severity_note": "Encrypted malware traffic evades DPI and SSL inspection.",
    },
}


def get_mitre_mapping(threat_type: str) -> dict[str, Any]:
    """Return MITRE ATT&CK mapping for a threat type string."""
    return MITRE_MAP.get(threat_type, {
        "tactic": "Unknown",
        "tactic_id": "TA0000",
        "techniques": [],
        "kill_chain_phase": "unknown",
        "severity_note": "No MITRE mapping available.",
    })


def enrich_alert_with_mitre(alert_dict: dict[str, Any]) -> dict[str, Any]:
    """Add MITRE ATT&CK fields to an alert dictionary in-place."""
    threat_type = alert_dict.get("threat_type", "")
    mapping = get_mitre_mapping(threat_type)
    alert_dict["mitre"] = mapping
    return alert_dict
