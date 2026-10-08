import json
import time
import random

class EventSimulator:
    def __init__(self):
        self.events = []

    def generate_deauth_anomaly(self, target_bssid="AA:BB:CC:DD:EE:FF", count=100):
        print(f"[*] Injecting {count} deauth events -> {target_bssid}")
        event = {
            "timestamp": time.time(),
            "type": "DEAUTH_FLOOD",
            "bssid": target_bssid,
            "count": count,
            "severity": "HIGH",
            "description": "Anomalous volume of simulated deauthentication frames detected."
        }
        self.events.append(event)
        return event

    def generate_rogue_ap_event(self, spoofed_ssid="LAB-AP"):
        print(f"[*] Injecting Rogue AP beacon event -> {spoofed_ssid}")
        event = {
            "timestamp": time.time(),
            "type": "ROGUE_AP",
            "ssid": spoofed_ssid,
            "severity": "CRITICAL",
            "description": "Unregistered BSSID advertising authorized SSID."
        }
        self.events.append(event)
        return event
        
    def get_events(self):
        return self.events
