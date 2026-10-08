import time


class EventSimulator:
    """Synthetic events for testing the detection engine."""

    def __init__(self):
        self.events = []

    def generate_deauth_anomaly(
        self,
        target_bssid="AA:BB:CC:DD:EE:FF",
        count=100,
    ):
        event = {
            "timestamp": time.time(),
            "type": "DEAUTH_FLOOD",
            "bssid": target_bssid,
            "count": count,
            "severity": "HIGH",
            "description": (
                f"Simulated {count} deauthentication events "
                f"against {target_bssid}."
            ),
        }

        self.events.append(event)

        return event

    def generate_rogue_ap_event(
        self,
        spoofed_ssid="LAB-AP",
    ):
        event = {
            "timestamp": time.time(),
            "type": "ROGUE_AP",
            "ssid": spoofed_ssid,
            "severity": "CRITICAL",
            "description": (
                f"Simulated rogue AP advertising "
                f"SSID '{spoofed_ssid}'."
            ),
        }

        self.events.append(event)

        return event

    def get_events(self):
        return self.events

    def clear_events(self):
        self.events.clear()
