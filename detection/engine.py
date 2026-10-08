class DetectionEngine:
    def __init__(self):
        self.alerts = []

    def analyze_pcap_stats(self, pcap_metadata):
        # Threshold analysis
        if pcap_metadata.get("management_frames", 0) > 1000:
            self.alerts.append({
                "source": "PCAP Analysis",
                "type": "High Management Frame Volume",
                "severity": "MEDIUM",
                "details": f"Found {pcap_metadata['management_frames']} management frames."
            })
            
    def ingest_simulated_events(self, events):
        for event in events:
            # Route events to alert queue
            self.alerts.append({
                "source": "Simulation Engine",
                "type": event.get("type"),
                "severity": event.get("severity"),
                "details": event.get("description")
            })

    def get_alerts(self):
        return self.alerts
