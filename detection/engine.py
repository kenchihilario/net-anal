class DetectionEngine:
    """
    Heuristic network anomaly detection.

    Alerts are indicators, not proof that an attack occurred.
    """

    def __init__(
        self,
        management_threshold=1000,
        deauth_threshold=50,
        disassoc_threshold=50,
        multi_bssid_threshold=2,
    ):
        self.alerts = []

        self.management_threshold = management_threshold
        self.deauth_threshold = deauth_threshold
        self.disassoc_threshold = disassoc_threshold
        self.multi_bssid_threshold = multi_bssid_threshold

    def analyze_pcap_stats(self, stats):
        self._check_management_volume(stats)
        self._check_deauth(stats)
        self._check_disassociation(stats)
        self._check_multiple_bssids(stats)

    def _check_management_volume(self, stats):
        count = stats.get("management_frames", 0)

        if count >= self.management_threshold:
            self.alerts.append({
                "source": "PCAP",
                "type": "HIGH_MANAGEMENT_VOLUME",
                "severity": "MEDIUM",
                "details": (
                    f"{count:,} management frames detected. "
                    f"Threshold: {self.management_threshold:,}."
                ),
            })

    def _check_deauth(self, stats):
        count = stats.get("deauthentication_frames", 0)

        if count >= self.deauth_threshold:
            by_bssid = stats.get("deauth_by_bssid", {})

            top = None

            if by_bssid:
                top = max(
                    by_bssid.items(),
                    key=lambda item: item[1]
                )

            details = (
                f"{count:,} deauthentication frames detected."
            )

            if top:
                details += (
                    f" Highest BSSID-associated count: "
                    f"{top[0]} ({top[1]:,})."
                )

            self.alerts.append({
                "source": "PCAP",
                "type": "DEAUTH_FLOOD",
                "severity": "HIGH",
                "details": details,
            })

    def _check_disassociation(self, stats):
        count = stats.get("disassociation_frames", 0)

        if count >= self.disassoc_threshold:
            self.alerts.append({
                "source": "PCAP",
                "type": "DISASSOCIATION_FLOOD",
                "severity": "HIGH",
                "details": (
                    f"{count:,} disassociation frames detected."
                ),
            })

    def _check_multiple_bssids(self, stats):
        ssids = stats.get("ssids", {})

        for ssid, info in ssids.items():
            bssids = info.get("bssids", [])

            if len(bssids) < self.multi_bssid_threshold:
                continue

            display = ssid if ssid else "<hidden>"

            self.alerts.append({
                "source": "PCAP",
                "type": "MULTIPLE_BSSIDS",
                "severity": "INFO",
                "details": (
                    f"SSID '{display}' is advertised by "
                    f"{len(bssids)} BSSIDs."
                ),
            })

    def get_alerts(self):
        return self.alerts

    def clear_alerts(self):
        self.alerts.clear()
