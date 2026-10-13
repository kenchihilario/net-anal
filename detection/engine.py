class DetectionEngine:
    def __init__(
        self,
        management_threshold=1000,
        deauth_threshold=50,
        disassoc_threshold=50,
        multi_bssid_threshold=2,
        syn_ratio_threshold=0.8,
    ):
        self.alerts = []
        self.management_threshold = management_threshold
        self.deauth_threshold = deauth_threshold
        self.disassoc_threshold = disassoc_threshold
        self.multi_bssid_threshold = multi_bssid_threshold
        self.syn_ratio_threshold = syn_ratio_threshold

    def analyze_pcap_stats(self, stats):
        self._check_management_volume(stats)
        self._check_deauth(stats)
        self._check_disassociation(stats)
        self._check_multiple_bssids(stats)
        self._check_syn_flood(stats)
        self._check_port_scan(stats)

    def analyze_live_networks(self, networks):
        if not networks:
            return
        ssid_map = {}
        for net in networks:
            ssid = net.get("SSID", "")
            auth = net.get("Authentication", "")
            enc = net.get("Encryption", "")
            bssid = net.get("BSSID", "")

            if "Open" in auth or "None" in auth or "None" in enc:
                self.alerts.append({
                    "source": "WLAN_SCAN",
                    "type": "OPEN_UNENCRYPTED_WIFI",
                    "severity": "MEDIUM",
                    "details": f"Network '{ssid}' (BSSID: {bssid}) operates without encryption ({auth}/{enc}).",
                })

            if ssid:
                ssid_map.setdefault(ssid, []).append(net)

        for ssid, items in ssid_map.items():
            if len(items) >= self.multi_bssid_threshold:
                bssid_list = [i.get("BSSID", "") for i in items if i.get("BSSID")]
                auth_set = set(i.get("Authentication", "") for i in items)
                if len(auth_set) > 1:
                    self.alerts.append({
                        "source": "WLAN_SCAN",
                        "type": "SUSPECTED_ROGUE_AP",
                        "severity": "HIGH",
                        "details": f"SSID '{ssid}' has {len(items)} BSSIDs with conflicting security types: {', '.join(auth_set)}.",
                    })
                else:
                    self.alerts.append({
                        "source": "WLAN_SCAN",
                        "type": "MULTIPLE_BSSIDS",
                        "severity": "INFO",
                        "details": f"SSID '{ssid}' is broadcast across {len(items)} BSSIDs: {', '.join(bssid_list)}.",
                    })

    def _check_management_volume(self, stats):
        count = stats.get("management_frames", 0)
        if count >= self.management_threshold:
            self.alerts.append({
                "source": "PCAP",
                "type": "HIGH_MANAGEMENT_VOLUME",
                "severity": "MEDIUM",
                "details": f"{count:,} management frames detected. Threshold: {self.management_threshold:,}.",
            })

    def _check_deauth(self, stats):
        count = stats.get("deauthentication_frames", 0)
        if count >= self.deauth_threshold:
            by_bssid = stats.get("deauth_by_bssid", {})
            top = None
            if by_bssid:
                top = max(by_bssid.items(), key=lambda item: item[1])
            details = f"{count:,} deauthentication frames detected."
            if top:
                details += f" Highest BSSID-associated count: {top[0]} ({top[1]:,})."
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
                "details": f"{count:,} disassociation frames detected.",
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
                "details": f"SSID '{display}' is advertised by {len(bssids)} BSSIDs.",
            })

    def _check_syn_flood(self, stats):
        syn_count = stats.get("tcp_syn_count", 0)
        ack_count = stats.get("tcp_ack_count", 0)
        tcp_total = stats.get("tcp_packets", 0)
        if tcp_total >= 50 and syn_count >= 40:
            ratio = syn_count / (syn_count + ack_count + 1)
            if ratio >= self.syn_ratio_threshold:
                self.alerts.append({
                    "source": "TRAFFIC",
                    "type": "SYN_FLOOD_SUSPECTED",
                    "severity": "HIGH",
                    "details": f"High ratio of TCP SYN flags detected ({syn_count} SYN vs {ack_count} ACK in {tcp_total} packets).",
                })

    def _check_port_scan(self, stats):
        port_counts = stats.get("top_ports", {})
        if len(port_counts) >= 5:
            unique_ports = len(stats.get("port_counts", port_counts))
            if unique_ports > 30:
                self.alerts.append({
                    "source": "TRAFFIC",
                    "type": "PORT_SCAN_SUSPECTED",
                    "severity": "MEDIUM",
                    "details": f"Traffic targeted {unique_ports} unique destination ports.",
                })

    def get_alerts(self):
        return self.alerts

    def clear_alerts(self):
        self.alerts.clear()
