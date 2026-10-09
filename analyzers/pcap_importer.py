import os
from collections import Counter

try:
    from scapy.all import rdpcap, Dot11, Dot11Elt
except ImportError:
    raise SystemExit(
        "Scapy is not installed.\n"
        "Run inside your .venv:\n"
        "    pip install scapy"
    )


class PcapImporter:
    """Offline PCAP/PCAPNG analyzer."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.packets = []

        self.metadata = {
            "filename": os.path.basename(filepath),
            "filepath": os.path.abspath(filepath),
            "total_packets": 0,
            "wifi_packets": 0,
            "management_frames": 0,
            "control_frames": 0,
            "data_frames": 0,
            "beacon_frames": 0,
            "probe_request_frames": 0,
            "probe_response_frames": 0,
            "authentication_frames": 0,
            "association_frames": 0,
            "deauthentication_frames": 0,
            "disassociation_frames": 0,
            "unique_bssids": set(),
            "unique_sources": set(),
            "ssids": {},
            "bssid_packet_counts": Counter(),
            "deauth_by_bssid": Counter(),
            "disassoc_by_bssid": Counter(),
        }

    def import_file(self):
        print(f"\n[+] Loading capture: {self.filepath}")

        if not os.path.isfile(self.filepath):
            print(f"[-] File not found: {self.filepath}")
            return False

        try:
            self.packets = rdpcap(self.filepath)
        except Exception as exc:
            print(f"[-] Could not read capture: {exc}")
            return False

        self.metadata["total_packets"] = len(self.packets)

        self._parse_packets()

        print(
            f"[+] Loaded {self.metadata['total_packets']:,} packets."
        )

        return True

    def _parse_packets(self):
        for packet in self.packets:
            if not packet.haslayer(Dot11):
                continue

            self.metadata["wifi_packets"] += 1

            frame = packet[Dot11]

            source = self._clean_mac(frame.addr2)
            bssid = self._clean_mac(frame.addr3)

            if source:
                self.metadata["unique_sources"].add(source)

            if bssid:
                self.metadata["unique_bssids"].add(bssid)
                self.metadata["bssid_packet_counts"][bssid] += 1

            if frame.type == 0:
                self.metadata["management_frames"] += 1
                self._parse_management(packet, frame.subtype, bssid)

            elif frame.type == 1:
                self.metadata["control_frames"] += 1

            elif frame.type == 2:
                self.metadata["data_frames"] += 1

    def _parse_management(self, packet, subtype, bssid):
        if subtype == 8:
            self.metadata["beacon_frames"] += 1
            self._parse_beacon(packet, bssid)

        elif subtype == 4:
            self.metadata["probe_request_frames"] += 1

        elif subtype == 5:
            self.metadata["probe_response_frames"] += 1

        elif subtype in (0, 1):
            self.metadata["association_frames"] += 1

        elif subtype == 11:
            self.metadata["authentication_frames"] += 1

        elif subtype == 10:
            self.metadata["disassociation_frames"] += 1

            if bssid:
                self.metadata["disassoc_by_bssid"][bssid] += 1

        elif subtype == 12:
            self.metadata["deauthentication_frames"] += 1

            if bssid:
                self.metadata["deauth_by_bssid"][bssid] += 1

    def _parse_beacon(self, packet, bssid):
        if not bssid:
            return

        ssid = self._extract_ssid(packet)

        if ssid is None:
            return

        if ssid not in self.metadata["ssids"]:
            self.metadata["ssids"][ssid] = {
                "bssids": set(),
                "beacon_count": 0,
            }

        self.metadata["ssids"][ssid]["bssids"].add(bssid)
        self.metadata["ssids"][ssid]["beacon_count"] += 1

    @staticmethod
    def _extract_ssid(packet):
        if not packet.haslayer(Dot11Elt):
            return None

        element = packet.getlayer(Dot11Elt)

        while element is not None:
            if getattr(element, "ID", None) == 0:
                raw = bytes(element.info)

                return raw.decode(
                    "utf-8",
                    errors="replace"
                )

            element = element.payload

            if not isinstance(element, Dot11Elt):
                break

        return None

    @staticmethod
    def _clean_mac(mac):
        if not mac:
            return None

        return str(mac).upper()

    def get_summary(self):
        ssids = {}

        for ssid, data in self.metadata["ssids"].items():
            ssids[ssid] = {
                "bssids": sorted(data["bssids"]),
                "beacon_count": data["beacon_count"],
            }

        return {
            "filename": self.metadata["filename"],
            "filepath": self.metadata["filepath"],
            "total_packets": self.metadata["total_packets"],
            "wifi_packets": self.metadata["wifi_packets"],
            "management_frames": self.metadata["management_frames"],
            "control_frames": self.metadata["control_frames"],
            "data_frames": self.metadata["data_frames"],
            "beacon_frames": self.metadata["beacon_frames"],
            "probe_request_frames":
                self.metadata["probe_request_frames"],
            "probe_response_frames":
                self.metadata["probe_response_frames"],
            "authentication_frames":
                self.metadata["authentication_frames"],
            "association_frames":
                self.metadata["association_frames"],
            "deauthentication_frames":
                self.metadata["deauthentication_frames"],
            "disassociation_frames":
                self.metadata["disassociation_frames"],
            "unique_bssids":
                sorted(self.metadata["unique_bssids"]),
            "unique_sources":
                sorted(self.metadata["unique_sources"]),
            "unique_bssid_count":
                len(self.metadata["unique_bssids"]),
            "unique_source_count":
                len(self.metadata["unique_sources"]),
            "ssids": ssids,
            "bssid_packet_counts":
                dict(self.metadata["bssid_packet_counts"]),
            "deauth_by_bssid":
                dict(self.metadata["deauth_by_bssid"]),
            "disassoc_by_bssid":
                dict(self.metadata["disassoc_by_bssid"]),
        }
