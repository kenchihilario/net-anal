import os
from collections import Counter

try:
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11, Dot11Elt
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
except ImportError:
    raise SystemExit(
        "Scapy is not installed.\n"
        "Run inside your .venv:\n"
        "    pip install scapy"
    )

class PcapImporter:
    def __init__(self, filepath=None):
        self.filepath = filepath
        self.packets = []
        self.metadata = {
            "filename": os.path.basename(filepath) if filepath else "live_stream",
            "filepath": os.path.abspath(filepath) if filepath else "live_stream",
            "total_packets": 0,
            "wifi_packets": 0,
            "ethernet_packets": 0,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "arp_packets": 0,
            "icmp_packets": 0,
            "dns_packets": 0,
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
            "unique_source_ips": set(),
            "unique_dest_ips": set(),
            "ssids": {},
            "bssid_packet_counts": Counter(),
            "deauth_by_bssid": Counter(),
            "disassoc_by_bssid": Counter(),
            "ip_source_counts": Counter(),
            "port_counts": Counter(),
            "tcp_syn_count": 0,
            "tcp_ack_count": 0,
        }

    def import_packets(self, packets):
        self.packets = list(packets)
        self.metadata["total_packets"] = len(self.packets)
        self._parse_packets()
        return True

    def import_file(self):
        if not self.filepath:
            return False

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
        print(f"[+] Loaded {self.metadata['total_packets']:,} packets.")
        return True

    def _parse_packets(self):
        for packet in self.packets:
            if packet.haslayer(Dot11):
                self._parse_dot11(packet)
            elif packet.haslayer(Ether):
                self._parse_ether(packet)

            if packet.haslayer(IP):
                self._parse_ip(packet[IP])
            elif packet.haslayer(IPv6):
                self._parse_ipv6(packet[IPv6])

            if packet.haslayer(TCP):
                self.metadata["tcp_packets"] += 1
                tcp = packet[TCP]
                self.metadata["port_counts"][tcp.dport] += 1
                flags = int(tcp.flags)
                if flags & 0x02:
                    self.metadata["tcp_syn_count"] += 1
                if flags & 0x10:
                    self.metadata["tcp_ack_count"] += 1

            elif packet.haslayer(UDP):
                self.metadata["udp_packets"] += 1
                udp = packet[UDP]
                self.metadata["port_counts"][udp.dport] += 1

            elif packet.haslayer(ICMP):
                self.metadata["icmp_packets"] += 1

            if packet.haslayer(DNS):
                self.metadata["dns_packets"] += 1

    def _parse_dot11(self, packet):
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

    def _parse_ether(self, packet):
        self.metadata["ethernet_packets"] += 1
        eth = packet[Ether]
        src = self._clean_mac(eth.src)
        if src:
            self.metadata["unique_sources"].add(src)
        if packet.haslayer(ARP):
            self.metadata["arp_packets"] += 1

    def _parse_ip(self, ip_layer):
        self.metadata["ip_packets"] += 1
        src = ip_layer.src
        dst = ip_layer.dst
        self.metadata["unique_source_ips"].add(src)
        self.metadata["unique_dest_ips"].add(dst)
        self.metadata["ip_source_counts"][src] += 1

    def _parse_ipv6(self, ipv6_layer):
        self.metadata["ip_packets"] += 1
        src = ipv6_layer.src
        dst = ipv6_layer.dst
        self.metadata["unique_source_ips"].add(src)
        self.metadata["unique_dest_ips"].add(dst)
        self.metadata["ip_source_counts"][src] += 1

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
                return raw.decode("utf-8", errors="replace")
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
            "ethernet_packets": self.metadata["ethernet_packets"],
            "ip_packets": self.metadata["ip_packets"],
            "tcp_packets": self.metadata["tcp_packets"],
            "udp_packets": self.metadata["udp_packets"],
            "arp_packets": self.metadata["arp_packets"],
            "icmp_packets": self.metadata["icmp_packets"],
            "dns_packets": self.metadata["dns_packets"],
            "management_frames": self.metadata["management_frames"],
            "control_frames": self.metadata["control_frames"],
            "data_frames": self.metadata["data_frames"],
            "beacon_frames": self.metadata["beacon_frames"],
            "probe_request_frames": self.metadata["probe_request_frames"],
            "probe_response_frames": self.metadata["probe_response_frames"],
            "authentication_frames": self.metadata["authentication_frames"],
            "association_frames": self.metadata["association_frames"],
            "deauthentication_frames": self.metadata["deauthentication_frames"],
            "disassociation_frames": self.metadata["disassociation_frames"],
            "unique_bssids": sorted(self.metadata["unique_bssids"]),
            "unique_sources": sorted(self.metadata["unique_sources"]),
            "unique_source_ips": sorted(self.metadata["unique_source_ips"]),
            "unique_dest_ips": sorted(self.metadata["unique_dest_ips"]),
            "unique_bssid_count": len(self.metadata["unique_bssids"]),
            "unique_source_count": len(self.metadata["unique_sources"]),
            "ssids": ssids,
            "bssid_packet_counts": dict(self.metadata["bssid_packet_counts"]),
            "deauth_by_bssid": dict(self.metadata["deauth_by_bssid"]),
            "disassoc_by_bssid": dict(self.metadata["disassoc_by_bssid"]),
            "top_source_ips": dict(self.metadata["ip_source_counts"].most_common(5)),
            "top_ports": dict(self.metadata["port_counts"].most_common(5)),
            "tcp_syn_count": self.metadata["tcp_syn_count"],
            "tcp_ack_count": self.metadata["tcp_ack_count"],
        }
