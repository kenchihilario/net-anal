import os
try:
    from scapy.all import rdpcap, Dot11
except ImportError:
    print("Scapy not installed. Please install it using 'pip install scapy'.")

class PcapImporter:
    def __init__(self, filepath):
        self.filepath = filepath
        self.packets = []
        self.metadata = {
            "filename": os.path.basename(filepath),
            "total_packets": 0,
            "management_frames": 0,
            "data_frames": 0,
            "unique_bssids": set()
        }

    def import_file(self):
        print(f"[+] Loading offline PCAP file: {self.filepath}")
        if not os.path.exists(self.filepath):
            print(f"[-] File not found: {self.filepath}")
            return False

        try:
            self.packets = rdpcap(self.filepath)
            self.metadata["total_packets"] = len(self.packets)
            self._parse_metadata()
            print(f"[+] Successfully loaded {self.metadata['total_packets']} packets.")
            return True
        except Exception as e:
            print(f"[-] Error reading PCAP: {e}")
            return False

    def _parse_metadata(self):
        for pkt in self.packets:
            if pkt.haslayer(Dot11):
                # Type 0 is Management, Type 2 is Data
                if pkt.type == 0:
                    self.metadata["management_frames"] += 1
                elif pkt.type == 2:
                    self.metadata["data_frames"] += 1
                
                if pkt.addr2: # Source MAC/BSSID
                    self.metadata["unique_bssids"].add(pkt.addr2)
                    
    def get_summary(self):
        summary = self.metadata.copy()
        summary["unique_bssids"] = list(summary["unique_bssids"])
        return summary
