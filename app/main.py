import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.pcap_importer import PcapImporter
from simulator.event_generator import EventSimulator
from detection.engine import DetectionEngine

def print_banner():
    print("""
  _  __  ___   _  _    ___   _  _   ___ 
 | |/ / | __| | \\| |  / __| | || | |_ _|
 | ' <  | _|  | .` | | (__  | __ |  | | 
 |_|\\_\\ |___| |_|\\_|  \\___| |_||_| |___|
                                                
    Kenchi Version of Offline PCAP Analysis
    """)

def main():
    print_banner()
    
    sample_pcap = "samples/test.pcap"
    importer = PcapImporter(sample_pcap)
    
    engine = DetectionEngine()
    
    if os.path.exists(sample_pcap):
        if importer.import_file():
            stats = importer.get_summary()
            print(f"\n[+] PCAP Stats: {json.dumps(stats, indent=2)}")
            engine.analyze_pcap_stats(stats)
    else:
        print(f"[!] Target PCAP not found: {sample_pcap}")

    print("\n[+] Initializing simulator...")
    sim = EventSimulator()
    sim.generate_deauth_anomaly()
    sim.generate_rogue_ap_event()
    
    engine.ingest_simulated_events(sim.get_events())
    
    print("\n" + "=" * 30 + " DETECTION ALERTS " + "=" * 30)
    alerts = engine.get_alerts()
    if not alerts:
        print("No alerts generated.")
    else:
        for i, alert in enumerate(alerts, 1):
            print(f"[{i}] [{alert['severity']}] {alert['source']} - {alert['type']}")
            print(f"    Details: {alert['details']}\n")

if __name__ == "__main__":
    main()
