import sys
import os
import json
import argparse
import subprocess
import time
import re
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzers.pcap_importer import PcapImporter
from detection.engine import DetectionEngine
from capture import (
    execute_capture, save_packets, get_wlan_interfaces,
    scan_visible_networks, is_root, IS_LINUX, IS_WINDOWS,
)


def print_banner():
    print(r"""
  _  __  ___   _  _    ___   _  _   ___ 
 | |/ / | __| | \| |  / __| | || | |_ _|
 | ' <  | _|  | .` | | (__  | __ |  | | 
 |_|\_\ |___| |_|\_|  \___| |_||_| |___|
                                                 
     Kenchi — Cross-Platform Wireless Analyzer
     Kali Linux + Windows 11 Ready
    """)


def format_network_table(networks, connected_bssid=""):
    lines = []
    header = f"  {'#':<4} {'SSID':<25} {'BSSID':<19} {'PWR':<8} {'CH':<5} {'BAND':<9} {'SECURITY':<22}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for idx, net in enumerate(networks, 1):
        ssid = (net.get("SSID") or "<Hidden>")[:24]
        bssid = net.get("BSSID", "")
        sig = net.get("Signal", "")
        ch = net.get("Channel", "")
        band = net.get("Band", "")
        auth = net.get("Authentication", "")
        enc = net.get("Encryption", "")
        sec = f"{auth}/{enc}"[:21] if auth else "Open"
        conn_tag = " [CONNECTED]" if connected_bssid and bssid.lower() == connected_bssid.lower() else ""
        lines.append(f"  [{idx:<2}] {ssid:<25} {bssid:<19} {sig:<8} {ch:<5} {band:<9} {sec:<22}{conn_tag}")
    return "\n".join(lines)


def elevate_privileges():
    if IS_WINDOWS:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            filtered_args = [a for a in sys.argv if a not in ("-e", "--elevate")]
            cmd_args = " ".join([f'"{a}"' for a in filtered_args[1:]])
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{filtered_args[0]}" {cmd_args}', None, 1,
            )
            if ret > 32:
                sys.exit(0)
            else:
                print("[!] Elevation request was cancelled or failed.")
    elif IS_LINUX:
        if not is_root():
            filtered_args = [a for a in sys.argv if a not in ("-e", "--elevate")]
            print("[+] Re-launching with sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + filtered_args)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Cross-Platform Wireless Network Analyzer")
    parser.add_argument("-p", "--pcap", type=str, default=None, help="Analyze an existing PCAP file")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("-m", "--monitor", action="store_true", default=None, help="Enable 802.11 monitor mode")
    parser.add_argument("--no-monitor", action="store_true", default=False, help="Disable monitor mode (use managed mode)")
    parser.add_argument("--channel", type=int, default=None, help="Wi-Fi channel for monitor mode")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Live capture duration in seconds (default: 15)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Max packet count (0 = unlimited)")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF capture filter")
    parser.add_argument("-e", "--elevate", action="store_true", help="Launch elevated (admin/sudo)")

    args, unknown = parser.parse_known_args()

    if args.elevate:
        elevate_privileges()

    target_pcap = args.pcap
    if not target_pcap and unknown and not unknown[0].startswith("-"):
        target_pcap = unknown[0]

    engine = DetectionEngine()

    if target_pcap:
        importer = PcapImporter(target_pcap)
        if importer.import_file():
            stats = importer.get_summary()
            print(f"\n[+] PCAP Stats: {json.dumps(stats, indent=2)}")
            engine.analyze_pcap_stats(stats)
        else:
            print(f"[!] Could not process PCAP file: {target_pcap}")
            return
    else:
        adapters = get_wlan_interfaces()

        connected_bssid = ""
        for a in adapters:
            if a.get("bssid"):
                connected_bssid = a["bssid"]
                break

        scan_iface = None
        for a in adapters:
            if a["state"] in ("connected", "managed"):
                scan_iface = a["name"]
                break

        print("[+] Scanning wireless airspace...")
        visible_nets = scan_visible_networks(interface=scan_iface)
        if visible_nets:
            print(f"\n[+] Discovered Wireless Networks ({len(visible_nets)} in range):")
            print(format_network_table(visible_nets, connected_bssid))
            print()
            engine.analyze_live_networks(visible_nets)
        else:
            if not is_root():
                if IS_LINUX:
                    print("[-] No networks found. Root privileges required for scanning on Linux.")
                    print(f"    Run: sudo python3 {' '.join(sys.argv)}")
                else:
                    print("[-] No wireless networks detected during airspace scan.")
            else:
                print("[-] No wireless networks detected during airspace scan.")

        selected_iface = args.interface
        selected_guid = None
        selected_channel = args.channel
        timeout = args.timeout
        monitor_mode = True if args.monitor is True else False

        if args.no_monitor:
            monitor_mode = False

        if adapters:
            print("[+] Available Wireless Adapters:")
            for idx, a in enumerate(adapters, 1):
                status_parts = []
                if a["monitor_support"]:
                    status_parts.append("MONITOR READY")
                else:
                    status_parts.append("MANAGED ONLY")

                if a["state"] == "connected":
                    status_parts.append(f"Connected: {a['ssid']}")
                    if a["channel"]:
                        status_parts.append(f"CH: {a['channel']}")
                    if a["signal"]:
                        status_parts.append(f"Signal: {a['signal']}")
                elif a["state"] == "monitor":
                    status_parts.append("IN MONITOR MODE")
                else:
                    status_parts.append("Disconnected")
                print(f"  [{idx}] {a['name']} ({a['description']})")
                print(f"      {' | '.join(status_parts)}\n")

        chosen_net = None
        if sys.stdin.isatty():
            if visible_nets:
                target_prompt = f"[?] Target Network [1-{len(visible_nets)}] (default: 1 - '{visible_nets[0].get('SSID')}'): "
                net_val = input(target_prompt).strip()
                target_idx = 0
                if net_val.isdigit() and 1 <= int(net_val) <= len(visible_nets):
                    target_idx = int(net_val) - 1
                chosen_net = visible_nets[target_idx]
                print(f"[+] Selected Target: {chosen_net.get('SSID')} (BSSID: {chosen_net.get('BSSID')}, Channel: {chosen_net.get('Channel')})")

                if not selected_channel and chosen_net.get("Channel"):
                    try:
                        selected_channel = int(chosen_net["Channel"])
                    except ValueError:
                        pass

            if not selected_iface and adapters:
                choice_str = input(f"[?] Select interface [1-{len(adapters)}] (default: 1): ").strip()
                chosen_idx = 0
                if choice_str.isdigit() and 1 <= int(choice_str) <= len(adapters):
                    chosen_idx = int(choice_str) - 1
                elif choice_str:
                    for i, a in enumerate(adapters):
                        if choice_str.lower() in a["name"].lower():
                            chosen_idx = i
                            break

                chosen_adapter = adapters[chosen_idx]
                selected_iface = chosen_adapter["name"]
                selected_guid = chosen_adapter["guid"]

                if args.monitor is None and not args.no_monitor:
                    if chosen_adapter["monitor_support"]:
                        mon_in = input("[?] Enable 802.11 Monitor Mode (raw beacon/deauth/management frames)? [Y/n]: ").strip().lower()
                        monitor_mode = (mon_in != "n")
                    else:
                        if IS_LINUX:
                            print(f"[!] Note: {selected_iface} may not support monitor mode with its current driver.")
                        else:
                            print(f"[!] Note: {selected_iface} operates in Managed Mode only on Windows.")
                        monitor_mode = False

                if monitor_mode:
                    default_ch = str(selected_channel) if selected_channel else (chosen_adapter.get("channel") or "36")
                    ch_prompt = f"[?] Wi-Fi Channel [1-165] (default: {default_ch}"
                    if chosen_net and chosen_net.get("Channel"):
                        ch_prompt += f" from '{chosen_net.get('SSID')}'"
                    ch_prompt += "): "
                    ch_in = input(ch_prompt).strip()
                    if ch_in.isdigit():
                        selected_channel = int(ch_in)
                    elif not selected_channel:
                        selected_channel = int(default_ch)

                dur_in = input(f"[?] Capture duration in seconds (default: {timeout}): ").strip()
                if dur_in.isdigit() and int(dur_in) > 0:
                    timeout = int(dur_in)

                if not is_root():
                    print("\n[!] WARNING: Running without administrator/root privileges.")
                    print("    Packet capture and monitor mode require elevated permissions.")
                    elev_in = input("[?] Elevate privileges now? [Y/n]: ").strip().lower()
                    if elev_in != "n":
                        elevate_privileges()
        else:
            if not selected_iface and adapters:
                chosen_adapter = adapters[0]
                selected_iface = chosen_adapter["name"]
                selected_guid = chosen_adapter["guid"]
                if args.monitor is None and not args.no_monitor:
                    monitor_mode = chosen_adapter["monitor_support"]
                if not selected_channel and chosen_adapter.get("channel"):
                    try:
                        selected_channel = int(chosen_adapter["channel"])
                    except ValueError:
                        selected_channel = 36

        if selected_iface and adapters and not selected_guid:
            for a in adapters:
                if a["name"].lower() == selected_iface.lower() or selected_iface.lower() in a["name"].lower():
                    selected_guid = a["guid"]
                    if not selected_channel and a.get("channel"):
                        try:
                            selected_channel = int(a["channel"])
                        except ValueError:
                            pass
                    break

        mode_label = "802.11 Monitor Mode" if monitor_mode else "Managed / Promiscuous Mode"
        chan_label = f", Channel: {selected_channel}" if selected_channel and monitor_mode else ""
        print(f"\n[+] Launching live real-time capture on {selected_iface or 'default'} ({mode_label}{chan_label})...")
        packets = execute_capture(
            interface=selected_iface,
            guid=selected_guid,
            count=args.count,
            timeout=timeout,
            bpf_filter=args.filter,
            monitor=monitor_mode,
            channel=selected_channel,
        )

        if packets:
            captures_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")
            os.makedirs(captures_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            cap_file = os.path.join(captures_dir, f"live_{ts}.pcap")
            save_packets(packets, cap_file)

            importer = PcapImporter(cap_file)
            importer.import_packets(packets)
            stats = importer.get_summary()
            print(f"\n[+] Live Traffic Stats:\n{json.dumps(stats, indent=2)}")
            engine.analyze_pcap_stats(stats)
        else:
            print("[!] No live packets captured during this session.")

    print("\n" + "=" * 30 + " DETECTION ALERTS " + "=" * 30)
    alerts = engine.get_alerts()
    if not alerts:
        print("[+] No anomalies detected.")
    else:
        for i, alert in enumerate(alerts, 1):
            print(f"[{i}] [{alert['severity']}] {alert['source']} - {alert['type']}")
            print(f"    Details: {alert['details']}\n")

    if sys.stdin.isatty():
        try:
            input("\n[+] Analysis complete. Press Enter to exit.")
        except (KeyboardInterrupt, EOFError):
            pass


if __name__ == "__main__":
    main()
