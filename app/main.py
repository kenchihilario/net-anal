import argparse
import os
import socket
import subprocess
import sys

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from analyzers.pcap_importer import PcapImporter
from detection.engine import DetectionEngine


def print_banner():
    print(r"""
  _  __  ___   _  _    ___   _  _   ___
 | |/ / | __| | \| |  / __| | || | |_ _|
 | ' <  | _|  | .` | | (__  | __ |  | |
 |_|\_\ |___| |_|\_|  \___| |_||_| |___|

             KENCHI NETWORK ANALYZER
    """)


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
        )

        return result.stdout.strip()

    except Exception as exc:
        return f"Error: {exc}"


def get_network_info():
    print("\n" + "=" * 65)
    print("                     NETWORK INFORMATION")
    print("=" * 65)

    hostname = socket.gethostname()

    print(f"\nHostname: {hostname}")

    interfaces = run_command([
        "ip",
        "-br",
        "addr",
    ])

    print("\nInterfaces:")
    print(interfaces)

    routes = run_command([
        "ip",
        "route",
    ])

    print("\nRouting table:")
    print(routes)

    print()


def discover_devices():
    print("\n" + "=" * 65)
    print("                    DEVICE DISCOVERY")
    print("=" * 65)

    print("\n[*] Looking for devices on the local network...")
    print("[*] This may take a few seconds.\n")

    output = run_command([
        "ip",
        "neigh",
        "show",
    ])

    if not output:
        print("[!] No neighbor entries found.")
        print(
            "[*] Try communicating with devices on the LAN "
            "first, then run discovery again."
        )
        return

    print(
        f"{'IP ADDRESS':<18}"
        f"{'MAC ADDRESS':<20}"
        f"{'STATE':<12}"
    )

    print("-" * 65)

    for line in output.splitlines():
        parts = line.split()

        if not parts:
            continue

        ip = parts[0]
        mac = "-"
        state = "-"

        for index, value in enumerate(parts):
            if value == "lladdr" and index + 1 < len(parts):
                mac = parts[index + 1]

            if value in (
                "REACHABLE",
                "STALE",
                "DELAY",
                "PROBE",
                "FAILED",
                "PERMANENT",
            ):
                state = value

        print(
            f"{ip:<18}"
            f"{mac:<20}"
            f"{state:<12}"
        )

    print()


def port_scan(target):
    print("\n" + "=" * 65)
    print("                       PORT SCAN")
    print("=" * 65)

    print(f"\nTarget: {target}")

    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Could not resolve target.")
        return

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
    }

    print("\nScanning common TCP ports...\n")

    found = []

    for port, service in common_ports.items():
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(0.25)

        try:
            result = sock.connect_ex(
                (target, port)
            )

            if result == 0:
                found.append(
                    (port, service)
                )

        except OSError:
            pass

        finally:
            sock.close()

    if not found:
        print("[+] No open common TCP ports detected.")
        return

    print(
        f"{'PORT':<10}"
        f"{'SERVICE':<20}"
        f"{'STATUS':<10}"
    )

    print("-" * 40)

    for port, service in found:
        print(
            f"{port:<10}"
            f"{service:<20}"
            f"{'OPEN':<10}"
        )

    print(
        f"\n[+] {len(found)} open common TCP port(s) found."
    )


def analyze_pcap(path):
    print("\n" + "=" * 65)
    print("                      PCAP ANALYSIS")
    print("=" * 65)

    importer = PcapImporter(path)

    if not importer.import_file():
        return

    stats = importer.get_summary()

    print("\nCapture statistics:")
    print(
        f"  Total packets:       "
        f"{stats['total_packets']:,}"
    )
    print(
        f"  Wi-Fi packets:       "
        f"{stats['wifi_packets']:,}"
    )
    print(
        f"  Management frames:   "
        f"{stats['management_frames']:,}"
    )
    print(
        f"  Control frames:      "
        f"{stats['control_frames']:,}"
    )
    print(
        f"  Data frames:         "
        f"{stats['data_frames']:,}"
    )
    print(
        f"  Beacon frames:       "
        f"{stats['beacon_frames']:,}"
    )
    print(
        f"  Deauthentication:    "
        f"{stats['deauthentication_frames']:,}"
    )
    print(
        f"  Disassociation:      "
        f"{stats['disassociation_frames']:,}"
    )
    print(
        f"  Unique BSSIDs:       "
        f"{stats['unique_bssid_count']:,}"
    )

    print("\nDetected SSIDs:")

    if not stats["ssids"]:
        print("  No beacon SSIDs found.")

    else:
        for ssid, info in stats["ssids"].items():
            display = ssid if ssid else "<hidden>"

            print(
                f"  {display:<25} "
                f"{len(info['bssids'])} BSSID(s)"
            )

    engine = DetectionEngine()
    engine.analyze_pcap_stats(stats)

    alerts = engine.get_alerts()

    print("\n" + "-" * 65)
    print("                         ALERTS")
    print("-" * 65)

    if not alerts:
        print("\n[+] No configured anomalies detected.")

    else:
        for number, alert in enumerate(
            alerts,
            start=1,
        ):
            print(
                f"\n[{number}] "
                f"[{alert['severity']}] "
                f"{alert['type']}"
            )

            print(
                f"    {alert['details']}"
            )


def interactive_menu():
    while True:
        print("\n" + "=" * 65)
        print("                  KENCHI NETWORK ANALYZER")
        print("=" * 65)

        print("""
  [1] Network Information
  [2] Discover Local Devices
  [3] Scan TCP Ports
  [4] Analyze PCAP
  [5] Exit
        """)

        choice = input("  Select an option: ").strip()

        if choice == "1":
            get_network_info()

        elif choice == "2":
            discover_devices()

        elif choice == "3":
            target = input(
                "\n  Enter authorized target IP/hostname: "
            ).strip()

            if target:
                port_scan(target)
            else:
                print("[!] Target cannot be empty.")

        elif choice == "4":
            path = input(
                "\n  Enter PCAP/PCAPNG path: "
            ).strip()

            if path:
                analyze_pcap(path)
            else:
                print("[!] Path cannot be empty.")

        elif choice == "5":
            print("\n[+] Exiting Kenchi Network Analyzer.")
            break

        else:
            print(
                "\n[!] Invalid option. "
                "Choose 1-5."
            )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Kenchi Network Analyzer"
    )

    parser.add_argument(
        "--info",
        action="store_true",
        help="Show local network information.",
    )

    parser.add_argument(
        "--discover",
        action="store_true",
        help="Show devices known to the local network neighbor table.",
    )

    parser.add_argument(
        "--ports",
        metavar="TARGET",
        help="Scan common TCP ports on an authorized target.",
    )

    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Analyze a PCAP or PCAPNG file.",
    )

    return parser.parse_args()


def main():
    print_banner()

    args = parse_args()

    if args.info:
        get_network_info()
        return 0

    if args.discover:
        discover_devices()
        return 0

    if args.ports:
        port_scan(args.ports)
        return 0

    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(
                f"\n[-] File not found: {args.pcap}"
            )
            return 1

        analyze_pcap(args.pcap)
        return 0

    interactive_menu()

    return 0


if __name__ == "__main__":
    sys.exit(main())
