import argparse
import os
import re
import socket
import subprocess
import sys
import time

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


def run_command(command, timeout=15):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return result.stdout.strip()

    except Exception as exc:
        return f"Error: {exc}"


def get_network_info():
    print("\nNETWORK INFORMATION")
    print(f"\nHostname: {socket.gethostname()}")

    print("\nInterfaces:")
    print(
        run_command([
            "ip",
            "-br",
            "addr",
        ])
    )

    print("\nRouting table:")
    print(
        run_command([
            "ip",
            "route",
        ])
    )


def discover_devices():
    print("\nDEVICE DISCOVERY")
    print("\n[*] Reading local network neighbor table...\n")

    output = run_command([
        "ip",
        "neigh",
        "show",
    ])

    if not output:
        print("[!] No devices found.")
        return

    print(
        f"{'IP ADDRESS':<18}"
        f"{'MAC ADDRESS':<20}"
        f"{'STATE':<15}"
    )

    print("-" * 53)

    for line in output.splitlines():
        parts = line.split()

        if not parts:
            continue

        ip = parts[0]
        mac = "-"
        state = "-"

        for index, value in enumerate(parts):

            if value == "lladdr":
                if index + 1 < len(parts):
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
            f"{state:<15}"
        )


def port_scan(target):
    print("\nPORT SCAN")
    print(f"\nTarget: {target}")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Could not resolve target.")
        return

    print(f"IP:     {target_ip}")

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

    print("\n[*] Scanning common TCP ports...\n")

    found = []

    for port, service in common_ports.items():
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(0.25)

        try:
            result = sock.connect_ex(
                (target_ip, port)
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
            f"OPEN"
        )

    print(
        f"\n[+] {len(found)} open port(s) detected."
    )


def get_wireless_interfaces():
    output = run_command([
        "iw",
        "dev",
    ])

    interfaces = []

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Interface "):
            interface = line.split(
                "Interface ",
                1
            )[1].strip()

            interfaces.append(interface)

    return interfaces


def choose_wireless_interface():
    interfaces = get_wireless_interfaces()

    if not interfaces:
        print(
            "\n[-] No wireless interfaces detected."
        )
        return None

    print("\nWIRELESS INTERFACES")

    for index, interface in enumerate(
        interfaces,
        start=1,
    ):
        print(
            f"  [{index}] {interface}"
        )

    while True:
        choice = input(
            "\n  Select wireless interface: "
        ).strip()

        try:
            number = int(choice)

            if 1 <= number <= len(interfaces):
                return interfaces[number - 1]

        except ValueError:
            pass

        print("[!] Invalid selection.")


def choose_channel():
    print("\nWI-FI CHANNEL")

    print("""
  [1] All channels
  [2] Specific channel
    """)

    while True:
        choice = input(
            "  Select: "
        ).strip()

        if choice == "1":
            return None

        if choice == "2":
            channel = input(
                "\n  Enter channel: "
            ).strip()

            if channel.isdigit():
                channel_number = int(channel)

                if 1 <= channel_number <= 196:
                    return channel_number

            print("[!] Invalid channel.")
            continue

        print("[!] Invalid selection.")


def start_monitor_mode(interface):
    print(
        f"\n[*] Preparing {interface} "
        f"for monitor mode..."
    )

    print(
        "[*] Stopping processes that may "
        "interfere with monitor mode..."
    )

    subprocess.run(
        [
            "sudo",
            "airmon-ng",
            "check",
            "kill",
        ],
        text=True,
    )

    time.sleep(1)

    print(
        f"\n[*] Starting monitor mode on {interface}..."
    )

    result = subprocess.run(
        [
            "sudo",
            "airmon-ng",
            "start",
            interface,
        ],
        capture_output=True,
        text=True,
    )

    print(result.stdout)

    if result.returncode != 0:
        print(result.stderr)
        return None

    interfaces = get_wireless_interfaces()

    monitor_interface = None

    for name in interfaces:
        if name.endswith("mon"):
            monitor_interface = name
            break

    if monitor_interface is None:
        possible_name = interface + "mon"

        if possible_name in interfaces:
            monitor_interface = possible_name

    if monitor_interface is None:
        print(
            "[-] Could not determine monitor "
            "interface."
        )

        return None

    print(
        f"[+] Monitor interface: "
        f"{monitor_interface}"
    )

    return monitor_interface


def stop_monitor_mode(monitor_interface):
    print(
        f"\n[*] Stopping monitor mode on "
        f"{monitor_interface}..."
    )

    subprocess.run(
        [
            "sudo",
            "airmon-ng",
            "stop",
            monitor_interface,
        ],
        text=True,
    )

    print(
        "[*] Restarting NetworkManager..."
    )

    subprocess.run(
        [
            "sudo",
            "systemctl",
            "restart",
            "NetworkManager",
        ],
        text=True,
    )

    print(
        "[+] Wireless interface restored."
    )


def parse_airodump_csv(path):
    networks = []

    if not os.path.isfile(path):
        return networks

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

    except OSError:
        return networks

    section = False

    for line in lines:

        line = line.strip()

        if line.startswith("BSSID"):
            section = True
            continue

        if not section:
            continue

        if not line:
            break

        parts = [
            item.strip()
            for item in line.split(",")
        ]

        if len(parts) < 14:
            continue

        bssid = parts[0]
        channel = parts[3]
        power = parts[8]
        privacy = parts[5]
        essid = parts[13]

        if not re.match(
            r"^[0-9A-Fa-f:]{17}$",
            bssid,
        ):
            continue

        networks.append({
            "bssid": bssid.upper(),
            "channel": channel,
            "power": power,
            "privacy": privacy,
            "essid": essid or "<hidden>",
        })

    return networks


def choose_network(networks):
    if not networks:
        print(
            "\n[!] No networks were recorded."
        )
        return None

    print("\nDETECTED NETWORKS\n")

    print(
        f"{'ID':<5}"
        f"{'BSSID':<20}"
        f"{'CH':<5}"
        f"{'PWR':<7}"
        f"{'SECURITY':<12}"
        f"ESSID"
    )

    print("-" * 75)

    for index, network in enumerate(
        networks,
        start=1,
    ):
        print(
            f"{index:<5}"
            f"{network['bssid']:<20}"
            f"{network['channel']:<5}"
            f"{network['power']:<7}"
            f"{network['privacy']:<12}"
            f"{network['essid']}"
        )

    while True:
        choice = input(
            "\n  Select network: "
        ).strip()

        try:
            number = int(choice)

            if 1 <= number <= len(networks):
                return networks[number - 1]

        except ValueError:
            pass

        print("[!] Invalid selection.")


def passive_capture(
    monitor_interface,
    network,
):
    bssid = network["bssid"]
    channel = network["channel"]
    essid = network["essid"]

    print(
        f"\n[*] Selected: {essid}"
    )

    print(
        f"[*] BSSID: {bssid}"
    )

    print(
        f"[*] Channel: {channel}"
    )

    filename = input(
        "\n  Capture filename "
        "(without extension): "
    ).strip()

    if not filename:
        filename = "kenchi-capture"

    filename = os.path.basename(
        filename
    )

    output_prefix = os.path.abspath(
        filename
    )

    print(
        f"\n[*] Starting passive capture..."
    )

    print(
        f"[*] Saving capture to: "
        f"{output_prefix}-01.cap"
    )

    print(
        "[*] No deauthentication frames "
        "will be transmitted."
    )

    print(
        "\n[*] Press Ctrl+C to stop.\n"
    )

    command = [
        "sudo",
        "airodump-ng",
        "--bssid",
        bssid,
        "--channel",
        str(channel),
        "--write",
        output_prefix,
        monitor_interface,
    ]

    try:
        subprocess.run(command)

    except KeyboardInterrupt:
        print(
            "\n\n[*] Passive capture stopped."
        )


def ask_passive_capture(
    monitor_interface,
    csv_path,
):
    networks = parse_airodump_csv(
        csv_path
    )

    print()

    answer = input(
        "Do you want to select a network "
        "for passive capture? [y/N]: "
    ).strip().lower()

    if answer not in (
        "y",
        "yes",
    ):
        return

    network = choose_network(
        networks
    )

    if not network:
        return

    passive_capture(
        monitor_interface,
        network,
    )


def wifi_scan():
    interface = choose_wireless_interface()

    if not interface:
        return

    channel = choose_channel()

    monitor_interface = start_monitor_mode(
        interface
    )

    if not monitor_interface:
        print(
            "\n[-] Failed to start monitor mode."
        )
        return

    print("\nWI-FI SCANNER")

    print(
        f"\n[*] Interface: "
        f"{monitor_interface}"
    )

    if channel is None:
        print(
            "[*] Channel mode: all channels"
        )

    else:
        print(
            f"[*] Channel: {channel}"
        )

        subprocess.run(
            [
                "sudo",
                "iw",
                "dev",
                monitor_interface,
                "set",
                "channel",
                str(channel),
            ],
            text=True,
        )

    capture_prefix = os.path.abspath(
        "kenchi-wifi-scan"
    )

    csv_path = (
        capture_prefix
        + "-01.csv"
    )

    print(
        "\n[*] Starting airodump-ng..."
    )

    print(
        "[*] Press Ctrl+C to stop scanning.\n"
    )

    try:
        command = [
            "sudo",
            "airodump-ng",
            "--write",
            capture_prefix,
            "--output-format",
            "csv",
        ]

        if channel is not None:
            command.extend([
                "--channel",
                str(channel),
            ])

        command.append(
            monitor_interface
        )

        subprocess.run(command)

    except KeyboardInterrupt:
        print(
            "\n\n[*] Scan stopped."
        )

    finally:
        ask_passive_capture(
            monitor_interface,
            csv_path,
        )

        stop_monitor_mode(
            monitor_interface
        )


def analyze_pcap(path):
    print("\nPCAP ANALYSIS")

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
        print(
            "  No beacon SSIDs found."
        )

    else:
        for ssid, info in stats["ssids"].items():

            display = (
                ssid
                if ssid
                else "<hidden>"
            )

            print(
                f"  {display:<25} "
                f"{len(info['bssids'])} BSSID(s)"
            )

    engine = DetectionEngine()

    engine.analyze_pcap_stats(
        stats
    )

    alerts = engine.get_alerts()

    print("\nALERTS")

    if not alerts:
        print(
            "\n[+] No configured anomalies detected."
        )

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

        print("""
  [1] Network Information
  [2] Discover Local Devices
  [3] Scan TCP Ports
  [4] Wi-Fi Monitor Mode / Scan
  [5] Analyze PCAP
  [6] Exit
        """)

        choice = input(
            "  Select an option: "
        ).strip()

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
                print(
                    "[!] Target cannot be empty."
                )

        elif choice == "4":

            wifi_scan()

        elif choice == "5":

            path = input(
                "\n  Enter PCAP/PCAPNG path: "
            ).strip()

            if path:

                analyze_pcap(path)

            else:

                print(
                    "[!] Path cannot be empty."
                )

        elif choice == "6":

            print(
                "\n[+] Exiting Kenchi Network Analyzer."
            )

            break

        else:

            print(
                "\n[!] Invalid option."
            )


def parse_args():

    parser = argparse.ArgumentParser(
        description="Kenchi Network Analyzer"
    )

    parser.add_argument(
        "--info",
        action="store_true",
        help="Show network information.",
    )

    parser.add_argument(
        "--discover",
        action="store_true",
        help="Show local network devices.",
    )

    parser.add_argument(
        "--ports",
        metavar="TARGET",
        help="Scan common TCP ports.",
    )

    parser.add_argument(
        "--wifi",
        action="store_true",
        help="Start Wi-Fi monitor mode and scanner.",
    )

    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Analyze PCAP/PCAPNG.",
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

    if args.wifi:

        wifi_scan()
        return 0

    if args.pcap:

        if not os.path.isfile(args.pcap):

            print(
                f"\n[-] File not found: "
                f"{args.pcap}"
            )

            return 1

        analyze_pcap(args.pcap)
        return 0

    interactive_menu()

    return 0


if __name__ == "__main__":
    sys.exit(main())
