import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

try:
    from scapy.all import sniff, wrpcap, conf
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11Deauth,
        Dot11ProbeReq,
        Dot11ProbeResp,
        Dot11AssoReq,
        Dot11Auth,
        RadioTap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"


def require_scapy():
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed in this Python environment.")
        print("[!] Install it by running:")
        print("    pip install scapy")
        sys.exit(1)


def is_root():
    if IS_LINUX:
        return os.geteuid() == 0
    elif IS_WINDOWS:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return False


def find_wlan_helper():
    cmd = shutil.which("WlanHelper.exe") or shutil.which("WlanHelper")
    if cmd:
        return cmd
    candidates = [
        r"C:\Windows\System32\WlanHelper.exe",
        r"C:\Windows\System32\Npcap\WlanHelper.exe",
        r"C:\Program Files\Npcap\WlanHelper.exe",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def ensure_npcap_dot11():
    if not IS_WINDOWS:
        return
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
        )
        val, _ = winreg.QueryValueEx(key, "Dot11Support")
        if val == 0:
            winreg.SetValueEx(key, "Dot11Support", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except Exception:
        pass


def _win_check_monitor_support(name, desc=""):
    d = desc.lower()
    chipsets = [
        "8811", "8812", "8814", "8821", "ar9271", "rt3070", "rt5370",
        "mt7601", "alfa", "rtl8811", "rtl8812", "rtl8814", "rtl8821",
        "atheros", "ralink", "mediatek"
    ]
    if any(k in d for k in chipsets):
        return True
    helper = find_wlan_helper()
    if helper:
        try:
            res = subprocess.run([helper, name, "modes"], capture_output=True, text=True, timeout=0.8)
            if "monitor" in (res.stdout or "").lower():
                return True
        except Exception:
            pass
    return False


def _win_set_monitor_mode(interface_name, guid=None, enable=True, channel=None):
    helper = find_wlan_helper()
    if not helper:
        return False
    targets = []
    if guid:
        clean_guid = guid.replace("{", "").replace("}", "").strip()
        targets.append(clean_guid)
    if interface_name:
        targets.append(interface_name)
    mode = "monitor" if enable else "managed"

    success = False
    for target in targets:
        try:
            res = subprocess.run(
                [helper, target, "mode", mode],
                capture_output=True,
                text=True,
                timeout=8,
            )
            out = (res.stdout or "") + (res.stderr or "")
            if "success" in out.lower() or (res.returncode == 0 and "error" not in out.lower() and "fail" not in out.lower()):
                success = True
                if enable and channel:
                    if channel <= 14:
                        subprocess.run(
                            [helper, target, "channel", str(channel)],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                    else:
                        ch_res = subprocess.run(
                            [helper, target, "channel", str(channel)],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if ch_res.returncode != 0:
                            freq = 5000 + 5 * channel
                            subprocess.run(
                                [helper, target, "freq", str(freq)],
                                capture_output=True,
                                text=True,
                                timeout=5,
                            )
                break
        except Exception:
            continue
    return success


def _win_get_wlan_interfaces():
    wlan_info = {}
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            stderr=subprocess.DEVNULL,
            text=True,
            errors="ignore",
        )
        curr = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "Name":
                    if curr and curr.get("Name"):
                        wlan_info[curr["Name"]] = curr
                    curr = {"Name": v}
                elif k in ["Description", "GUID", "State", "SSID", "AP BSSID",
                            "Band", "Channel", "Radio type", "Signal", "Rssi"]:
                    curr[k] = v
        if curr and curr.get("Name"):
            wlan_info[curr["Name"]] = curr
    except Exception:
        pass

    adapters = []
    seen = set()
    for dev in conf.ifaces.values():
        name = getattr(dev, "name", "")
        desc = getattr(dev, "description", "")
        netw = getattr(dev, "network_name", name)
        if any(x in name for x in ["-0000", "Pseudo", "Kernel Debug", "Miniport"]):
            continue
        if name.startswith("\\Device\\"):
            continue
        is_wifi = "wi-fi" in name.lower() or "wireless" in desc.lower() or "802.11" in desc.lower()
        if not is_wifi and name not in wlan_info:
            continue
        if name in seen:
            continue
        seen.add(name)

        guid = None
        if "{" in netw and "}" in netw:
            guid = netw[netw.find("{") + 1:netw.find("}")]

        info = wlan_info.get(name, {})
        full_desc = info.get("Description") or desc
        can_monitor = _win_check_monitor_support(name, full_desc)

        adapters.append({
            "name": name,
            "description": full_desc,
            "guid": info.get("GUID") or guid,
            "device": netw,
            "state": info.get("State", "disconnected"),
            "ssid": info.get("SSID", ""),
            "bssid": info.get("AP BSSID", ""),
            "channel": info.get("Channel", ""),
            "band": info.get("Band", ""),
            "signal": info.get("Signal", ""),
            "radio_type": info.get("Radio type", ""),
            "monitor_support": can_monitor,
        })

    mon_adapters = [a for a in adapters if a.get("monitor_support")]
    other_connected = [a for a in adapters if not a.get("monitor_support") and a.get("state") == "connected"]
    other_disconnected = [a for a in adapters if not a.get("monitor_support") and a.get("state") != "connected"]
    return mon_adapters + other_connected + other_disconnected


def _linux_get_wlan_interfaces():
    adapters = []
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return adapters

    for iface in sorted(os.listdir(net_dir)):
        phy_path = os.path.join(net_dir, iface, "phy80211")
        wireless_path = os.path.join(net_dir, iface, "wireless")
        is_wifi = os.path.isdir(phy_path) or os.path.isdir(wireless_path)
        if not is_wifi:
            continue

        info = {
            "name": iface,
            "description": "",
            "guid": None,
            "device": iface,
            "state": "disconnected",
            "ssid": "",
            "bssid": "",
            "channel": "",
            "band": "",
            "signal": "",
            "radio_type": "",
            "monitor_support": False,
        }

        driver_link = os.path.join(net_dir, iface, "device", "driver")
        if os.path.islink(driver_link):
            info["description"] = os.path.basename(os.readlink(driver_link))

        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "info"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    mode = line.split("type ", 1)[1].strip()
                    if mode == "monitor":
                        info["state"] = "monitor"
                    elif mode == "managed":
                        info["state"] = "managed"
                elif line.startswith("channel "):
                    m = re.match(r"channel\s+(\d+)", line)
                    if m:
                        info["channel"] = m.group(1)
                        ch = int(m.group(1))
                        info["band"] = "5 GHz" if ch > 14 else "2.4 GHz"
        except Exception:
            pass

        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "link"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            if "Not connected" not in out:
                info["state"] = "connected"
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("SSID:"):
                        info["ssid"] = line.split(":", 1)[1].strip()
                    elif line.startswith("signal:"):
                        info["signal"] = line.split(":", 1)[1].strip()
                    elif "Connected to" in line:
                        m = re.search(r"([0-9a-fA-F:]{17})", line)
                        if m:
                            info["bssid"] = m.group(1)
        except Exception:
            pass

        try:
            phy_name = None
            phy_index_path = os.path.join(net_dir, iface, "phy80211", "name")
            if os.path.isfile(phy_index_path):
                with open(phy_index_path) as f:
                    phy_name = f.read().strip()
            if not phy_name:
                out = subprocess.check_output(
                    ["iw", "dev", iface, "info"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                for line in out.splitlines():
                    if "wiphy" in line:
                        idx = line.strip().split()[-1]
                        phy_name = f"phy{idx}"
                        break

            if phy_name:
                out = subprocess.check_output(
                    ["iw", "phy", phy_name, "info"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                if "* monitor" in out.lower():
                    info["monitor_support"] = True
        except Exception:
            pass

        if not info["monitor_support"] and shutil.which("airmon-ng"):
            info["monitor_support"] = True

        adapters.append(info)

    return adapters


def _linux_set_monitor_mode(interface, enable=True, channel=None):
    if not is_root():
        print("[!] Root privileges required to change interface mode on Linux.")
        return False

    if enable:
        if shutil.which("airmon-ng"):
            print(f"[+] Using airmon-ng to enable monitor mode on {interface}...")
            try:
                subprocess.run(
                    ["airmon-ng", "check", "kill"],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception:
                pass

            try:
                res = subprocess.run(
                    ["airmon-ng", "start", interface],
                    capture_output=True, text=True, timeout=15,
                )
                out = (res.stdout or "") + (res.stderr or "")

                mon_iface = interface + "mon"
                if os.path.isdir(f"/sys/class/net/{mon_iface}"):
                    print(f"[+] Monitor interface created: {mon_iface}")
                    if channel:
                        _linux_set_channel(mon_iface, channel)
                    return mon_iface
                elif os.path.isdir(f"/sys/class/net/{interface}"):
                    if channel:
                        _linux_set_channel(interface, channel)
                    return interface
                else:
                    m = re.search(r"\(monitor mode (?:vif )?enabled(?: on \[.*?\])? for \[.*?\](\w+)\)", out)
                    if not m:
                        m = re.search(r"monitor mode (?:already )?enabled on (\w+)", out, re.I)
                    if m:
                        new_iface = m.group(1)
                        if channel:
                            _linux_set_channel(new_iface, channel)
                        return new_iface
            except Exception as e:
                print(f"[!] airmon-ng failed: {e}")

        print(f"[+] Using iw to enable monitor mode on {interface}...")
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", interface, "set", "type", "monitor"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", interface, "up"],
                           capture_output=True, timeout=5)
            if channel:
                _linux_set_channel(interface, channel)
            return interface
        except Exception as e:
            print(f"[!] iw monitor mode failed: {e}")
            return False
    else:
        if shutil.which("airmon-ng"):
            try:
                subprocess.run(
                    ["airmon-ng", "stop", interface],
                    capture_output=True, text=True, timeout=15,
                )
                return True
            except Exception:
                pass

        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", interface, "up"],
                           capture_output=True, timeout=5)
            if shutil.which("systemctl"):
                subprocess.run(
                    ["systemctl", "restart", "NetworkManager"],
                    capture_output=True, timeout=10,
                )
            return True
        except Exception:
            return False


def _linux_set_channel(interface, channel):
    try:
        subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        try:
            subprocess.run(
                ["iwconfig", interface, "channel", str(channel)],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass


def _linux_scan_networks(interface=None):
    networks = []
    if not is_root():
        return networks

    if not interface:
        adapters = _linux_get_wlan_interfaces()
        managed = [a for a in adapters if a["state"] in ("managed", "connected")]
        if managed:
            interface = managed[0]["name"]
        elif adapters:
            interface = adapters[0]["name"]
        else:
            return networks

    try:
        subprocess.run(
            ["iw", "dev", interface, "scan", "trigger"],
            capture_output=True, timeout=5,
        )
        time.sleep(2)
        out = subprocess.check_output(
            ["iw", "dev", interface, "scan", "dump"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except Exception:
        try:
            out = subprocess.check_output(
                ["iw", "dev", interface, "scan"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            )
        except Exception:
            return networks

    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if current and current.get("BSSID"):
                networks.append(current)
            bssid_match = re.match(r"BSS\s+([0-9a-fA-F:]{17})", line)
            current = {
                "BSSID": bssid_match.group(1).upper() if bssid_match else "",
                "SSID": "",
                "Signal": "",
                "Channel": "",
                "Band": "",
                "Authentication": "",
                "Encryption": "",
            }
        elif line.startswith("SSID:"):
            current["SSID"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            current["Signal"] = line.split(":", 1)[1].strip()
        elif line.startswith("DS Parameter set: channel"):
            ch = line.split("channel", 1)[1].strip()
            current["Channel"] = ch
            try:
                current["Band"] = "5 GHz" if int(ch) > 14 else "2.4 GHz"
            except ValueError:
                pass
        elif "* primary channel:" in line:
            ch = line.split(":", 1)[1].strip()
            current["Channel"] = current.get("Channel") or ch
        elif "RSN:" in line or "WPA:" in line:
            if "RSN:" in line:
                current["Authentication"] = "WPA2-Personal"
                current["Encryption"] = "CCMP"
            elif "WPA:" in line:
                current["Authentication"] = "WPA-Personal"
                current["Encryption"] = "TKIP"
        elif "Group cipher:" in line:
            current["Encryption"] = line.split(":", 1)[1].strip()
        elif "Authentication suites:" in line:
            suite = line.split(":", 1)[1].strip()
            if "SAE" in suite:
                current["Authentication"] = "WPA3-Personal"
            elif "PSK" in suite:
                auth_prefix = "WPA2" if "RSN" in current.get("Authentication", "") or current.get("Authentication", "").startswith("WPA2") else "WPA"
                current["Authentication"] = f"{auth_prefix}-Personal"
            elif "802.1X" in suite or "EAP" in suite:
                current["Authentication"] = "WPA2-Enterprise"

    if current and current.get("BSSID"):
        networks.append(current)

    for net in networks:
        if not net.get("Authentication"):
            net["Authentication"] = "Open"
            net["Encryption"] = "None"

    return networks


def get_wlan_interfaces():
    require_scapy()
    if IS_WINDOWS:
        return _win_get_wlan_interfaces()
    elif IS_LINUX:
        return _linux_get_wlan_interfaces()
    else:
        print(f"[!] Unsupported platform: {sys.platform}")
        return []


def check_monitor_support(name, desc=""):
    if IS_WINDOWS:
        return _win_check_monitor_support(name, desc)
    elif IS_LINUX:
        adapters = _linux_get_wlan_interfaces()
        for a in adapters:
            if a["name"] == name:
                return a["monitor_support"]
    return False


def set_monitor_mode(interface_name, guid=None, enable=True, channel=None):
    if IS_WINDOWS:
        return _win_set_monitor_mode(interface_name, guid=guid, enable=enable, channel=channel)
    elif IS_LINUX:
        return _linux_set_monitor_mode(interface_name, enable=enable, channel=channel)
    return False


def scan_visible_networks(interface=None):
    if IS_WINDOWS:
        return _win_scan_networks()
    elif IS_LINUX:
        return _linux_scan_networks(interface)
    return []


def _win_scan_networks():
    try:
        try:
            import ctypes
            wlan = ctypes.windll.wlanapi
            client_handle = ctypes.c_void_p()
            neg = ctypes.c_ulong()
            if wlan.WlanOpenHandle(2, None, ctypes.byref(neg), ctypes.byref(client_handle)) == 0:
                class GUID(ctypes.Structure):
                    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
                class WLAN_INTERFACE_INFO(ctypes.Structure):
                    _fields_ = [("InterfaceGuid", GUID),
                                ("strInterfaceDescription", ctypes.c_wchar * 256),
                                ("isState", ctypes.c_int)]
                p_info = ctypes.c_void_p()
                wlan.WlanEnumInterfaces(client_handle, None, ctypes.byref(p_info))
                if p_info and p_info.value:
                    num = ctypes.c_ulong.from_address(p_info.value).value
                    base_ptr = p_info.value + 8
                    for i in range(num):
                        guid_ptr = ctypes.c_void_p(base_ptr + (i * ctypes.sizeof(WLAN_INTERFACE_INFO)))
                        wlan.WlanScan(client_handle, guid_ptr, None, None, None)
                wlan.WlanCloseHandle(client_handle, None)
        except Exception:
            pass

        time.sleep(1.2)

        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            stderr=subprocess.DEVNULL,
            text=True,
            errors="ignore",
        )
        networks = []
        seen = set()
        curr = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("SSID "):
                if curr and curr.get("SSID") and curr.get("BSSID"):
                    sig = (curr.get("SSID"), curr.get("BSSID"))
                    if sig not in seen:
                        seen.add(sig)
                        networks.append(curr)
                curr = {"SSID": line.split(":", 1)[1].strip()}
            elif line.startswith("BSSID "):
                curr["BSSID"] = line.split(":", 1)[1].strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k in ["Network type", "Authentication", "Encryption", "Signal",
                          "Radio type", "Band", "Channel"]:
                    curr[k] = v
        if curr and curr.get("SSID") and curr.get("BSSID"):
            sig = (curr.get("SSID"), curr.get("BSSID"))
            if sig not in seen:
                networks.append(curr)
        return networks
    except Exception:
        return []


def list_interfaces():
    adapters = get_wlan_interfaces()
    print("\n[+] Available Wireless Interfaces:")
    for i, a in enumerate(adapters, 1):
        status = []
        if a["monitor_support"]:
            status.append("MONITOR MODE READY")
        else:
            status.append("MANAGED MODE ONLY")

        if a["state"] == "connected":
            status.append(f"Connected: '{a['ssid']}'")
            if a["bssid"]:
                status.append(f"BSSID: {a['bssid']}")
            if a["channel"]:
                status.append(f"CH: {a['channel']}")
            if a["signal"]:
                status.append(f"Signal: {a['signal']}")
        elif a["state"] == "monitor":
            status.append("IN MONITOR MODE")
            if a["channel"]:
                status.append(f"CH: {a['channel']}")
        else:
            status.append("Disconnected")

        print(f"  [{i}] {a['name']} ({a['description']})")
        print(f"      {' | '.join(status)}")
        print(f"      Device: {a['device']}\n")


def save_packets(packets, output_path):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Saved {len(packets)} packets to: {output_path}")


def analyze_pcap(filepath):
    try:
        from analyzers.pcap_importer import PcapImporter
        from detection.engine import DetectionEngine
    except ImportError as err:
        print(f"[!] Could not import analysis modules: {err}")
        return

    print("\n" + "=" * 30 + " AUTOMATED ANALYSIS " + "=" * 30)
    importer = PcapImporter(filepath)
    if not importer.import_file():
        print("[-] Failed to load capture for analysis.")
        return

    stats = importer.get_summary()
    print(f"\n[+] Extracted Stats Summary:\n{json.dumps(stats, indent=2)}")

    engine = DetectionEngine()
    engine.analyze_pcap_stats(stats)

    alerts = engine.get_alerts()
    print("\n" + "=" * 30 + " DETECTION ALERTS " + "=" * 30)
    if not alerts:
        print("[+] No anomalies detected.")
    else:
        for idx, alert in enumerate(alerts, 1):
            print(f"[{idx}] [{alert['severity']}] {alert['source']} - {alert['type']}")
            print(f"    Details: {alert['details']}\n")


def _make_live_callback(verbose=True):
    stats = {
        "count": 0,
        "beacons": 0,
        "deauths": 0,
        "probes": 0,
        "data": 0,
        "other": 0,
        "ssids_seen": set(),
        "start": time.time(),
    }

    def callback(pkt):
        stats["count"] += 1
        elapsed = time.time() - stats["start"]
        tag = ""

        if pkt.haslayer(Dot11):
            frame = pkt[Dot11]
            src = frame.addr2 or "??:??:??:??:??:??"
            dst = frame.addr1 or "ff:ff:ff:ff:ff:ff"
            bssid = frame.addr3 or ""

            if pkt.haslayer(Dot11Beacon):
                stats["beacons"] += 1
                ssid = _extract_ssid_from_pkt(pkt)
                display_ssid = ssid if ssid else "<Hidden>"
                stats["ssids_seen"].add(display_ssid)
                ch = _extract_channel_from_pkt(pkt)
                ch_str = f" CH:{ch}" if ch else ""
                if verbose:
                    tag = f"  BEACON  {display_ssid:<24} BSSID:{bssid}{ch_str}"

            elif pkt.haslayer(Dot11Deauth):
                stats["deauths"] += 1
                reason = pkt[Dot11Deauth].reason
                tag = f"  DEAUTH  {src} -> {dst}  reason={reason}"

            elif pkt.haslayer(Dot11ProbeReq):
                stats["probes"] += 1
                ssid = _extract_ssid_from_pkt(pkt)
                tag = f"  PROBE   {src} looking for '{ssid or '*'}'"

            elif (Dot11ProbeResp and pkt.haslayer(Dot11ProbeResp)) or (frame.type == 0 and frame.subtype == 5):
                ssid = _extract_ssid_from_pkt(pkt)
                tag = f"  PROBERESP  {bssid} -> {dst} '{ssid or ''}'"

            elif frame.type == 0:
                subtypes = {
                    0: "ASSOC_REQ", 1: "ASSOC_RESP", 2: "REASSOC_REQ",
                    3: "REASSOC_RESP", 10: "DISASSOC", 11: "AUTH", 12: "DEAUTH",
                }
                name = subtypes.get(frame.subtype, f"MGMT_{frame.subtype}")
                tag = f"  {name:<10} {src} -> {dst}"

            elif frame.type == 2:
                stats["data"] += 1
                if verbose and (stats["data"] <= 5 or stats["data"] % 25 == 0):
                    tag = f"  DATA    {src} -> {dst} ({stats['data']} data frames)"

            else:
                stats["other"] += 1

        else:
            stats["other"] += 1
            if verbose or stats["other"] <= 5 or stats["other"] % 20 == 0:
                summary = pkt.summary()[:80] if hasattr(pkt, 'summary') else "PKT"
                tag = f"  {summary}"

        if tag:
            print(f"    [{stats['count']:>5}] {elapsed:>6.1f}s{tag}")
        elif stats["count"] % 100 == 0:
            print(
                f"    [{stats['count']:>5}] {elapsed:>6.1f}s  "
                f"(beacons:{stats['beacons']} deauths:{stats['deauths']} "
                f"probes:{stats['probes']} data:{stats['data']} "
                f"SSIDs:{len(stats['ssids_seen'])})",
                end="\r", flush=True,
            )

    return callback, stats


def _extract_ssid_from_pkt(pkt):
    if not pkt.haslayer(Dot11Elt):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            raw = bytes(elt.info)
            if raw:
                return raw.decode("utf-8", errors="replace")
            return ""
        elt = elt.payload
        if not isinstance(elt, Dot11Elt):
            break
    return None


def _extract_channel_from_pkt(pkt):
    if not pkt.haslayer(Dot11Elt):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 3:
            raw = bytes(elt.info)
            if raw:
                return raw[0]
        elt = elt.payload
        if not isinstance(elt, Dot11Elt):
            break
    return None


def execute_capture(interface=None, guid=None, count=0, timeout=None,
                    bpf_filter=None, monitor=False, channel=None):
    require_scapy()

    if not is_root():
        if IS_WINDOWS:
            print("\n[!] Administrator privileges required for live packet capture on Windows (Npcap driver access).")
            print("[!] Please run your terminal as Administrator:")
            print("    Start-Process powershell -Verb runAs")
        elif IS_LINUX:
            print("\n[!] Root privileges required for live packet capture on Linux.")
            print("[!] Please run with sudo:")
            print(f"    sudo python3 {' '.join(sys.argv)}")
        return []

    if IS_WINDOWS:
        ensure_npcap_dot11()

    kwargs = {}
    target_iface = interface
    target_guid = guid
    actual_monitor_iface = None

    if IS_WINDOWS and interface:
        try:
            dev = conf.ifaces.dev_from_name(interface)
            target_iface = dev.network_name
            if not target_guid and "{" in target_iface and "}" in target_iface:
                target_guid = target_iface[target_iface.find("{") + 1:target_iface.find("}")]
        except Exception:
            target_iface = interface
        kwargs["iface"] = target_iface
    elif IS_LINUX and interface:
        kwargs["iface"] = interface

    if count and count > 0:
        kwargs["count"] = count
    if timeout and timeout > 0:
        kwargs["timeout"] = timeout
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    monitor_active = False
    if monitor:
        if IS_WINDOWS:
            print(f"[+] Setting {interface or 'adapter'} into 802.11 Monitor Mode via WlanHelper...")
            if _win_set_monitor_mode(interface, guid=target_guid, enable=True, channel=channel):
                monitor_active = True
                print("[+] Monitor mode activated successfully.")
                if channel:
                    print(f"[+] Channel tuned to {channel}.")
            else:
                print("[!] WlanHelper monitor mode activation failed or not supported by this adapter driver.")
                print("[!] Capturing in standard Promiscuous Mode.")

        elif IS_LINUX:
            print(f"[+] Setting {interface or 'adapter'} into 802.11 Monitor Mode...")
            result = _linux_set_monitor_mode(interface, enable=True, channel=channel)
            if result:
                monitor_active = True
                if isinstance(result, str) and result != interface:
                    actual_monitor_iface = result
                    kwargs["iface"] = result
                    print(f"[+] Monitor mode activated on {result}.")
                else:
                    print(f"[+] Monitor mode activated on {interface}.")
                if channel:
                    print(f"[+] Channel tuned to {channel}.")
            else:
                print("[!] Monitor mode activation failed.")
                print("[!] Capturing in standard mode.")

    if monitor_active:
        kwargs["monitor"] = True
        if IS_WINDOWS:
            try:
                dev = conf.ifaces.dev_from_name(interface)
                dev.raw80211 = True
            except Exception:
                pass

    desc = []
    capture_iface = actual_monitor_iface or interface
    if capture_iface:
        desc.append(f"interface={capture_iface}")
    if monitor_active:
        desc.append("mode=802.11 monitor")
    elif monitor:
        desc.append("mode=promiscuous (fallback)")
    else:
        desc.append("mode=managed/promiscuous")
    if channel and monitor_active:
        desc.append(f"channel={channel}")
    if count:
        desc.append(f"count={count}")
    if timeout:
        desc.append(f"timeout={timeout}s")
    if bpf_filter:
        desc.append(f"filter='{bpf_filter}'")

    print(f"\n[+] Starting live packet capture ({', '.join(desc)})...")
    print("[+] Press Ctrl+C at any time to finish and save.")
    print()

    live_callback, live_stats = _make_live_callback(verbose=monitor_active)
    kwargs["prn"] = live_callback
    kwargs["store"] = True

    try:
        captured = sniff(**kwargs)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
        captured = []
    except PermissionError:
        print("\n[!] Permission error: Elevated privileges required to capture packets.")
        return []
    except Exception as exc:
        if kwargs.get("monitor"):
            print(f"\n[!] Monitor mode sniff failed ({exc}). Retrying in standard mode...")
            kwargs["monitor"] = False
            try:
                captured = sniff(**kwargs)
            except Exception as inner_exc:
                print(f"\n[!] Sniff error: {inner_exc}")
                return []
        else:
            print(f"\n[!] Sniff error: {exc}")
            return []
    finally:
        restore_iface = actual_monitor_iface or interface
        if monitor_active:
            if IS_WINDOWS:
                print(f"\n[+] Restoring {interface or 'adapter'} back to Managed Mode...")
                _win_set_monitor_mode(interface, guid=target_guid, enable=False)
                print("[+] Adapter restored to Managed Mode.")
            elif IS_LINUX:
                print(f"\n[+] Restoring {restore_iface or 'adapter'} back to Managed Mode...")
                _linux_set_monitor_mode(restore_iface, enable=False)
                print("[+] Adapter restored to Managed Mode.")

    elapsed = time.time() - live_stats["start"]
    print(f"\n[+] Capture finished: {len(captured)} total packets in {elapsed:.1f}s.")
    if live_stats["beacons"] or live_stats["deauths"] or live_stats["probes"]:
        print(f"    Beacons: {live_stats['beacons']}  |  Deauths: {live_stats['deauths']}  |  "
              f"Probes: {live_stats['probes']}  |  Data: {live_stats['data']}  |  "
              f"Unique SSIDs: {len(live_stats['ssids_seen'])}")
    return captured


def run_continuous(interface, guid, interval, count, bpf_filter, output_dir,
                   auto_analyze, monitor, channel):
    os.makedirs(output_dir, exist_ok=True)
    round_num = 1
    print(f"[+] Continuous capture mode active. Rotating every {interval}s.")
    try:
        while True:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}_r{round_num}.pcap"
            output_file = os.path.join(output_dir, filename)

            print(f"\n--- [Round {round_num}] Starting capture ({interval}s) ---")
            packets = execute_capture(
                interface=interface,
                guid=guid,
                count=count,
                timeout=interval,
                bpf_filter=bpf_filter,
                monitor=monitor,
                channel=channel,
            )

            if len(packets) > 0:
                save_packets(packets, output_file)
                if auto_analyze:
                    analyze_pcap(output_file)
            else:
                print("[-] No packets captured in this interval.")

            round_num += 1
    except KeyboardInterrupt:
        print("\n[+] Continuous capture stopped by user.")


def main():
    parser = argparse.ArgumentParser(
        description="Cross-Platform Wireless Packet Capture (Kali Linux / Windows 11)"
    )
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface to capture from")
    parser.add_argument("-m", "--monitor", action="store_true", default=False,
                        help="Enable 802.11 monitor mode")
    parser.add_argument("--channel", type=int, default=None,
                        help="Wi-Fi channel for monitor mode")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Maximum packet count to capture (0 = unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Capture timeout in seconds (default: 30)")
    parser.add_argument("-f", "--filter", type=str, default=None,
                        help="BPF capture filter (e.g. 'wlan', 'port 80')")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Output PCAP file path")
    parser.add_argument("-a", "--analyze", action="store_true",
                        help="Automatically run detection engine on captured PCAP")
    parser.add_argument("-r", "--rotate", type=int, default=0,
                        help="Continuous capture mode: rotation interval in seconds")
    parser.add_argument("-l", "--list-interfaces", action="store_true",
                        help="List all network interfaces and exit")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    adapters = get_wlan_interfaces()
    selected_iface = args.interface
    selected_guid = None
    selected_channel = args.channel

    if not selected_iface and sys.stdin.isatty() and adapters:
        print("\n[+] Available Wireless Interfaces:")
        for idx, a in enumerate(adapters, 1):
            tag = " [MONITOR READY]" if a["monitor_support"] else " [MANAGED ONLY]"
            status = []
            if a["state"] == "connected":
                status.append(f"Connected: {a['ssid']}")
                if a["channel"]:
                    status.append(f"CH: {a['channel']}")
                if a["signal"]:
                    status.append(f"Signal: {a['signal']}")
            elif a["state"] == "monitor":
                status.append("IN MONITOR MODE")
            else:
                status.append("Disconnected")
            print(f"  [{idx}] {a['name']} ({a['description']}){tag} - {' | '.join(status)}")

        prompt_str = f"\n[?] Select interface [1-{len(adapters)}] (default: 1): "
        val = input(prompt_str).strip()
        chosen_idx = 0
        if val.isdigit() and 1 <= int(val) <= len(adapters):
            chosen_idx = int(val) - 1
        elif val:
            for i, a in enumerate(adapters):
                if val.lower() in a["name"].lower():
                    chosen_idx = i
                    break

        selected_iface = adapters[chosen_idx]["name"]
        selected_guid = adapters[chosen_idx]["guid"]
        if not selected_channel and adapters[chosen_idx].get("channel"):
            try:
                selected_channel = int(adapters[chosen_idx]["channel"])
            except ValueError:
                pass
    elif not selected_iface and adapters:
        selected_iface = adapters[0]["name"]
        selected_guid = adapters[0]["guid"]
        if not selected_channel and adapters[0].get("channel"):
            try:
                selected_channel = int(adapters[0]["channel"])
            except ValueError:
                pass

    captures_dir = os.path.join(base_dir, "captures")
    os.makedirs(captures_dir, exist_ok=True)

    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(captures_dir, f"capture_{timestamp}.pcap")

    if args.rotate and args.rotate > 0:
        run_continuous(
            interface=selected_iface,
            guid=selected_guid,
            interval=args.rotate,
            count=args.count,
            bpf_filter=args.filter,
            output_dir=captures_dir,
            auto_analyze=args.analyze,
            monitor=args.monitor,
            channel=selected_channel,
        )
        return

    packets = execute_capture(
        interface=selected_iface,
        guid=selected_guid,
        count=args.count,
        timeout=args.timeout,
        bpf_filter=args.filter,
        monitor=args.monitor,
        channel=selected_channel,
    )

    if len(packets) > 0:
        save_packets(packets, output_file)
        if args.analyze:
            analyze_pcap(output_file)
    else:
        print("[!] No packets captured.")


if __name__ == "__main__":
    main()
