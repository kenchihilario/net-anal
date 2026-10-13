# Kenchi — Cross-Platform Wireless Pen Tool

Real-time wireless network analyzer and packet capture tool. Works on both **Kali Linux** and **Windows 11**.

## Features

- **Cross-platform**: Full support for Kali Linux and Windows 11
- **Real monitor mode**: Uses `airmon-ng`/`iw` on Linux, `WlanHelper`/Npcap on Windows
- **Live airspace scanning**: Discovers nearby Wi-Fi networks with `iw dev scan` (Linux) or `netsh wlan` (Windows)
- **Real-time packet decode**: Shows beacons, deauths, probes, and management frames live during capture
- **Threat detection engine**: Detects deauth floods, rogue APs, SYN floods, port scans, open networks
- **PCAP analysis**: Import and analyze existing `.pcap` files
- **Continuous capture**: Rotate captures on an interval with auto-analysis

---

## Requirements

### Kali Linux
- Python 3.8+
- `iw`, `airmon-ng` (pre-installed on Kali)
- Root privileges (`sudo`)

### Windows 11
- Python 3.8+
- [Npcap](https://npcap.com/) installed with **"Support raw 802.11 traffic"** checked
- Administrator privileges

---

## Installation

```bash
git clone <your-repo-url>
cd wireless_pen
python -m venv .venv
```

### Activate & install

**Linux (Kali):**
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows 11:**
```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Usage

### Interactive mode (recommended)

**Linux:**
```bash
sudo .venv/bin/python app/main.py
```

**Windows (run PowerShell as Administrator):**
```powershell
.\.venv\Scripts\python.exe app\main.py
```

The tool will:
1. Scan the airspace and show all visible Wi-Fi networks
2. List your wireless adapters and their capabilities
3. Let you pick a target network and adapter
4. Ask whether to enable monitor mode
5. Capture packets with real-time decode output
6. Run the detection engine and report alerts

### Command-line flags

| Flag | Description |
|------|-------------|
| `-p FILE` | Analyze an existing PCAP file |
| `-i IFACE` | Specify network interface |
| `-m` | Enable 802.11 monitor mode |
| `--no-monitor` | Force managed/promiscuous mode |
| `--channel N` | Set Wi-Fi channel (1-165) |
| `-t SECS` | Capture duration (default: 15) |
| `-c COUNT` | Max packets (0 = unlimited) |
| `-f FILTER` | BPF filter (e.g. `wlan`, `port 80`) |
| `-e` | Auto-elevate to admin/sudo |


## Detection Engine

The tool automatically checks for:

| Alert | Severity | Trigger |
|-------|----------|---------|
| Open Wi-Fi | MEDIUM | Unencrypted network detected |
| Rogue AP | HIGH | Same SSID, conflicting security types |
| Deauth Flood | HIGH | 50+ deauthentication frames |
| Disassoc Flood | HIGH | 50+ disassociation frames |
| SYN Flood | HIGH | Abnormal SYN/ACK ratio |
| Port Scan | MEDIUM | 30+ unique destination ports |
| Multiple BSSIDs | INFO | Same SSID on multiple access points |

---

## Project Structure

```
wireless_pen/
├── app/
│   └── main.py              # Main interactive entry point
├── analyzers/
│   └── pcap_importer.py     # PCAP file parsing and statistics
├── detection/
│   └── engine.py            # Threat detection rules
├── capture.py               # Cross-platform capture module
├── captures/                # Saved PCAP files
├── requirements.txt
└── README.md
```

---

## Notes

- **Monitor mode** requires a wireless adapter that supports it. On Kali, most USB adapters with Atheros/Realtek chipsets work. On Windows, you need Npcap with 802.11 support.
- Without monitor mode, the tool captures in **promiscuous mode** — you'll see IP/TCP/UDP traffic but not raw 802.11 management frames (beacons, deauths, probes).
- The detection engine works on both live captures and imported PCAP files.

Still in development..
