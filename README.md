# Wi-Fi Security Analysis and Training Platform

A defensive, isolated laboratory tool for demonstrating wireless attack detection and emulation using offline PCAP files and simulated events.

## Features
- **Offline PCAP Analysis**: Import and analyze `.pcap` files without interacting with live wireless hardware.
- **Attack Simulation**: Generate synthetic, local event logs representing common wireless attacks for detection training.
- **Detection Engine**: Correlates imported data and simulated events to produce security alerts.
- **Training Captive Portal**: A local, benign web interface for demonstrating portal detection mechanisms.

## Setup
```bash
pip install -r requirements.txt
python app/main.py
```
