# 📡 NetScan Pro

> Real-time network scanner with full GUI — devices, ports, vulnerabilities, speed test & Wi-Fi analysis

[![Build](https://github.com/mintpro004/mint-netscanpro-V1/actions/workflows/build.yml/badge.svg)](https://github.com/mintpro004/mint-netscanpro-V1/actions)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20ChromeOS-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

| Feature | Description |
|---|---|
| 📡 **Device Discovery** | Real ARP/ICMP scan — finds every device on your network with IP, MAC, vendor, hostname, latency |
| 🗺 **Network Map** | Live topology view — router at centre, all devices as nodes |
| 🔍 **Port Scanner** | TCP connect scan — common ports, top-100, or full 1–1024 with service & banner detection |
| 🛡 **Vulnerability Analysis** | CVE-based rules — Telnet, SMBv1, RDP, MongoDB, Redis, VNC, default credentials & more |
| ⚡ **Speed Test** | Real download/upload/ping via Cloudflare — no third-party apps needed |
| 📶 **Wi-Fi Scanner** | 2.4GHz & 5GHz networks, signal strength, channel, security type |
| 🔔 **Alerts** | New device detection, offline alerts, security events |
| 🌐 **ISP & DNS Info** | Public IP, ISP name, location, DNS servers via ipinfo.io |

---

## 🚀 Quick Start (All Devices)

### 1. Prerequisites
Ensure you have **Python 3.8+** and **Nmap** installed.

| OS | Command |
|---|---|
| **Ubuntu/Debian** | `sudo apt update && sudo apt install python3 python3-pip nmap` |
| **macOS** | `brew install python nmap` |
| **Windows** | Download [Python](https://www.python.org/) and [Nmap](https://nmap.org/download.html) |

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/mintpro004/mint-netscanpro-V1.git
cd mint-netscanpro-V1

# Run setup script
# Linux / macOS / ChromeOS / Raspberry Pi:
bash scripts/setup.sh

# Windows (Admin PowerShell):
.\scripts\setup.bat
```

### 3. Launching

#### **Mode A: Web UI (Works on all devices including Mobile)**
```bash
python3 backend/scanner.py
```
Open **`http://localhost:7832`** in any browser.

#### **Mode B: Desktop App (Electron)**
```bash
cd frontend && npm start
```

---

## 📦 Device Specific Guides

### 🐧 Linux (Ubuntu, Debian, Kali)
For the most accurate device discovery (ARP scanning), the backend needs permission to use raw sockets:
```bash
sudo setcap cap_net_raw+ep $(which python3)
python3 backend/scanner.py
```
Alternatively, run with sudo: `sudo python3 backend/scanner.py`

### 🍎 macOS
Apple's security may restrict network discovery. Run with `sudo` for full functionality:
```bash
sudo python3 backend/scanner.py
```

### 💻 ChromeOS (Crostini)
1. Enable **Linux (Beta)** in Settings.
2. Follow the standard Linux installation steps.
3. Access the UI via `http://127.0.0.1:7832` in the Chrome browser.
*Note: Wi-Fi scanning is restricted by the ChromeOS VM.*

### 🥧 Raspberry Pi
NetScan Pro is ideal for a headless Raspberry Pi:
```bash
# Run in background on all interfaces
python3 backend/scanner.py --host 0.0.0.0 &
```
You can now access the scanner from any device on the network at `http://<raspberry-pi-ip>:7832`.

### 🪟 Windows
1. Run PowerShell as **Administrator**.
2. Run `.\scripts\setup.bat`.
3. If the firewall prompts you, allow **Python** to access Private and Public networks.

### 📱 Mobile (iOS / Android)
No installation needed! Just run the backend on your PC/Pi:
1. Start backend: `python3 backend/scanner.py --host 0.0.0.0`
2. Find your computer's IP (e.g., `192.168.1.15`).
3. On your phone, open: `http://192.168.1.15:7832`

---

## 🔨 Build Distributable Packages

```bash
cd frontend
npm install

# Build for current OS
npm run build:linux   # Creates .AppImage, .deb, .rpm
npm run build:mac     # Creates .dmg
npm run build:win     # Creates .exe installer
```

---

## 🔌 API Reference

The backend exposes a REST API on port `7832`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/devices` | GET | List all found devices |
| `/api/scan/start` | POST | Trigger a new network scan |
| `/api/ports/scan` | POST | Scan ports for a specific IP |
| `/api/speedtest` | GET | Run a network speed test |

---

## ⚠️ Permissions & Legal

- **Authorized access only**: Only scan networks you own or have permission to test.
- **Raw Sockets**: ARP scanning requires root/admin or `cap_net_raw` on Linux.
- **Privacy**: All data stays on your local machine.

---

## 📄 License

MIT — Copyright (c) 2025 NetScan Pro
