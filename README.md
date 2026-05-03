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

## 🚀 Quick Start

### Option A — Installer (Recommended)

Download the latest release for your platform from [Releases](https://github.com/mintpro004/mint-netscanpro-V1/releases):

| Platform | Download |
|---|---|
| Ubuntu / Debian | `.deb` package |
| Any Linux | `.AppImage` (no install needed) |
| Fedora / RHEL | `.rpm` package |
| macOS | `.dmg` |
| Windows | `.exe` installer |

---

### Option B — Run from source

**1. Clone the repo**
```bash
git clone https://github.com/mintpro004/mint-netscanpro-V1.git
cd mint-netscanpro-V1
```

**2. Run the setup script**
```bash
# Linux / macOS / ChromeOS
bash scripts/setup.sh

# Windows
scripts\setup.bat
```

**3. Start the app**

```bash
# Web UI mode (works everywhere including mobile browsers)
python3 backend/scanner.py
# → Open http://127.0.0.1:7832 in any browser

# Desktop GUI mode (requires Node.js)
cd frontend && npm start
```

---

## 📦 Platform Guide

### 🐧 Ubuntu / Debian

```bash
# Install .deb (from Releases page)
sudo dpkg -i netscan-pro_1.0.0_amd64.deb

# Or from source
sudo apt-get install python3 python3-pip nmap net-tools
bash scripts/setup.sh
```

For full ARP scanning (finds devices that block ICMP):
```bash
sudo setcap cap_net_raw+ep $(which python3)
# or
sudo python3 backend/scanner.py
```

---

### 💻 ChromeOS (Crostini Linux)

```bash
# Enable Linux in ChromeOS Settings → Advanced → Developers
# Open the Linux Terminal, then:
git clone https://github.com/mintpro004/mint-netscanpro-V1.git
cd mint-netscanpro-V1
bash scripts/setup.sh
python3 backend/scanner.py
# Open Chrome → http://127.0.0.1:7832
```

> **Note:** Wi-Fi scanning is limited on ChromeOS — the web UI still works fully for device discovery, port scanning, speed test and vulnerability analysis.

---

### 🍎 macOS

```bash
# Option 1: Download the .dmg from Releases

# Option 2: From source
brew install python3 nmap
git clone https://github.com/mintpro004/mint-netscanpro-V1.git
cd mint-netscanpro-V1 && bash scripts/setup.sh
```

For ARP scanning on macOS you may need to run with sudo:
```bash
sudo python3 backend/scanner.py
```

---

### 🪟 Windows

1. Download and run the `.exe` installer from [Releases](https://github.com/mintpro004/mint-netscanpro-V1/releases)
2. Run as **Administrator** for full scanning capability
3. Allow through Windows Firewall when prompted

Or from source (PowerShell as Administrator):
```powershell
git clone https://github.com/mintpro004/mint-netscanpro-V1.git
cd mint-netscanpro-V1
.\scripts\setup.bat
```

---

### 📱 Mobile (iOS / Android)

NetScan Pro doesn't need an app install on mobile. Run the backend on any machine on your network:

```bash
# On your Linux/Mac/Windows machine — bind to all interfaces:
python3 backend/scanner.py --host 0.0.0.0
```

Then on your phone, open:
```
http://YOUR_COMPUTER_IP:7832
```

The web UI is fully responsive and works on mobile browsers.

---

## 🔨 Build Distributable Packages

```bash
cd frontend
npm install

# Linux (.AppImage + .deb + .rpm)
npm run build:linux

# macOS (.dmg)
npm run build:mac

# Windows (.exe installer)
npm run build:win

# All platforms (needs Linux host for cross-compile)
npm run build:all
```

Built packages appear in `frontend/dist/`.

---

## 🏗 Project Structure

```
netscan-pro/
├── backend/
│   ├── scanner.py          # Python backend — all scanning logic & HTTP API
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── main.js             # Electron main process (desktop GUI)
│   ├── package.json        # Electron + build config (all platforms)
│   └── public/
│       └── index.html      # Full web UI (also served by backend)
├── scripts/
│   ├── setup.sh            # Linux/macOS/ChromeOS setup
│   └── setup.bat           # Windows setup
├── assets/
│   └── icon.*              # App icons (png/ico/icns)
├── .github/
│   └── workflows/
│       └── build.yml       # CI/CD — auto-builds all platforms on tag push
└── README.md
```

---

## 🔌 API Reference

The Python backend exposes a local REST API on `http://127.0.0.1:7832`:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/interfaces` | Network interfaces & CIDRs |
| GET | `/api/devices` | All discovered devices |
| POST | `/api/scan/start` | Start network scan `{"cidr": "192.168.1.0/24"}` |
| GET | `/api/scan/status` | Scan progress & device count |
| POST | `/api/ports/scan` | Port scan `{"ip": "x.x.x.x", "range": "common"}` |
| GET | `/api/vulnerabilities` | CVE-based findings for all devices |
| GET | `/api/wifi` | Wi-Fi networks |
| GET | `/api/speedtest` | Run speed test |
| GET | `/api/public` | Public IP & ISP info |
| GET | `/api/dns` | DNS servers |
| GET | `/api/alerts` | Event alerts |
| GET | `/api/system` | CPU/RAM/network stats |

---

## ⚠️ Permissions & Legal

- **Legal use only** — only scan networks you own or have explicit permission to test
- Raw socket scanning (ARP) requires elevated permissions on most OS
- The app never sends your network data anywhere — all scanning is local
- Speed test uses Cloudflare's public test endpoint (10MB download, 2MB upload)

---

## 🤝 Contributing

```bash
# Fork → clone → branch → PR
git checkout -b feature/my-feature
# Make changes
git commit -m "feat: add my feature"
git push origin feature/my-feature
# Open a PR on GitHub
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)
