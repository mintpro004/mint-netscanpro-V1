#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║          NetScan Pro — Universal Setup Script           ║
# ║  Supports: Ubuntu, Debian, ChromeOS, Fedora, macOS     ║
# ╚══════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GRN}[✓]${NC} $1"; }
warn() { echo -e "${YEL}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLU}[i]${NC} $1"; }

echo ""
echo -e "${BLU}╔══════════════════════════════════════╗${NC}"
echo -e "${BLU}║       NetScan Pro — Setup            ║${NC}"
echo -e "${BLU}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Detect OS ──
OS_TYPE=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_TYPE="$ID"
  OS_LIKE="${ID_LIKE:-}"
elif [ "$(uname)" = "Darwin" ]; then
  OS_TYPE="macos"
fi

info "Detected OS: ${OS_TYPE} (${PRETTY_NAME:-$(uname)})"

# ── ChromeOS Linux (Crostini) detection ──
IS_CHROMEOS=false
if [ -f /etc/.cros_milestone ] || grep -q "cros" /proc/version 2>/dev/null; then
  IS_CHROMEOS=true
  warn "ChromeOS/Crostini detected — some Wi-Fi features may be limited"
fi

# ── Package manager detection ──
install_pkg() {
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y "$@"
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y "$@"
  elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm "$@"
  elif command -v brew &>/dev/null; then
    brew install "$@"
  else
    warn "Could not install $* — install manually"
  fi
}

# ── Python ──
echo ""
info "Checking Python 3..."
if ! command -v python3 &>/dev/null; then
  warn "Python3 not found — installing..."
  install_pkg python3 python3-pip
else
  PYVER=$(python3 --version 2>&1 | awk '{print $2}')
  log "Python $PYVER found"
fi

# pip
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
  warn "pip not found — installing..."
  install_pkg python3-pip
fi
log "pip ready"

# ── System tools ──
echo ""
info "Installing system network tools..."

if [ "$OS_TYPE" = "macos" ]; then
  if ! command -v brew &>/dev/null; then
    warn "Homebrew not found. Install from https://brew.sh for best experience."
  else
    brew install nmap netcat 2>/dev/null || true
    log "macOS tools installed"
  fi
else
  # Linux (Debian/Ubuntu/ChromeOS/Fedora)
  PKGS="nmap net-tools iproute2 iputils-ping"
  
  # Network manager for Wi-Fi scanning
  if ! command -v nmcli &>/dev/null; then
    PKGS="$PKGS network-manager"
  fi
  
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y $PKGS 2>/dev/null || warn "Some packages failed — continuing"
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y nmap net-tools iproute iputils NetworkManager 2>/dev/null || true
  elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm nmap net-tools iproute2 networkmanager 2>/dev/null || true
  fi
  log "System tools installed"
fi

# ── Python packages ──
echo ""
info "Installing Python packages..."
cd "$(dirname "$0")/.."

pip3 install --user --quiet psutil netifaces 2>/dev/null || \
  python3 -m pip install --user --quiet psutil netifaces 2>/dev/null || \
  warn "Could not install Python packages automatically — try: pip3 install psutil netifaces"

# Try scapy (optional, needs root for full ARP)
pip3 install --user --quiet scapy 2>/dev/null || true

log "Python packages installed"

# ── Node.js / npm ──
echo ""
info "Checking Node.js..."
if ! command -v node &>/dev/null; then
  warn "Node.js not found."
  if [ "$OS_TYPE" = "macos" ]; then
    warn "Install from: https://nodejs.org or run: brew install node"
  else
    # Use NodeSource for Debian/Ubuntu
    if command -v apt-get &>/dev/null; then
      info "Installing Node.js 20 via NodeSource..."
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null
      sudo apt-get install -y nodejs 2>/dev/null
    else
      warn "Install Node.js from: https://nodejs.org"
    fi
  fi
else
  NODEVER=$(node --version)
  log "Node.js $NODEVER found"
fi

if command -v npm &>/dev/null; then
  log "npm $(npm --version) found"
fi

# ── Install npm dependencies ──
echo ""
info "Installing Electron & build dependencies..."
cd frontend
if command -v npm &>/dev/null; then
  npm install --silent
  log "npm dependencies installed"
else
  warn "npm not available — skipping Electron install. GUI mode won't work without Node.js."
fi
cd ..

# ── Desktop shortcut (Linux) ──
if [ "$OS_TYPE" != "macos" ] && [ -d "$HOME/.local/share/applications" ]; then
  echo ""
  info "Creating desktop shortcut..."
  INSTALL_DIR="$(pwd)"
  cat > "$HOME/.local/share/applications/netscan-pro.desktop" << EOF
[Desktop Entry]
Name=NetScan Pro
Comment=Network Scanner & Monitor
Exec=bash -c "cd $INSTALL_DIR && python3 backend/scanner.py & sleep 2 && xdg-open http://127.0.0.1:7832 || sensible-browser http://127.0.0.1:7832"
Icon=$INSTALL_DIR/assets/icon.png
Terminal=false
Type=Application
Categories=Network;System;
StartupNotify=true
EOF
  chmod +x "$HOME/.local/share/applications/netscan-pro.desktop"
  log "Desktop shortcut created"
fi

# ── Permissions note ──
echo ""
warn "For full scanning (ARP, ICMP), raw socket access may be needed:"
if [ "$OS_TYPE" = "macos" ]; then
  echo "  • Run with sudo for ARP scanning: sudo python3 backend/scanner.py"
else
  echo "  • Grant cap_net_raw: sudo setcap cap_net_raw+ep \$(which python3)"
  echo "  • Or just run with: sudo python3 backend/scanner.py"
fi

# ── Done ──
echo ""
echo -e "${GRN}╔══════════════════════════════════════╗${NC}"
echo -e "${GRN}║        Setup complete! ✓             ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════╝${NC}"
echo ""
echo "  Run backend only (web browser UI):"
echo -e "    ${BLU}python3 backend/scanner.py${NC}"
echo "  Then open: http://127.0.0.1:7832"
echo ""
echo "  Run as desktop GUI app (Electron):"
echo -e "    ${BLU}cd frontend && npm start${NC}"
echo ""
echo "  Build distributable packages:"
echo -e "    ${BLU}cd frontend && npm run build:linux${NC}   # AppImage + .deb"
echo -e "    ${BLU}cd frontend && npm run build:mac${NC}     # .dmg"
echo -e "    ${BLU}cd frontend && npm run build:win${NC}     # .exe installer"
echo ""
