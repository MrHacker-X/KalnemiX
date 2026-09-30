#!/usr/bin/env bash
# KalnemiX v2.0 - dependency installer
# https://github.com/MrHacker-X
# Detects your package manager; never force-installs; verifies at the end.

set -u

YL='\033[38;5;179m'; GR='\033[38;5;150m'; DM='\033[38;5;245m'; WH='\033[1;97m'; XX='\033[0m'
ok()   { echo -e "  ${GR}[✔]${XX} ${WH}$1${XX}"; }
info() { echo -e "  ${YL}[~]${XX} ${WH}$1${XX}"; }
warn() { echo -e "  ${YL}[!]${XX} ${DM}$1${XX}"; }

# ---------------------------------------------------------------- priv check
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi
fi

# ------------------------------------------------------------- pm detection
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
elif command -v apk >/dev/null 2>&1; then PKG="apk"
fi

is_termux() { [ -d "/data/data/com.termux/files/" ]; }

pkg_install() {
  # pkg_install <pkg>  - best-effort install, no set -e aborts
  case "$PKG" in
    apt)    $SUDO apt-get install -y "$1" >/dev/null 2>&1 ;;
    dnf)    $SUDO dnf install -y "$1" >/dev/null 2>&1 ;;
    yum)    $SUDO yum install -y "$1" >/dev/null 2>&1 ;;
    pacman) $SUDO pacman -S --noconfirm "$1" >/dev/null 2>&1 ;;
    zypper) $SUDO zypper install -y "$1" >/dev/null 2>&1 ;;
    apk)    $SUDO apk add "$1" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

pip_install() {
  # pip_install <pkg> - try PIP_BREAK_SYSTEM_PACKAGES first, fall back to venv
  if python3 -m pip install --user "$1" >/dev/null 2>&1; then
    return 0
  fi
  if python3 -m pip install --break-system-packages --user "$1" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

have() { command -v "$1" >/dev/null 2>&1; }

echo
echo -e "  ${YL}$(printf '%.0s─' {1..62})${XX}"
echo -e "  ${WH}K A L N E M I X${XX}  ${DM}setup${XX}"
echo -e "  ${YL}$(printf '%.0s─' {1..62})${XX}"
echo

if is_termux; then
  info "platform: termux"
  PKG="apt"
else
  info "platform: $(uname -s) · package manager: ${PKG:-none}"
fi

[ -z "$PKG" ] && ! is_termux && {
  warn "no supported package manager found (apt/dnf/yum/pacman/zypper/apk)"
  warn "install these manually: whois nmap sslscan traceroute exiftool dnsutils"
  warn "then: pip3 install requests bs4 dnspython html5lib"
  exit 1
}

# ------------------------------------------------------------------ packages
info "installing system tools…"

if is_termux; then
  apt update -y >/dev/null 2>&1
  for p in whois nmap sslscan traceroute exiftool python python-pip; do
    have "$p" || apt install -y "$p" >/dev/null 2>&1 && ok "$p" || warn "$p (skipped)"
  done
else
  case "$PKG" in
    apt)
      $SUDO apt-get update -y >/dev/null 2>&1
      for p in whois nmap sslscan traceroute libimage-exiftool-perl dnsutils; do
        pkg_install "$p" && ok "$p" || warn "$p (skipped)"
      done
      ;;
    dnf|yum)
      for p in whois nmap sslscan traceroute perl-image-exiftool bind-utils; do
        pkg_install "$p" && ok "$p" || warn "$p (skipped)"
      done
      ;;
    pacman)
      for p in whois nmap sslscan traceroute exiftool bind; do
        pkg_install "$p" && ok "$p" || warn "$p (skipped)"
      done
      ;;
    zypper)
      for p in whois nmap sslscan traceroute exiftool bind-utils; do
        pkg_install "$p" && ok "$p" || warn "$p (skipped)"
      done
      ;;
    apk)
      for p in whois nmap sslscan traceroute exiftool bind-tools; do
        pkg_install "$p" && ok "$p" || warn "$p (skipped)"
      done
      ;;
  esac
fi

# ---------------------------------------------------------------- python deps
info "installing python dependencies…"

if is_termux; then
  PIP="pip"
else
  PIP="pip3"
fi

for p in requests beautifulsoup4 dnspython html5lib; do
  if "$PIP" show "$p" >/dev/null 2>&1; then
    ok "$p (already installed)"
  else
    pip_install "$p" && ok "$p" || warn "$p (pip failed - install manually)"
  fi
done

# ---------------------------------------------------------------- verify
echo
info "verifying…"
MISSING=0
for t in whois nmap sslscan traceroute exiftool; do
  if have "$t"; then ok "$t"; else warn "$t missing (some modules will degrade)"; MISSING=$((MISSING+1)); fi
done
python3 - <<'PYEOF' || MISSING=$((MISSING+1))
import importlib
for m in ("requests", "bs4", "dns.resolver"):
    try:
        importlib.import_module(m)
    except ImportError:
        raise SystemExit(1)
PYEOF
if [ $? -eq 0 ]; then ok "python modules (requests · bs4 · dnspython)"; fi

echo
if [ "$MISSING" -eq 0 ]; then
  echo -e "  ${GR}[✔]${XX} ${WH}setup complete - run: ${YL}python3 kalnemix.py${XX}"
else
  echo -e "  ${YL}[!]${XX} ${WH}setup finished with ${MISSING} optional gap(s) - kalnemix still runs, some modules degrade gracefully"
fi
echo
