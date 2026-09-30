<div align="center">

# ⃤ K A L N E M I X ⃤

### *Web reconnaissance toolkit - 18 OSINT modules, zero exploitation, one menu.*

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-BSL--1.0-38;5;179?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux-38;5;150?style=flat-square)
![Modules](https://img.shields.io/badge/Recon%20Modules-18-38;5;245?style=flat-square)
![Network](https://img.shields.io/badge/Attitude-OSINT%20Only-38;5;179?style=flat-square)
![Stars](https://img.shields.io/github/stars/MrHacker-X/KalnemiX?style=flat-square&color=38;5;179)

</div>

---

## 📋 Table of Contents

- [🎯 Why KalnemiX?](#-why-kalnemix)
- [🧭 Tool Purpose](#-tool-purpose)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [✨ Features](#-features)
- [⌨️ Usage](#%EF%B8%8F-usage)
- [🖥️ Preview](#%EF%B8%8F-preview)
- [🧰 Tech Stack](#-tech-stack)
- [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [👨‍💻 Developer](#-developer)

---

## 🎯 Why KalnemiX?

> Most "web pentesting" tools on GitHub are two things at once: **broken** and **dishonest**. Broken - because they're hardcoded to 2022-era endpoints with stale cookies. Dishonest - because they ship with password gates that phone home to a Telegram channel just to let you run the code you already downloaded.
>
> **KalnemiX v2.0 removes both problems.** No password gate. No Telegram walls. No fake flicker animations. Every module was rewritten with error containment (one module failing never kills the tool), fallback paths when an external binary is missing, and a `--doctor` command that tells you exactly what's installed. What's left is an honest recon toolkit: 18 modules that read **public** information about a target, wrapped in a clean typographic UI.

---

## 🧭 Tool Purpose

**KalnemiX exists for exactly three legitimate purposes - and nothing else:**

| # | Purpose | Example |
|---|---------|---------|
| 1️⃣ | **Security research & authorized recon** | Mapping the public attack surface (DNS, whois, headers, subdomains) of systems **you own or have written permission to test** |
| 2️⃣ | **Learning & education** | Understanding how whois, DNS records, TLS certificates, HTTP headers and OSINT sources fit together |
| 3️⃣ | **CTF & lab practice** | Practicing recon methodology on lab ranges, HackTheBox-style boxes, and your own VPS |

**What this tool is NOT:** it is **not** an exploitation framework, **not** a vulnerability scanner, and **not** a way into anyone's systems. Every module reads *publicly available* information - the same data a `whois` command or a browser can see. The reverse-shell and deface-page **generators** produce files for **your own lab work**; deploying them against systems you don't own is a serious crime in nearly every jurisdiction.

**Rule of thumb:** if you don't own it and don't have written permission - don't point the tool at it.

---

## 🚀 Quick Start

```bash
git clone https://github.com/MrHacker-X/KalnemiX.git
cd KalnemiX
./setup.sh                    # installs deps (apt/dnf/pacman/zypper/apk/Termux)
python3 kalnemix.py           # interactive menu
```

No menu needed - run one module directly:

```bash
python3 kalnemix.py -m 2      # ip lookup
python3 kalnemix.py -m 6      # dns lookup
python3 kalnemix.py --doctor  # check what's installed
```

---

## 📦 Installation

### One-command setup

```bash
git clone https://github.com/MrHacker-X/KalnemiX.git
cd KalnemiX
chmod +x setup.sh
./setup.sh
python3 kalnemix.py
```

<details>
<summary><b>🛠 What setup.sh does (and doesn't do)</b></summary>

**Does:**
- Detects your package manager automatically: `apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`, or Termux
- Installs system tools: `whois`, `nmap`, `sslscan`, `traceroute`, `exiftool`, `dnsutils`
- Installs Python packages: `requests`, `beautifulsoup4`, `dnspython`, `html5lib`
- Handles PEP 668 (`--break-system-packages`) automatically with `--user` fallbacks
- **Verifies** every dependency at the end and tells you exactly what's missing

**Doesn't:**
- No `sudo` abuse - skips cleanly if a package is unavailable
- No fake progress bars, no flicker, no banner cat-walls
- **No more overwriting dnspython's `resolver.py`** - the v1.x hack that broke Termux is gone

</details>

### Supported Systems

| OS | Status | Notes |
|----|--------|-------|
| 🐧 Debian / Ubuntu / Kali | ✅ Fully supported | `apt` detected automatically |
| 🐧 Fedora / RHEL | ✅ Fully supported | `dnf`/`yum` detected automatically |
| 🐧 Arch / Manjaro | ✅ Fully supported | `pacman` detected automatically |
| 🐧 openSUSE | ✅ Fully supported | `zypper` detected automatically |
| 🐧 Alpine | ✅ Fully supported | `apk` detected automatically |
| 📱 Termux (Android) | ✅ Fully supported | v1.x resolver hack removed |
| 🪟 Windows | ❌ Not supported | Use WSL |

> 💡 After install, run `python3 kalnemix.py --doctor` to see exactly which modules are fully enabled. KalnemiX **degrades gracefully**: missing `sslscan` only disables module 15, everything else keeps working.

---

## ✨ Features

| | Feature | Description |
|---|---------|-------------|
| 🔍 | **18 recon modules** | whois → IP → subdomains → headers → robots → DNS → PTR → traceroute → ports → links → paths → hashes → EXIF → subnets → TLS → OS → 2 generators |
| 🧭 | **Direct module CLI** | `-m 6` runs DNS lookup without opening the menu |
| 🩺 | **`--doctor` command** | Instant environment report: what's installed, what's missing, what degrades |
| 🛟 | **Graceful degradation** | Missing `whois`? Falls back to RDAP. Missing `dnspython`? Falls back to `nslookup`. Missing `exiftool`? Basic metadata fallback |
| 🧱 | **Error containment** | A module crashing can never kill the menu - every module is isolated |
| 🛡️ | **Safe exit everywhere** | Ctrl+C / Ctrl+D always exits clean - no tracebacks, no half-written files |
| 🔀 | **Multi-source subdomain enum** | crt.sh + hackertarget merged and deduplicated |
| 🎨 | **Typographic UI** | Clean muted palette, aligned columns, no ASCII art, no flicker |
| 🚫 | **Zero gatekeeping** | No password walls, no Telegram checks, no phoning home |
| 🖥️ | **Polished menu flow** | `press enter to continue` after every module, single/double-digit module input |
| 🩹 | **Honest labeling** | Every module does exactly what its name says - nothing hidden |

<details>
<summary><b>🔄 What changed from v1.x?</b></summary>

| v1.x (old) | v2.0 (now) |
|------------|------------|
| Password gate fetched from a dead `hackwithalex` URL | **Removed** - your tool, no gates |
| Telegram links baked into menus + exit flow | **Removed** everywhere |
| `xdg-open` fired YouTube on exit without asking | **Removed** - nothing opens without you asking |
| Overwrote dnspython's `resolver.py` on Termux (broke it) | **Removed** - stock dnspython works |
| ASCII banner via `cat core/banr.txt` | Clean typographic banner |
| One crashed module killed the whole tool | Every module isolated |
| "Hacker's Name" prompts (cringe) | Straightforward professional prompts |
| apk/dnf/pacman users stuck at "apt not found" | All 6 package managers detected |
| PEP 668 (new Debian) broke `pip install` | Handled automatically |
| v2.0 plain text banner | v2.1 block-letter wordmark (safe terminal glyphs) |
| v2.0 modules dumped you back to menu instantly | v2.1 press-enter pause after every module |
| Only `01`–`18` accepted | `1`–`9` work too |
| Separate "connect" menu | Merged into about |

</details>

---

## ⌨️ Usage

### Interactive mode

```bash
python3 kalnemix.py
```

| Option | Action |
|--------|--------|
| `1`–`18` | Run a recon module (single or double digits both work) |
| `a` | About - tool info, maker & license |
| `0` | Exit |

### One-shot CLI

| Flag | Description | Example |
|------|-------------|---------|
| `-m, --module` | Run one module (1–18) directly | `-m 2` |
| `--doctor` | Show environment/dependency status | `--doctor` |
| `--check` | Exit 0 if all deps present, 1 otherwise (CI-friendly) | `--check` |
| `-v, --version` | Print version | |

### The 18 modules

| # | Module | What it does |
|---|--------|--------------|
| 01 | whois lookup | registrar, dates, status (RDAP fallback if `whois` missing) |
| 02 | ip lookup | geolocation, ISP, ASN via ip-api |
| 03 | find subdomains | crt.sh + hackertarget, merged |
| 04 | http headers | full response header dump |
| 05 | robots scanner | robots.txt disallow map |
| 06 | dns lookup | A, AAAA, MX, NS, TXT, SOA, CNAME |
| 07 | reverse dns | PTR record for an IP |
| 08 | traceroute | network path to target |
| 09 | port scan | nmap TCP 1–N scan |
| 10 | extract links | crawl a page, list internal/external URLs |
| 11 | hidden paths | directory/file probing via wordlist |
| 12 | crack hash | md5/sha1/sha2 wordlist recovery (auto-detected algo) |
| 13 | image metadata | EXIF dump for a local file |
| 14 | subnet lookup | CIDR → netmask, broadcast, host range, max hosts |
| 15 | tls scan | sslscan cipher/cert report |
| 16 | os fingerprint | nmap -O (root required) |
| 17 | reverse shell | generates a PHP payload file for **your own lab** |
| 18 | deface page | generates a demo HTML template for **your own lab** |

---

## 🖥️ Preview

<div align="center">

<img src="https://i.ibb.co/zhfXHyCQ/image.png" alt="KalnemiX v2.1 - terminal preview" width="760">

</div>

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.8+ |
| Networking | `requests` (single shared session, custom UA) |
| Parsing | `beautifulsoup4` + `html5lib` |
| DNS | `dnspython` with `nslookup` fallback |
| Externals | `whois` · `nmap` · `sslscan` · `traceroute` · `exiftool` (all optional) |
| UI | Hand-rolled ANSI palette with tty/`NO_COLOR` auto-detection |
| Setup | POSIX `bash` with 6 package-manager detections |

---

## ⚠️ Disclaimer

> ### Read this before using KalnemiX.
>
> 1. **Recon only.** KalnemiX reads **publicly available** information (whois, DNS, HTTP headers, certificates). It does not exploit, attack, or gain access to anything.
> 2. **Authorization is mandatory.** Only use this tool on systems **you own** or have **explicit written permission** to test. Scanning systems without authorization is illegal in most countries - including under the computer misuse / CFAA-style laws.
> 3. **Generators are lab tools.** The reverse-shell and deface-page generators create files for testing **your own** lab environments and demonstrating impact in authorized engagements. Deploying them against third-party systems is a serious crime.
> 4. **You are responsible.** KalnemiX is provided "as is" under the Boost Software License 1.0, with no warranty of any kind. The author is **not liable** for any misuse, damage, or legal consequences resulting from use or abuse of this tool.
> 5. **Respect rate limits.** Public OSINT sources (crt.sh, ip-api, hackertarget) throttle abuse. KalnemiX is built for targeted recon, not mass scanning - hammering them can get your IP blocked and is not what this tool is for.

---

## 🤝 Contributing

Contributions are welcome!

```bash
# 1. fork it
# 2. create your branch
git checkout -b feature/amazing-feature
# 3. commit
git commit -m "Add amazing feature"
# 4. push
git push origin feature/amazing-feature
# 5. open a Pull Request
```

Ideas worth exploring: JSON/CSV output for every module, `-o results.json` flag, more OSINT sources, unit-test suite for the parsers.

---

## 📜 License

Distributed under the **Boost Software License 1.0**. See [`LICENSE`](LICENSE) for details.

---

## 👨‍💻 Developer

| | |
|---|---|
| **Dev** | MrHacker-X |
| **GitHub** | [github.com/MrHacker-X](https://github.com/MrHacker-X) |
| **Email** | [contact@vritrasec.com](mailto:contact@vritrasec.com) |
| **Website** | [vritrasec.com](https://vritrasec.com) |
| **Network** | [link.vritrasec.com](https://link.vritrasec.com) |

---

<div align="center">

### ⭐ Star the repo if KalnemiX sharpened your recon workflow ⭐

*Built with discipline by MrHacker-X - recon responsibly, always.*

</div>
