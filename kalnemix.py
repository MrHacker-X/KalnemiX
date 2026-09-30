#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KalnemiX v2.0 - web reconnaissance & recon-aids toolkit.

Important: this is an OPEN-SOURCE-INTELLIGENCE (OSINT) / RECON tool.
It reads PUBLIC information about a target: whois records, DNS records,
HTTP headers, robots.txt, public subdomains, TLS certificate data.
It does not exploit, attack, or gain access to anything.

Authorized-use only: run it against systems YOU own or have written
permission to test. See the DISCLAIMER in README.md.

Author : MrHacker-X  (https://github.com/MrHacker-X)
Site   : https://vritrasec.com
License: BSL-1.0 (Boost Software License)
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin


try:
    import requests
except ImportError:
    print("[x] missing dependency: requests  (pip3 install requests)")
    sys.exit(1)

__version__ = "2.1.0"
PROG = os.path.basename(sys.argv[0]) or "kalnemix"
START = os.path.dirname(os.path.abspath(__file__))

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
REQ = requests.Session()
REQ.headers["User-Agent"] = UA


class SafeExit(Exception):
    """User aborted input - handled centrally, clean exit."""


# optional deps: degrade instead of crash
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import ssl  # noqa: F401
    HAS_SSL = True
except ImportError:
    HAS_SSL = False


def _color_ok() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


COLOR = _color_ok()
WH = "\033[1;97m" if COLOR else ""
YL = "\033[38;5;179m" if COLOR else ""
GR = "\033[38;5;150m" if COLOR else ""
DM = "\033[38;5;245m" if COLOR else ""
XX = "\033[0m" if COLOR else ""

RULE = "─" * 62


# ---------------------------------------------------------------- UI helpers


def rule() -> None:
    print(f"  {YL}{RULE}{XX}")


def header(subtitle: str) -> None:
    print()
    rule()
    print(f"  {WH}{subtitle}{XX}")
    rule()


def kv(key: str, val: str, width: int = 14) -> None:
    gap = " " * max(0, width - len(key))
    print(f"  {YL}{key}{XX}{gap}  {DM}····{XX}  {WH}{val}{XX}")


def item(num: str, label: str, desc: str = "", dim: bool = False,
         align: int = 13, numw: int = 2) -> None:
    gap = (" " * max(0, align - len(label))) if desc else ""
    tail = f"  {DM}····  {desc}{XX}" if desc else ""
    c = DM if dim else GR
    sp = " " * max(0, numw - len(num))
    print(f"  [{YL}{num}{XX}]{sp} {c}{label}{XX}{gap}{tail}")


def say(msg: str) -> None:
    print(f"  {GR}›{XX} {WH}{msg}{XX}")


def note(msg: str) -> None:
    print(f"  {DM}···· {msg}{XX}")


def err(msg: str) -> None:
    print(f"  {YL}[!]{XX} {DM}{msg}{XX}")


def ask(prompt: str) -> str:
    try:
        return input(f"  {YL}›{XX} {prompt}: ").strip()
    except EOFError:
        raise SafeExit from None
    # KeyboardInterrupt propagates to the central handler in main()


def confirm(prompt: str) -> bool:
    try:
        raw = input(f"  {YL}›{XX} {prompt} [{GR}y{XX}/N]: ").strip().lower()
    except EOFError:
        raise SafeExit from None
    return raw in ("y", "yes")


def pause() -> None:
    try:
        input(f"  {YL}›{XX} {DM}enter to continue{XX}")
    except EOFError:
        raise SafeExit from None
    print()


# ------------------------------------------------------------- net utilities


def norm_target(target: str) -> str:
    """strip scheme/path from a user-supplied target."""
    target = target.strip().replace("http://", "").replace("https://", "")
    return target.split("/")[0].strip()


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_host(target: str) -> str | None:
    if is_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def http_get(url: str, timeout: int = 10):
    try:
        return REQ.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def detect_scheme(target: str) -> str:
    """probe https then http; return whichever answers (or http as best guess)."""
    for scheme in ("https", "http"):
        if http_get(f"{scheme}://{target}/", timeout=5) is not None:
            return scheme
    return "http"


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def sh(cmd: list, timeout: int = 120) -> str:
    """run an external tool, return its stdout (empty on failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        return out.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# ------------------------------------------------------------------- banner


_BLOCK_FONT = {
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    "L": ["█    ", "█    ", "█    ", "█    ", "█████"],
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "X": ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
}


def _wordmark_rows(text: str) -> list:
    """compose 5-row block-letter wordmark from safe full-block glyphs."""
    rows = [""] * 5
    for ch in text.upper():
        glyph = _BLOCK_FONT.get(ch)
        if glyph is None:
            glyph = ["   "] * 5  # unknown char -> blank column
        for i in range(5):
            rows[i] += (" " if rows[i] else "") + glyph[i]
    return rows


def banner() -> None:
    print()
    rule()
    rows = _wordmark_rows("KALNEMIX")
    width = max(len(r) for r in rows)
    pad = " " * max(2, (62 - width) // 2)
    for r in rows:
        print(f"  {pad}{YL}{r}{XX}")
    sub = f"web recon · osint · v{__version__}"
    print(f"  {DM}{sub.center(62)}{XX}")
    rule()
    print(f"  {DM}use only on systems you own or are authorized to test{XX}")
    print()


# =========================================================== recon modules ==
# every action_* function is wrapped by run_action() which handles
# setup/teardown, target resolution and error containment.


def act_whois(target: str) -> None:
    if tool_available("whois"):
        out = sh(["whois", target])
        if out.strip():
            for line in out.splitlines():
                if line.strip():
                    print(f"  {DM}{line}{XX}")
            return
    header("whois lookup - web fallback")
    resp = http_get(f"https://rdap.org/domain/{target}")
    if resp is None or resp.status_code != 200:
        err("rdap lookup failed - install whois or check connectivity")
        return
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        err("rdap returned invalid data")
        return
    ev = {}
    for e in data.get("events", []):
        ev[e.get("eventAction", "")] = e.get("eventDate", "")
    ent = data.get("entities", [])
    registrar = ""
    if ent:
        for e in ent:
            roles = e.get("roles", [])
            if "registrar" in roles:
                v = e.get("vcardArray", [])
                if len(v) > 1:
                    for item_ in v[1]:
                        if item_[0] == "fn":
                            registrar = item_[3]
                            break
    kv("domain", data.get("ldhName", target))
    kv("registrar", registrar or "n/a")
    kv("registered", ev.get("registration", "n/a"))
    kv("expires", ev.get("expiration", "n/a"))
    kv("updated", ev.get("last changed", ev.get("last update of rdap database", "n/a")))
    kv("status", ", ".join(data.get("status", [])) or "n/a")


def act_ipinfo(target: str) -> None:
    ip = resolve_host(target)
    if not ip:
        err(f"could not resolve {target}")
        return
    resp = http_get(f"http://ip-api.com/json/{ip}")
    if resp is None or resp.status_code != 200:
        err("ip-api lookup failed")
        return
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        err("ip-api returned invalid data")
        return
    kv("query", data.get("query", "n/a"))
    kv("country", f"{data.get('country', 'n/a')} ({data.get('countryCode', '??')})")
    kv("region", data.get("regionName", "n/a"))
    kv("city", data.get("city", "n/a"))
    kv("zip", data.get("zip", "n/a"))
    kv("lat/lon", f"{data.get('lat', '?')}, {data.get('lon', '?')}")
    kv("timezone", data.get("timezone", "n/a"))
    kv("isp", data.get("isp", "n/a"))
    kv("org", data.get("org", "n/a"))
    kv("asn", data.get("as", "n/a"))


def act_subdomains(target: str) -> None:
    domain = norm_target(target)
    header(f"subdomain enumeration - {domain}")
    found = set()
    resp = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=45)
    if resp is not None and resp.status_code == 200:
        try:
            for row in resp.json():
                name = row.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and n.endswith("." + domain) and "*" not in n:
                        found.add(n)
        except (json.JSONDecodeError, ValueError):
            pass
    resp = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                    timeout=15)
    if resp is not None and resp.status_code == 200 and "error" not in resp.text.lower():
        for line in resp.text.splitlines():
            if line.strip():
                sub = line.split(",")[0].strip().lower()
                if sub.endswith("." + domain):
                    found.add(sub)
    if not found:
        err(f"no subdomains found for {domain} (sources may be rate-limited)")
        return
    print()
    w = max(len(s) for s in found)
    for i, sub in enumerate(sorted(found), 1):
        item(str(i), sub, dim=True, align=max(w, 8))
    print()
    note(f"{len(found)} subdomain(s) discovered for {domain}")


def act_http_headers(target: str) -> None:
    url = f"https://{norm_target(target)}"
    try:
        resp = REQ.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException:
        try:
            resp = REQ.get(f"http://{norm_target(target)}", timeout=10,
                           allow_redirects=True)
        except requests.RequestException:
            err("connection failed")
            return
    print()
    for key, value in resp.headers.items():
        kv(key.lower(), value)
    print()
    kv("final url", resp.url)
    kv("status", f"{resp.status_code} {resp.reason}")


def act_robots(target: str) -> None:
    base = f"https://{norm_target(target)}"
    resp = http_get(f"{base}/robots.txt")
    if resp is None or resp.status_code != 200:
        resp = http_get(f"http://{norm_target(target)}/robots.txt")
    if resp is None or resp.status_code != 200:
        err("no robots.txt found (or server unreachable)")
        return
    print()
    for line in resp.text.splitlines():
        line = line.strip()
        if line.lower().startswith("user-agent"):
            print(f"\n  {YL}{line}{XX}")
        elif line.lower().startswith(("disallow", "allow", "sitemap")):
            kv(*[p.strip() for p in line.split(":", 1)])
    print()


def act_dns(target: str) -> None:
    domain = norm_target(target)
    header(f"dns records - {domain}")
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    if HAS_DNS:
        for rt in rtypes:
            try:
                ans = dns.resolver.resolve(domain, rt, lifetime=6)
                vals = [r.to_text() for r in ans]
                kv(rt.lower(), "; ".join(vals[:3]) + (" …" if len(vals) > 3 else ""))
            except Exception:
                kv(rt.lower(), "-")
    else:
        out = sh(["nslookup", "-type=any", domain], timeout=15)
        if not out.strip():
            err("dns lookup failed - install dnspython or dnsutils")
            return
        for line in out.splitlines():
            if line.strip():
                print(f"  {DM}{line}{XX}")
        note("tip: pip3 install dnspython for richer record typing")


def act_reverse_dns(target: str) -> None:
    ip = resolve_host(target)
    if not ip:
        err(f"could not resolve {target}")
        return
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        host = "n/a"
    kv("ip", ip)
    kv("ptr", host)


def act_traceroute(target: str) -> None:
    ip = resolve_host(target)
    if not ip:
        err(f"could not resolve {target}")
        return
    if tool_available("traceroute"):
        out = sh(["traceroute", ip], timeout=90)
        if out.strip():
            for line in out.splitlines():
                print(f"  {DM}{line}{XX}")
            return
    note("traceroute not installed - falling back to tcp hops via query")
    resp = http_get(f"https://api.hackertarget.com/mtr/?q={ip}", timeout=30)
    if resp is None or resp.status_code != 200 or "error" in resp.text.lower():
        err("traceroute failed")
        return
    for line in resp.text.splitlines():
        print(f"  {DM}{line}{XX}")


def act_ports(target: str) -> None:
    if not tool_available("nmap"):
        err("nmap not installed - run setup.sh first")
        return
    ip = resolve_host(target)
    if not ip:
        err(f"could not resolve {target}")
        return
    endport = ask("end port [1000]").strip() or "1000"
    if not endport.isdigit() or int(endport) > 65535 or int(endport) < 1:
        err("invalid port, using 1000")
        endport = "1000"
    say(f"nmap scanning {ip} ports 1-{endport} (this can take a while)")
    print()
    out = sh(["nmap", "-vv", "-p", f"1-{endport}", "-T4", ip], timeout=600)
    for line in out.splitlines():
        if line.strip():
            print(f"  {DM}{line}{XX}")


def act_extract_links(target: str) -> None:
    scheme = detect_scheme(norm_target(target))
    resp = http_get(f"{scheme}://{norm_target(target)}")
    if resp is None or resp.status_code != 200:
        err("could not fetch page")
        return
    from bs4 import BeautifulSoup  # deferred - bs4 optional for other features
    soup = BeautifulSoup(resp.text, "html.parser")
    print()
    seen = set()
    count = 0
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(resp.url, href)
        if full in seen:
            continue
        seen.add(full)
        count += 1
        ext = "ext" if urlparse(full).netloc != urlparse(resp.url).netloc else "int"
        item(str(count), full, ext, dim=True, align=5)
        if count >= 60:
            note("showing first 60 links - output truncated")
            break
    print()
    note(f"{count} link(s) extracted from {resp.url}")


def act_hidden_paths(target: str) -> None:
    scheme = detect_scheme(norm_target(target))
    base = f"{scheme}://{norm_target(target)}"
    default_list = os.path.join(START, "core", "directories.txt")
    path = ask("wordlist (enter for default)")
    if not path:
        path = default_list
        note("default wordlist selected")
    if not os.path.isfile(path):
        err(f"wordlist not found: {path}")
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            words = [w.strip().strip("/") for w in fh if w.strip()]
    except OSError as exc:
        err(f"cannot read wordlist: {exc}")
        return
    say(f"probing {len(words)} common paths on {base} (10 threads)")
    print()
    found = []
    lock = threading.Lock()

    def probe(word: str):
        u = f"{base}/{word}"
        try:
            r = REQ.get(u, timeout=6, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                with lock:
                    found.append((u, r.status_code))
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = [pool.submit(probe, w) for w in words]
        for _ in as_completed(futs):
            pass
    if not found:
        err("no accessible paths found (or host blocks probing)")
        return
    w = max(len(u) for u, _ in found)
    for u, code in sorted(found):
        item(str(code), u, dim=True, align=max(w, 8))
    print()
    note(f"{len(found)} path(s) responded")


def act_hash_crack() -> None:
    target_hash = ask("hash to crack").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32,128}", target_hash):
        err("not a valid hex hash (md5/sha-family expected)")
        return
    wordlist = ask("wordlist (enter for default)").strip()
    if not wordlist:
        wordlist = os.path.join(START, "core", "passwords.txt")
        note("default wordlist selected")
    if not os.path.isfile(wordlist):
        err(f"wordlist not found: {wordlist}")
        return
    by_len = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
              96: "sha384", 128: "sha512"}
    algo = by_len.get(len(target_hash))
    if not algo:
        err(f"unsupported hash length {len(target_hash)} (md5/sha1/sha2 family)")
        return
    say(f"algorithm auto-detected: {algo}")
    say(f"loading wordlist {wordlist}")
    print()
    tried = 0
    try:
        with open(wordlist, "r", encoding="latin-1") as fh:
            for line in fh:
                word = line.rstrip("\r\n")
                tried += 1
                if tried % 50000 == 0:
                    print(f"\r  {DM}···· {tried} tried{XX}", end="", flush=True)
                digest = hashlib.new(algo, word.encode()).hexdigest()
                if digest == target_hash:
                    print()
                    print()
                    kv("hash", target_hash)
                    kv("algorithm", algo)
                    kv("plaintext", word)
                    print()
                    return
    except OSError as exc:
        err(f"cannot read wordlist: {exc}")
        return
    print(f"\r  {' ' * 40}\r", end="")
    err(f"not cracked after {tried} candidate(s) - try a bigger wordlist")


def act_image_metadata() -> None:
    path = ask("image path")
    if not path:
        return
    if not os.path.isfile(path):
        err(f"file not found: {path}")
        return
    if tool_available("exiftool"):
        out = sh(["exiftool", path], timeout=30)
        if out.strip():
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    kv(k.strip().lower(), v.strip())
            return
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read()
    kv("file", os.path.basename(path))
    kv("size", f"{size:,} bytes")
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    kv("md5", md5)
    kv("sha1", sha1)
    note("install exiftool for full metadata extraction")


def act_subnet(target: str) -> None:
    if "/" not in target:
        target = target + "/32"
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        err(f"invalid ip/network: {target}")
        return
    hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    kv("network", str(net))
    kv("netmask", str(net.netmask))
    kv("broadcast", str(net.broadcast_address))
    kv("wildcard", str(net.hostmask))
    kv("prefix", f"/{net.prefixlen}")
    kv("host bits", str(net.max_prefixlen - net.prefixlen))
    kv("max hosts", f"{hosts:,}")
    if net.prefixlen <= 30:
        kv("range", f"{net.network_address + 1} - {net.broadcast_address - 1}")
    version = "ipv4" if net.version == 4 else "ipv6"
    note(f"address family: {version}")


def act_tls(target: str) -> None:
    if not tool_available("sslscan"):
        err("sslscan not installed - run setup.sh first")
        return
    host = norm_target(target)
    say(f"sslscan {host} (may take ~30s)")
    print()
    out = sh(["sslscan", "--no-colour", host], timeout=120)
    for line in out.splitlines():
        if line.strip():
            print(f"  {DM}{line}{XX}")


def act_os_fingerprint(target: str) -> None:
    if os.geteuid() != 0:
        err("os fingerprinting needs root (nmap -O) - re-run with sudo")
        return
    if not tool_available("nmap"):
        err("nmap not installed - run setup.sh first")
        return
    ip = resolve_host(target)
    if not ip:
        err(f"could not resolve {target}")
        return
    say(f"nmap -O {ip} (this can take a few minutes)")
    print()
    out = sh(["nmap", "-O", ip], timeout=600)
    for line in out.splitlines():
        if line.strip():
            print(f"  {DM}{line}{XX}")


def act_reverse_shell() -> None:
    ip = ask("your listener ip")
    port = ask("your listener port").strip()
    if not ip or not port.isdigit():
        err("valid ip and numeric port required")
        return
    template = os.path.join(START, "core", "reverse_shell.php")
    if not os.path.isfile(template):
        err(f"template missing: {template}")
        return
    try:
        with open(template, "r", encoding="utf-8") as fh:
            php = fh.read()
    except OSError as exc:
        err(f"cannot read template: {exc}")
        return
    php = php.replace("$ip = '127.0.0.1';", f"$ip = '{ip}';")
    php = php.replace("$port = 1234;", f"$port = {port};")
    out_path = os.path.join(os.getcwd(), "reverse-shell.php")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(php)
    except OSError as exc:
        err(f"cannot write output: {exc}")
        return
    kv("file", out_path)
    kv("listener", f"{ip}:{port}")
    print()
    note("start a handler first:  nc -lvnp " + port)
    note("for authorized testing only - deploying this on systems you do")
    note("not own is a crime in nearly every jurisdiction.")


def act_deface_page() -> None:
    say("authorized-use reminder: deface pages are for testing your OWN")
    note("sites and demonstrating markup-injection impact in a pentest report.")
    if not confirm("acknowledge and continue?"):
        return
    name = ask("hacker name").strip()
    tagline = ask("tagline").strip()
    message = ask("message").strip()
    logo = ask("logo url or path (enter for default)").strip()
    contact1 = ask("contact (email)").strip()
    contact2 = ask("contact (social/other)").strip()
    if not name:
        err("name is required")
        return
    if not logo:
        logo = "https://vritrasec.com/assets/all-images/logo.webp"
        note("default logo selected")
    template = os.path.join(START, "core", "deface.html")
    if not os.path.isfile(template):
        err(f"template missing: {template}")
        return
    try:
        with open(template, "r", encoding="utf-8") as fh:
            html = fh.read()
    except OSError as exc:
        err(f"cannot read template: {exc}")
        return
    for old, new in (("{{NAME}}", name), ("{{MESSAGE}}", message),
                     ("{{LOGO}}", logo), ("{{TAGLINE}}", tagline),
                     ("{{CONTACT}}", contact1), ("{{SOCIAL}}", contact2)):
        html = html.replace(old, new)
    out_path = os.path.join(os.getcwd(), "index.html")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html)
    except OSError as exc:
        err(f"cannot write output: {exc}")
        return
    kv("file", out_path)
    kv("author", name)
    print()
    note("for testing your own sites only.")


# -------------------------------------------------------------- menu layer


RECON_ITEMS = [
    ("01", "whois lookup", "domain registration + registrar"),
    ("02", "ip lookup", "geolocation · isp · asn"),
    ("03", "find subdomains", "crt.sh + hackertarget, merged"),
    ("04", "http headers", "server response header dump"),
    ("05", "robots scanner", "robots.txt disallow map"),
    ("06", "dns lookup", "a · aaaa · mx · ns · txt · soa"),
    ("07", "reverse dns", "ptr record for an ip"),
    ("08", "traceroute", "network path to target"),
    ("09", "port scan", "nmap tcp scan (1-N)"),
    ("10", "extract links", "crawl a page, list every url"),
    ("11", "hidden paths", "dir/file probing via wordlist"),
    ("12", "crack hash", "md5/sha wordlist recovery"),
    ("13", "image metadata", "exif dump for a local file"),
    ("14", "subnet lookup", "cidr → mask · range · hosts"),
    ("15", "tls scan", "sslscan cipher/cert report"),
    ("16", "os fingerprint", "nmap -O (root required)"),
    ("17", "reverse shell", "generate php payload file"),
    ("18", "deface page", "generate demo html template"),
]


def _do_recon(num: str, target: str | None = None) -> None:
    """run one recon module with a target prompt and error containment."""
    if num == "12":
        header("crack hash")
        act_hash_crack()
        print()
        return
    if num == "13":
        header("image metadata")
        act_image_metadata()
        print()
        return
    if num == "17":
        header("reverse shell generator")
        act_reverse_shell()
        print()
        return
    if num == "18":
        header("deface page generator")
        act_deface_page()
        print()
        return

    if target is None:
        raw = ask("target (domain or ip)").strip()
    else:
        raw = target.strip()
        say(f"target: {raw}")
    if not raw:
        err("empty target - cancelled")
        return
    # subnet lookup keeps CIDR notation intact (10.0.0.0/24)
    target = raw if num == "14" else norm_target(raw)
    if num in ("09", "15", "16"):
        if not is_ip(target) and resolve_host(target) is None:
            err(f"cannot resolve {target}")
            return
    print()
    try:
        if num == "01":
            act_whois(target)
        elif num == "02":
            act_ipinfo(target)
        elif num == "03":
            act_subdomains(target)
        elif num == "04":
            act_http_headers(target)
        elif num == "05":
            act_robots(target)
        elif num == "06":
            act_dns(target)
        elif num == "07":
            act_reverse_dns(target)
        elif num == "08":
            act_traceroute(target)
        elif num == "09":
            act_ports(target)
        elif num == "10":
            act_extract_links(target)
        elif num == "11":
            act_hidden_paths(target)
        elif num == "14":
            act_subnet(target)
        elif num == "15":
            act_tls(target)
        elif num == "16":
            act_os_fingerprint(target)
    except requests.RequestException as e:
        err(f"network error: {e.__class__.__name__}")
    except Exception as e:  # module isolation - menu must survive anything
        err(f"{e.__class__.__name__}: {e}")
    print()


def act_about() -> None:
    header("about")
    kv("tool", f"KalnemiX v{__version__}")
    kv("type", "web recon & osint toolkit")
    kv("modules", f"{len(RECON_ITEMS)} recon aids + 2 generators")
    kv("network", "public osint sources + local nmap/sslscan")
    kv("license", "boost software license 1.0")
    print()
    kv("dev", "MrHacker-X")
    kv("github", "github.com/MrHacker-X")
    kv("email", "contact@vritrasec.com")
    kv("website", "vritrasec.com")
    kv("link", "link.vritrasec.com")
    print()
    print(f"  {DM}recon only - no exploitation. test only what you own or{XX}")
    print(f"  {DM}have written permission to test.{XX}")
    print()


MENU_ACTIONS = {
    "01": "whois lookup",
    "02": "ip lookup",
    "03": "find subdomains",
    "04": "http headers",
    "05": "robots scanner",
    "06": "dns lookup",
    "07": "reverse dns",
    "08": "traceroute",
    "09": "port scan",
    "10": "extract links",
    "11": "hidden paths",
    "12": "crack hash",
    "13": "image metadata",
    "14": "subnet lookup",
    "15": "tls scan",
    "16": "os fingerprint",
    "17": "reverse shell",
    "18": "deface page",
}


def main_menu() -> None:
    w = max(len(label) for _, label, _ in RECON_ITEMS)
    for num, label, desc in RECON_ITEMS:
        item(num, label, desc, align=w)
    item("a", "about", "tool · maker · license", dim=True, align=w)
    item("0", "exit", "", dim=True, align=w)
    ch = ask("module").lower()
    if ch == "0":
        raise SafeExit
    if ch.isdigit():
        ch = ch.zfill(2)  # accept 1..9 as 01..09
    if ch == "a":
        act_about()
        pause()
        return
    if ch in MENU_ACTIONS:
        _do_recon(ch)
        pause()
        return
    print(f"  {DM}invalid choice{XX}\n")


def check_env() -> list:
    """return a list of (name, ok, note) for optional externals."""
    checks = [
        ("whois", tool_available("whois"), "or rdap fallback will be used"),
        ("nmap", tool_available("nmap"), "needed for port scan + os fingerprint"),
        ("sslscan", tool_available("sslscan"), "needed for tls scan"),
        ("traceroute", tool_available("traceroute"), "or a web fallback is used"),
        ("exiftool", tool_available("exiftool"), "or a basic fallback is used"),
        ("bs4", True, ""),  # filled below
    ]
    try:
        import bs4  # noqa: F401
        checks[-1] = ("bs4", True, "needed for extract links")
    except ImportError:
        checks[-1] = ("bs4", False, "needed for extract links")
    try:
        import dns.resolver  # noqa: F401
        checks.append(("dnspython", True, "richer dns records"))
    except ImportError:
        checks.append(("dnspython", False, "nslookup fallback will be used"))
    return checks


def cmd_doctor() -> None:
    header(f"environment check - {PROG} v{__version__}")
    kv("python", sys.version.split()[0])
    kv("platform", sys.platform)
    for name, ok, hint in check_env():
        mark = "ok " if ok else "missing"
        val = f"{mark}" + (f"  {DM}···· {hint}{XX}" if hint else "")
        kv(name, val)
    print()


def cmd_setup_check() -> int:
    missing = [n for n, ok, _ in check_env() if not ok]
    if missing:
        err("missing: " + ", ".join(missing))
        print()
        note("run ./setup.sh to install everything")
        return 1
    say("all dependencies present")
    return 0


# -------------------------------------------------------------------- cli --


def cli(args) -> int:
    if args.doctor:
        cmd_doctor()
        return 0
    if args.check:
        return cmd_setup_check()

    if args.module:
        m = args.module.zfill(2)
        if m not in MENU_ACTIONS:
            print(f"  {DM}unknown module '{args.module}' - valid: "
                  f"{'-'.join(k.lstrip('0') or '0' for k in MENU_ACTIONS)}{XX}")
            return 2
        try:
            _do_recon(m, target=args.target)
        except SafeExit:
            print(f"  {DM}safe exit - recon responsibly.{XX}\n")
            return 0
        except KeyboardInterrupt:
            print(f"\n  {DM}safe exit - recon responsibly.{XX}\n")
            return 130
        return 0

    while True:
        try:
            banner()
            main_menu()
        except SafeExit:
            print(f"  {DM}safe exit - recon responsibly.{XX}\n")
            return 0
        except KeyboardInterrupt:
            print(f"\n  {DM}safe exit - recon responsibly.{XX}\n")
            return 130


def main() -> None:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="KalnemiX - web recon & osint toolkit. "
                    "Authorized testing only.")
    parser.add_argument("-m", "--module", metavar="N",
                        help="run one module directly (1-18)")
    parser.add_argument("-t", "--target", metavar="TARGET",
                        help="target for --module (skips the prompt)")
    parser.add_argument("--doctor", action="store_true",
                        help="show environment/dependency status and exit")
    parser.add_argument("--check", action="store_true",
                        help="exit 0 if all deps present, 1 otherwise")
    parser.add_argument("-v", "--version", action="version",
                        version=f"{PROG} {__version__}")
    args = parser.parse_args()
    try:
        sys.exit(cli(args))
    except SafeExit:
        print(f"  {DM}safe exit - recon responsibly.{XX}\n")
        sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n  {DM}safe exit - recon responsibly.{XX}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
