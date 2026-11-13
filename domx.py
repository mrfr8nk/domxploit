#!/usr/bin/env python3
"""
DOM-X 2 ULTIMATE — High-Reliability CIDR + Domain + Mixed Scanner
Made by Mr Frank ( give credits if u wanna redistribute)
t.me/mrfrankofc • wa.me/mrfr4nkofc

Fixed / Upgraded:
  • Sliding-window executor — no more skipped hosts on huge files/CIDRs
  • Realistic Chrome 131 browser headers (rotating UA + Sec-Fetch + XFF)
  • Retry pass for timed-out hosts (catches WAF soft-blocks)
  • Full file order preserved, no dedupe collisions
  • Custom port support in settings
"""

import socket
import ipaddress
import ssl
import argparse
import sys
import os
import time
import json
import re
import random
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime
import threading
import http.client
from urllib.parse import urlparse, urljoin

# ───────────── COLORS ─────────────
class C:
    R  = "\033[0m";  B  = "\033[1m";  D  = "\033[2m"
    RD = "\033[31m"; GN = "\033[32m"; YL = "\033[33m"
    BL = "\033[34m"; MG = "\033[35m"; CY = "\033[36m"
    WH = "\033[37m"
    BR = "\033[91m"; BG = "\033[92m"; BY = "\033[93m"
    BB = "\033[94m"; BM = "\033[95m"; BC = "\033[96m"
    BW = "\033[97m"

if os.name == "nt":
    os.system("")

BANNER = f"""
{C.BM}{C.B}  ██████╗  ██████╗ ███╗   ███╗    {C.BC}██╗  ██╗
{C.BM}{C.B}  ██╔══██╗██╔═══██╗████╗ ████║   {C.BC}╚██╗██╔╝
{C.BM}{C.B}  ██║  ██║██║   ██║██╔████╔██║    {C.BC}╚███╔╝
{C.BM}{C.B}  ██║  ██║██║   ██║██║╚██╔╝██║    {C.BC}██╔██╗
{C.BM}{C.B}  ██████╔╝╚██████╔╝██║ ╚═╝ ██║    {C.BC}██╔╝ ██╗
{C.BM}{C.B}  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝    {C.BC}╚═╝  ╚═╝{C.R}

{C.BY}{C.B}  ┌──────────────────────────────────────────❯
│  {C.BM}💀  DOM-X 2 ULTIMATE — RELIABLE SCANNER  💀{C.BY}
│  {C.BW}Free Internet For All !{C.BY}
│  {C.D}Made By Mr Frank OFC{C.BY}
│  {C.BC}  t.me/mrfrankofc  ◈  wa.me/mrfr4nkofc{C.BY}
└──────────────────────────────────────────────▣{C.R}
"""

STATE_FILE = "domx_state.json"

# ───────────── BROWSER HEADERS (Chrome 131 realistic) ─────────────
HEADERS = {
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "accept-language": "en-US,en;q=0.9,hi;q=0.8",
    "dnt": "1",
    "priority": "u=0, i",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/114.0.1823.67",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:114.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:112.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 12; Mobile; rv:115.0) Gecko/115.0 Firefox/115.0",
    "Mozilla/5.0 (Android 13; Tablet; rv:112.0) Gecko/112.0 Firefox/112.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro Build/SQ3A.220605.009) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:113.0) Gecko/20100101 Firefox/113.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:113.0) Gecko/20100101 Firefox/113.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.124 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0; .NET4.6; .NET4.5; .NET4.7) like Gecko",
]

EXTRA_HEADERS = {
    "X-Originating-IP": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Host": "127.0.0.1",
    "X-Forwarded-Host": "127.0.0.1",
}

def build_headers(host=None, rotate_ua=True, inject_xff=True):
    h = dict(HEADERS)
    if rotate_ua:
        h["user-agent"] = random.choice(USER_AGENTS)
    if inject_xff:
        h.update(EXTRA_HEADERS)
    if host:
        h["host"] = host
    return h

# ───────────── HOSTER SIGNATURES ─────────────
HEADER_SIGS = [
    ("cloudflare",   ["cf-ray", "cf-cache-status", "cloudflare"]),
    ("akamai",       ["akamaighost", "akamai-grn", "x-akamai-transformed"]),
    ("fastly",       ["fastly", "x-served-by", "x-fastly-request-id"]),
    ("varnish",      ["varnish", "x-varnish", "via-varnish"]),
    ("aws-cloudfront", ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"]),
    ("aws-s3",       ["amazons3", "x-amz-request-id"]),
    ("azure",        ["azure", "x-azure-ref"]),
    ("google",       ["gws", "google frontend", "gfe"]),
    ("nginx",        ["nginx"]),
    ("apache",       ["apache"]),
    ("iis",          ["microsoft-iis"]),
    ("litespeed",    ["litespeed"]),
    ("openresty",    ["openresty"]),
    ("caddy",        ["caddy"]),
    ("github",       ["github.com", "githubusercontent"]),
    ("netlify",      ["netlify"]),
    ("vercel",       ["vercel"]),
    ("heroku",       ["heroku"]),
    ("sucuri",       ["sucuri", "x-sucuri-id"]),
    ("incapsula",    ["incap_ses", "visid_incap", "x-iinfo"]),
    ("imperva",      ["imperva"]),
    ("bunny",        ["bunnycdn", "bunny.net"]),
    ("keycdn",       ["keycdn"]),
    ("stackpath",    ["stackpath"]),
]

IP_PREFIX_SIGS = [
    ("cloudflare",   ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                      "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                      "104.26.", "104.27.", "172.64.", "172.65.", "172.66.",
                      "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
                      "162.158.", "162.159.", "188.114.", "197.234.", "198.41."]),
    ("akamai",       ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.",
                      "23.37.", "23.38.", "23.39.", "23.40.", "23.41.",
                      "23.42.", "23.43.", "23.44.", "23.45.", "23.46.",
                      "23.47.", "23.48.", "23.49.", "23.50.", "23.51.",
                      "23.52.", "23.53.", "23.54.", "23.55.", "23.56.",
                      "23.57.", "23.58.", "23.59.", "23.60.", "23.61.",
                      "23.62.", "23.63.", "96.6.", "96.7.", "96.16."]),
    ("fastly",       ["151.101.", "199.232.", "157.52.", "185.31.17.",
                      "185.31.18.", "185.31.19.", "23.235."]),
    ("aws",          ["3.", "13.", "18.", "34.", "35.", "52.", "54.",
                      "107.20.", "176.34."]),
    ("azure",        ["13.64.", "13.65.", "13.66.", "13.67.", "13.68.",
                      "13.69.", "13.70.", "13.71.", "13.72.", "13.73.",
                      "13.74.", "13.75.", "13.76.", "13.77.", "13.78.",
                      "20.", "40.", "52.1"]),
    ("google",       ["34.64.", "34.65.", "34.96.", "34.98.", "34.100.",
                      "34.101.", "34.102.", "35.184.", "35.185.", "35.186.",
                      "35.187.", "35.188.", "35.190.", "35.191.", "35.192.",
                      "35.193.", "35.194.", "35.195.", "35.196.", "35.197.",
                      "35.198.", "35.199.", "35.200.", "35.201.", "35.202.",
                      "35.203.", "35.204.", "35.205.", "35.206.", "35.207.",
                      "35.208.", "35.209.", "142.250.", "142.251.", "172.217."]),
]

def detect_hoster(headers, ip):
    hdrs = {}
    for k, v in headers:
        hdrs[k.lower()] = v.lower()
    joined = " ".join(f"{k} {v}" for k, v in hdrs.items())
    for name, sigs in HEADER_SIGS:
        for sig in sigs:
            if sig in joined:
                return name
    for name, prefixes in IP_PREFIX_SIGS:
        for p in prefixes:
            if ip.startswith(p):
                return name
    return "unknown"

# ───────────── GLOBAL CONFIG ─────────────
DEFAULT_PORTS = [80, 443]

CONFIG = {
    "threads": 150,
    "timeout": 2.5,
    "retries": 1,
    "ports": DEFAULT_PORTS,
    "output": "domx_results.txt",
}

# ───────────── HTTP HELPERS ─────────────
def http_get(url, timeout, max_redirects=8):
    current = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        if not parsed.hostname:
            return None
        scheme = parsed.scheme or "https"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        hdrs = build_headers(host=parsed.hostname)
        hdrs["connection"] = "close"

        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    parsed.hostname, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)

            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            headers = resp.getheaders()

            if resp.status in (301, 302, 303, 307, 308):
                location = dict((k.lower(), v) for k, v in headers).get("location")
                resp.read(64)
                conn.close()
                if location:
                    current = urljoin(current, location)
                    continue
                return (resp.status, current, headers)

            resp.read(256)
            conn.close()
            return (resp.status, current, headers)
        except Exception:
            try: conn.close()
            except Exception: pass
            return None
    return None

# ───────────── CIDR MODE ─────────────
def scan_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass

def grab_cidr_banner(ip, port, timeout=2.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s, server_hostname=ip)
            except Exception:
                s.close()
                return "-"

        ua = random.choice(USER_AGENTS)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Accept-Encoding: identity\r\n"
            f"Connection: close\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n\r\n"
        )
        s.sendall(req.encode())

        data = b""
        while len(data) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        s.close()

        for line in data.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                return line.split(b":", 1)[1].strip().decode(errors="replace")
        first = data.split(b"\r\n", 1)[0].decode(errors="replace").strip()
        return first or "-"
    except Exception:
        return "-"

def scan_host_ip(ip, timeout, ports=None):
    ports = ports or CONFIG["ports"]
    open_ports = []
    for p in ports:
        if scan_port(ip, p, timeout):
            open_ports.append((p, grab_cidr_banner(ip, p)))
    return (ip, open_ports) if open_ports else None

# ───────────── DOMAIN MODE ─────────────
def resolve(domain, timeout):
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None

def scan_domain(domain, timeout):
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).hostname or domain
    domain = domain.rstrip("/")
    ip = resolve(domain, timeout)
    if not ip:
        return None
    result = http_get(f"https://{domain}/", timeout)
    if not result:
        result = http_get(f"http://{domain}/", timeout)
    if not result:
        return None
    status, final_url, headers = result
    hoster = detect_hoster(headers, ip)
    return {"domain": domain, "ip": ip, "status": status,
            "hoster": hoster, "link": final_url}

# ───────────── MIXED MODE ─────────────
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def is_ipv4(s):
    if not IPV4_RE.match(s):
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False

def parse_target_line(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if " #" in s:
        s = s.split(" #", 1)[0].strip()
    if not s:
        return None
    parts = re.split(r"[\t,]|\s{1,}", s, maxsplit=1)
    host = parts[0].strip()
    ip = parts[1].strip() if len(parts) > 1 else None
    if "://" in host:
        p = urlparse(host)
        host = p.hostname or ""
        host = host.rstrip("/").lower()
    if not host:
        return None
    if is_ipv4(host):
        return {"host": None, "ip": host}
    if ip and not is_ipv4(ip):
        ip = None
    return {"host": host, "ip": ip}

def _http_get_with_sni(url, sni_host, timeout, connect_ip=None, max_redirects=8):
    current = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        scheme = parsed.scheme or "https"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        connect_host = connect_ip or parsed.hostname
        if not connect_host:
            return None
        host_header = sni_host or parsed.hostname

        hdrs = build_headers(host=host_header)
        hdrs["connection"] = "close"

        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if connect_ip and host_header and not is_ipv4(host_header):
                    raw = socket.create_connection((connect_ip, port), timeout=timeout)
                    wrapped = ctx.wrap_socket(raw, server_hostname=host_header)
                    conn = http.client.HTTPSConnection(
                        connect_host, port, timeout=timeout, context=ctx)
                    conn.sock = wrapped
                else:
                    conn = http.client.HTTPSConnection(
                        connect_host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(connect_host, port, timeout=timeout)
        except Exception:
            return None

        try:
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            headers = resp.getheaders()

            if resp.status in (301, 302, 303, 307, 308):
                location = dict((k.lower(), v) for k, v in headers).get("location")
                resp.read(64)
                conn.close()
                if location:
                    current = urljoin(current, location)
                    connect_ip = None
                    sni_host = None
                    continue
                return (resp.status, current, headers)

            resp.read(256)
            conn.close()
            return (resp.status, current, headers)
        except Exception:
            try: conn.close()
            except Exception: pass
            return None
    return None

def scan_mixed(entry, timeout):
    host = entry.get("host")
    ip = entry.get("ip")
    candidates = []
    if host:
        candidates.append(("https", host, host))
        candidates.append(("http",  host, host))
    if ip:
        candidates.append(("https", ip, host or ip))
        candidates.append(("http",  ip, host or ip))

    for scheme, connect_to, sni in candidates:
        url = f"{scheme}://{connect_to}/"
        result = _http_get_with_sni(
            url, sni, timeout,
            connect_ip=connect_to if ip and connect_to == ip else None)
        if not result:
            continue
        status, final_url, headers = result
        used_ip = ip
        if not used_ip:
            used_ip = resolve(connect_to, timeout) or "-"
        hoster = detect_hoster(headers, used_ip if used_ip != "-" else "0.0.0.0")
        return {
            "host": host or "",
            "ip": used_ip,
            "status": status,
            "hoster": hoster,
            "link": final_url,
        }
    return None

# ───────────── SLIDING-WINDOW EXECUTOR ─────────────
def sliding_window_map(func, items, threads, max_inflight=None,
                       progress_cb=None, stop_event=None):
    if max_inflight is None:
        max_inflight = max(threads * 8, 200)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        it = iter(enumerate(items))
        inflight = {}
        for _ in range(max_inflight):
            try:
                idx, item = next(it)
            except StopIteration:
                break
            fut = pool.submit(func, item)
            inflight[fut] = (idx, item)

        done_count = 0
        while inflight:
            if stop_event is not None and stop_event.is_set():
                break
            done_set, _ = wait(list(inflight.keys()), timeout=0.5,
                               return_when=FIRST_COMPLETED)
            for fut in done_set:
                idx, item = inflight.pop(fut)
                try:
                    res = fut.result()
                except Exception:
                    res = None
                done_count += 1
                if progress_cb:
                    progress_cb(done_count, res, item)
                yield idx, res
                try:
                    nidx, nitem = next(it)
                    nfut = pool.submit(func, nitem)
                    inflight[nfut] = (nidx, nitem)
                except StopIteration:
                    pass
        for fut in inflight:
            fut.cancel()
        pool.shutdown(wait=False, cancel_futures=True)

# ───────────── UI HELPERS ─────────────
def bar(done, total, w=22):
    f = int(w * done / total) if total else 0
    pct = (done / total * 100) if total else 0
    return (f"{C.BG}{'█'*f}{C.D}{'░'*(w-f)}{C.R} "
            f"{C.BY}{pct:5.1f}%{C.R} {C.D}{done}/{total}{C.R}")

def color_status(s):
    if 200 <= s < 300: return C.BG
    if 300 <= s < 400: return C.CY
    if 400 <= s < 500: return C.BY
    if s >= 500: return C.BR
    return C.WH

def show_cidr(ip, port, banner):
    print(f"{C.BG}{C.B} OPEN {C.R} "
          f"{C.BW}{ip}{C.R}{C.D}:{port}{C.R} {C.CY}↳ {banner}{C.R}")

def show_domain(r):
    sc = color_status(r["status"])
    host_part = r.get('host','') or "-"
    print(f"{C.BG}{C.B} LIVE {C.R} {C.BW}{r['ip']:<16}{C.R} "
          f"{C.BM}{host_part:<28}{C.R} "
          f"{sc}[{r['status']}]{C.R} {C.BM}{r['hoster']:<13}{C.R} "
          f"{C.CY}{r['link']}{C.R}")

# ───────────── STATE ─────────────
def load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return None

def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def clear_state():
    try:
        if os.path.isfile(STATE_FILE):
            os.remove(STATE_FILE)
    except Exception:
        pass

# ───────────── CIDR ENGINE ─────────────
def run_cidr_scan(cidr, threads, timeout, output, quiet=False):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"{C.BR}[!] Invalid CIDR:{C.R} {e}")
        return [], 0, 0

    hosts = [str(ip) for ip in net.hosts()]
    total = len(hosts)

    if not quiet:
        print(f"\n{C.CY}Mode    :{C.R} {C.BW}CIDR {CONFIG['ports']}{C.R}")
        print(f"{C.CY}Target  :{C.R} {C.BW}{cidr}{C.R}")
        print(f"{C.CY}Hosts   :{C.R} {C.BW}{total}{C.R}")
        print(f"{C.CY}Threads :{C.R} {C.BW}{threads}{C.R}")
        print(f"{C.CY}Timeout :{C.R} {C.BW}{timeout}s{C.R}")
        print(f"{C.CY}Retries :{C.R} {C.BW}{CONFIG['retries']}{C.R}")
        print(f"{C.CY}Output  :{C.R} {C.BW}{output}{C.R}\n")

    if not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X 2 — CIDR Scan\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("# Format  : ip:port\tbanner\n")
            f.write("#" + "-"*56 + "\n")

    found = []
    done = 0
    start = time.time()
    ports = CONFIG["ports"]
    missed = []

    def task1(ip):
        return scan_host_ip(ip, timeout, ports)

    def on_result(count, res, item):
        nonlocal done
        done = count
        if res:
            ip, pdata = res
            found.append(res)
            with open(output, "a", encoding="utf-8") as f:
                for port, banner in pdata:
                    f.write(f"{ip}:{port}\t{banner}\n")
            if not quiet:
                sys.stdout.write("\r" + " "*90 + "\r")
                for port, banner in pdata:
                    show_cidr(ip, port, banner)
        else:
            missed.append(item)
        if not quiet:
            sys.stdout.write("\r" + bar(done, total))
            sys.stdout.flush()

    try:
        for _ in sliding_window_map(task1, hosts, threads,
                                    max_inflight=threads*8,
                                    progress_cb=on_result):
            pass

        for retry in range(CONFIG["retries"]):
            if not missed:
                break
            if not quiet:
                sys.stdout.write("\r" + " "*90 + "\r")
                print(f"{C.BY}[↻] Retry pass {retry+1}/{CONFIG['retries']} "
                      f"on {len(missed)} timed-out hosts{C.R}")
            retry_list = missed[:]
            missed = []
            r_done = [0]

            def on_retry(count, res, item):
                r_done[0] = count
                if res:
                    ip, pdata = res
                    found.append(res)
                    with open(output, "a", encoding="utf-8") as f:
                        for port, banner in pdata:
                            f.write(f"{ip}:{port}\t{banner}\n")
                    if not quiet:
                        sys.stdout.write("\r" + " "*90 + "\r")
                        for port, banner in pdata:
                            show_cidr(ip, port, banner)
                else:
                    missed.append(item)
                if not quiet:
                    sys.stdout.write("\r" + f"{C.BY}retry {bar(r_done[0], len(retry_list))}")
                    sys.stdout.flush()

            for _ in sliding_window_map(task1, retry_list, threads,
                                        max_inflight=threads*8,
                                        progress_cb=on_retry):
                pass
    except KeyboardInterrupt:
        print(f"\n{C.BY}[!] Interrupted{C.R}")
        raise

    return found, done, time.time() - start

# ───────────── DOMAIN ENGINE ─────────────
def run_domain_scan(domains, threads, timeout, output, quiet=False):
    total = len(domains)

    if not quiet:
        print(f"\n{C.CY}Mode    :{C.R} {C.BW}Domain (redirects followed){C.R}")
        print(f"{C.CY}Domains :{C.R} {C.BW}{total}{C.R}")
        print(f"{C.CY}Threads :{C.R} {C.BW}{threads}{C.R}")
        print(f"{C.CY}Timeout :{C.R} {C.BW}{timeout}s{C.R}")
        print(f"{C.CY}Output  :{C.R} {C.BW}{output}{C.R}\n")

    if not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X 2 — Domain Scan\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} {'HOST':<28} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*100 + "\n")

    found = 0
    done = 0
    start = time.time()
    missed = []

    def task(d):
        return scan_domain(d, timeout)

    def on_result(count, r, item):
        nonlocal done, found
        done = count
        if r:
            found += 1
            with open(output, "a", encoding="utf-8") as f:
                f.write(f"{r['ip']:<16} {r['domain']:<28} "
                        f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
            if not quiet:
                sys.stdout.write("\r" + " "*110 + "\r")
                show_domain({"ip": r["ip"], "host": r["domain"],
                             "status": r["status"], "hoster": r["hoster"],
                             "link": r["link"]})
        else:
            missed.append(item)
        if not quiet:
            sys.stdout.write("\r" + bar(done, total))
            sys.stdout.flush()

    try:
        for _ in sliding_window_map(task, domains, threads,
                                    max_inflight=threads*8,
                                    progress_cb=on_result):
            pass
        for retry in range(CONFIG["retries"]):
            if not missed:
                break
            retry_list = missed[:]
            missed = []
            if not quiet:
                sys.stdout.write("\r" + " "*100 + "\r")
                print(f"{C.BY}[↻] Retrying {len(retry_list)} failed domains{C.R}")
            rc = [0]
            def on_retry(count, r, item):
                nonlocal found
                rc[0] = count
                if r:
                    found += 1
                    with open(output, "a", encoding="utf-8") as f:
                        f.write(f"{r['ip']:<16} {r['domain']:<28} "
                                f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
                    if not quiet:
                        sys.stdout.write("\r" + " "*110 + "\r")
                        show_domain({"ip": r["ip"], "host": r["domain"],
                                     "status": r["status"], "hoster": r["hoster"],
                                     "link": r["link"]})
                else:
                    missed.append(item)
                if not quiet:
                    sys.stdout.write("\r" + f"{C.BY}retry {bar(rc[0], len(retry_list))}")
                    sys.stdout.flush()
            for _ in sliding_window_map(task, retry_list, threads,
                                        max_inflight=threads*8,
                                        progress_cb=on_retry):
                pass
    except KeyboardInterrupt:
        print(f"\n{C.BY}[!] Interrupted{C.R}")
        raise

    return found, done, time.time() - start

# ───────────── MIXED ENGINE ─────────────
def run_mixed_scan(entries, threads, timeout, output, quiet=False):
    total = len(entries)

    if not quiet:
        print(f"\n{C.CY}Mode    :{C.R} {C.BW}Mixed host+IP (https→http→ip){C.R}")
        print(f"{C.CY}Targets :{C.R} {C.BW}{total}{C.R}")
        print(f"{C.CY}Threads :{C.R} {C.BW}{threads}{C.R}")
        print(f"{C.CY}Timeout :{C.R} {C.BW}{timeout}s{C.R}")
        print(f"{C.CY}Output  :{C.R} {C.BW}{output}{C.R}\n")

    if not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X 2 — Mixed Host+IP Scan\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} {'HOST':<30} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*104 + "\n")

    found = 0
    done = 0
    start = time.time()
    missed = []

    def task(e):
        return scan_mixed(e, timeout)

    def on_result(count, r, item):
        nonlocal done, found
        done = count
        if r:
            found += 1
            with open(output, "a", encoding="utf-8") as f:
                f.write(f"{r['ip']:<16} {r['host']:<30} "
                        f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
            if not quiet:
                sys.stdout.write("\r" + " "*120 + "\r")
                show_domain(r)
        else:
            missed.append(item)
        if not quiet:
            sys.stdout.write("\r" + bar(done, total))
            sys.stdout.flush()

    try:
        for _ in sliding_window_map(task, entries, threads,
                                    max_inflight=threads*8,
                                    progress_cb=on_result):
            pass
        for retry in range(CONFIG["retries"]):
            if not missed:
                break
            retry_list = missed[:]
            missed = []
            if not quiet:
                sys.stdout.write("\r" + " "*120 + "\r")
                print(f"{C.BY}[↻] Retrying {len(retry_list)} failed targets{C.R}")
            rc = [0]
            def on_retry(count, r, item):
                nonlocal found
                rc[0] = count
                if r:
                    found += 1
                    with open(output, "a", encoding="utf-8") as f:
                        f.write(f"{r['ip']:<16} {r['host']:<30} "
                                f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
                    if not quiet:
                        sys.stdout.write("\r" + " "*120 + "\r")
                        show_domain(r)
                else:
                    missed.append(item)
                if not quiet:
                    sys.stdout.write("\r" + f"{C.BY}retry {bar(rc[0], len(retry_list))}")
                    sys.stdout.flush()
            for _ in sliding_window_map(task, retry_list, threads,
                                        max_inflight=threads*8,
                                        progress_cb=on_retry):
                pass
    except KeyboardInterrupt:
        print(f"\n{C.BY}[!] Interrupted{C.R}")
        raise

    return found, done, time.time() - start

# ───────────── FILE READERS ─────────────
def read_cidr_file(path):
    valid, invalid = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if " #" in s:
                s = s.split(" #", 1)[0].strip()
            try:
                valid.append(str(ipaddress.ip_network(s, strict=False)))
            except ValueError:
                invalid += 1
    return valid, invalid

def read_domain_file(path):
    valid, skipped = [], 0
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if " #" in s:
                s = s.split(" #", 1)[0].strip()
            if len(s) > 253 or "." not in s:
                skipped += 1
                continue
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            valid.append(s)
    return valid, skipped

def read_target_file(path):
    entries = []
    seen = set()
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            e = parse_target_line(raw)
            if not e:
                stripped = raw.strip()
                if stripped and not stripped.startswith("#"):
                    skipped += 1
                continue
            if e.get("host"):
                key = ("H", e["host"], e.get("ip") or "")
            else:
                key = ("I", e["ip"], "")
            if key in seen:
                continue
            seen.add(key)
            entries.append(e)
    return entries, skipped

# ───────────── BATCH WRAPPERS ─────────────
def run_cidr_batch(cidrs, threads, timeout, output, resume_state=None):
    start_idx = 0
    grand_found = 0
    grand_done = 0
    t_all = time.time()

    if resume_state:
        start_idx = resume_state.get("last_index", 0) + 1
        grand_found = resume_state.get("grand_found", 0)
        grand_done = resume_state.get("grand_done", 0)
        print(f"{C.BY}[↻] Resuming from CIDR #{start_idx+1}/{len(cidrs)}{C.R}")

    for idx, cidr in enumerate(cidrs):
        if idx < start_idx:
            continue
        try:
            hc = max(0, ipaddress.ip_network(cidr).num_addresses - 2)
        except Exception:
            hc = 0
        print(f"\n{C.BC}{C.B}━━━ [{idx+1}/{len(cidrs)}] {C.BY}{cidr}{C.BC} "
              f"({hc} hosts) ━━━{C.R}")
        try:
            found, done, elapsed = run_cidr_scan(cidr, threads, timeout, output)
        except KeyboardInterrupt:
            save_state({"mode": "cidr", "last_index": idx-1,
                        "grand_found": grand_found, "grand_done": grand_done,
                        "cidrs": cidrs, "output": output})
            print(f"{C.BY}[!] Interrupted. Resume with --resume{C.R}")
            return None
        grand_found += len(found)
        grand_done += done
        rate = done/elapsed if elapsed else 0
        print(f"{C.BG}  ✔ {len(found)} open{C.R} • "
              f"{done} scanned • {elapsed:.1f}s • {rate:.0f}/s")
        save_state({"mode": "cidr", "last_index": idx,
                    "grand_found": grand_found, "grand_done": grand_done,
                    "cidrs": cidrs, "output": output})

    elapsed_all = time.time() - t_all
    with open(output, "a", encoding="utf-8") as f:
        f.write("#" + "-"*56 + "\n")
        f.write(f"# Batch finished : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"# Duration       : {elapsed_all:.1f}s\n")
        f.write(f"# Total scanned  : {grand_done}\n")
        f.write(f"# Total open     : {grand_found}\n")
    print(f"\n{C.BC}{C.B}━━━ CIDR BATCH COMPLETE ━━━{C.R}")
    print(f"  {C.CY}•{C.R} CIDRs   : {C.BW}{len(cidrs)}{C.R}")
    print(f"  {C.CY}•{C.R} Scanned : {C.BW}{grand_done}{C.R}")
    print(f"  {C.CY}•{C.R} Open    : {C.BG}{C.B} {grand_found} {C.R}")
    print(f"  {C.CY}•{C.R} Time    : {C.BW}{elapsed_all/3600:.2f}h{C.R}")
    print(f"  {C.CY}•{C.R} Saved   : {C.BY}{output}{C.R}\n")
    clear_state()
    return True

def run_domain_batch(domains, threads, timeout, output, resume_state=None):
    start_idx = 0
    grand_found = 0
    grand_done = 0
    t_all = time.time()

    if resume_state:
        start_idx = resume_state.get("last_index", 0) + 1
        grand_found = resume_state.get("grand_found", 0)
        grand_done = resume_state.get("grand_done", 0)
        print(f"{C.BY}[↻] Resuming from domain #{start_idx+1}/{len(domains)}{C.R}")

    if start_idx == 0 and not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X 2 — Domain Batch\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} {'HOST':<28} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*100 + "\n")

    remaining = domains[start_idx:]
    chunk = 2000
    for i in range(0, len(remaining), chunk):
        block = remaining[i:i+chunk]
        cur_idx = start_idx + i
        print(f"\n{C.BC}{C.B}━━━ Domains {cur_idx+1}..{cur_idx+len(block)} "
              f"/ {len(domains)} ━━━{C.R}")
        try:
            found, done, elapsed = run_domain_scan(block, threads, timeout, output)
        except KeyboardInterrupt:
            save_state({"mode": "domain", "last_index": cur_idx-1,
                        "grand_found": grand_found, "grand_done": grand_done,
                        "domains": domains, "output": output})
            print(f"{C.BY}[!] Interrupted. Resume with --resume{C.R}")
            return None
        grand_found += found
        grand_done += done
        rate = done/elapsed if elapsed else 0
        print(f"{C.BG}  ✔ {found} live{C.R} • "
              f"{done} scanned • {elapsed:.1f}s • {rate:.1f}/s")
        save_state({"mode": "domain", "last_index": cur_idx + len(block) - 1,
                    "grand_found": grand_found, "grand_done": grand_done,
                    "domains": domains, "output": output})

    elapsed_all = time.time() - t_all
    with open(output, "a", encoding="utf-8") as f:
        f.write("#" + "-"*100 + "\n")
        f.write(f"# Batch finished : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"# Duration       : {elapsed_all:.1f}s\n")
        f.write(f"# Total scanned  : {grand_done}\n")
        f.write(f"# Total live     : {grand_found}\n")
    print(f"\n{C.BC}{C.B}━━━ DOMAIN BATCH COMPLETE ━━━{C.R}")
    print(f"  {C.CY}•{C.R} Domains : {C.BW}{len(domains)}{C.R}")
    print(f"  {C.CY}•{C.R} Scanned : {C.BW}{grand_done}{C.R}")
    print(f"  {C.CY}•{C.R} Live    : {C.BG}{C.B} {grand_found} {C.R}")
    print(f"  {C.CY}•{C.R} Time    : {C.BW}{elapsed_all/3600:.2f}h{C.R}")
    print(f"  {C.CY}•{C.R} Saved   : {C.BY}{output}{C.R}\n")
    clear_state()
    return True

def run_mixed_batch(entries, threads, timeout, output, resume_state=None):
    start_idx = 0
    grand_found = 0
    grand_done = 0
    t_all = time.time()

    if resume_state:
        start_idx = resume_state.get("last_index", 0) + 1
        grand_found = resume_state.get("grand_found", 0)
        grand_done = resume_state.get("grand_done", 0)
        print(f"{C.BY}[↻] Resuming from mixed target #{start_idx+1}/{len(entries)}{C.R}")

    if start_idx == 0 and not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X 2 — Mixed Host+IP Batch\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} {'HOST':<30} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*104 + "\n")

    remaining = entries[start_idx:]
    chunk = 2000
    for i in range(0, len(remaining), chunk):
        block = remaining[i:i+chunk]
        cur_idx = start_idx + i
        print(f"\n{C.BC}{C.B}━━━ Mixed targets {cur_idx+1}..{cur_idx+len(block)} "
              f"/ {len(entries)} ━━━{C.R}")
        try:
            found, done, elapsed = run_mixed_scan(block, threads, timeout, output)
        except KeyboardInterrupt:
            save_state({"mode": "mixed", "last_index": cur_idx-1,
                        "grand_found": grand_found, "grand_done": grand_done,
                        "entries": entries, "output": output})
            print(f"{C.BY}[!] Interrupted. Resume with --resume{C.R}")
            return None
        grand_found += found
        grand_done += done
        rate = done/elapsed if elapsed else 0
        print(f"{C.BG}  ✔ {found} live{C.R} • "
              f"{done} scanned • {elapsed:.1f}s • {rate:.1f}/s")
        save_state({"mode": "mixed", "last_index": cur_idx + len(block) - 1,
                    "grand_found": grand_found, "grand_done": grand_done,
                    "entries": entries, "output": output})

    elapsed_all = time.time() - t_all
    with open(output, "a", encoding="utf-8") as f:
        f.write("#" + "-"*104 + "\n")
        f.write(f"# Batch finished : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"# Duration       : {elapsed_all:.1f}s\n")
        f.write(f"# Total scanned  : {grand_done}\n")
        f.write(f"# Total live     : {grand_found}\n")
    print(f"\n{C.BC}{C.B}━━━ MIXED BATCH COMPLETE ━━━{C.R}")
    print(f"  {C.CY}•{C.R} Targets : {C.BW}{len(entries)}{C.R}")
    print(f"  {C.CY}•{C.R} Scanned : {C.BW}{grand_done}{C.R}")
    print(f"  {C.CY}•{C.R} Live    : {C.BG}{C.B} {grand_found} {C.R}")
    print(f"  {C.CY}•{C.R} Time    : {C.BW}{elapsed_all/3600:.2f}h{C.R}")
    print(f"  {C.CY}•{C.R} Saved   : {C.BY}{output}{C.R}\n")
    clear_state()
    return True

# ───────────── PROMPTS ─────────────
def ask(t):
    try:
        return input(t).strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n{C.BY}[!] Cancelled{C.R}")
        sys.exit(0)

def prompt_cidr():
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}Enter CIDR block{C.R} {C.D}(e.g. 192.168.1.0/24){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if not raw:
            continue
        try:
            ipaddress.ip_network(raw, strict=False)
            return raw
        except ValueError as e:
            print(f"{C.BR}  ✘ Invalid CIDR:{C.R} {e}\n")

def prompt_domain():
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}Enter domain{C.R} {C.D}(e.g. example.com){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if raw and "." in raw:
            return raw
        print(f"{C.BR}  ✘ Invalid domain{C.R}\n")

def prompt_file(label, hint):
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}{label}{C.R} {C.D}({hint}){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if not raw:
            continue
        if not os.path.isfile(raw):
            print(f"{C.BR}  ✘ File not found:{C.R} {raw}\n")
            continue
        return raw

def prompt_int(label, default):
    while True:
        raw = ask(f"{C.BC}  {label}{C.R} {C.D}[default {default}]{C.R}: ")
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            print(f"{C.BR}  ✘ Must be a number{C.R}")

def prompt_float(label, default):
    while True:
        raw = ask(f"{C.BC}  {label}{C.R} {C.D}[default {default}]{C.R}: ")
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            print(f"{C.BR}  ✘ Must be a number{C.R}")

def prompt_ports(default):
    raw = ask(f"{C.BC}  Ports{C.R} {C.D}[default {','.join(map(str, default))}]{C.R}: ")
    if not raw:
        return default
    try:
        parts = [p.strip() for p in raw.replace(" ", ",").split(",") if p.strip()]
        ports = [int(p) for p in parts]
        if not ports:
            return default
        for p in ports:
            if p < 1 or p > 65535:
                raise ValueError
        return ports
    except ValueError:
        print(f"{C.BR}  ✘ Invalid ports, using default{C.R}")
        return default

# ───────────── MENU ─────────────
def show_menu():
    print(f"{C.BC}{C.B}  ┌──────────────────────◈")
    print(f"  │           {C.BY}MAIN MENU{C.BC} ")
    print(f"  ├───────────── {C.BM}CIDR MODE{C.BC} ──⟢")
    print(f"  │  {C.BW}1){C.BC} Scan CIDR subnet")
    print(f"  │  {C.BW}2){C.BC} Scan CIDR list from file")
    print(f"  ├─────────── {C.BM}DOMAIN MODE{C.BC} ──⟢")
    print(f"  │  {C.BW}3){C.BC} Scan single domain")
    print(f"  │  {C.BW}4){C.BC} Scan domain list from file")
    print(f"  ├──────────── {C.BM}MIXED MODE{C.BC} ──⟢")
    print(f"  │  {C.BW}9){C.BC} Scan mixed host+IP file")
    print(f"  ├─────────────── {C.BM}OTHER{C.BC} ──⟢")
    print(f"  │  {C.BW}5){C.BC} Custom settings  {C.D}(ports){C.R}")
    print(f"  │  {C.BW}6){C.BC} View last results")
    print(f"  │  {C.BW}7){C.BC} About")
    print(f"  │  {C.BW}8){C.BC} Exit")
    print(f"  └──────────────────────◈")
    print(f"  {C.D}Current: threads={CONFIG['threads']} timeout={CONFIG['timeout']}s "
          f"ports={CONFIG['ports']} retries={CONFIG['retries']}{C.R}")

def menu_choose():
    valid = {str(i) for i in range(1, 10)}
    while True:
        ch = ask(f"\n{C.BC}  ▶{C.R} {C.BW}Choose [1-9]{C.R}: ")
        if ch in valid:
            return ch
        print(f"{C.BR}  ✘ Invalid choice{C.R}")

def custom_settings():
    print(f"\n{C.BC}{C.B}  ── Custom Settings ──{C.R}")
    CONFIG["threads"] = prompt_int("Threads", CONFIG["threads"])
    CONFIG["timeout"] = prompt_float("Timeout (sec)", CONFIG["timeout"])
    CONFIG["retries"] = prompt_int("Retry passes (0-5)", CONFIG["retries"])
    CONFIG["ports"] = prompt_ports(CONFIG["ports"])
    out = ask(f"{C.BC}  Output file{C.R} {C.D}[default {CONFIG['output']}]{C.R}: ")
    if out:
        CONFIG["output"] = out
    print(f"\n{C.BG}  ✔ Settings updated{C.R}")
    print(f"  {C.D}ports now = {CONFIG['ports']}{C.R}")

def show_about():
    print(f"\n{C.BC}{C.B}  ── ABOUT DOM-X 2 ULTIMATE ──{C.R}")
    print(f"  {C.CY}Author    :{C.R} {C.BW}Mr Frank{C.R}")
    print(f"  {C.CY}Telegram  :{C.R} {C.BC}t.me/mrfrankofc{C.R}")
    print(f"  {C.CY}WhatsApp  :{C.R} {C.BC}wa.me/mrfr4nkofc{C.R}")
    print(f"  {C.CY}Features  :{C.R} CIDR • Domain • Mixed • Custom ports • Retry • Chrome headers")
    print(f"\n  {C.D}Use only on infrastructure you own or have permission to test.{C.R}\n")

def view_results(output):
    if not os.path.isfile(output):
        print(f"{C.BR}  ✘ No results file at {output}{C.R}")
        return
    print(f"\n{C.BC}{C.B}── {output} ──{C.R}")
    try:
        with open(output, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in lines[:80]:
            print(line.rstrip())
        if len(lines) > 80:
            print(f"{C.D}  ... ({len(lines)-80} more lines){C.R}")
    except Exception as e:
        print(f"{C.BR}  ✘ Error reading file: {e}{C.R}")
    print()

# ───────────── MAIN ─────────────
def is_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return "/" in s or s.replace(".", "").isdigit()
    except ValueError:
        return False

def main():
    print(BANNER)

    p = argparse.ArgumentParser(description="Dom-X 2 Ultimate — CIDR + Domain + Mixed Scanner")
    p.add_argument("target", nargs="?", default=None, help="CIDR, domain, or 'host ip'")
    p.add_argument("-f", "--file", default=None, help="CIDR/domain/mixed list file")
    p.add_argument("--mode", choices=["cidr", "domain", "mixed"], default=None)
    p.add_argument("-t", "--threads", type=int, default=CONFIG["threads"])
    p.add_argument("-T", "--timeout", type=float, default=CONFIG["timeout"])
    p.add_argument("-p", "--ports", default=None,
                   help="Comma-separated ports for CIDR mode (default 80,443)")
    p.add_argument("-r", "--retries", type=int, default=CONFIG["retries"])
    p.add_argument("-o", "--output", default=CONFIG["output"])
    p.add_argument("--resume", action="store_true")
    args = p.parse_args()

    CONFIG["threads"] = args.threads
    CONFIG["timeout"] = args.timeout
    CONFIG["retries"] = args.retries
    CONFIG["output"] = args.output
    if args.ports:
        try:
            CONFIG["ports"] = [int(x) for x in args.ports.split(",")]
        except ValueError:
            print(f"{C.BR}[!] Invalid --ports, using defaults{C.R}")

    # ── Direct target ──
    if args.target:
        target = args.target
        mode = args.mode
        if not mode:
            parsed = parse_target_line(target)
            if is_cidr(target):
                mode = "cidr"
            elif parsed and parsed.get("host") and parsed.get("ip"):
                mode = "mixed"
            else:
                mode = "domain"

        if mode == "cidr":
            if not is_cidr(target):
                print(f"{C.BR}[!] Invalid CIDR{C.R}"); sys.exit(1)
            found, done, elapsed = run_cidr_scan(
                target, CONFIG["threads"], CONFIG["timeout"], CONFIG["output"])
            print(f"\n{C.BC}{C.B}━━━ COMPLETE ━━━{C.R}")
            print(f"  {C.CY}•{C.R} Scanned : {C.BW}{done}{C.R}")
            print(f"  {C.CY}•{C.R} Open    : {C.BG}{C.B} {len(found)} {C.R}")
            print(f"  {C.CY}•{C.R} Saved   : {C.BY}{CONFIG['output']}{C.R}\n")
        elif mode == "mixed":
            e = parse_target_line(target)
            if not e:
                print(f"{C.BR}[!] Cannot parse target{C.R}"); sys.exit(1)
            r = scan_mixed(e, CONFIG["timeout"])
            if r:
                show_domain(r)
                if not os.path.isfile(CONFIG["output"]):
                    with open(CONFIG["output"], "w", encoding="utf-8") as f:
                        f.write("# Dom-X 2 Results\n" + "#" + "-"*104 + "\n")
                with open(CONFIG["output"], "a", encoding="utf-8") as f:
                    f.write(f"{r['ip']:<16} {r['host']:<30} "
                            f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
                print(f"\n{C.BG}  ✔ Saved to {CONFIG['output']}{C.R}\n")
            else:
                print(f"{C.BR}  ✘ No response from {target}{C.R}\n")
        else:
            r = scan_domain(target, CONFIG["timeout"])
            if r:
                show_domain({"ip": r["ip"], "host": r["domain"],
                             "status": r["status"], "hoster": r["hoster"],
                             "link": r["link"]})
                if not os.path.isfile(CONFIG["output"]):
                    with open(CONFIG["output"], "w", encoding="utf-8") as f:
                        f.write("# Dom-X 2 Results\n" + "#" + "-"*104 + "\n")
                with open(CONFIG["output"], "a", encoding="utf-8") as f:
                    f.write(f"{r['ip']:<16} {r['domain']:<30} "
                            f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
                print(f"\n{C.BG}  ✔ Saved to {CONFIG['output']}{C.R}\n")
            else:
                print(f"{C.BR}  ✘ No response{C.R}\n")
        return

    # ── Batch file ──
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{C.BR}[!] File not found:{C.R} {args.file}"); sys.exit(1)

        mode = args.mode
        if not mode:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    mode = "cidr" if is_cidr(s) else "mixed"
                    break
        if not mode:
            print(f"{C.BR}[!] Empty file{C.R}"); sys.exit(1)

        state = load_state() if args.resume else None

        if mode == "cidr":
            cidrs, invalid = read_cidr_file(args.file)
            if invalid:
                print(f"{C.BY}[!] Skipped {invalid} invalid lines{C.R}")
            print(f"{C.BW}[*] Loaded {len(cidrs)} CIDRs from {args.file}{C.R}")
            run_cidr_batch(cidrs, CONFIG["threads"], CONFIG["timeout"],
                           CONFIG["output"], state)
        elif mode == "mixed":
            entries, skipped = read_target_file(args.file)
            if skipped:
                print(f"{C.BY}[!] Skipped {skipped} unparseable lines{C.R}")
            print(f"{C.BW}[*] Loaded {len(entries)} unique targets from {args.file}{C.R}")
            run_mixed_batch(entries, CONFIG["threads"], CONFIG["timeout"],
                            CONFIG["output"], state)
        else:
            domains, skipped = read_domain_file(args.file)
            if skipped:
                print(f"{C.BY}[!] Skipped {skipped} malformed lines{C.R}")
            print(f"{C.BW}[*] Loaded {len(domains)} domains from {args.file}{C.R}")
            run_domain_batch(domains, CONFIG["threads"], CONFIG["timeout"],
                             CONFIG["output"], state)
        return

    # ── Interactive menu ──
    while True:
        show_menu()
        choice = menu_choose()

        if choice == "1":
            cidr = prompt_cidr()
            found, done, elapsed = run_cidr_scan(
                cidr, CONFIG["threads"], CONFIG["timeout"], CONFIG["output"])
            print(f"\n{C.BC}{C.B}━━━ COMPLETE ━━━{C.R}")
            print(f"  {C.CY}•{C.R} Scanned : {C.BW}{done}{C.R}")
            print(f"  {C.CY}•{C.R} Open    : {C.BG}{C.B} {len(found)} {C.R}")
            print(f"  {C.CY}•{C.R} Saved   : {C.BY}{CONFIG['output']}{C.R}\n")

        elif choice == "2":
            path = prompt_file("Enter CIDR list file", "1 CIDR per line")
            cidrs, invalid = read_cidr_file(path)
            if invalid:
                print(f"{C.BY}[!] Skipped {invalid} invalid lines{C.R}")
            if not cidrs:
                print(f"{C.BR}  ✘ No valid CIDRs{C.R}"); continue
            print(f"{C.BW}[*] Loaded {len(cidrs)} CIDRs{C.R}")
            state = load_state()
            if state and state.get("mode") == "cidr" and state.get("cidrs") == cidrs:
                yn = ask(f"{C.BY}  ↻ Found unfinished run. Resume? [y/N]{C.R}: ")
                if yn.lower() != "y":
                    state = None
            try:
                run_cidr_batch(cidrs, CONFIG["threads"], CONFIG["timeout"],
                               CONFIG["output"], state)
            except KeyboardInterrupt:
                pass

        elif choice == "3":
            d = prompt_domain()
            r = scan_domain(d, CONFIG["timeout"])
            if r:
                show_domain({"ip": r["ip"], "host": r["domain"],
                             "status": r["status"], "hoster": r["hoster"],
                             "link": r["link"]})
                if not os.path.isfile(CONFIG["output"]):
                    with open(CONFIG["output"], "w", encoding="utf-8") as f:
                        f.write("# Dom-X 2 Results\n" + "#" + "-"*104 + "\n")
                with open(CONFIG["output"], "a", encoding="utf-8") as f:
                    f.write(f"{r['ip']:<16} {r['domain']:<30} "
                            f"[{r['status']}] {r['hoster']:<13} {r['link']}\n")
                print(f"\n{C.BG}  ✔ Saved to {CONFIG['output']}{C.R}\n")
            else:
                print(f"{C.BR}  ✘ No response{C.R}\n")

        elif choice == "4":
            path = prompt_file("Enter domain list file", "1 domain per line")
            domains, skipped = read_domain_file(path)
            if skipped:
                print(f"{C.BY}[!] Skipped {skipped} malformed{C.R}")
            if not domains:
                print(f"{C.BR}  ✘ No valid domains{C.R}"); continue
            print(f"{C.BW}[*] Loaded {len(domains)} domains{C.R}")
            state = load_state()
            if state and state.get("mode") == "domain" and state.get("domains") == domains:
                yn = ask(f"{C.BY}  ↻ Found unfinished run. Resume? [y/N]{C.R}: ")
                if yn.lower() != "y":
                    state = None
            try:
                run_domain_batch(domains, CONFIG["threads"], CONFIG["timeout"],
                                 CONFIG["output"], state)
            except KeyboardInterrupt:
                pass

        elif choice == "9":
            path = prompt_file("Enter mixed host+IP file",
                               "domain.com<TAB>1.2.3.4 OR domain.com OR 1.2.3.4")
            entries, skipped = read_target_file(path)
            if skipped:
                print(f"{C.BY}[!] Skipped {skipped} unparseable lines{C.R}")
            if not entries:
                print(f"{C.BR}  ✘ No valid targets{C.R}"); continue
            print(f"{C.BW}[*] Loaded {len(entries)} unique targets{C.R}")
            state = load_state()
            if state and state.get("mode") == "mixed" and state.get("entries") == entries:
                yn = ask(f"{C.BY}  ↻ Found unfinished run. Resume? [y/N]{C.R}: ")
                if yn.lower() != "y":
                    state = None
            try:
                run_mixed_batch(entries, CONFIG["threads"], CONFIG["timeout"],
                                CONFIG["output"], state)
            except KeyboardInterrupt:
                pass

        elif choice == "5":
            custom_settings()

        elif choice == "6":
            view_results(CONFIG["output"])

        elif choice == "7":
            show_about()

        elif choice == "8":
            print(f"{C.BY}  ✌ Goodbye — Mr Frank{C.R}")
            print(f"{C.BC}  📢 t.me/mrfrankofc  💬 wa.me/mrfr4nkofc{C.R}\n")
            sys.exit(0)

if __name__ == "__main__":
    main()
