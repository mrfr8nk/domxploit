#!/usr/bin/env python3
"""
Dom-X — Combined CIDR + Domain Scanner
Made by Mr Frank
t.me/mrfrankofc • wa.me/mrfr4nkofc

Features:
  • CIDR mode  : scan IP ranges on 80/443, grab Server banner, save open hosts
  • Domain mode: resolve → follow redirects → final status + hoster detection
  • Both modes : batch-file scan, resume support, colored UI, skull banner
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
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# ───────────── BANNER ─────────────
BANNER = f"""
{C.BM}{C.B}  ██████╗  ██████╗ ███╗   ███╗    {C.BC}██╗  ██╗
{C.BM}{C.B}  ██╔══██╗██╔═══██╗████╗ ████║   {C.BC}╚██╗██╔╝
{C.BM}{C.B}  ██║  ██║██║   ██║██╔████╔██║    {C.BC}╚███╔╝
{C.BM}{C.B}  ██║  ██║██║   ██║██║╚██╔╝██║    {C.BC}██╔██╗
{C.BM}{C.B}  ██████╔╝╚██████╔╝██║ ╚═╝ ██║    {C.BC}██╔╝ ██╗
{C.BM}{C.B}  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝    {C.BC}╚═╝  ╚═╝{C.R}

{C.BY}{C.B}  ┌──────────────────────────────────────────❯
  │  {C.BM}💀  DOM-X — CIDR + DOMAIN SCANNER  💀{C.BY}         
  │  {C.BW}Free Internet For All !{C.BY}            
  │  {C.D}Made By Mr Frank OFC{C.BY}                              
  │  {C.BC}  t.me/mrfrankofc  ◈  wa.me/mrfr4nkofc{C.BY}      
  └──────────────────────────────────────────────▣{C.R}
"""

STATE_FILE = "domx_state.json"

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


# ───────────── SHARED HTTP (for domain mode) ─────────────
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
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(parsed.hostname, port,
                                                   timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
            conn.request("GET", path, headers={
                "Host": parsed.hostname,
                "User-Agent": "Mozilla/5.0 (DomX/1.0)",
                "Accept": "*/*",
                "Connection": "close",
            })
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
        s.close()


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
                s.close(); return "-"
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        data = b""
        while len(data) < 4096:
            chunk = s.recv(1024)
            if not chunk: break
            data += chunk
            if b"\r\n\r\n" in data: break
        s.close()
        for line in data.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                return line.split(b":", 1)[1].strip().decode(errors="replace")
        first = data.split(b"\r\n", 1)[0].decode(errors="replace").strip()
        return first or "-"
    except Exception:
        return "-"


def scan_host_ip(ip, timeout):
    open_ports = []
    if scan_port(ip, 80, timeout):
        open_ports.append((80, grab_cidr_banner(ip, 80)))
    if scan_port(ip, 443, timeout):
        open_ports.append((443, grab_cidr_banner(ip, 443)))
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


# ───────────── UI ─────────────
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
    print(f"{C.BG}{C.B} LIVE {C.R} {C.BW}{r['ip']:<16}{C.R} "
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
        if os.path.isfile(STATE_FILE): os.remove(STATE_FILE)
    except Exception:
        pass


# ───────────── CIDR ENGINE ─────────────
def run_cidr_scan(cidr, threads, timeout, output, quiet=False):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"{C.BR}[!] Invalid CIDR:{C.R} {e}"); return [], 0, 0

    hosts = [str(ip) for ip in net.hosts()]
    total = len(hosts)

    if not quiet:
        print(f"\n{C.CY}Mode    :{C.R} {C.BW}CIDR (80, 443){C.R}")
        print(f"{C.CY}Target  :{C.R} {C.BW}{cidr}{C.R}")
        print(f"{C.CY}Hosts   :{C.R} {C.BW}{total}{C.R}")
        print(f"{C.CY}Threads :{C.R} {C.BW}{threads}{C.R}")
        print(f"{C.CY}Timeout :{C.R} {C.BW}{timeout}s{C.R}")
        print(f"{C.CY}Output  :{C.R} {C.BW}{output}{C.R}\n")

    if not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X — CIDR Scan\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("# Format  : ip:port<TAB>banner\n")
            f.write("#" + "-"*56 + "\n")

    found = []
    done = 0
    lock = threading.Lock()
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(scan_host_ip, ip, timeout) for ip in hosts]
            for fut in as_completed(futures):
                res = fut.result()
                with lock:
                    done += 1
                    if res:
                        ip, ports = res
                        found.append(res)
                        with open(output, "a", encoding="utf-8") as f:
                            for port, banner in ports:
                                f.write(f"{ip}:{port}\t{banner}\n")
                        if not quiet:
                            sys.stdout.write("\r" + " "*80 + "\r")
                            for port, banner in ports:
                                show_cidr(ip, port, banner)
                    if not quiet:
                        sys.stdout.write("\r" + bar(done, total)); sys.stdout.flush()
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
            f.write("# Dom-X — Domain Scan\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*72 + "\n")

    found = 0
    done = 0
    lock = threading.Lock()
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(scan_domain, d, timeout) for d in domains]
            for fut in as_completed(futures):
                r = fut.result()
                with lock:
                    done += 1
                    if r:
                        found += 1
                        with open(output, "a", encoding="utf-8") as f:
                            f.write(f"{r['ip']:<16} [{r['status']}] "
                                    f"{r['hoster']:<13} {r['link']}\n")
                        if not quiet:
                            sys.stdout.write("\r" + " "*90 + "\r")
                            show_domain(r)
                    if not quiet:
                        sys.stdout.write("\r" + bar(done, total)); sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n{C.BY}[!] Interrupted{C.R}")
        raise

    return found, done, time.time() - start


# ───────────── BATCH (CIDR file) ─────────────
def read_cidr_file(path):
    valid, invalid = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            try:
                valid.append(str(ipaddress.ip_network(s, strict=False)))
            except ValueError:
                invalid += 1
    return valid, invalid


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
        if idx < start_idx: continue
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


# ───────────── BATCH (Domain file) ─────────────
def read_domain_file(path):
    valid, skipped = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            if len(s) > 253 or "." not in s:
                skipped += 1; continue
            valid.append(s)
    return valid, skipped


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

    # Only a header once, so partial writes are still readable
    if start_idx == 0 and not os.path.isfile(output):
        with open(output, "w", encoding="utf-8") as f:
            f.write("# Dom-X — Domain Batch\n")
            f.write(f"# Started : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"# {'IP':<16} STATUS  HOSTER          LINK\n")
            f.write("#" + "-"*72 + "\n")

    remaining = domains[start_idx:]
    chunk = 1000
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
        f.write("#" + "-"*72 + "\n")
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


# ───────────── PROMPTS ─────────────
def ask(t):
    try:
        return input(t).strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n{C.BY}[!] Cancelled{C.R}"); sys.exit(0)


def prompt_cidr():
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}Enter CIDR block{C.R} {C.D}(e.g. 192.168.1.0/24){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if not raw: continue
        try: ipaddress.ip_network(raw, strict=False); return raw
        except ValueError as e: print(f"{C.BR}  ✘ Invalid CIDR:{C.R} {e}\n")


def prompt_domain():
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}Enter domain{C.R} {C.D}(e.g. example.com){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if raw and "." in raw: return raw
        print(f"{C.BR}  ✘ Invalid domain{C.R}\n")


def prompt_file(label, hint):
    while True:
        raw = ask(f"{C.BC}┌─{C.R} {C.BW}{label}{C.R} {C.D}({hint}){C.R}\n"
                  f"{C.BC}└─▶{C.R} ")
        if not raw: continue
        if not os.path.isfile(raw):
            print(f"{C.BR}  ✘ File not found:{C.R} {raw}\n"); continue
        return raw


def prompt_int(label, default):
    while True:
        raw = ask(f"{C.BC}  {label}{C.R} {C.D}[default {default}]{C.R}: ")
        if not raw: return default
        try: return int(raw)
        except ValueError: print(f"{C.BR}  ✘ Must be a number{C.R}")


def prompt_float(label, default):
    while True:
        raw = ask(f"{C.BC}  {label}{C.R} {C.D}[default {default}]{C.R}: ")
        if not raw: return default
        try: return float(raw)
        except ValueError: print(f"{C.BR}  ✘ Must be a number{C.R}")


# ───────────── MENU ─────────────
def show_menu():
    print(f"{C.BC}{C.B}  ┌──────────────────────◈")
    print(f"  │           {C.BY}MAIN MENU{C.BC} ")
    print(f"  ├───────────── {C.BM}CIDR MODE{C.BC} ──⟢")
    print(f"  │  {C.BW}1){C.BC} Scan CIDR subnet")
    print(f"  │  {C.BW}2){C.BC} Scan CIDR list from file")
    print(f"  ├─────────── {C.BM}DOMAIN MODE{C.BC} ──⟢")
    print(f"  │  {C.BW}3){C.BC} Scan single domain ")
    print(f"  │  {C.BW}4){C.BC} Scan domain list from file ")
    print(f"  ├─────────────── {C.BM}OTHER{C.BC} ──⟢")
    print(f"  │  {C.BW}5){C.BC} Custom settings")
    print(f"  │  {C.BW}6){C.BC} View last results")
    print(f"  │  {C.BW}7){C.BC} About")
    print(f"  │  {C.BW}8){C.BC} Exit ")
    print(f"  └──────────────────────◈{C.R}")


def menu_choose():
    while True:
        ch = ask(f"\n{C.BC}  ▶{C.R} {C.BW}Choose [1-8]{C.R}: ")
        if ch in [str(i) for i in range(1, 9)]: return ch
        print(f"{C.BR}  ✘ Invalid choice{C.R}")


def custom_settings(d):
    print(f"\n{C.BC}{C.B}  ── Custom Settings ──{C.R}")
    d["threads"] = prompt_int("Threads", d["threads"])
    d["timeout"] = prompt_float("Timeout (sec)", d["timeout"])
    out = ask(f"{C.BC}  Output file{C.R} {C.D}[default {d['output']}]{C.R}: ")
    if out: d["output"] = out
    print(f"\n{C.BG}  ✔ Settings updated{C.R}")
    return d


def show_about():
    print(f"\n{C.BC}{C.B}  ── ABOUT DOM-X ──{C.R}")
    print(f"  {C.CY}Author    :{C.R} {C.BW}Mr Frank{C.R}")
    print(f"  {C.CY}Telegram  :{C.R} {C.BC}t.me/mrfrankofc{C.R}")
    print(f"  {C.CY}WhatsApp  :{C.R} {C.BC}wa.me/mrfr4nkofc{C.R}")
    print(f"  {C.CY}Features  :{C.R} CIDR scan (80/443) • Domain scan (redirects + hoster) • batch • resume")
    print(f"\n  {C.D}Use only on infrastructure you own or have permission to test.{C.R}\n")


def view_results(output):
    if not os.path.isfile(output):
        print(f"{C.BR}  ✘ No results file at {output}{C.R}"); return
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
def main():
    print(BANNER)

    p = argparse.ArgumentParser(description="Dom-X — CIDR + Domain Scanner")
    p.add_argument("target", nargs="?", default=None,
                   help="CIDR or domain")
    p.add_argument("-f", "--file", default=None, help="CIDR or domain list file")
    p.add_argument("--mode", choices=["cidr", "domain"], default=None,
                   help="Force mode (auto-detected by default)")
    p.add_argument("-t", "--threads", type=int, default=500,
                   help="Threads (default 500)")
    p.add_argument("-T", "--timeout", type=float, default=2.0,
                   help="Timeout seconds (default 2.0)")
    p.add_argument("-o", "--output", default="domx_results.txt",
                   help="Output file")
    p.add_argument("--resume", action="store_true",
                   help="Resume from previous interrupted run")
    args = p.parse_args()

    # ── Auto-detect mode from target ──
    def is_cidr(s):
        try:
            ipaddress.ip_network(s, strict=False)
            return "/" in s or s.replace(".", "").isdigit()
        except ValueError:
            return False

    # ── Direct target (single) ──
    if args.target:
        mode = args.mode or ("cidr" if is_cidr(args.target) else "domain")

        if mode == "cidr":
            try:
                ipaddress.ip_network(args.target, strict=False)
            except ValueError as e:
                print(f"{C.BR}[!] Invalid CIDR:{C.R} {e}"); sys.exit(1)
            found, done, elapsed = run_cidr_scan(
                args.target, args.threads, args.timeout, args.output)
            rate = done / elapsed if elapsed else 0
            print(f"\n{C.BC}{C.B}━━━ COMPLETE ━━━{C.R}")
            print(f"  {C.CY}•{C.R} Scanned : {C.BW}{done}{C.R}")
            print(f"  {C.CY}•{C.R} Open    : {C.BG}{C.B} {len(found)} {C.R}")
            print(f"  {C.CY}•{C.R} Time    : {C.BW}{elapsed:.1f}s{C.R}")
            print(f"  {C.CY}•{C.R} Rate    : {C.BW}{rate:.1f}/s{C.R}")
            print(f"  {C.CY}•{C.R} Saved   : {C.BY}{args.output}{C.R}\n")

        else:  # domain
            r = scan_domain(args.target, args.timeout)
            if r:
                show_domain(r)
                if not os.path.isfile(args.output):
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write("# Dom-X Results\n" + "#" + "-"*72 + "\n")
                with open(args.output, "a", encoding="utf-8") as f:
                    f.write(f"{r['ip']:<16} [{r['status']}] "
                            f"{r['hoster']:<13} {r['link']}\n")
                print(f"\n{C.BG}  ✔ Saved to {args.output}{C.R}\n")
            else:
                print(f"{C.BR}  ✘ No response from {args.target}{C.R}\n")
        return

    # ── Batch file ──
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{C.BR}[!] File not found:{C.R} {args.file}"); sys.exit(1)

        # Sniff first non-comment, non-blank line to decide mode
        mode = args.mode
        if not mode:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"): continue
                    mode = "cidr" if is_cidr(s) else "domain"
                    break

        if not mode:
            print(f"{C.BR}[!] Empty file{C.R}"); sys.exit(1)

        state = load_state() if args.resume else None

        if mode == "cidr":
            cidrs, invalid = read_cidr_file(args.file)
            if invalid:
                print(f"{C.BY}[!] Skipped {invalid} invalid lines{C.R}")
            print(f"{C.BW}[*] Loaded {len(cidrs)} CIDRs from {args.file}{C.R}")
            run_cidr_batch(cidrs, args.threads, args.timeout, args.output, state)
        else:
            domains, skipped = read_domain_file(args.file)
            if skipped:
                print(f"{C.BY}[!] Skipped {skipped} malformed lines{C.R}")
            print(f"{C.BW}[*] Loaded {len(domains)} domains from {args.file}{C.R}")
            run_domain_batch(domains, args.threads, args.timeout, args.output, state)
        return

    # ── Interactive menu ──
    settings = {
        "threads": args.threads,
        "timeout": args.timeout,
        "output":  args.output,
    }

    while True:
        show_menu()
        choice = menu_choose()

        # ── 1) CIDR subnet ──
        if choice == "1":
            cidr = prompt_cidr()
            found, done, elapsed = run_cidr_scan(
                cidr, settings["threads"], settings["timeout"], settings["output"])
            rate = done / elapsed if elapsed else 0
            print(f"\n{C.BC}{C.B}━━━ COMPLETE ━━━{C.R}")
            print(f"  {C.CY}•{C.R} Scanned : {C.BW}{done}{C.R}")
            print(f"  {C.CY}•{C.R} Open    : {C.BG}{C.B} {len(found)} {C.R}")
            print(f"  {C.CY}•{C.R} Time    : {C.BW}{elapsed:.1f}s{C.R}")
            print(f"  {C.CY}•{C.R} Rate    : {C.BW}{rate:.1f}/s{C.R}")
            print(f"  {C.CY}•{C.R} Saved   : {C.BY}{settings['output']}{C.R}\n")

        # ── 2) CIDR list from file ──
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
                yn = ask(f"{C.BY}  ↻ Found unfinished run (CIDR #{state['last_index']+1}). "
                         f"Resume? [y/N]{C.R}: ")
                if yn.lower() != "y": state = None
            try:
                run_cidr_batch(cidrs, settings["threads"], settings["timeout"],
                               settings["output"], state)
            except KeyboardInterrupt:
                pass

        # ── 3) Single domain ──
        elif choice == "3":
            d = prompt_domain()
            r = scan_domain(d, settings["timeout"])
            if r:
                show_domain(r)
                if not os.path.isfile(settings["output"]):
                    with open(settings["output"], "w", encoding="utf-8") as f:
                        f.write("# Dom-X Results\n" + "#" + "-"*72 + "\n")
                with open(settings["output"], "a", encoding="utf-8") as f:
                    f.write(f"{r['ip']:<16} [{r['status']}] "
                            f"{r['hoster']:<13} {r['link']}\n")
                print(f"\n{C.BG}  ✔ Saved to {settings['output']}{C.R}\n")
            else:
                print(f"{C.BR}  ✘ No response{C.R}\n")

        # ── 4) Domain list from file ──
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
                yn = ask(f"{C.BY}  ↻ Found unfinished run (domain #{state['last_index']+1}). "
                         f"Resume? [y/N]{C.R}: ")
                if yn.lower() != "y": state = None
            try:
                run_domain_batch(domains, settings["threads"], settings["timeout"],
                                 settings["output"], state)
            except KeyboardInterrupt:
                pass

        # ── 5) Custom settings ──
        elif choice == "5":
            settings = custom_settings(settings)

        # ── 6) View results ──
        elif choice == "6":
            view_results(settings["output"])

        # ── 7) About ──
        elif choice == "7":
            show_about()

        # ── 8) Exit ──
        elif choice == "8":
            print(f"{C.BY}  ✌ Goodbye — Mr Frank{C.R}")
            print(f"{C.BC}  📢 t.me/mrfrankofc  💬 wa.me/mrfr4nkofc{C.R}\n")
            sys.exit(0)


if __name__ == "__main__":
    main()
