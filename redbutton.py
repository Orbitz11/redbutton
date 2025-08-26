import os
import sys
import time
import json
import hashlib
import threading
import socket
import subprocess
import shutil
import getpass
import base64
import ssl
import ipaddress
import win32evtlog
from datetime import datetime, timedelta
import usb.core
import usb.util
import re, json, math, argparse, uuid, signal
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest


try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except Exception:
    class Dummy:
        def __getattr__(self, k):
            return ''
    Fore = Style = Dummy()
    def init(*args, **kwargs):
        pass

VERSION = "1.5"
UPDATE_INFO_URL = "https://raw.githubusercontent.com/Orbitz11/redbutton/main/update.json"

logo = r"""
 /$$$$$$$                  /$$ /$$$$$$$              /$$     /$$                        
| $$__  $$                | $$| $$__  $$            | $$    | $$                        
| $$  \ $$  /$$$$$$   /$$$$$$$| $$  \ $$ /$$   /$$ /$$$$$$ /$$$$$$    /$$$$$$  /$$$$$$$ 
| $$$$$$$/ /$$__  $$ /$$__  $$| $$$$$$$ | $$  | $$|_  $$_/|_  $$_/   /$$__  $$| $$__  $$
| $$__  $$| $$$$$$$$| $$  | $$| $$__  $$| $$  | $$  | $$    | $$    | $$  \ $$| $$  \ $$
| $$  \ $$| $$_____/| $$  | $$| $$  \ $$| $$  | $$  | $$ /$$| $$ /$$| $$  | $$| $$  | $$
| $$  | $$|  $$$$$$$|  $$$$$$$| $$$$$$$/|  $$$$$$/  |  $$$$/|  $$$$/|  $$$$$$/| $$  | $$
|__/  |__/ \_______/ \_______/|_______/  \______/    \___/   \___/   \______/ |__/  |__/
"""



def print_header():
    print(Fore.RED + logo)
    print(Fore.YELLOW + f"[Info] v{VERSION} [Coded by: White Pirates]\n" + Style.RESET_ALL)

def colored_option(index, text):
    return Fore.RED + "[" + Fore.WHITE + f"{index:02}" + Fore.RED + "] " + Fore.YELLOW + text + Style.RESET_ALL

SUSPICIOUS_EXTS = {".exe", ".scr", ".dll", ".vbs", ".js", ".jar", ".bat", ".ps1", ".cmd", ".hta", ".sys", ".com", ".pif"}
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443]

def confirm(prompt="Are you sure? (y/n): "):
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except KeyboardInterrupt:
        print()
        return False

def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def disconnect_internet():
    if sys.platform.startswith("win"):
        try:
            subprocess.run(["ipconfig", "/release"], check=False)
            print("Done.")
        except Exception as e:
            print("Error:", e)
    else:
        try:
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "networking", "off"], check=False)
                print("Done.")
            else:
                print("Unsupported automatic method on this OS.")
        except Exception as e:
            print("Error:", e)

def find_suspicious_files(base_paths=None, days=7):
    if base_paths is None:
        user = os.path.expanduser("~")
        base_paths = [
            os.path.join(user, "Desktop"),
            os.path.join(user, "Downloads"),
            os.path.join(user, "AppData", "Local", "Temp"),
            os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
        ]
    cutoff = datetime.now() - timedelta(days=days)
    results = []
    for base in base_paths:
        if not base or not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    ext = os.path.splitext(fname)[1].lower()
                    mtime = datetime.fromtimestamp(os.path.getmtime(path))
                    if ext in SUSPICIOUS_EXTS or mtime >= cutoff:
                        try:
                            sha = sha256_of_file(path)
                        except Exception:
                            sha = None
                        results.append({"path": path, "ext": ext, "mtime": mtime.isoformat(), "sha256": sha})
                except Exception:
                    continue
    return results

def quarantine_file(path, quarantine_dir=None):
    if quarantine_dir is None:
        quarantine_dir = os.path.join(os.path.expanduser("~"), "RedButton_Quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    try:
        dest = os.path.join(quarantine_dir, os.path.basename(path))
        shutil.move(path, dest)
        print(f"Moved {path} to {dest}")
    except Exception as e:
        print("Error:", e)

def lock_system():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            print("Done.")
        except Exception:
            try:
                subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])
                print("Done.")
            except Exception as e:
                print("Error:", e)
    else:
        cmds = [["gnome-screensaver-command", "-l"],["xdg-screensaver", "lock"],["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"]]
        for c in cmds:
            try:
                subprocess.run(c, check=False)
                print("Done.")
                return
            except Exception:
                continue
        print("Not supported automatically on this OS.")

def derive_key(password: str, salt: bytes):
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography not available")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_folder(folder_path):
    if not HAS_CRYPTO:
        print("Install cryptography")
        return
    if not os.path.exists(folder_path):
        print("Folder not found")
        return
    password = getpass.getpass("Enter password: ")
    if not password:
        print("Empty password")
        return
    base_name = os.path.abspath(folder_path.rstrip(os.sep))
    tmp_zip = base_name + "_rbtmp"
    try:
        zipfile_path = shutil.make_archive(tmp_zip, 'zip', folder_path)
    except Exception as e:
        print("Error:", e)
        return
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    with open(zipfile_path, "rb") as rf:
        data = rf.read()
    encrypted = f.encrypt(data)
    out_path = zipfile_path + ".redbtn"
    with open(out_path, "wb") as wf:
        wf.write(salt + encrypted)
    try:
        os.remove(zipfile_path)
    except Exception:
        pass
    print("Encrypted file:", out_path)

def decrypt_file(enc_path):
    if not HAS_CRYPTO:
        print("Install cryptography")
        return
    if not os.path.exists(enc_path):
        print("File not found")
        return
    password = getpass.getpass("Enter password: ")
    with open(enc_path, "rb") as rf:
        content = rf.read()
    salt = content[:16]
    encrypted = content[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        data = f.decrypt(encrypted)
    except Exception:
        print("Wrong password or corrupted file")
        return
    out_zip = enc_path + ".decrypted.zip"
    with open(out_zip, "wb") as wf:
        wf.write(data)
    try:
        extract_dir = enc_path + "_extracted"
        shutil.unpack_archive(out_zip, extract_dir)
        os.remove(out_zip)
        print("Extracted to:", extract_dir)
    except Exception:
        print("Decrypted to:", out_zip)


def port_scan(host="127.0.0.1", ports=None, timeout=0.4):
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    threads = []
    lock = threading.Lock()
    def worker(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            r = s.connect_ex((host, p))
            if r == 0:
                with lock:
                    open_ports.append(p)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    for p in ports:
        t = threading.Thread(target=worker, args=(p,))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return sorted(open_ports)

PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt"
}

def banner_grab(host, port, timeout=1.0):
    try:
        if port == 443 or port == 8443:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    try:
                        s.settimeout(timeout)
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode(errors='ignore') + b"\r\n\r\n")
                        data = s.recv(256)
                    except Exception:
                        data = b""
            txt = data.decode(errors="ignore").splitlines()
            return txt[0].strip() if txt else "tls"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            data = s.recv(256)
            if not data and port in (80,8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(256)
        except Exception:
            data = b""
        finally:
            try:
                s.close()
            except Exception:
                pass
        line = data.decode(errors="ignore").splitlines()
        return line[0].strip() if line else ""
    except Exception:
        return ""

def service_scan(host, ports):
    results = []
    for p in ports:
        banner = banner_grab(host, p)
        service = PORT_SERVICE_MAP.get(p, "unknown")
        results.append({"port": p, "service": service, "banner": banner})
    return results

def list_processes():
    print("Running processes (user, PID, name):")
    if HAS_PSUTIL:
        try:
            for p in psutil.process_iter(['pid','name','username']):
                try:
                    print(f"{p.info.get('username','?'):20} | {p.info.get('pid'):6} | {p.info.get('name')}")
                except Exception:
                    continue
        except Exception as e:
            print("Error:", e)
    else:
        if sys.platform.startswith("win"):
            try:
                out = subprocess.check_output(["tasklist"], shell=False, text=True, stderr=subprocess.DEVNULL)
                print(out)
            except Exception as e:
                print("Error:", e)
        else:
            try:
                out = subprocess.check_output(["ps", "aux"], text=True)
                print(out)
            except Exception as e:
                print("Error:", e)

def disk_usage():
    print("Disk Usage:")
    if HAS_PSUTIL:
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                try:
                    u = psutil.disk_usage(p.mountpoint)
                    print(f"{p.device} ({p.mountpoint}) Total:{u.total/(1024**3):.2f}GB Used:{u.used/(1024**3):.2f}GB Free:{u.free/(1024**3):.2f}GB FS:{p.fstype}")
                except Exception:
                    continue
        except Exception as e:
            print("Error:", e)
    else:
        roots = [os.path.expanduser("~"), "/"]
        seen = set()
        for r in roots:
            try:
                root = os.path.abspath(r)
                if root in seen:
                    continue
                usage = shutil.disk_usage(root)
                seen.add(root)
                print(f"{root} Total:{usage.total/(1024**3):.2f}GB Used:{(usage.total-usage.free)/(1024**3):.2f}GB Free:{usage.free/(1024**3):.2f}GB")
            except Exception:
                continue

def monitor_resources():
    if not HAS_PSUTIL:
        print("Install psutil")
        return
    try:
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass
        time.sleep(0.2)
        processes = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent']):
            try:
                info = p.info
                processes.append((info.get('cpu_percent',0.0), info.get('memory_percent',0.0), info.get('pid'), info.get('name')))
            except Exception:
                continue
        processes.sort(reverse=True, key=lambda x: (x[0], x[1]))
        print(f"{'PID':>6} {'CPU%':>6} {'MEM%':>6} Process")
        for cpu, mem, pid, name in processes[:15]:
            print(f"{pid:6} {cpu:6.1f} {mem:6.1f} {name}")
    except Exception as e:
        print("Error:", e)

def network_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        hostname = "Unknown"
        local_ip = "Unknown"
    public_ip = "Unknown"
    if HAS_REQUESTS:
        try:
            public_ip = requests.get("https://api.ipify.org", timeout=3).text
        except Exception:
            public_ip = "Unavailable"
    else:
        public_ip = "requests not installed"
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    print(f"Public IP: {public_ip}")
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            for ifname, addlist in addrs.items():
                print(f"\nInterface: {ifname}")
                for addr in addlist:
                    fam = getattr(addr.family, 'name', addr.family)
                    print(f"  - {fam}: {addr.address}")
        except Exception:
            pass

def find_large_files(base_path=None, top_n=10):
    if base_path is None:
        base_path = os.path.expanduser("~")
    print(f"Scanning largest files in: {base_path}")
    files = []
    for root, dirs, filenames in os.walk(base_path):
        for fname in filenames:
            try:
                path = os.path.join(root, fname)
                size = os.path.getsize(path)
                files.append((size, path))
            except Exception:
                continue
    files.sort(reverse=True)
    for size, path in files[:top_n]:
        print(f"{size/(1024**2):.2f} MB - {path}")


def temp_cleaner(do_remove=True):
    temp_dirs = []
    if os.name == "nt":
        temp_dirs.extend([os.environ.get("TEMP",""), os.environ.get("TMP","")])
    else:
        temp_dirs.extend([os.environ.get("TMPDIR","/tmp"), "/var/tmp"])
    temp_dirs = [d for d in set(temp_dirs) if d]
    removed_total = 0
    for tdir in temp_dirs:
        print(f" - {tdir}")
        if not os.path.exists(tdir):
            print("   not present")
            continue
        entries = os.listdir(tdir)
        print(f"   contains {len(entries)} entries")
        if do_remove:
            removed = 0
            for f in entries:
                try:
                    fpath = os.path.join(tdir, f)
                    if os.path.isfile(fpath) or os.path.islink(fpath):
                        os.remove(fpath)
                        removed += 1
                    elif os.path.isdir(fpath):
                        shutil.rmtree(fpath, ignore_errors=True)
                        removed += 1
                except Exception:
                    continue
            removed_total += removed
            print(f"   removed approx {removed} entries")
    print("Done.")
    return removed_total


def check_hosts_file():
    if sys.platform.startswith("win"):
        hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
    else:
        hosts_path = "/etc/hosts"
    if not os.path.exists(hosts_path):
        print("Hosts file not found:", hosts_path)
        return
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print("Unable to read hosts file:", e)
        return
    entries = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    print(f"Hosts file: {hosts_path}")
    if entries:
        print("Non-comment entries:")
        for s in entries:
            print("  ", s)
    else:
        print("No non-comment entries found")

def auto_update():
    if not HAS_REQUESTS:
        print("Install requests")
        return
    if not UPDATE_INFO_URL:
        print("Set UPDATE_INFO_URL in code")
        return
    try:
        r = requests.get(UPDATE_INFO_URL, timeout=6)
        r.raise_for_status()
        info = r.json()
        remote_ver = str(info.get("version", ""))
        url = info.get("url")
        expected_sha = info.get("sha256")
        if not remote_ver or not url:
            print("Malformed update info")
            return
        if remote_ver <= VERSION:
            print(f"Already up-to-date (local {VERSION}, remote {remote_ver})")
            return
        print(f"New version available: {remote_ver}")
        data = requests.get(url, timeout=10).content
        if expected_sha and len(expected_sha) > 10:
            sha = hashlib.sha256(data).hexdigest()
            if sha.lower() != expected_sha.lower():
                print("SHA256 mismatch")
                return
        cur = os.path.abspath(sys.argv[0])
        bak = cur + ".bak"
        with open(bak, "wb") as f:
            f.write(open(cur, "rb").read())
        with open(cur, "wb") as f:
            f.write(data)
        print(f"Updated to {remote_ver}. Backup: {bak}. Restart the tool.")
    except Exception as e:
        print("Update failed:", e)


def geoip_lookup(ip: str) -> dict:
    if not HAS_REQUESTS:
        return {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,timezone,isp,org,as,query"
        r = requests.get(url, timeout=4)
        j = r.json()
        if j.get("status") == "success":
            return {"ip": j.get("query"), "country": j.get("country"), "region": j.get("regionName"), "city": j.get("city"), "lat": j.get("lat"), "lon": j.get("lon"), "timezone": j.get("timezone"), "isp": j.get("isp"), "org": j.get("org"), "asn": j.get("as")}
    except Exception:
        pass
    return {}

THREAT_SOURCES = [
    ("tor_exit", "https://check.torproject.org/torbulkexitlist"),
    ("firehol_level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
    ("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt"),
    ("spamhaus_edrop", "https://www.spamhaus.org/drop/edrop.txt")
]

def download_text(url):
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            return r.text
    except Exception:
        return ""
    return ""

def parse_list(text):
    ips = set()
    nets = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith(";"):
            continue
        if " " in s:
            s = s.split()[0]
        if ";" in s:
            s = s.split(";")[0].strip()
        try:
            if "/" in s:
                nets.append(ipaddress.ip_network(s, strict=False))
            else:
                ipaddress.ip_address(s)
                ips.add(s)
        except Exception:
            continue
    return ips, nets

def ip_reputation(ip):
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    rep = {"ip": ip, "listed_in": [], "tor_exit": False}
    try:
        target = ipaddress.ip_address(ip)
    except Exception:
        rep["error"] = "invalid ip"
        return rep
    for name, url in THREAT_SOURCES:
        txt = download_text(url)
        if not txt:
            continue
        ips, nets = parse_list(txt)
        if ip in ips:
            rep["listed_in"].append(name)
            if name == "tor_exit":
                rep["tor_exit"] = True
            continue
        found = False
        for n in nets:
            try:
                if target in n:
                    found = True
                    break
            except Exception:
                continue
        if found:
            rep["listed_in"].append(name)
            if name == "tor_exit":
                rep["tor_exit"] = True
    geo = geoip_lookup(ip)
    if geo:
        rep["geo"] = geo
    return rep

def handle_client(client_socket, addr):
    ip, port = addr[0], addr[1]
    print(f"Connection from {addr}")
    geo = geoip_lookup(ip)
    if geo:
        print("GeoIP:", json.dumps(geo, ensure_ascii=False))
    try:
        client_socket.send(b"Welcome\n")
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            msg = data.decode(errors='ignore').strip()
            print(f"Received from {addr}: {msg}")
            client_socket.send(b"OK\n")
    except Exception as e:
        print(f"Client error {addr}: {e}")
    finally:
        client_socket.close()
        print(f"Connection closed {addr}")

def honeypot_server(host='0.0.0.0', port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"Honeypot listening on {host}:{port}")
    try:
        while True:
            client_socket, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("Honeypot stopped")
    finally:
        server.close()

def full_scan():
    list_processes()
    print("Scanning suspicious files (last 7 days)...")
    hits = find_suspicious_files(days=7)
    print(f"Suspicious files found: {len(hits)}")
    for h in hits[:10]:
        print(f" - {h['path']} sha256:{h.get('sha256')}")
    print("Local port scan (127.0.0.1)...")
    open_ports = port_scan("127.0.0.1")
    print("Open ports:", open_ports if open_ports else "None")

def threat_scan():
    target = input("Enter target IP or hostname: ").strip()
    if not target:
        print("No target provided")
        return
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        print("Cannot resolve target")
        return
    print(f"Resolved target: {target} -> {ip}")
    ports_in = input("Enter comma-separated ports or press Enter for common set: ").strip()
    if ports_in:
        try:
            ports_list = [int(x.strip()) for x in ports_in.split(",") if x.strip()]
        except Exception:
            ports_list = COMMON_PORTS
    else:
        ports_list = COMMON_PORTS
    print(f"Scanning ports on {ip}...")
    open_ports = port_scan(ip, ports=ports_list)
    if open_ports:
        print("Open ports:", open_ports)
        details = service_scan(ip, open_ports)
        for d in details:
            p = d.get("port")
            svc = d.get("service")
            ban = d.get("banner") or ""
            if len(ban) > 140:
                ban = ban[:140] + "..."
            print(f" - {p} {svc} | {ban}")
    else:
        print("No open ports from provided list")
    if confirm("Check IP reputation? (y/n): "):
        rep = ip_reputation(ip)
        if rep.get("error"):
            print("Reputation error:", rep.get("error"))
        else:
            listed = rep.get("listed_in", [])
            if listed:
                print("Listed in:", ", ".join(listed))
            else:
                print("No listings found in selected sources")
            if rep.get("tor_exit"):
                print("TOR exit node: True")
            geo = rep.get("geo")
            if geo:
                print("Geo:", json.dumps(geo, ensure_ascii=False))

def menu():
    print()
    print(colored_option(1, "Disconnect Internet"))
    print(colored_option(2, "Find Suspicious Files"))
    print(colored_option(3, "Lock System"))
    print(colored_option(4, "Encrypt Folder"))
    print(colored_option(5, "Decrypt File (.redbtn)"))
    print(colored_option(6, "Port Scan"))
    print(colored_option(7, "Full Scan"))
    print(colored_option(8, "Honeypot"))
    print(colored_option(9, "Auto Update"))
    print(colored_option(10, "Threat Scan"))
    print(colored_option(11, "Malware Scanner"))
    print(colored_option(12, "Password Leak Checker"))
    print(colored_option(13, "USB Attack Detection"))
    print(colored_option(14, "AI-Based Log Analyzer"))
    print(colored_option(0, "Exit"))

def check_system_updates():
    if not sys.platform.startswith("win"):
        print("Windows only")
        return
    cmd = 'powershell -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot"'
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=90)
        print(output)
    except subprocess.CalledProcessError as e:
        print("PowerShell failed. You may need PSWindowsUpdate or admin rights.")
        print("Output:", e.output if hasattr(e, 'output') else e)
    except Exception as e:
        print("Error:", e)



def malware_analyzer_online(api_key):
    if not HAS_REQUESTS:
        print("Install requests")
        return
    file_path = input("Enter file path to scan: ").strip()
    if not os.path.isfile(file_path):
        print("File not found")
        return

    print("Calculating SHA256...")
    file_hash = sha256_of_file(file_path)
    print("SHA256:", file_hash)

    headers = {"x-apikey": api_key}
    url = "https://www.virustotal.com/api/v3/files/" + file_hash

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)
            print("Malicious detections:", malicious)
            print("Undetected:", undetected)
            print("Full report URL: https://www.virustotal.com/gui/file/" + file_hash)

        elif r.status_code == 404:
            print("[ℹ] File not in VirusTotal database → uploading now...")
            upload_url = "https://www.virustotal.com/api/v3/files"
            with open(file_path, "rb") as f:
                upload_response = requests.post(upload_url, headers=headers, files={"file": f})

            if upload_response.status_code != 200:
                print(" Upload error:", upload_response.text)
                return

            analysis_id = upload_response.json()["data"]["id"]
            print(f"[✔] Uploaded. Analysis ID: {analysis_id}")

    
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            while True:
                analysis_resp = requests.get(analysis_url, headers=headers).json()
                status = analysis_resp["data"]["attributes"]["status"]

                if status == "completed":
                    stats = analysis_resp["data"]["attributes"]["stats"]
                    print("Malicious detections:", stats.get("malicious", 0))
                    print("Undetected:", stats.get("undetected", 0))
                    print("Full report URL: https://www.virustotal.com/gui/file/" + file_hash)
                    break
                else:
                    print("[*] Still analyzing... please wait")
                    time.sleep(5)

        else:
            print("Error from VirusTotal:", r.status_code, r.text)

    except Exception as e:
        print("Error querying VirusTotal:", e)



def password_leak_checker():
    if not HAS_REQUESTS:
        print("Install requests")
        return
    pwd = getpass.getpass("Enter password to check: ").strip()
    if not pwd:
        print("Empty password")
        return
    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        headers = {"User-Agent": f"redbutton/{VERSION}"}
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers=headers, timeout=10)
        if r.status_code != 200:
            print("Error:", r.status_code)
            return
        found = 0
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip().upper() == suffix:
                try:
                    found = int(parts[1].strip())
                except:
                    found = 0
                break
        if found > 0:
            print("Found in breaches:", found)
        else:
            print("No leak found for this password")
    except Exception as e:
        print("Error:", e)

HAS_USB = True

def usb_attack_detection(scan_exts=None):
    if not HAS_PSUTIL:
        print("psutil required for USB detection")
        return

    if scan_exts is None:
        scan_exts = SUSPICIOUS_EXTS.union({".inf"})

    print("[*] Monitoring for USB devices... Press Ctrl+C to stop.")
    known_devices = set(p.device for p in psutil.disk_partitions(all=False))

    try:
        while True:
            time.sleep(3)
            current_devices = set(p.device for p in psutil.disk_partitions(all=False))
            new_devs = current_devices - known_devices
            if new_devs:
                for dev in new_devs:
                    print(f"[!] New USB storage detected: {dev}")
                    try:
                        mountpoint = [p.mountpoint for p in psutil.disk_partitions(all=False) if p.device == dev]
                        if not mountpoint:
                            continue
                        mountpoint = mountpoint[0]
                        print(f"    Mounted at: {mountpoint}")

                        suspicious_found = False
                        for root, dirs, files in os.walk(mountpoint):
                            for fname in files:
                                ext = os.path.splitext(fname)[1].lower()
                                if ext in scan_exts:
                                    fpath = os.path.join(root, fname)
                                    sha = None
                                    try:
                                        sha = sha256_of_file(fpath)
                                    except Exception:
                                        pass
                                    suspicious_found = True
                                    print(f"    [*] Suspicious file: {fpath} (sha256={sha})")

                        if not suspicious_found:
                            print("    No suspicious files detected.")

                    except Exception as e:
                        print("   Error scanning device:", e)

            known_devices = current_devices

            if HAS_USB:
                devs = usb.core.find(find_all=True)
                for d in devs:
                    try:
                        if d.bDeviceClass == 3:
                            print("[*] Warning: New HID USB device detected (possible BadUSB)")
                    except:
                        continue

    except KeyboardInterrupt:
        print("\n[*] Stopped USB monitoring.")
        


IP_RE = re.compile(r'(?<![\d\.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d\.])')
TS_CANDIDATES = [
    ("%b %d %H:%M:%S", lambda s: datetime.strptime(s, "%b %d %H:%M:%S").replace(year=datetime.utcnow().year)),
    ("%Y-%m-%dT%H:%M:%S", lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")),
    ("%Y-%m-%d %H:%M:%S", lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M:%S")),
    ("%d/%b/%Y:%H:%M:%S", lambda s: datetime.strptime(s, "%d/%b/%Y:%H:%M:%S")),
]
LEVEL_PAT = re.compile(r'\b(critical|crit|error|err|warn|warning|info|notice|debug)\b', re.IGNORECASE)
PROC_PAT = re.compile(r'([a-zA-Z0-9_\-/.]+)(?:\[\d+\])?:')
USER_PAT = re.compile(r'\buser\s*=?\s*([a-zA-Z0-9_\-\.$]+)|\bfor\s+([a-zA-Z0-9_\-\.$]+)\b', re.IGNORECASE)
HTTP_PAT = re.compile(r'\bGET\b|\bPOST\b|\bHTTP/\d', re.IGNORECASE)
FAIL_PAT = re.compile(r'fail|denied|invalid|error|refused|unauthorized|forbidden|not\s+allowed', re.IGNORECASE)
AUTH_PAT = re.compile(r'\bssh\b|\bsudo\b|\blogin\b|\bpasswd\b|\bpam\b|\bauth', re.IGNORECASE)
WEB_PAT = re.compile(r'wp-login|xmlrpc\.php|\.php|/admin|/login|\b404\b|\b403\b', re.IGNORECASE)
PS_PAT = re.compile(r'powershell|Invoke-WebRequest|bitsadmin|reg\s+add|vssadmin|certutil', re.IGNORECASE)
LINUX_CMD_PAT = re.compile(r'curl|wget|base64\s+-d|nc\s+-e|/dev/tcp|chmod\s+\+s|useradd|chattr\s+\+i', re.IGNORECASE)

def parse_timestamp(s):
    s = s.strip()
    for fmt, fn in TS_CANDIDATES:
        try:
            if fmt == "%b %d %H:%M:%S":
                m = re.match(r'^[A-Za-z]{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}', s)
                if not m: continue
                return fn(m.group(0))
            if fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                m = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', s)
                if not m: continue
                return fn(m.group(0))
            if fmt == "%d/%b/%Y:%H:%M:%S":
                m = re.search(r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}', s)
                if not m: continue
                return fn(m.group(0))
        except: continue
    return None

def extract(text):
    ips = IP_RE.findall(text) or []
    level = None
    ml = LEVEL_PAT.search(text)
    if ml: level = ml.group(1).lower()
    proc = None
    mp = PROC_PAT.search(text)
    if mp: proc = mp.group(1).lower()
    user = None
    mu = USER_PAT.search(text)
    if mu: user = (mu.group(1) or mu.group(2))
    http = 1 if HTTP_PAT.search(text) else 0
    fail = 1 if FAIL_PAT.search(text) else 0
    auth = 1 if AUTH_PAT.search(text) else 0
    webp = 1 if WEB_PAT.search(text) else 0
    ps = 1 if PS_PAT.search(text) else 0
    lnx = 1 if LINUX_CMD_PAT.search(text) else 0
    return ips, level, proc, user, http, fail, auth, webp, ps, lnx

def level_to_int(x):
    if not x: return 3
    x = x.lower()
    if x in ("critical","crit"): return 5
    if x in ("error","err"): return 4
    if x in ("warn","warning"): return 3
    if x in ("notice","info"): return 2
    if x in ("debug",): return 1
    return 3

def hour_features(ts):
    if ts is None: return 0.0, 0.0
    h = ts.hour + ts.minute/60.0
    return math.sin(2*math.pi*h/24.0), math.cos(2*math.pi*h/24.0)

def build_pipeline():
    text_col = "text"
    num_cols = ["level_i","ip_count","http","fail","auth","web","ps","lnx","msg_len","digits","hour_sin","hour_cos"]
    pre = ColumnTransformer([
        ("txt", TfidfVectorizer(max_features=5000, ngram_range=(1,2), min_df=2), text_col),
        ("num", StandardScaler(with_mean=False), num_cols),
    ], remainder="drop", sparse_threshold=0.3)
    model = IsolationForest(n_estimators=300, contamination=0.03, random_state=42, n_jobs=-1)
    pipe = Pipeline([("pre", pre), ("clf", model)])
    return pipe

def rule_engine(df):
    alerts = []
    ip_fail = df[df["fail"]==1].groupby("ip", dropna=False).size().sort_values(ascending=False)
    for ip, cnt in ip_fail.items():
        if ip and cnt >= 10:
            alerts.append(f"[ALERT] Multiple failed logins from {ip} ({cnt})")
    ps_hits = df["ps"].sum()
    if ps_hits >= 1:
        alerts.append("[ALERT] Suspicious PowerShell activity detected")
    lnx_hits = df["lnx"].sum()
    if lnx_hits >= 1:
        alerts.append("[ALERT] Suspicious Linux command detected")
    return alerts

def normalize_scores(scores):
    s = np.array(scores, dtype=float)
    if s.size == 0: return s
    p5, p95 = np.percentile(s, [5,95])
    denom = max(p95 - p5, 1e-9)
    z = (s - p5) / denom
    return np.clip(z, 0, 1)

def run_ai_analyzer():
    print("[1] Windows Server")
    print("[2] Linux Server")
    choice = input("Select server OS [1/2]: ").strip()

    if choice == "1":
        log_file = r"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        if not win32evtlog:
            print("[!] pywin32 (win32evtlog) غير متاح. لازم تسطبه: pip install pywin32")
            return
        server = 'localhost'
        logtype = 'Security'
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            pipe = build_pipeline()
            df_init = pd.DataFrame([{
                "level_i":0,"ip_count":0,"http":0,"fail":0,"auth":0,"web":0,"ps":0,"lnx":0,
                "msg_len":0,"digits":0,"hour_sin":0,"hour_cos":0,"text":""
            }])
            pipe.fit(df_init)

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    raw = f"Event ID: {event.EventID}, Source: {event.SourceName}, Time: {event.TimeGenerated}"
                    ts = event.TimeGenerated
                    sinh, cosh = hour_features(ts)
                    row = pd.DataFrame([{
                        "level_i": level_to_int("info"),
                        "ip_count": 0,
                        "http": 0,"fail": 0,"auth": 0,"web": 0,"ps": 0,"lnx": 0,
                        "msg_len": len(raw),"digits": sum(c.isdigit() for c in raw),
                        "hour_sin": sinh,"hour_cos": cosh,
                        "text": raw
                    }])
                    ypred = pipe.predict(row)[0]
                    score = -pipe.decision_function(row)[0]
                    norm_score = normalize_scores([score])[0]
                    alerts = rule_engine(row)

                    if ypred == -1 or norm_score > 0.8 or alerts:
                        print(f"[THREAT] {raw}")
                        for a in alerts:
                            print(a)
                time.sleep(2)
        except KeyboardInterrupt:
            print("[AI Log Analyzer] stopped")

    elif choice == "2":
        print("Select Linux Server Distribution:")
        distros = {
            "1": ("Ubuntu/Debian", "/var/log/auth.log"),
            "2": ("CentOS/RHEL/Fedora", "/var/log/secure"),
            "3": ("Kali Linux", "/var/log/auth.log"),
            "4": ("openSUSE", "/var/log/messages"),
        }
        for k, (name, path) in distros.items():
            print(f"[{k}] {name} (default log: {path})")
        d_choice = input("Select distribution: ").strip()
        log_file = distros.get(d_choice, distros["1"])[1]

        if not os.path.isfile(log_file):
            print("Log file not found:", log_file)
            return

        print(f"[AI Log Analyzer] Monitoring {log_file} ... Press Ctrl+C to stop")
        pipe = build_pipeline()
        df_init = pd.DataFrame([{
            "level_i":0,"ip_count":0,"http":0,"fail":0,"auth":0,"web":0,"ps":0,"lnx":0,
            "msg_len":0,"digits":0,"hour_sin":0,"hour_cos":0,"text":""
        }])
        pipe.fit(df_init)
        try:
            with open(log_file, "r", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    raw = line.strip()
                    ts = parse_timestamp(raw)
                    ips, level, proc, user, http, fail, auth, webp, ps, lnx = extract(raw)
                    sinh, cosh = hour_features(ts)
                    row = pd.DataFrame([{
                        "level_i": level_to_int(level),
                        "ip_count": len(ips),
                        "http": http,"fail": fail,"auth": auth,"web": webp,"ps": ps,"lnx": lnx,
                        "msg_len": len(raw),"digits": sum(c.isdigit() for c in raw),
                        "hour_sin": sinh,"hour_cos": cosh,
                        "text": f"{proc or ''} {raw}"
                    }])
                    ypred = pipe.predict(row)[0]
                    score = -pipe.decision_function(row)[0]
                    norm_score = normalize_scores([score])[0]
                    alerts = rule_engine(row)

                    if ypred == -1 or norm_score > 0.8 or alerts:
                        print(f"[THREAT] {raw}")
                        for a in alerts:
                            print(a)
        except KeyboardInterrupt:
            print("\n[AI Log Analyzer] stopped")
    else:
        print("Invalid choice")


def main_loop():
    print_header()
    while True:
        try:
            menu()
            choice = input("\nChoose an option: ").strip()
            if choice == "1":
                if confirm("This will disconnect the internet. Continue? (y/n): "):
                    disconnect_internet()
            elif choice == "2":
                days_in = input("Scan files changed in last (days, default 7): ").strip()
                try:
                    days = int(days_in) if days_in else 7
                except:
                    days = 7
                hits = find_suspicious_files(days=days)
                if not hits:
                    print("No suspicious files found")
                else:
                    for i, h in enumerate(hits, 1):
                        print(f"\n[{i:02}] {h['path']}\n    ext: {h['ext']}  mtime: {h['mtime']}\n    sha256: {h.get('sha256')}")
                    if confirm("\nMove selected to quarantine? (y/n): "):
                        idxs = input("Enter file numbers or 'all': ").strip()
                        if idxs.lower() == "all":
                            selected = list(range(1, len(hits)+1))
                        else:
                            selected = []
                            for token in idxs.split():
                                try:
                                    j = int(token)
                                    if 1 <= j <= len(hits):
                                        selected.append(j)
                                except:
                                    continue
                        for j in selected:
                            h = hits[j-1]
                            if confirm(f"Quarantine {h['path']} ? (y/n): "):
                                quarantine_file(h['path'])
            elif choice == "3":
                if confirm("Lock the workstation now? (y/n): "):
                    lock_system()
            elif choice == "4":
                folder = input("Enter path to folder: ").strip()
                if folder and confirm(f"Encrypt folder {folder}? (y/n): "):
                    encrypt_folder(folder)
            elif choice == "5":
                enc = input("Enter path to encrypted file (.redbtn): ").strip()
                if enc and confirm(f"Decrypt file {enc}? (y/n): "):
                    decrypt_file(enc)
            elif choice == "6":
                target = input("Enter target (default 127.0.0.1): ").strip() or "127.0.0.1"
                ports = input("Enter comma-separated ports or press Enter: ").strip()
                if ports:
                    try:
                        ports_list = [int(x.strip()) for x in ports.split(",") if x.strip()]
                    except:
                        ports_list = COMMON_PORTS
                else:
                    ports_list = COMMON_PORTS
                if confirm(f"Run port scan on {target} with ports {ports_list}? (y/n): "):
                    open_ports = port_scan(target, ports_list)
                    print("Open ports:", open_ports if open_ports else "None")
            elif choice == "7":
                if confirm("Run full scan now? (y/n): "):
                    full_scan()
            elif choice == "8":
                if confirm("Start Honeypot server? (y/n): "):
                    host = input("Bind host (default 0.0.0.0): ").strip() or '0.0.0.0'
                    try:
                        port = int(input("Port (default 2222): ").strip() or '2222')
                    except Exception:
                        port = 2222
                    honeypot_server(host, port)
            elif choice == "9":
                if confirm("Check for updates now? (y/n): "):
                    auto_update()
            elif choice == "10":
                threat_scan()
            elif choice == "11":
                api_key = input("Enter your VirusTotal API key: ").strip()
                if api_key:
                    malware_analyzer_online(api_key)
                else:
                    print("API key is required")
            elif choice == "12":
                password_leak_checker()
                
            elif choice == "13":
                usb_attack_detection()
                
            elif choice == "14":
                run_ai_analyzer()
                
                
            elif choice == "0":
                if confirm("Exit the program? (y/n): "):
                    print("Bye")
                    break
            else:
                print("Invalid option")
            time.sleep(0.25)
        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting.")
            break
        except Exception as e:
            print("Unexpected error:", e)
            time.sleep(1)

if __name__ == "__main__":
    main_loop()
