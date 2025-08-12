import os
import sys
import time
import hashlib
import threading
import socket
import subprocess
import shutil
import getpass
import base64
from datetime import datetime, timedelta

from colorama import init, Fore, Style

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
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_PDF = True
except Exception:
    HAS_PDF = False

init(autoreset=True)

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
    print(Fore.YELLOW + "[Info] v1.1 [Coded By : White Pirates]\n" + Style.RESET_ALL)

def colored_option(index, text):
    return (
        Fore.RED + "[" +
        Fore.WHITE + f"{index:02}" +
        Fore.RED + "] " +
        Fore.YELLOW + text +
        Style.RESET_ALL
    )

def print_loading():
    print(Fore.RED + "[*] " + Style.RESET_ALL + "Working...")

def print_done():
    print(Fore.GREEN + "Done." + Style.RESET_ALL)

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
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Running: ipconfig /release (may require admin privileges)")
        try:
            subprocess.run(["ipconfig", "/release"], check=False)
            print_done()
        except Exception as e:
            print("Error while disconnecting internet:", e)
    else:
        try:
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "networking", "off"], check=False)
                print_done()
            else:
                print("Non-Windows OS — please run appropriate system commands manually (requires admin).")
        except Exception as e:
            print("Error while attempting to disconnect network:", e)

SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".dll", ".vbs", ".js", ".jar", ".bat", ".ps1", ".cmd", ".hta", ".sys", ".com", ".pif"
}

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
                        results.append({
                            "path": path,
                            "ext": ext,
                            "mtime": mtime,
                            "sha256": sha
                        })
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
        print(f"Moved {path} to quarantine: {dest}")
    except Exception as e:
        print("Error while moving file:", e)

def lock_system():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            print_done()
        except Exception:
            try:
                subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])
                print_done()
            except Exception as e:
                print("Failed to lock system:", e)
    else:
        cmds = [
            ["gnome-screensaver-command", "-l"],
            ["xdg-screensaver", "lock"],
            ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"]
        ]
        for c in cmds:
            try:
                subprocess.run(c, check=False)
                print_done()
                return
            except Exception:
                continue
        print("Screen lock not supported automatically on this OS in current version.")

def derive_key(password: str, salt: bytes):
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography not available")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_folder(folder_path):
    if not HAS_CRYPTO:
        print("Cryptography library not installed. Install with: pip install cryptography")
        return
    if not os.path.exists(folder_path):
        print("Folder not found.")
        return
    password = getpass.getpass("Enter password to create encryption key: ")
    if not password:
        print("Empty password. Cancelled.")
        return
    base_name = os.path.abspath(folder_path.rstrip(os.sep))
    tmp_zip = base_name + "_redbtn_temp"
    try:
        zipfile_path = shutil.make_archive(tmp_zip, 'zip', folder_path)
    except Exception as e:
        print("Error creating archive:", e)
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
    print("Encrypted file created:", out_path)
    print("Keep the password safe — without it, files cannot be recovered.")
def decrypt_file(enc_path):
    if not HAS_CRYPTO:
        print("Cryptography library not installed. Install with: pip install cryptography")
        return
    if not os.path.exists(enc_path):
        print("Encrypted file not found.")
        return
    password = getpass.getpass("Enter password to decrypt: ")
    with open(enc_path, "rb") as rf:
        content = rf.read()
    salt = content[:16]
    encrypted = content[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        data = f.decrypt(encrypted)
    except Exception:
        print("Wrong password or corrupted file.")
        return
    out_zip = enc_path + ".decrypted.zip"
    with open(out_zip, "wb") as wf:
        wf.write(data)
    try:
        extract_dir = enc_path + "_extracted"
        shutil.unpack_archive(out_zip, extract_dir)
        os.remove(out_zip)
        print("Decrypted and extracted to:", extract_dir)
    except Exception:
        print("Decrypted to:", out_zip)
        print("To extract manually, unzip the file.")

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3389,5900,8080]

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

def list_processes():
    print("Running processes (user, PID, process name):")
    if HAS_PSUTIL:
        try:
            for p in psutil.process_iter(['pid','name','username']):
                try:
                    print(f"{p.info.get('username','?'):20} | {p.info.get('pid'):6} | {p.info.get('name')}")
                except Exception:
                    continue
        except Exception as e:
            print("Error enumerating processes with psutil:", e)
    else:
        if sys.platform.startswith("win"):
            try:
                out = subprocess.check_output(["tasklist"], shell=False, text=True, stderr=subprocess.DEVNULL)
                print(out)
            except Exception as e:
                print("Unable to list processes:", e)
        else:
            try:
                out = subprocess.check_output(["ps", "aux"], text=True)
                print(out)
            except Exception as e:
                print("Unable to list processes:", e)

def disk_usage():
    print("Disk Usage Info:")
    if HAS_PSUTIL:
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    total_gb = usage.total / (1024**3)
                    used_gb = usage.used / (1024**3)
                    free_gb = usage.free / (1024**3)
                    print(f"{p.device} ({p.mountpoint}) - Total: {total_gb:.2f}GB | Used: {used_gb:.2f}GB | Free: {free_gb:.2f}GB | FS: {p.fstype}")
                except Exception:
                    continue
        except Exception as e:
            print("Error reading disk partitions:", e)
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
                total_gb = usage.total / (1024**3)
                used_gb = (usage.total - usage.free) / (1024**3)
                free_gb = usage.free / (1024**3)
                print(f"{root} - Total: {total_gb:.2f}GB | Used: {used_gb:.2f}GB | Free: {free_gb:.2f}GB")
            except Exception:
                continue

def monitor_resources():
    print("Top Processes by CPU and Memory:")
    if not HAS_PSUTIL:
        print("psutil not installed. Install with: pip install psutil")
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
                processes.append((
                    info.get('cpu_percent', 0.0),
                    info.get('memory_percent', 0.0),
                    info.get('pid'),
                    info.get('name')
                ))
            except Exception:
                continue
        processes.sort(reverse=True, key=lambda x: (x[0], x[1]))
        print(f"{'PID':>6} {'CPU%':>6} {'MEM%':>6} Process")
        for cpu, mem, pid, name in processes[:15]:
            print(f"{pid:6} {cpu:6.1f} {mem:6.1f} {name}")
    except Exception as e:
        print("Error monitoring resources:", e)

def network_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
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
                    print(f"  - {addr.family.name if hasattr(addr.family, 'name') else addr.family}: {addr.address}")
        except Exception:
            pass

def find_large_files(base_path=None, top_n=10):
    if base_path is None:
        base_path = os.path.expanduser("~")
    print(f"Scanning for largest files in: {base_path} (this may take a while)...")
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
    print(f"Largest {top_n} files in {base_path}:")
    for size, path in files[:top_n]:
        print(f"{size/(1024**2):.2f} MB - {path}")

def temp_cleaner(do_remove=True):
    temp_dirs = []
    if os.name == "nt":
        temp_dirs.extend([os.environ.get("TEMP",""), os.environ.get("TMP","")])
    else:
        temp_dirs.extend([os.environ.get("TMPDIR","/tmp"), "/var/tmp"])
    temp_dirs = [d for d in set(temp_dirs) if d]
    for tdir in temp_dirs:
        print(f" - {tdir}")
        if not os.path.exists(tdir):
            print("   (not present)")
            continue
        entries = os.listdir(tdir)
        print(f"   Contains {len(entries)} entries")
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
            print(f"   Removed approx {removed} entries from {tdir}")
    print_done()

def save_pdf_report(report_path=None):
    if not HAS_PDF:
        print("reportlab not installed. Install: pip install reportlab")
        return
    if report_path is None:
        report_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    try:
        c = canvas.Canvas(report_path, pagesize=letter)
        line = 750
        c.setFont("Helvetica-Bold", 14)
        c.drawString(60, line, "Security Scan Report")
        line -= 20
        c.setFont("Helvetica", 10)
        c.drawString(60, line, f"Generated: {datetime.now().isoformat()}")
        line -= 30
        if HAS_PSUTIL:
            try:
                partitions = psutil.disk_partitions(all=False)
                c.drawString(60, line, "Disk partitions summary:")
                line -= 14
                for p in partitions[:8]:
                    try:
                        usage = psutil.disk_usage(p.mountpoint)
                        text = f"{p.device} ({p.mountpoint}) - {usage.total//(1024**3)}GB total, {usage.free//(1024**3)}GB free"
                        c.drawString(72, line, text)
                        line -= 12
                    except Exception:
                        continue
            except Exception:
                pass
        hits = find_suspicious_files(days=7)
        c.drawString(60, line, f"Suspicious files found (scan): {len(hits)}")
        line -= 20
        c.drawString(60, line, "Note: For full details, run the tool interactively.")
        c.save()
        print("PDF report saved to:", report_path)
    except Exception as e:
        print("Failed to write PDF report:", e)

def check_hosts_file():
    if sys.platform.startswith("win"):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
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
    suspicious = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    print(f"Hosts file: {hosts_path}")
    if suspicious:
        print("Non-comment entries found (may be normal, inspect manually):")
        for s in suspicious:
            print("  ", s)
    else:
        print("No non-comment (suspicious) entries found.")

def check_system_updates():
    if not sys.platform.startswith("win"):
        print("Update check currently implemented for Windows only.")
        return
    cmd = 'powershell -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot"'
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=90)
        print(output)
    except subprocess.CalledProcessError as e:
        print("PowerShell command failed. You may need the PSWindowsUpdate module or admin rights.")
        print("Output:", e.output if hasattr(e, 'output') else e)
    except Exception as e:
        print("Error while checking updates:", e)

def menu():
    print()
    print(colored_option(1, "Disconnect Internet"))
    print(colored_option(2, "Find Suspicious Files"))
    print(colored_option(3, "Lock System"))
    print(colored_option(4, "Encrypt Folder"))
    print(colored_option(5, "Decrypt File (.redbtn)"))
    print(colored_option(6, "Port Scan"))
    print(colored_option(7, "Full Scan"))
    print(colored_option(8, "Disk Usage"))
    print(colored_option(9, "CPU & RAM Monitor"))
    print(colored_option(10, "Network Info"))
    print(colored_option(11, "Find Large Files"))
    print(colored_option(12, "Temp Cleaner"))
    print(colored_option(13, "Save PDF Report"))
    print(colored_option(14, "Check Hosts File"))
    print(colored_option(15, "Check System Updates"))
    print(colored_option(0, "Exit"))

def full_scan():
    list_processes()
    print("Scanning suspicious files (last 7 days)...")
    hits = find_suspicious_files(days=7)
    print(f"Suspicious files found: {len(hits)} (showing first 10)")
    for h in hits[:10]:
        print(f" - {h['path']} (sha256:{h.get('sha256')})")
    print("Local port scan (127.0.0.1)...")
    open_ports = port_scan("127.0.0.1")
    print("Open ports:", open_ports if open_ports else "None")

def main_loop():
    print_header()
    while True:
        try:
            menu()
            choice = input("\nChoose an option: ").strip()
            if choice == "1":
                if confirm("This will disconnect the internet. Continue? (y/n): "):
                    print_loading()
                    disconnect_internet()
                    print_done()
            elif choice == "2":
                days_in = input("Scan files changed in last (days, default 7): ").strip()
                try:
                    days = int(days_in) if days_in else 7
                except:
                    days = 7
                print_loading()
                hits = find_suspicious_files(days=days)
                if not hits:
                    print("No suspicious files found in default locations.")
                else:
                    for i, h in enumerate(hits, 1):
                        print(f"\n[{i:02}] {h['path']}\n    ext: {h['ext']}  --  mtime: {h['mtime']}\n    sha256: {h.get('sha256')}")
                    if confirm("\nMove selected files to quarantine? (y/n): "):
                        idxs = input("Enter file numbers separated by space or 'all': ").strip()
                        if idxs.lower() == "all":
                            for h in hits:
                                if confirm(f"Quarantine {h['path']} ? (y/n): "):
                                    quarantine_file(h['path'])
                        else:
                            for token in idxs.split():
                                try:
                                    j = int(token) - 1
                                    if 0 <= j < len(hits):
                                        if confirm(f"Quarantine {hits[j]['path']} ? (y/n): "):
                                            quarantine_file(hits[j]['path'])
                                except:
                                    continue
                print_done()
            elif choice == "3":
                if confirm("Lock the local workstation now? (y/n): "):
                    print_loading()
                    lock_system()
                    print_done()
            elif choice == "4":
                folder = input("Enter path to folder to encrypt: ").strip()
                if folder:
                    if confirm(f"Create encrypted archive for folder {folder}? (y/n): "):
                        print_loading()
                        encrypt_folder(folder)
                        print_done()
            elif choice == "5":
                enc = input("Enter path to encrypted file (.redbtn): ").strip()
                if enc and confirm(f"Decrypt file {enc}? (y/n): "):
                    print_loading()
                    decrypt_file(enc)
                    print_done()
            elif choice == "6":
                target = input("Enter target (default 127.0.0.1): ").strip() or "127.0.0.1"
                ports = input("Enter comma-separated ports or press Enter for common ports: ").strip()
                if ports:
                    try:
                        ports_list = [int(x.strip()) for x in ports.split(",") if x.strip()]
                    except:
                        ports_list = COMMON_PORTS
                else:
                    ports_list = COMMON_PORTS
                if confirm(f"Run port scan on {target} with ports {ports_list}? (y/n): "):
                    print_loading()
                    open_ports = port_scan(target, ports_list)
                    if open_ports:
                        print("Open ports:", open_ports)
                    else:
                        print("No open ports found from given list.")
                    print_done()
            elif choice == "7":
                if confirm("Run full scan now? (y/n): "):
                    print_loading()
                    full_scan()
                    print_done()
            elif choice == "8":
                if confirm("Show disk usage info? (y/n): "):
                    print_loading()
                    disk_usage()
                    print_done()
            elif choice == "9":
                if confirm("Show CPU & RAM monitor? (y/n): "):
                    monitor_resources()
            elif choice == "10":
                if confirm("Show network info? (y/n): "):
                    network_info()
            elif choice == "11":
                path = input("Enter folder path (leave blank for home): ").strip() or None
                try:
                    n = int(input("How many top files to show (default 10): ").strip() or "10")
                except Exception:
                    n = 10
                if confirm(f"Scan {path or 'home'} for top {n} largest files? (y/n): "):
                    find_large_files(path, top_n=n)
            elif choice == "12":
                if confirm("Clean temp files now? This will remove files from temp directories. (y/n): "):
                    print_loading()
                    temp_cleaner(do_remove=True)
                    print_done()
            elif choice == "13":
                fname = input("Enter PDF filename (leave blank for autogenerated): ").strip() or None
                if confirm("Create PDF report now? (y/n): "):
                    save_pdf_report(fname)
            elif choice == "14":
                if confirm("Check hosts file for non-comment entries? (y/n): "):
                    check_hosts_file()
            elif choice == "15":
                if confirm("Check system updates? (Windows only) (y/n): "):
                    check_system_updates()
            elif choice == "0":
                if confirm("Exit the program? (y/n): "):
                    print("Exiting. Keep your passwords and backups safe.")
                    break
            else:
                print("Invalid option, try again.")
            time.sleep(0.3)
        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting.")
            break
        except Exception as e:
            print("Unexpected error:", e)
            time.sleep(1)

if __name__ == "__main__":
    main_loop()
import os
import sys
import time
import hashlib
import threading
import socket
import subprocess
import shutil
import getpass
import base64
from datetime import datetime, timedelta
from colorama import init, Fore, Style

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
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_PDF = True
except Exception:
    HAS_PDF = False

init(autoreset=True)

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
    print(Fore.YELLOW + "[Info] v1.1 [Coded By : White Pirates]\n" + Style.RESET_ALL)

def colored_option(index, text):
    return (
        Fore.RED + "[" +
        Fore.WHITE + f"{index:02}" +
        Fore.RED + "] " +
        Fore.YELLOW + text +
        Style.RESET_ALL
    )

def print_loading():
    print(Fore.RED + "[*] " + Style.RESET_ALL + "Working...")

def print_done():
    print(Fore.GREEN + "Done." + Style.RESET_ALL)

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
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Running: ipconfig /release (may require admin privileges)")
        try:
            subprocess.run(["ipconfig", "/release"], check=False)
            print_done()
        except Exception as e:
            print("Error while disconnecting internet:", e)
    else:
        try:
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "networking", "off"], check=False)
                print_done()
            else:
                print("Non-Windows OS — please run appropriate system commands manually (requires admin).")
        except Exception as e:
            print("Error while attempting to disconnect network:", e)

SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".dll", ".vbs", ".js", ".jar", ".bat", ".ps1", ".cmd", ".hta", ".sys", ".com", ".pif"
}

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
                        results.append({
                            "path": path,
                            "ext": ext,
                            "mtime": mtime,
                            "sha256": sha
                        })
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
        print(f"Moved {path} to quarantine: {dest}")
    except Exception as e:
        print("Error while moving file:", e)

def lock_system():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            print_done()
        except Exception:
            try:
                subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])
                print_done()
            except Exception as e:
                print("Failed to lock system:", e)
    else:
        cmds = [
            ["gnome-screensaver-command", "-l"],
            ["xdg-screensaver", "lock"],
            ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"]
        ]
        for c in cmds:
            try:
                subprocess.run(c, check=False)
                print_done()
                return
            except Exception:
                continue
        print("Screen lock not supported automatically on this OS in current version.")

def derive_key(password: str, salt: bytes):
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography not available")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_folder(folder_path):
    if not HAS_CRYPTO:
        print("Cryptography library not installed. Install with: pip install cryptography")
        return
    if not os.path.exists(folder_path):
        print("Folder not found.")
        return
    password = getpass.getpass("Enter password to create encryption key: ")
    if not password:
        print("Empty password. Cancelled.")
        return
    base_name = os.path.abspath(folder_path.rstrip(os.sep))
    tmp_zip = base_name + "_redbtn_temp"
    try:
        zipfile_path = shutil.make_archive(tmp_zip, 'zip', folder_path)
    except Exception as e:
        print("Error creating archive:", e)
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
    print("Encrypted file created:", out_path)
    print("Keep the password safe — without it, files cannot be recovered.")

def decrypt_file(enc_path):
    if not HAS_CRYPTO:
        print("Cryptography library not installed. Install with: pip install cryptography")
        return
    if not os.path.exists(enc_path):
        print("Encrypted file not found.")
        return
    password = getpass.getpass("Enter password to decrypt: ")
    with open(enc_path, "rb") as rf:
        content = rf.read()
    salt = content[:16]
    encrypted = content[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        data = f.decrypt(encrypted)
    except Exception:
        print("Wrong password or corrupted file.")
        return
    out_zip = enc_path + ".decrypted.zip"
    with open(out_zip, "wb") as wf:
        wf.write(data)
    try:
        extract_dir = enc_path + "_extracted"
        shutil.unpack_archive(out_zip, extract_dir)
        os.remove(out_zip)
        print("Decrypted and extracted to:", extract_dir)
    except Exception:
        print("Decrypted to:", out_zip)
        print("To extract manually, unzip the file.")

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3389,5900,8080]

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

def list_processes():
    print("Running processes (user, PID, process name):")
    if HAS_PSUTIL:
        try:
            for p in psutil.process_iter(['pid','name','username']):
                try:
                    print(f"{p.info.get('username','?'):20} | {p.info.get('pid'):6} | {p.info.get('name')}")
                except Exception:
                    continue
        except Exception as e:
            print("Error enumerating processes with psutil:", e)
    else:
        if sys.platform.startswith("win"):
            try:
                out = subprocess.check_output(["tasklist"], shell=False, text=True, stderr=subprocess.DEVNULL)
                print(out)
            except Exception as e:
                print("Unable to list processes:", e)
        else:
            try:
                out = subprocess.check_output(["ps", "aux"], text=True)
                print(out)
            except Exception as e:
                print("Unable to list processes:", e)

def disk_usage():
    print("Disk Usage Info:")
    if HAS_PSUTIL:
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    total_gb = usage.total / (1024**3)
                    used_gb = usage.used / (1024**3)
                    free_gb = usage.free / (1024**3)
                    print(f"{p.device} ({p.mountpoint}) - Total: {total_gb:.2f}GB | Used: {used_gb:.2f}GB | Free: {free_gb:.2f}GB | FS: {p.fstype}")
                except Exception:
                    continue
        except Exception as e:
            print("Error reading disk partitions:", e)
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
                total_gb = usage.total / (1024**3)
                used_gb = (usage.total - usage.free) / (1024**3)
                free_gb = usage.free / (1024**3)
                print(f"{root} - Total: {total_gb:.2f}GB | Used: {used_gb:.2f}GB | Free: {free_gb:.2f}GB")
            except Exception:
                continue

def monitor_resources():
    print("Top Processes by CPU and Memory:")
    if not HAS_PSUTIL:
        print("psutil not installed. Install with: pip install psutil")
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
                processes.append((
                    info.get('cpu_percent', 0.0),
                    info.get('memory_percent', 0.0),
                    info.get('pid'),
                    info.get('name')
                ))
            except Exception:
                continue
        processes.sort(reverse=True, key=lambda x: (x[0], x[1]))
        print(f"{'PID':>6} {'CPU%':>6} {'MEM%':>6} Process")
        for cpu, mem, pid, name in processes[:15]:
            print(f"{pid:6} {cpu:6.1f} {mem:6.1f} {name}")
    except Exception as e:
        print("Error monitoring resources:", e)

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
                    print(f"  - {addr.family.name if hasattr(addr.family, 'name') else addr.family}: {addr.address}")
        except Exception:
            pass

def find_large_files(base_path=None, top_n=10):
    if base_path is None:
        base_path = os.path.expanduser("~")
    print(f"Scanning for largest files in: {base_path} (this may take a while)...")
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
    print(f"Largest {top_n} files in {base_path}:")
    for size, path in files[:top_n]:
        print(f"{size/(1024**2):.2f} MB - {path}")

def temp_cleaner(do_remove=True):
    temp_dirs = []
    if os.name == "nt":
        temp_dirs.extend([os.environ.get("TEMP",""), os.environ.get("TMP","")])
    else:
        temp_dirs.extend([os.environ.get("TMPDIR","/tmp"), "/var/tmp"])
    temp_dirs = [d for d in set(temp_dirs) if d]
    for tdir in temp_dirs:
        print(f" - {tdir}")
        if not os.path.exists(tdir):
            print("   (not present)")
            continue
        entries = os.listdir(tdir)
        print(f"   Contains {len(entries)} entries")
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
            print(f"   Removed approx {removed} entries from {tdir}")
    print_done()

def save_pdf_report(report_path=None):
    if not HAS_PDF:
        print("reportlab not installed. Install: pip install reportlab")
        return
    if report_path is None:
        report_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    try:
        c = canvas.Canvas(report_path, pagesize=letter)
        line = 750
        c.setFont("Helvetica-Bold", 14)
        c.drawString(60, line, "Security Scan Report")
        line -= 20
        c.setFont("Helvetica", 10)
        c.drawString(60, line, f"Generated: {datetime.now().isoformat()}")
        line -= 30
        if HAS_PSUTIL:
            try:
                partitions = psutil.disk_partitions(all=False)
                c.drawString(60, line, "Disk partitions summary:")
                line -= 14
                for p in partitions[:8]:
                    try:
                        usage = psutil.disk_usage(p.mountpoint)
                        text = f"{p.device} ({p.mountpoint}) - {usage.total//(1024**3)}GB total, {usage.free//(1024**3)}GB free"
                        c.drawString(72, line, text)
                        line -= 12
                    except Exception:
                        continue
            except Exception:
                pass
        hits = find_suspicious_files(days=7)
        c.drawString(60, line, f"Suspicious files found (scan): {len(hits)}")
        line -= 20
        c.drawString(60, line, "Note: For full details, run the tool interactively.")
        c.save()
        print("PDF report saved to:", report_path)
    except Exception as e:
        print("Failed to write PDF report:", e)

def check_hosts_file():
    if sys.platform.startswith("win"):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
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
    suspicious = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    print(f"Hosts file: {hosts_path}")
    if suspicious:
        print("Non-comment entries found (may be normal, inspect manually):")
        for s in suspicious:
            print("  ", s)
    else:
        print("No non-comment (suspicious) entries found.")

def check_system_updates():
    if not sys.platform.startswith("win"):
        print("Update check currently implemented for Windows only.")
        return
    cmd = 'powershell -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot"'
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=90)
        print(output)
    except subprocess.CalledProcessError as e:
        print("PowerShell command failed. You may need the PSWindowsUpdate module or admin rights.")
        print("Output:", e.output if hasattr(e, 'output') else e)
    except Exception as e:
        print("Error while checking updates:", e)

def menu():
    print()
    print(colored_option(1, "Disconnect Internet"))
    print(colored_option(2, "Find Suspicious Files"))
    print(colored_option(3, "Lock System"))
    print(colored_option(4, "Encrypt Folder"))
    print(colored_option(5, "Decrypt File (.redbtn)"))
    print(colored_option(6, "Port Scan"))
    print(colored_option(7, "Full Scan"))
    print(colored_option(8, "Disk Usage"))
    print(colored_option(9, "CPU & RAM Monitor"))
    print(colored_option(10, "Network Info"))
    print(colored_option(11, "Find Large Files"))
    print(colored_option(12, "Temp Cleaner"))
    print(colored_option(13, "Save PDF Report"))
    print(colored_option(14, "Check Hosts File"))
    print(colored_option(15, "Check System Updates"))
    print(colored_option(0, "Exit"))

def full_scan():
    list_processes()
    print("Scanning suspicious files (last 7 days)...")
    hits = find_suspicious_files(days=7)
    print(f"Suspicious files found: {len(hits)} (showing first 10)")
    for h in hits[:10]:
        print(f" - {h['path']} (sha256:{h.get('sha256')})")
    print("Local port scan (127.0.0.1)...")
    open_ports = port_scan("127.0.0.1")
    print("Open ports:", open_ports if open_ports else "None")

def main_loop():
    print_header()
    while True:
        try:
            menu()
            choice = input("\nChoose an option: ").strip()
            if choice == "1":
                if confirm("This will disconnect the internet. Continue? (y/n): "):
                    print_loading()
                    disconnect_internet()
                    print_done()
            elif choice == "2":
                days_in = input("Scan files changed in last (days, default 7): ").strip()
                try:
                    days = int(days_in) if days_in else 7
                except:
                    days = 7
                print_loading()
                hits = find_suspicious_files(days=days)
                if not hits:
                    print("No suspicious files found in default locations.")
                else:
                    for i, h in enumerate(hits, 1):
                        print(f"\n[{i:02}] {h['path']}\n    ext: {h['ext']}  --  mtime: {h['mtime']}\n    sha256: {h.get('sha256')}")
                    if confirm("\nMove selected files to quarantine? (y/n): "):
                        idxs = input("Enter file numbers separated by space or 'all': ").strip()
                        if idxs.lower() == "all":
                            for h in hits:
                                if confirm(f"Quarantine {h['path']} ? (y/n): "):
                                    quarantine_file(h['path'])
                        else:
                            for token in idxs.split():
                                try:
                                    j = int(token) - 1
                                    if 0 <= j < len(hits):
                                        if confirm(f"Quarantine {hits[j]['path']} ? (y/n): "):
                                            quarantine_file(hits[j]['path'])
                                except:
                                    continue
                print_done()
            elif choice == "3":
                if confirm("Lock the local workstation now? (y/n): "):
                    print_loading()
                    lock_system()
                    print_done()
            elif choice == "4":
                folder = input("Enter path to folder to encrypt: ").strip()
                if folder:
                    if confirm(f"Create encrypted archive for folder {folder}? (y/n): "):
                        print_loading()
                        encrypt_folder(folder)
                        print_done()
            elif choice == "5":
                enc = input("Enter path to encrypted file (.redbtn): ").strip()
                if enc and confirm(f"Decrypt file {enc}? (y/n): "):
                    print_loading()
                    decrypt_file(enc)
                    print_done()
            elif choice == "6":
                target = input("Enter target (default 127.0.0.1): ").strip() or "127.0.0.1"
                ports = input("Enter comma-separated ports or press Enter for common ports: ").strip()
                if ports:
                    try:
                        ports_list = [int(x.strip()) for x in ports.split(",") if x.strip()]
                    except:
                        ports_list = COMMON_PORTS
                else:
                    ports_list = COMMON_PORTS
                if confirm(f"Run port scan on {target} with ports {ports_list}? (y/n): "):
                    print_loading()
                    open_ports = port_scan(target, ports_list)
                    if open_ports:
                        print("Open ports:", open_ports)
                    else:
                        print("No open ports found from given list.")
                    print_done()
            elif choice == "7":
                if confirm("Run full scan now? (y/n): "):
                    print_loading()
                    full_scan()
                    print_done()
            elif choice == "8":
                if confirm("Show disk usage info? (y/n): "):
                    print_loading()
                    disk_usage()
                    print_done()
            elif choice == "9":
                if confirm("Show CPU & RAM monitor? (y/n): "):
                    monitor_resources()
            elif choice == "10":
                if confirm("Show network info? (y/n): "):
                    network_info()
            elif choice == "11":
                path = input("Enter folder path (leave blank for home): ").strip() or None
                try:
                    n = int(input("How many top files to show (default 10): ").strip() or "10")
                except Exception:
                    n = 10
                if confirm(f"Scan {path or 'home'} for top {n} largest files? (y/n): "):
                    find_large_files(path, top_n=n)
            elif choice == "12":
                if confirm("Clean temp files now? This will remove files from temp directories. (y/n): "):
                    print_loading()
                    temp_cleaner(do_remove=True)
                    print_done()
            elif choice == "13":
                fname = input("Enter PDF filename (leave blank for autogenerated): ").strip() or None
                if confirm("Create PDF report now? (y/n): "):
                    save_pdf_report(fname)
            elif choice == "14":
                if confirm("Check hosts file for non-comment entries? (y/n): "):
                    check_hosts_file()
            elif choice == "15":
                if confirm("Check system updates? (Windows only) (y/n): "):
                    check_system_updates()
            elif choice == "0":
                if confirm("Exit the program? (y/n): "):
                    print("Exiting. Keep your passwords and backups safe.")
                    break
            else:
                print("Invalid option, try again.")
            time.sleep(0.3)
        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting.")
            break
        except Exception as e:
            print("Unexpected error:", e)
            time.sleep(1)

if __name__ == "__main__":
    main_loop()
