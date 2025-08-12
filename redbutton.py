
import os
import sys
import time
import hashlib
import threading
import socket
import subprocess
import shutil
import getpass
from datetime import datetime, timedelta

try:
    from colorama import init, Fore, Style
except ImportError:
    print("Please install colorama: pip install colorama")
    sys.exit(1)

init(autoreset=True)


SAFE_MODE = False


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
    print(Fore.YELLOW + "[Info] v1.0 [Coded By : White Pirates]\n")

def colored_option(index, text):
    
    return (
        Fore.RED + "[" +
        Fore.WHITE + str(index) +
        Fore.RED + "] " +
        Fore.YELLOW + text +
        Style.RESET_ALL
    )

def print_loading():
    print(Fore.RED + "[*]" + Style.RESET_ALL + " Working...")

def print_done():
    print(Fore.GREEN + "✔ Done!" + Style.RESET_ALL)

def confirm(prompt="Are you sure? (y/n): "):
    return input(prompt).strip().lower() in ("y", "yes")



def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()


def disconnect_internet():
    print("\n📡 Disconnecting Internet — Mode:", "SIMULATE" if SAFE_MODE else "LIVE")
    if SAFE_MODE:
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Simulation: Would run 'ipconfig /release' on Windows")
        return
    if sys.platform.startswith("win"):
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Running: ipconfig /release ... (may require admin privileges)")
        try:
            subprocess.run(["ipconfig", "/release"], check=False)
            print_done()
        except Exception as e:
            print(Fore.RED + "Error while disconnecting internet:", e)
    else:
        print("Non-Windows OS — run appropriate system commands manually.")


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
                        results.append({
                            "path": path,
                            "ext": ext,
                            "mtime": mtime,
                            "sha256": sha256_of_file(path)
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
        if SAFE_MODE:
            print(f"[Simulation] Moving {path} -> {dest}")
        else:
            shutil.move(path, dest)
            print(f"Moved {path} to quarantine: {dest}")
    except Exception as e:
        print("Error while moving file:", e)


def lock_system():
    print("\n🔒 Locking system...")
    if SAFE_MODE:
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Screen lock would be executed if SAFE_MODE=False")
        return
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
                print(Fore.RED + "Failed to lock system:", e)
    else:
        print("Screen lock not supported automatically on this OS in current version.")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

def derive_key(password: str, salt: bytes):
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
    zipfile_path = shutil.make_archive(tmp_zip, 'zip', folder_path)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    with open(zipfile_path, "rb") as rf:
        data = rf.read()
    encrypted = f.encrypt(data)
    out_path = zipfile_path + ".redbtn"
    with open(out_path, "wb") as wf:
        wf.write(salt + encrypted)
    if not SAFE_MODE:
        os.remove(zipfile_path)
    else:
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Encrypted file created, temp archive NOT removed due to SAFE_MODE.")
    print(Fore.GREEN + "Encrypted file created:" + Style.RESET_ALL, out_path)
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
    print(Fore.GREEN + "Decrypted to:" + Style.RESET_ALL, out_zip)
    if not SAFE_MODE:
        try:
            extract_dir = enc_path + "_extracted"
            shutil.unpack_archive(out_zip, extract_dir)
            os.remove(out_zip)
            print(Fore.GREEN + "Extracted to:" + Style.RESET_ALL, extract_dir)
        except Exception as e:
            print("Error extracting archive:", e)
    else:
        print(Fore.RED + "[*] " + Style.RESET_ALL + "Archive not extracted due to SAFE_MODE.")


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
            s.close()
    for p in ports:
        t = threading.Thread(target=worker, args=(p,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return sorted(open_ports)


try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

def list_processes():
    print("\n🔎 Running processes (user, PID, process name):")
    if HAS_PSUTIL:
        for p in psutil.process_iter(['pid','name','username']):
            try:
                print(f"{p.info.get('username','?'):20} | {p.info.get('pid'):6} | {p.info.get('name')}")
            except Exception:
                continue
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



def menu():
    print()
    print(colored_option(1, "Disconnect Internet"))
    print(colored_option(2, "Find Suspicious Files"))
    print(colored_option(3, "Lock System"))
    print(colored_option(4, "Encrypt Folder"))
    print(colored_option(5, "Decrypt File (.redbtn)"))
    print(colored_option(6, "Port Scan"))
    print(colored_option(7, "Full Scan"))
    print(colored_option(0, "Exit"))

def main_loop():
    print_header()
    while True:
        menu()
        choice = input("\nChoose an option: ").strip()
        if choice == "1":
            print("\n[Option 1] Disconnect Internet")
            if SAFE_MODE:
                print_loading()
                print(Fore.RED + "[*] " + Style.RESET_ALL + "SAFE_MODE is ON — this is a simulation.")
                if confirm("Show simulation now? (y/n): "):
                    disconnect_internet()
            else:
                if confirm("Warning: This will disconnect internet. Continue? (y/n): "):
                    print_loading()
                    disconnect_internet()
            print_done()
        elif choice == "2":
            print("\n[Option 2] Find Suspicious Files")
            days = input("Scan files changed in last (days, default 7): ").strip()
            try:
                days = int(days) if days else 7
            except:
                days = 7
            print_loading()
            hits = find_suspicious_files(days=days)
            if not hits:
                print("No suspicious files found in default locations.")
            else:
                for i, h in enumerate(hits, 1):
                    print(f"\n[{i}] {h['path']}\n    ext: {h['ext']}  --  mtime: {h['mtime']}\n    sha256: {h['sha256']}")
                if confirm("\nMove selected files to quarantine? (y/n): "):
                    idxs = input("Enter file numbers separated by space or 'all': ").strip()
                    if idxs.lower() == "all":
                        for h in hits:
                            quarantine_file(h['path'])
                    else:
                        for token in idxs.split():
                            try:
                                j = int(token) - 1
                                if 0 <= j < len(hits):
                                    quarantine_file(hits[j]['path'])
                            except:
                                continue
            print_done()
        elif choice == "3":
            print("\n[Option 3] Lock System")
            if confirm("Execute screen lock now? (y/n): "):
                print_loading()
                lock_system()
                print_done()
        elif choice == "4":
            print("\n[Option 4] Encrypt Folder")
            folder = input("Enter path to folder to encrypt: ").strip()
            if folder:
                if confirm(f"An encrypted file will be created for folder {folder}. Continue? (y/n): "):
                    print_loading()
                    encrypt_folder(folder)
            print_done()
        elif choice == "5":
            print("\n[Option 5] Decrypt File")
            enc = input("Enter path to encrypted file (.redbtn): ").strip()
            if enc:
                print_loading()
                decrypt_file(enc)
            print_done()
        elif choice == "6":
            print("\n[Option 6] Port Scan")
            target = input("Enter target (default 127.0.0.1): ").strip() or "127.0.0.1"
            ports = input("Enter comma-separated ports or press Enter for common ports: ").strip()
            if ports:
                try:
                    ports_list = [int(x.strip()) for x in ports.split(",") if x.strip()]
                except:
                    ports_list = COMMON_PORTS
            else:
                ports_list = COMMON_PORTS
            print_loading()
            open_ports = port_scan(target, ports_list)
            if open_ports:
                print("Open ports:", open_ports)
            else:
                print("No open ports found from given list.")
            print_done()
        elif choice == "7":
            print("\n[Option 7] Full Scan")
            print("1) Show running processes")
            list_processes()
            print("\n2) Scan suspicious files (default 7 days)")
            hits = find_suspicious_files(days=7)
            print(f"Suspicious files found: {len(hits)} (showing first 10)")
            for h in hits[:10]:
                print(f" - {h['path']} (sha256:{h['sha256']})")
            print("\n3) Local port scan (127.0.0.1)")
            print_loading()
            open_ports = port_scan("127.0.0.1")
            print("Open ports:", open_ports if open_ports else "None")
            print_done()
        elif choice == "0":
            print("👋 Exiting. Keep your passwords and backups safe.")
            break
        else:
            print("Invalid option, try again.")
        time.sleep(1)

if __name__ == "__main__":
    main_loop()
