import os
import time
import json
import requests
import subprocess
import psutil
import threading
from datetime import datetime
from rich.table import Table
from rich.console import Console
from rich.live import Live
from rich.text import Text
import ctypes
from ctypes import wintypes

# ----------------------------
# Config / Files
# ----------------------------
CONFIG_FILE = "config.json"
COOKIE_FILE = "cookies.txt"

console = Console()

# Default config (merged into existing config if needed)
DEFAULT_CONFIG = {
    "gameId": 2753915549,
    "checkInterval": 60,  # Default lebih lama untuk hindari rate limit
    "presenceCheckInterval": 30,  # Interval khusus untuk cek presence
    "processCheckInterval": 10,   # Interval khusus untuk cek process
    "maxOnlineChecks": 3,
    "maxOfflineChecks": 3,
    "launchDelay": 15,
    "TotalInstance": 10,
    "WindowsPerRow": 3,
    "FixedSize": "530x400",
    "SortAccounts": True,
    "ArrangeWindows": True,
    "Kill Process > Ram": True,
    "Ram Usage (Each Process)": 3,
    "AutoRestart": True,
    "RestartDelay": 5
}

# Roblox exe names to detect
ROBLOX_EXE_NAMES = {"robloxplayerbeta.exe", "robloxplayer.exe", "robloxplayerlauncher.exe"}

# Global locks untuk prevent race condition
process_lock = threading.Lock()
restart_lock = threading.Lock()
presence_lock = threading.Lock()

# ----------------------------
# Helpers / Logging
# ----------------------------
def nowstr():
    return datetime.now().strftime("%H:%M:%S")

def log(msg):
    line = f"[{nowstr()}] {msg}"
    console.print(line)

def load_or_create_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            log(f"Error load config.json: {e}")
            cfg = {}
    # merge defaults
    updated = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
            updated = True
    if updated:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            log("config.json: menambahkan field default baru")
        except:
            pass
    return cfg

def ensure_cookie_file():
    if not os.path.exists(COOKIE_FILE):
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write("")  # kosong
        log("cookies.txt dibuat (kosong). Isi 1 cookie per baris lalu jalankan ulang.")
        return False
    return True

def load_cookies():
    if not os.path.exists(COOKIE_FILE):
        return []
    with open(COOKIE_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines

# ----------------------------
# Windows / HWND helpers (Win32 via ctypes)
# ----------------------------
user32 = ctypes.WinDLL('user32', use_last_error=True)

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
IsWindowVisible = user32.IsWindowVisible
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowTextW = user32.GetWindowTextW
MoveWindow = user32.MoveWindow
SetForegroundWindow = user32.SetForegroundWindow

def enum_windows():
    results = []
    @EnumWindowsProc
    def _proc(hwnd, lParam):
        if IsWindowVisible(hwnd):
            length = GetWindowTextLengthW(hwnd)
            buffer = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buffer, length + 1)
            text = buffer.value
            results.append((hwnd, text))
        return True
    EnumWindows(_proc, 0)
    return results

def hwnd_to_pid(hwnd):
    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value

def move_resize_hwnd(hwnd, x, y, w, h):
    try:
        MoveWindow(hwnd, int(x), int(y), int(w), int(h), True)
    except Exception as e:
        # ignore
        pass

# ----------------------------
# RAM Monitoring Functions
# ----------------------------
def get_process_ram_usage(pid):
    """Mendapatkan penggunaan RAM dari process tertentu dalam GB"""
    try:
        if pid and psutil.pid_exists(pid):
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            # Convert bytes to GB
            ram_usage_gb = memory_info.rss / (1024 ** 3)
            return round(ram_usage_gb, 2)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return 0

def check_and_kill_high_ram_processes(accounts, ram_threshold_gb, launch_delay, cfg_game_id):
    """Memeriksa dan mengkill process yang menggunakan RAM melebihi threshold, lalu restart"""
    with process_lock:
        killed_accounts = []
        
        for acc in accounts:
            pid = acc.get("pid")
            if pid:
                ram_usage = get_process_ram_usage(pid)
                if ram_usage > ram_threshold_gb:
                    log(f"{acc['username']} menggunakan {ram_usage}GB RAM (> {ram_threshold_gb}GB) -> killing process")
                    if kill_pid(pid):
                        acc["pid"] = None
                        killed_accounts.append(acc)
                        log(f"{acc['username']}: Process killed karena penggunaan RAM tinggi")
                    else:
                        log(f"{acc['username']}: Gagal kill process karena RAM tinggi")
        
        # Restart accounts yang di-kill dengan delay
        if killed_accounts:
            log(f"Restarting {len(killed_accounts)} accounts yang di-kill karena RAM tinggi")
            
            for i, acc in enumerate(killed_accounts):
                if i > 0:
                    # Delay untuk account selain yang pertama
                    time.sleep(launch_delay)
                
                log(f"Restarting {acc['username']}...")
                new_pid, reason = launch_via_protocol(acc["cookie"], cfg_game_id)
                
                if new_pid:
                    acc["pid"] = new_pid
                    log(f"{acc['username']}: Restarted dengan PID {new_pid}")
                else:
                    log(f"{acc['username']}: Restart failed ({reason})")
        
        return len(killed_accounts)

# ----------------------------
# Roblox / API functions
# ----------------------------
def get_user_from_cookie(cookie):
    try:
        r = requests.get("https://users.roblox.com/v1/users/authenticated",
                         headers={"Cookie": f".ROBLOSECURITY={cookie}"},
                         timeout=10)
        if r.status_code == 200:
            d = r.json()
            return str(d["id"]), d.get("name") or d.get("displayName") or d["id"]
    except Exception as e:
        # ignore
        pass
    return None, None

def get_presence(cookie, user_id):
    with presence_lock:
        try:
            r = requests.post("https://presence.roblox.com/v1/presence/users",
                              headers={"Cookie": f".ROBLOSECURITY={cookie}", "Content-Type": "application/json"},
                              json={"userIds": [int(user_id)]},
                              timeout=10)
            if r.status_code == 200:
                pres = r.json()["userPresences"][0]["userPresenceType"]
                # 0=Offline,1=Online,2=InGame,3=InStudio
                return int(pres)
        except Exception as e:
            # ignore
            pass
        return -1

def get_auth_ticket(cookie):
    try:
        # get CSRF
        r1 = requests.post("https://auth.roblox.com/v1/authentication-ticket",
                           headers={"Cookie": f".ROBLOSECURITY={cookie}", "Content-Type": "application/json"},
                           timeout=10)
        csrf = r1.headers.get("x-csrf-token")
        if not csrf:
            return None
        r2 = requests.post("https://auth.roblox.com/v1/authentication-ticket",
                           headers={
                               "Cookie": f".ROBLOSECURITY={cookie}",
                               "X-CSRF-TOKEN": csrf,
                               "Referer": "https://www.roblox.com/",
                               "Origin": "https://www.roblox.com",
                               "User-Agent": "Mozilla/5.0",
                               "Content-Type": "application/json"
                           },
                           data="{}",
                           timeout=10)
        if r2.status_code == 200:
            # ticket is in header 'rbx-authentication-ticket'
            return r2.headers.get("rbx-authentication-ticket")
    except Exception as e:
        pass
    return None

def list_current_roblox_pids():
    with process_lock:
        res = []
        for p in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                if p.info['name'] and p.info['name'].lower() in ROBLOX_EXE_NAMES:
                    res.append((p.info['pid'], p.info.get('create_time', 0)))
            except Exception:
                pass
        return dict(res)  # pid -> create_time

def find_new_roblox_pid(before_pids, timeout=20):
    """Tunggu sampai ada pid baru yang bukan di before_pids. Return pid or None."""
    start = time.time()
    while time.time() - start < timeout:
        cur = list_current_roblox_pids()  # dict pid->create_time
        new = [pid for pid in cur.keys() if pid not in before_pids]
        if new:
            # pilih yang paling baru (max create_time)
            new.sort(key=lambda p: cur[p], reverse=True)
            return new[0]
        time.sleep(0.5)
    return None

def kill_pid(pid):
    with process_lock:
        try:
            if pid and psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.kill()
                return True
        except Exception:
            pass
        return False

def is_process_running(pid):
    """Cek apakah process dengan PID tertentu masih berjalan"""
    if pid is None:
        return False
    try:
        return psutil.pid_exists(pid)
    except:
        return False

def is_roblox_process_running(pid):
    """Cek apakah process dengan PID tertentu adalah process Roblox yang masih berjalan"""
    if not is_process_running(pid):
        return False
    try:
        p = psutil.Process(pid)
        return p.name().lower() in ROBLOX_EXE_NAMES
    except:
        return False

# ----------------------------
# Launch / Assign PID
# ----------------------------
def launch_via_protocol(cookie, cfg_game_id):
    """Return new pid if found, otherwise None."""
    with process_lock:
        ticket = get_auth_ticket(cookie)
        if not ticket:
            return None, "no-ticket"
        protocol = (
            f"roblox-player:1+launchmode:play+gameinfo:{ticket}"
            f"+launchtime:{int(time.time()*1000)}"
            f"+placelauncherurl:https%3A%2F%2Fwww.roblox.com%2FGame%2FPlaceLauncher.ashx%3Frequest%3DRequestGame%26placeId%3D{cfg_game_id}"
        )
        # capture current Roblox pids
        before = list_current_roblox_pids()
        try:
            # start using start (let OS handle protocol)
            subprocess.Popen(["cmd", "/c", "start", "", protocol], shell=True)
        except Exception as e:
            return None, "start-failed"
        # find new pid
        new_pid = find_new_roblox_pid(before, timeout=25)
        if new_pid:
            return new_pid, "ok"
        return None, "no-new-pid"

# ----------------------------
# Duplicate Account Detection - DIPERBAIKI
# ----------------------------
def detect_and_kill_duplicate_accounts(accounts):
    """Deteksi dan kill proses untuk akun yang duplikat (username/cookie sama)"""
    with process_lock:
        killed_count = 0
        
        # Group accounts by username
        username_groups = {}
        for acc in accounts:
            username = acc["username"]
            if username not in username_groups:
                username_groups[username] = []
            username_groups[username].append(acc)
        
        # Untuk setiap grup username, jika ada lebih dari 1 account, keep yang terbaru
        for username, acc_list in username_groups.items():
            if len(acc_list) > 1:
                log(f"Detected duplicate account: {username} ({len(acc_list)} instances)")
                
                # Filter hanya yang memiliki PID aktif
                active_accounts = [acc for acc in acc_list if acc.get("pid") and is_roblox_process_running(acc["pid"])]
                
                if len(active_accounts) > 1:
                    # Sort by create time (process yang lebih baru dipertahankan)
                    active_accounts.sort(key=lambda x: psutil.Process(x["pid"]).create_time(), reverse=True)
                    
                    # Keep the first one (yang paling baru), kill the rest
                    keep_acc = active_accounts[0]
                    for acc in active_accounts[1:]:
                        pid = acc.get("pid")
                        if pid and is_roblox_process_running(pid):
                            if kill_pid(pid):
                                log(f"Killed duplicate process PID {pid} for {username}")
                                killed_count += 1
                                acc["pid"] = None
                                acc["online_count"] = 0
                                acc["offline_count"] = 0
                                acc["unknown_count"] = 0
                            else:
                                log(f"Failed to kill duplicate process PID {pid} for {username}")
        
        return killed_count

# ----------------------------
# Match existing Roblox processes to accounts
# ----------------------------
def match_existing_processes_to_accounts(accounts):
    """Mencocokkan proses Roblox yang sudah berjalan dengan akun berdasarkan cookie"""
    with process_lock:
        log("Mencari proses Roblox yang sudah berjalan...")
        
        # Dapatkan semua proses Roblox yang sedang berjalan
        roblox_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
            try:
                if proc.info['name'] and proc.info['name'].lower() in ROBLOX_EXE_NAMES:
                    roblox_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        log(f"Found {len(roblox_processes)} Roblox processes running")
        
        # Untuk setiap akun, coba cocokkan dengan proses yang ada
        matched_count = 0
        for acc in accounts:
            if acc.get("pid") is not None:
                continue  # Skip jika sudah ada PID
                
            # Cek status presence untuk menentukan apakah akun sedang dalam game
            presence = get_presence(acc["cookie"], acc["user_id"])
            
            if presence == 2:  # InGame - kemungkinan besar ada proses yang berjalan
                # Cari proses Roblox yang paling baru
                if roblox_processes:
                    # Urutkan berdasarkan waktu pembuatan (terbaru pertama)
                    roblox_processes.sort(key=lambda p: p.info['create_time'], reverse=True)
                    
                    # Ambil proses terbaru dan assign ke akun ini
                    newest_proc = roblox_processes[0]
                    acc["pid"] = newest_proc.info['pid']
                    matched_count += 1
                    log(f"Matched existing process PID {newest_proc.info['pid']} to {acc['username']}")
                    
                    # Hapus proses yang sudah dipakai dari list
                    roblox_processes.pop(0)
        
        log(f"Berhasil mencocokkan {matched_count} proses yang sudah berjalan")
        return matched_count

# ----------------------------
# Arrange windows by pid mapping
# ----------------------------
def arrange_windows_for_pids(pid_ordered_list, config):
    """
    pid_ordered_list: list of pids in the order we want to place (index -> position)
    config contains WindowsPerRow and FixedSize
    """
    try:
        size = config.get("FixedSize", "530x400").lower().split("x")
        w, h = int(size[0]), int(size[1])
        per_row = max(1, int(config.get("WindowsPerRow", 3)))

        # enum windows visible and map hwnd->pid and title
        hwnds = enum_windows()
        pid_to_hwnds = {}
        for hwnd, title in hwnds:
            pid = hwnd_to_pid(hwnd)
            # optionally filter out very short titles
            pid_to_hwnds.setdefault(pid, []).append((hwnd, title))

        # For each pid in our list, if there's a window, move/resize it
        placed = 0
        for idx, pid in enumerate(pid_ordered_list):
            if pid is None:
                continue
            if pid not in pid_to_hwnds:
                continue
            # choose the first hwnd for the pid that has some title
            candidates = pid_to_hwnds[pid]
            chosen = None
            for hwnd, title in candidates:
                if title and len(title.strip()) > 0:
                    chosen = hwnd
                    break
            if chosen is None and candidates:
                chosen = candidates[0][0]
            if chosen:
                row = placed // per_row
                col = placed % per_row
                x = col * w
                y = row * h
                move_resize_hwnd(chosen, x, y, w, h)
                placed += 1
    except Exception as e:
        pass  # ignore arrangement errors

# ----------------------------
# Presence Checking Function - TERPISAH
# ----------------------------
def check_presence_for_accounts(accounts, config):
    """Fungsi terpisah untuk cek presence dengan interval sendiri"""
    with presence_lock:
        for acc in accounts:
            presence = get_presence(acc["cookie"], acc["user_id"])
            
            # Update counters berdasarkan status
            if presence == 0:  # Offline
                acc["offline_count"] += 1
                acc["online_count"] = 0
                acc["unknown_count"] = 0
            elif presence == 1:  # Online
                acc["online_count"] += 1
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
            elif presence == 2:  # InGame - reset semua counter
                acc["online_count"] = 0
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
            else:  # Unknown/Error
                acc["unknown_count"] += 1
                acc["online_count"] = 0
                acc["offline_count"] = 0

# ----------------------------
# Process Checking Function - TERPISAH
# ----------------------------
def check_processes_for_accounts(accounts):
    """Fungsi terpisah untuk cek status process dengan interval sendiri"""
    with process_lock:
        for acc in accounts:
            pid = acc.get("pid")
            if pid:
                # Cek apakah process masih berjalan
                if not is_roblox_process_running(pid):
                    acc["pid"] = None
                    # Jika process mati, increment offline count
                    acc["offline_count"] += 1

# ----------------------------
# Auto Restart Logic - DIPERBAIKI dengan lock
# ----------------------------
def check_and_restart_offline_accounts(accounts, config, last_launch_time, launch_delay):
    """Cek dan restart akun sesuai logika yang diperbaiki"""
    with restart_lock:
        restart_count = 0
        
        for acc in accounts:
            pid = acc.get("pid")
            cookie = acc["cookie"]
            user_id = acc["user_id"]
            username = acc["username"]
            
            # Cek apakah process Roblox masih berjalan
            process_running = is_roblox_process_running(pid)
            
            # LOGICA UTAMA YANG DIPERBAIKI:
            needs_restart = False
            reason = ""
            
            # 1. Jika status InGame (2) - BIARKAN, jangan restart
            if acc.get("last_presence") == 2:
                continue
            
            # 2. Process tidak berjalan -> status dianggap Offline
            if not process_running:
                needs_restart = True
                reason = "Process tidak berjalan (Offline)"
                
                # Gunakan offline_count untuk threshold checking
                if acc["offline_count"] >= int(config.get("maxOfflineChecks", 3)):
                    needs_restart = True
                    reason = f"Offline count {acc['offline_count']} mencapai threshold"
            
            # 3. Process berjalan tapi status Online - cek threshold
            elif process_running and acc.get("last_presence") == 1:
                if acc["online_count"] >= int(config.get("maxOnlineChecks", 3)):
                    needs_restart = True
                    reason = f"Online count {acc['online_count']} mencapai threshold"
            
            # 4. Process berjalan tapi status Offline - cek threshold
            elif process_running and acc.get("last_presence") == 0:
                if acc["offline_count"] >= int(config.get("maxOfflineChecks", 3)):
                    needs_restart = True
                    reason = f"Offline count {acc['offline_count']} mencapai threshold"
            
            # 5. Process berjalan tapi status Unknown/Error - cek threshold
            elif process_running and acc.get("last_presence") == -1:
                if acc["unknown_count"] >= int(config.get("maxOnlineChecks", 3)):
                    needs_restart = True
                    reason = f"Unknown count {acc['unknown_count']} mencapai threshold"
            
            # Eksekusi restart jika diperlukan
            if needs_restart and config.get("AutoRestart", True):
                # Apply launch delay
                current_time = time.time()
                time_since_last_launch = current_time - last_launch_time[0]
                
                if time_since_last_launch < launch_delay:
                    wait_time = launch_delay - time_since_last_launch
                    time.sleep(wait_time)
                
                # Kill process lama jika masih ada
                if pid and is_process_running(pid):
                    log(f"{username}: Killing process PID {pid} ({reason})")
                    kill_pid(pid)
                    time.sleep(2)  # Beri waktu lebih untuk process benar-benar terminate
                
                # Launch process baru sesuai username dan cookie
                log(f"{username}: {reason} -> restarting...")
                new_pid, launch_reason = launch_via_protocol(cookie, config.get("gameId"))
                last_launch_time[0] = time.time()
                
                if new_pid:
                    acc["pid"] = new_pid
                    acc["online_count"] = 0
                    acc["offline_count"] = 0
                    acc["unknown_count"] = 0
                    log(f"{username}: Berhasil restart dengan PID {new_pid}")
                    restart_count += 1
                else:
                    log(f"{username}: Gagal restart ({launch_reason})")
                
                # Additional delay between restarts
                time.sleep(float(config.get("RestartDelay", 5)))
        
        return restart_count

# ----------------------------
# Main logic - DIPERBAIKI dengan timing terpisah
# ----------------------------
def main():
    cfg = load_or_create_config()
    # ensure cookie file
    ok = ensure_cookie_file()
    if not ok:
        return

    cookies = load_cookies()
    if not cookies:
        log("cookie.txt kosong. Isi 1 cookie per baris.")
        return

    # load accounts (get user id / name)
    accounts = []
    for ck in cookies:
        uid, uname = get_user_from_cookie(ck)
        if uid:
            accounts.append({
                "cookie": ck,
                "user_id": uid,
                "username": uname,
                "pid": None,
                "online_count": 0,
                "offline_count": 0,
                "unknown_count": 0,
                "last_presence": -1,
                "last_checked": 0
            })
            log(f"Loaded {uname} ({uid})")
        else:
            log("Cookie invalid / expired (skip one line)")

    if not accounts:
        log("Tidak ada akun valid.")
        return

    # sort if requested
    if cfg.get("SortAccounts", True):
        accounts.sort(key=lambda a: a["username"].lower())

    # apply TotalInstance limit
    total_instances = int(cfg.get("TotalInstance", 10))
    if total_instances < len(accounts):
        accounts = accounts[:total_instances]

    # Mencocokkan proses yang sudah berjalan dengan akun
    match_existing_processes_to_accounts(accounts)

    # Variables untuk mengontrol delay
    last_launch_time = [time.time()]
    last_presence_check = time.time()
    last_process_check = time.time()
    last_duplicate_check = time.time()
    last_ram_check = time.time()

    # Get intervals from config
    check_interval = float(cfg.get("checkInterval", 60))
    presence_interval = float(cfg.get("presenceCheckInterval", 30))
    process_interval = float(cfg.get("processCheckInterval", 10))
    duplicate_interval = 60  # Check duplicates every 60 seconds
    ram_interval = 30  # Check RAM every 30 seconds

    # Clear screen sebelum memulai live table
    console.clear()

    with Live(refresh_per_second=4, console=console, screen=False) as live:
        while True:
            current_time = time.time()
            
            # Check for duplicate accounts (setiap 60 detik)
            if current_time - last_duplicate_check >= duplicate_interval:
                killed_duplicates = detect_and_kill_duplicate_accounts(accounts)
                if killed_duplicates > 0:
                    log(f"Killed {killed_duplicates} duplicate account processes")
                last_duplicate_check = current_time
            
            # Check RAM usage (setiap 30 detik)
            if current_time - last_ram_check >= ram_interval and cfg.get("Kill Process > Ram", False):
                ram_threshold = float(cfg.get("Ram Usage (Each Process)", 3))
                killed_count = check_and_kill_high_ram_processes(accounts, ram_threshold, 
                                                               float(cfg.get("launchDelay", 15)), 
                                                               cfg.get("gameId"))
                if killed_count > 0:
                    log(f"Restarted {killed_count} processes karena penggunaan RAM tinggi")
                last_ram_check = current_time
            
            # Check presence (setiap presence_interval detik)
            if current_time - last_presence_check >= presence_interval:
                check_presence_for_accounts(accounts, cfg)
                last_presence_check = current_time
            
            # Check processes (setiap process_interval detik)
            if current_time - last_process_check >= process_interval:
                check_processes_for_accounts(accounts)
                last_process_check = current_time
            
            # Auto restart logic (menggunakan data dari presence dan process checks)
            if cfg.get("AutoRestart", True):
                restart_count = check_and_restart_offline_accounts(accounts, cfg, last_launch_time, 
                                                                 float(cfg.get("launchDelay", 15)))
                if restart_count > 0:
                    log(f"Auto-restarted {restart_count} accounts sesuai threshold config")

            # Update display table
            pid_order = []
            table = Table(title="Roblox Auto Rejoin Monitor", show_header=True, header_style="bold magenta")
            table.add_column("No.", justify="right", width=4)
            table.add_column("Username", min_width=15, overflow="fold")
            table.add_column("UserID", width=12)
            table.add_column("Status", width=45)

            for i, acc in enumerate(accounts, start=1):
                name = acc["username"]
                uid = acc["user_id"]
                pid = acc.get("pid")
                presence = acc.get("last_presence", -1)
                
                pid_running = is_roblox_process_running(pid)
                
                # Status message
                status_msg = ""
                if presence == 2:  # InGame
                    status_msg = "In Game ✅"
                elif presence == 1:  # Online
                    if pid_running:
                        status_msg = f"Online [{acc['online_count']}/{cfg.get('maxOnlineChecks',3)}]"
                    else:
                        status_msg = f"Online [{acc['online_count']}/{cfg.get('maxOnlineChecks',3)}] (No Process)"
                elif presence == 0:  # Offline
                    if pid_running:
                        status_msg = f"Offline [{acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}] (Process Running)"
                    else:
                        status_msg = f"Offline [{acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}]"
                else:  # Unknown
                    if pid_running:
                        status_msg = f"Unknown [{acc['unknown_count']}/{cfg.get('maxOnlineChecks',3)}] (Process Running)"
                    else:
                        status_msg = f"Unknown [{acc['unknown_count']}/{cfg.get('maxOnlineChecks',3)}]"

                pid_order.append(pid)

                # Color coding
                username_text = Text(name)
                status_text = Text(status_msg)
                
                if presence == 2:  # InGame - hijau
                    username_text.stylize("bold green")
                    status_text.stylize("bold green")
                elif presence == 1:  # Online - biru
                    username_text.stylize("bold blue")
                    status_text.stylize("bold blue")
                elif presence == 0:  # Offline - merah
                    username_text.stylize("bold red")
                    status_text.stylize("bold red")
                else:  # Unknown - kuning
                    username_text.stylize("bold yellow")
                    status_text.stylize("bold yellow")

                table.add_row(str(i), username_text, str(uid), status_text)

            live.update(table)

            # Arrange windows if enabled
            if cfg.get("ArrangeWindows", True):
                arrange_windows_for_pids(pid_order, cfg)

            # Wait for next cycle sesuai checkInterval utama
            time.sleep(check_interval)

if __name__ == "__main__":
    try:
        log("Starting Roblox Auto Rejoin Monitor (Improved Timing & Locking)")
        log("Fitur: Interval terpisah untuk presence, process, dan duplicate checks")
        main()
    except KeyboardInterrupt:
        log("Program dihentikan oleh user")
    except Exception as e:
        log(f"Error: {e}")
