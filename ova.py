import os
import time
import json
import requests
import subprocess
import psutil
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
    "checkInterval": 60,         # interval untuk pengecekan presence/online (detik)
    "ProcCheckInterval": 5,      # interval untuk pengecekan proses/pid/ram (detik). default 5s (bisa diubah)
    "maxOnlineChecks": 3,
    "maxOfflineChecks": 3,
    "launchDelay": 15,           # delay SETELAH berhasil launch Roblox
    "accountLaunchCooldown": 30, # jeda khusus tiap akun (mencegah double launch)
    "TotalInstance": 30,
    "WindowsPerRow": 10,
    "FixedSize": "10x30",
    "SortAccounts": True,
    "ArrangeWindows": True,
    "Kill Process > Ram": True,
    "Ram Usage (Each Process)": 3,
    "EnableMultiInstance": True   # Fitur baru untuk enable multi-instance
}

# Roblox exe names to detect
ROBLOX_EXE_NAMES = {"robloxplayerbeta.exe", "robloxplayer.exe", "robloxplayerlauncher.exe"}

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

def check_and_kill_high_ram_processes(accounts, ram_threshold_gb):
    """Memeriksa dan mengkill process yang menggunakan RAM melebihi threshold.
       Hanya melakukan kill; tidak melakukan restart di sini (sesuai permintaan)."""
    killed_accounts = []
    
    for acc in accounts:
        pid = acc.get("pid")
        if pid and is_roblox_process_running(pid):
            ram_usage = get_process_ram_usage(pid)
            if ram_usage > ram_threshold_gb:
                log(f"{acc['username']} menggunakan {ram_usage}GB RAM (> {ram_threshold_gb}GB) -> killing process ONLY")
                if kill_ram(pid):
                    # set pid None, counters reset agar proc-loop selanjutnya bisa mendeteksi offline dan start ulang
                    acc["pid"] = None
                    acc["offline_count"] = 0
                    acc["online_count"] = 0
                    acc["unknown_count"] = 0
                    acc.setdefault("last_launch", 0)      # waktu terakhir launch
                    acc.setdefault("launching", False)    # status sedang launching
                    killed_accounts.append(acc)
                    log(f"{acc['username']}: Process killed karena penggunaan RAM tinggi")
                else:
                    log(f"{acc['username']}: Gagal kill process karena RAM tinggi")
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

# Kill via RAM (replacing kill_pid)
def kill_ram(pid, acc=None):
    """Kill Roblox process via RAM (force kill)"""
    try:
        if pid and psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            proc.kill()
            log(f"Process PID {pid} killed via RAM")
            if acc:
                acc["pid"] = None
                acc["online_count"] = 0
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
            return True
    except Exception as e:
        log(f"Failed kill_ram PID {pid}: {e}")
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
# Launch / Assign PID - MODIFIED FOR DELAY AFTER LAUNCH
# ----------------------------
def launch_via_protocol(cookie, cfg_game_id, enable_multi_instance=True):
    """Return new pid if found, otherwise None."""
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

def apply_post_launch_delay(delay_seconds, account_name):
    """Menerapkan delay SETELAH berhasil launch Roblox"""
    if delay_seconds > 0:
        log(f"{account_name}: Menunggu {delay_seconds} detik setelah launch...")
        for i in range(delay_seconds, 0, -1):
            log(f"{account_name}: Delay {i}s...")
            time.sleep(1)
        log(f"{account_name}: Delay selesai, melanjutkan...")

# ----------------------------
# Duplicate Account Detection - MODIFIED FOR MULTI-INSTANCE
# ----------------------------
def detect_and_kill_duplicate_accounts(accounts, enable_multi_instance=True):
    """Deteksi dan kill proses untuk akun yang duplikat (username/cookie sama)
       Dengan multi-instance, kita izinkan multiple instance untuk akun berbeda"""
    killed_count = 0
    
    if enable_multi_instance:
        # Dalam mode multi-instance, hanya kill jika cookie sama (akun sama)
        cookie_groups = {}
        for acc in accounts:
            cookie = acc["cookie"]
            if cookie not in cookie_groups:
                cookie_groups[cookie] = []
            cookie_groups[cookie].append(acc)
        
        for cookie, acc_list in cookie_groups.items():
            if len(acc_list) > 1:
                username = acc_list[0]["username"]
                log(f"Detected duplicate cookie: {username} ({len(acc_list)} instances)")
                
                # Keep hanya 1 instance per cookie, kill sisanya
                keep_acc = acc_list[0]
                for acc in acc_list[1:]:
                    pid = acc.get("pid")
                    if pid and is_roblox_process_running(pid):
                        if kill_ram(pid):
                            log(f"Killed duplicate process PID {pid} for {username}")
                            killed_count += 1
                    
                    # Reset the duplicate account
                    acc["pid"] = None
                    acc["online_count"] = 0
                    acc["offline_count"] = 0
                    acc["unknown_count"] = 0
    else:
        # Mode single-instance: traditional duplicate detection
        username_groups = {}
        for acc in accounts:
            username = acc["username"]
            if username not in username_groups:
                username_groups[username] = []
            username_groups[username].append(acc)
        
        for username, acc_list in username_groups.items():
            if len(acc_list) > 1:
                log(f"Detected duplicate account: {username} ({len(acc_list)} instances)")
                
                acc_list.sort(key=lambda x: (
                    x["pid"] is None,
                    -x.get("online_count", 0),
                    -x.get("offline_count", 0)
                ))
                
                keep_acc = acc_list[0]
                for acc in acc_list[1:]:
                    pid = acc.get("pid")
                    if pid and is_roblox_process_running(pid):
                        if kill_ram(pid):
                            log(f"Killed duplicate process PID {pid} for {username}")
                            killed_count += 1
                    
                    acc["pid"] = None
                    acc["online_count"] = 0
                    acc["offline_count"] = 0
                    acc["unknown_count"] = 0
    
    return killed_count

# ----------------------------
# Match existing Roblox processes to accounts
# ----------------------------
def match_existing_processes_to_accounts(accounts):
    """Mencocokkan proses Roblox yang sudah berjalan dengan akun berdasarkan cookie"""
    log("Mencari proses Roblox yang sudah berjalan...")
    
    roblox_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in ROBLOX_EXE_NAMES:
                roblox_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    log(f"Found {len(roblox_processes)} Roblox processes running")
    
    matched_count = 0
    for acc in accounts:
        if acc.get("pid") is not None:
            continue
        
        presence = get_presence(acc["cookie"], acc["user_id"])
        
        if presence == 2:  # InGame - kemungkinan besar ada proses yang berjalan
            if roblox_processes:
                roblox_processes.sort(key=lambda p: p.info['create_time'], reverse=True)
                newest_proc = roblox_processes[0]
                acc["pid"] = newest_proc.info['pid']
                matched_count += 1
                log(f"Matched existing process PID {newest_proc.info['pid']} to {acc['username']}")
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

        hwnds = enum_windows()
        pid_to_hwnds = {}
        for hwnd, title in hwnds:
            pid = hwnd_to_pid(hwnd)
            pid_to_hwnds.setdefault(pid, []).append((hwnd, title))

        placed = 0
        for idx, pid in enumerate(pid_ordered_list):
            if pid is None:
                continue
            if pid not in pid_to_hwnds:
                continue
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
        pass

# ----------------------------
# MODIFIED: proc loop dengan delay setelah launch
# ----------------------------
def proc_cycle(accounts, cfg, last_launch_time):
    """
    Fungsi ini berjalan di setiap ProcCheckInterval:
    - Delay diterapkan SETELAH berhasil launch Roblox
    - Support multi-instance untuk akun berbeda
    """
    pid_order = []
    enable_multi_instance = cfg.get("EnableMultiInstance", True)
    launch_delay = float(cfg.get("launchDelay", 15))

    def force_close_account_process(acc, timeout=3.0):
        pid = acc.get("pid")
        if not pid:
            return
        try:
            proc = psutil.Process(pid)
            if proc.is_running():
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=timeout)
                except Exception:
                    pass
                if proc.is_running():
                    try:
                        proc.kill()
                    except Exception:
                        pass
                log(f"{acc['username']}: force closed Roblox PID {pid}")
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            log(f"{acc['username']}: Error force closing PID {pid}: {e}")

    # 1) Deteksi duplicate dengan multi-instance support
    killed_duplicates = detect_and_kill_duplicate_accounts(accounts, enable_multi_instance)
    if killed_duplicates > 0:
        log(f"Killed {killed_duplicates} duplicate account processes")

    # 2) Check RAM and kill heavy processes (only kill)
    if cfg.get("Kill Process > Ram", False):
        ram_threshold = float(cfg.get("Ram Usage (Each Process)", 3))
        killed_count = check_and_kill_high_ram_processes(accounts, ram_threshold)
        if killed_count > 0:
            log(f"Killed {killed_count} processes karena penggunaan RAM tinggi ")
            console.clear()

    # 3) Untuk tiap akun, cek process existence + presence
    for acc in accounts:
        cookie = acc["cookie"]
        uid = acc["user_id"]
        name = acc["username"]
        pid = acc.get("pid")

        pid_running = is_roblox_process_running(pid)
        if not pid_running and pid is not None:
            acc["pid"] = None
            pid = None

        presence = get_presence(cookie, uid)

        # Jika process tidak berjalan DAN presence == Offline (0) -> langsung launch tanpa menunggu threshold
        if not pid and (presence == 0 or presence == -1 or presence == 1):
            now = time.time()

            # cek cooldown per akun
            if now - acc.get("last_launch", 0) < float(cfg.get("accountLaunchCooldown", 30)):
                continue

            if presence == 0 or presence == -1:
                log(f"{name}: akun offline & presence={presence} -> launching")
            else:
                log(f"{name}: PID hilang tapi presence={presence} -> launching")

            # LAUNCH PROCESS - TANPA DELAY SEBELUM
            new_pid, reason = launch_via_protocol(cookie, cfg.get("gameId"), enable_multi_instance)
            
            # APPLY DELAY SETELAH BERHASIL LAUNCH
            if new_pid:
                # Update waktu launch dan status
                last_launch_time[0] = time.time()
                acc["last_launch"] = time.time()
                acc["launching"] = False
                acc["pid"] = new_pid
                acc["online_count"] = 0
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
                
                log(f"{name}: Berhasil launch -> PID {new_pid}")
                
                # TERAPKAN DELAY SETELAH BERHASIL LAUNCH
                apply_post_launch_delay(launch_delay, name)
                
            else:
                log(f"{name}: Gagal launch ({reason})")
                console.clear()
                
        pid_order.append(acc.get("pid"))

    # 4) Handle stale processes
    for acc in accounts:
        pid = acc.get("pid")
        if pid and not is_roblox_process_running(pid):
            presence = get_presence(acc["cookie"], acc["user_id"])
            if presence in (1, 2):
                log(f"{acc['username']}: Detected stale PID {pid} + presence={presence} -> force closing this account only")
                force_close_account_process(acc)
                acc["pid"] = None
                acc["online_count"] = 0
                acc["offline_count"] = 0
                acc["unknown_count"] = 0

    return pid_order

def presence_cycle(accounts, cfg):
    """
    Fungsi ini dijalankan setiap checkInterval:
    - update presence counters (online_count, offline_count, unknown_count)
    - catat info untuk live table
    """
    for acc in accounts:
        cookie = acc["cookie"]
        uid = acc["user_id"]

        presence = get_presence(cookie, uid)

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

def check_and_kill_max_checks(accounts, cfg):
    """
    Cek apakah counter presence (online/offline/unknown) sudah mencapai max.
    Kalau ya, langsung kill via RAM (tanpa restart).
    """
    killed_accounts = []
    max_online = int(cfg.get("maxOnlineChecks", 3))
    max_offline = int(cfg.get("maxOfflineChecks", 3))
    max_unknown = int(cfg.get("maxOnlineChecks", 3))

    for acc in accounts:
        pid = acc.get("pid")
        if pid and is_roblox_process_running(pid):
            if acc["online_count"] >= max_online:
                log(f"{acc['username']}: Online check max tercapai ({acc['online_count']}/{max_online}) -> killing via RAM")
                if kill_ram(pid, acc):
                    killed_accounts.append(acc)
            elif acc["offline_count"] >= max_offline:
                log(f"{acc['username']}: Offline check max tercapai ({acc['offline_count']}/{max_offline}) -> killing via RAM")
                if kill_ram(pid, acc):
                    killed_accounts.append(acc)
            elif acc["unknown_count"] >= max_unknown:
                log(f"{acc['username']}: Unknown check max tercapai ({acc['unknown_count']}/{max_unknown}) -> killing via RAM")
                if kill_ram(pid, acc):
                    killed_accounts.append(acc)
    return len(killed_accounts)

# ----------------------------
# Main logic
# ----------------------------
def main():
    cfg = load_or_create_config()
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
    presence_interval = float(cfg.get("checkInterval", 10))
    proc_interval = float(cfg.get("ProcCheckInterval", 5))

    # Clear screen sebelum memulai live table
    console.clear()

    # live table
    with Live(refresh_per_second=4, console=console, screen=False) as live:
        next_proc = time.time()
        next_presence = time.time()
        pid_order_for_arrange = []

        while True:
            now = time.time()

            if now >= next_proc:
                pid_order_for_arrange = proc_cycle(accounts, cfg, last_launch_time)
                next_proc = now + proc_interval

            if now >= next_presence:
                presence_cycle(accounts, cfg)
                killed_max = check_and_kill_max_checks(accounts, cfg)
                if killed_max > 0:
                    log(f"Killed {killed_max} processes karena mencapai max checks")
                    console.clear()
                next_presence = now + presence_interval

            # Build live table display
            table = Table(title="Roblox Multi-Instance Monitor (Delay After Launch)", show_header=True, header_style="bold magenta")
            table.add_column("No.", justify="right", width=4)
            table.add_column("Username", min_width=15, overflow="fold")
            table.add_column("UserID", width=12)
            table.add_column("Status", width=45)

            for i, acc in enumerate(accounts, start=1):
                cookie = acc["cookie"]
                uid = acc["user_id"]
                name = acc["username"]
                pid = acc.get("pid")

                pid_running = is_roblox_process_running(pid)
                if not pid_running and pid is not None:
                    acc["pid"] = None
                    pid = None

                status_msg = ""
                presence_display = -1
                if acc.get("offline_count", 0) > 0 and acc.get("online_count", 0) == 0 and acc.get("unknown_count", 0) == 0:
                    presence_display = 0
                elif acc.get("online_count", 0) > 0:
                    presence_display = 1
                elif acc.get("unknown_count", 0) > 0:
                    presence_display = -1
                else:
                    presence_display = get_presence(cookie, uid)

                if presence_display == 2:
                    status_msg = "In Game ✅"
                elif presence_display == 1:
                    if pid_running:
                        status_msg = f"Online [{acc['online_count']}/{cfg.get('maxOnlineChecks',3)}]"
                    else:
                        status_msg = f"Online [{acc['online_count']}/{cfg.get('maxOnlineChecks',3)}] (No Process)"
                elif presence_display == 0:
                    if pid_running:
                        status_msg = f"Offline [{acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}] (Process Running)"
                    else:
                        status_msg = f"Offline [{acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}] (No Process)"
                else:
                    if pid_running:
                        status_msg = f"Unknown [{acc['unknown_count']}/{cfg.get('maxOnlineChecks',3)}] (Process Running)"
                    else:
                        status_msg = f"Unknown [{acc['unknown_count']}/{cfg.get('maxOnlineChecks',3)}]"

                username_text = Text(name)
                status_text = Text(status_msg)

                if presence_display == 2:
                    username_text.stylize("bold green")
                    status_text.stylize("bold green")
                elif presence_display == 1:
                    username_text.stylize("bold blue")
                    status_text.stylize("bold blue")
                elif presence_display == 0:
                    username_text.stylize("bold red")
                    status_text.stylize("bold red")
                else:
                    username_text.stylize("bold yellow")
                    status_text.stylize("bold yellow")

                if (presence_display == 1 and acc["online_count"] >= int(cfg.get("maxOnlineChecks", 3)) - 1) or \
                   (presence_display == 0 and acc["offline_count"] >= int(cfg.get("maxOfflineChecks", 3)) - 1) or \
                   (presence_display == -1 and acc["unknown_count"] >= int(cfg.get("maxOnlineChecks", 3)) - 1):
                    status_text.stylize("bold magenta")

                table.add_row(str(i), username_text, str(uid), status_text)

            live.update(table)

            if cfg.get("ArrangeWindows", True):
                arrange_windows_for_pids(pid_order_for_arrange, cfg)

            time.sleep(0.25)


if __name__ == "__main__":
    try:
        log("Starting Roblox Multi-Instance Monitor (Delay After Launch)")
        log("Fitur: - Delay setelah launch - Multi-instance support")
        main()
    except KeyboardInterrupt:
        log("Program dihentikan oleh user")
    except Exception as e:
        log(f"Error: {e}")
