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
    "checkInterval": 10,
    "maxOnlineChecks": 3,
    "maxOfflineChecks": 3,
    "launchDelay": 15,
    "TotalInstance": 10,
    "WindowsPerRow": 3,
    "FixedSize": "530x400",
    "SortAccounts": True,
    "ArrangeWindows": True,
    "Kill Process > Ram": True,
    "Ram Usage (Each Process)": 3
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

def check_and_kill_high_ram_processes(accounts, ram_threshold_gb, launch_delay, cfg_game_id):
    """Memeriksa dan mengkill process yang menggunakan RAM melebihi threshold, lalu restart"""
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

def kill_pid(pid):
    try:
        if pid and psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.kill()
            return True
    except Exception:
        pass
    return False

# ----------------------------
# Launch / Assign PID
# ----------------------------
def launch_via_protocol(cookie, cfg_game_id):
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
# Main logic
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

    # Variables untuk mengontrol delay antar peluncuran
    last_launch_time = 0
    launch_delay = float(cfg.get("launchDelay", 15))

    # Flag untuk menandai apakah ini adalah iterasi pertama
    first_iteration = True

    # live table
    with Live(refresh_per_second=4, console=console, screen=True) as live:
        while True:
            # Check RAM usage and kill processes if enabled
            if cfg.get("Kill Process > Ram", False):
                ram_threshold = float(cfg.get("Ram Usage (Each Process)", 3))
                killed_count = check_and_kill_high_ram_processes(accounts, ram_threshold, launch_delay, cfg.get("gameId"))
                if killed_count > 0 and first_iteration:
                    log(f"Restarted {killed_count} processes karena penggunaan RAM tinggi")

            # For arranging windows later, collect pid order list
            pid_order = []

            table = Table(title="Roblox Auto Rejoin Monitor", expand=True)
            table.add_column("No.", justify="right", width=3)
            table.add_column("Username", overflow="fold")
            table.add_column("UserID", width=12)
            table.add_column("Status", width=20)

            # iterate accounts and update
            for i, acc in enumerate(accounts, start=1):
                cookie = acc["cookie"]
                uid = acc["user_id"]
                name = acc["username"]
                pid = acc.get("pid")

                presence = get_presence(cookie, uid)

                # normalize presence string
                PRES_MAP = { -1: "Unknown", 0: "Offline", 1: "Online", 2: "InGame", 3: "InStudio" }
                pres_str = PRES_MAP.get(presence, "Unknown")

                # check if pid still exists and is Roblox process
                pid_running = False
                if pid and psutil.pid_exists(pid):
                    try:
                        p = psutil.Process(pid)
                        if p.name().lower() in ROBLOX_EXE_NAMES:
                            pid_running = True
                        else:
                            pid_running = False
                    except Exception:
                        pid_running = False
                else:
                    pid_running = False
                    acc["pid"] = None  # reset if pid died

                # Logic:
                status_msg = ""
                launched_pid = None
                needs_launch = False

                if presence == 0:  # Offline
                    if pid_running:
                        acc["offline_count"] += 1
                        acc["online_count"] = 0
                        status_msg = f"Offline (proc running) {acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}"
                        if acc["offline_count"] >= int(cfg.get("maxOfflineChecks", 3)):
                            if first_iteration:
                                log(f"{name}: Offline {acc['offline_count']}x with process {pid} running -> restarting")
                            killed = kill_pid(pid)
                            if killed and first_iteration:
                                log(f"{name}: killed pid {pid}")
                            acc["pid"] = None
                            time.sleep(1)
                            needs_launch = True
                    else:
                        acc["offline_count"] = 0
                        acc["online_count"] = 0
                        status_msg = "Offline -> launching"
                        if first_iteration:
                            log(f"{name} - Offline (no pid) -> launching")
                        needs_launch = True

                elif presence == 1:  # Online
                    acc["online_count"] += 1
                    acc["offline_count"] = 0
                    status_msg = f"Online {acc['online_count']}/{cfg.get('maxOnlineChecks',3)}"
                    if acc["online_count"] >= int(cfg.get("maxOnlineChecks", 3)):
                        if first_iteration:
                            log(f"{name}: Online stuck {acc['online_count']}x -> restarting")
                        if pid_running and pid:
                            if kill_pid(pid) and first_iteration:
                                log(f"{name}: killed pid {pid} before relaunch")
                            acc["pid"] = None
                            time.sleep(1)
                        needs_launch = True

                elif presence == 2:  # InGame
                    acc["online_count"] = 0
                    acc["offline_count"] = 0
                    status_msg = "In Game"

                else:
                    status_msg = "Unknown"

                # Handle launching with proper delay
                if needs_launch:
                    current_time = time.time()
                    time_since_last_launch = current_time - last_launch_time
                    
                    if time_since_last_launch < launch_delay:
                        wait_time = launch_delay - time_since_last_launch
                        time.sleep(wait_time)
                    
                    new_pid, reason = launch_via_protocol(cookie, cfg.get("gameId"))
                    last_launch_time = time.time()
                    
                    if new_pid:
                        acc["pid"] = new_pid
                        status_msg = f"Launched PID {new_pid}"
                        if first_iteration:
                            log(f"{name}: Launched new PID {new_pid}")
                    else:
                        status_msg = f"Launch failed ({reason})"
                        if first_iteration:
                            log(f"{name}: Launch failed ({reason})")
                    
                    acc["online_count"] = 0
                    acc["offline_count"] = 0

                # append pid to pid_order for arranging windows (None if no pid)
                pid_order.append(acc.get("pid"))

                # Buat teks dengan warna yang sesuai
                username_text = Text(name)
                if presence == 2:  # InGame - hijau
                    username_text.stylize("bold green")
                elif presence == 1:  # Online - biru
                    username_text.stylize("bold blue")
                elif presence == 0:  # Offline - merah
                    username_text.stylize("bold red")
                else:  # Unknown - default
                    username_text.stylize("bold yellow")

                status_text = Text(status_msg)
                if "In Game" in status_msg:
                    status_text.stylize("bold green")
                elif "Online" in status_msg:
                    status_text.stylize("bold blue")
                elif "Offline" in status_msg:
                    status_text.stylize("bold red")
                else:
                    status_text.stylize("bold yellow")

                table.add_row(str(i), username_text, str(uid), status_text)

            # Update live table
            live.update(table)

            # Set flag first_iteration menjadi False setelah iterasi pertama selesai
            if first_iteration:
                first_iteration = False
                # Clear screen setelah iterasi pertama selesai
                console.clear()

            # arrange windows if enabled
            if cfg.get("ArrangeWindows", True):
                arrange_windows_for_pids(pid_order, cfg)

            # Wait for next cycle
            time.sleep(float(cfg.get("checkInterval", 10)))

if __name__ == "__main__":
    log("Starting Roblox Auto Rejoin Monitor (cookies.txt mode)")

    main()
