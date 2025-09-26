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
from rich.panel import Panel
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
    "checkInterval": 60,
    "presenceCheckInterval": 30,
    "processCheckInterval": 10,
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

# Global variables untuk log management
log_messages = []
max_log_lines = 5
last_log_update = 0
log_lock = threading.Lock()

# Global locks untuk prevent race condition
process_lock = threading.Lock()
restart_lock = threading.Lock()
presence_lock = threading.Lock()

# ----------------------------
# Helpers / Logging - DIPERBAIKI
# ----------------------------
def nowstr():
    return datetime.now().strftime("%H:%M:%S")

def add_log(msg):
    """Tambahkan log ke buffer dengan batasan jumlah line"""
    global log_messages, last_log_update
    with log_lock:
        line = f"[{nowstr()}] {msg}"
        log_messages.append(line)
        # Batasi jumlah log lines
        if len(log_messages) > max_log_lines:
            log_messages = log_messages[-max_log_lines:]
        last_log_update = time.time()

def clear_logs():
    """Hapus semua logs"""
    global log_messages
    with log_lock:
        log_messages = []

def get_log_display():
    """Dapatkan log untuk ditampilkan di panel"""
    with log_lock:
        return "\n".join(log_messages) if log_messages else "Tidak ada aktivitas terkini..."

def load_or_create_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            add_log(f"Error load config.json: {e}")
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
            add_log("config.json: menambahkan field default baru")
        except:
            pass
    return cfg

def ensure_cookie_file():
    if not os.path.exists(COOKIE_FILE):
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write("")  # kosong
        add_log("cookies.txt dibuat (kosong). Isi 1 cookie per baris lalu jalankan ulang.")
        return False
    return True

def load_cookies():
    if not os.path.exists(COOKIE_FILE):
        return []
    with open(COOKIE_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines

# ----------------------------
# Windows / HWND helpers
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
                    add_log(f"{acc['username']} menggunakan {ram_usage}GB RAM (> {ram_threshold_gb}GB) -> killing process")
                    if kill_pid(pid):
                        acc["pid"] = None
                        killed_accounts.append(acc)
                        add_log(f"{acc['username']}: Process killed karena penggunaan RAM tinggi")
                    else:
                        add_log(f"{acc['username']}: Gagal kill process karena RAM tinggi")
        
        if killed_accounts:
            add_log(f"Restarting {len(killed_accounts)} accounts yang di-kill karena RAM tinggi")
            
            for i, acc in enumerate(killed_accounts):
                if i > 0:
                    time.sleep(launch_delay)
                
                add_log(f"Restarting {acc['username']}...")
                new_pid, reason = launch_via_protocol(acc["cookie"], cfg_game_id)
                
                if new_pid:
                    acc["pid"] = new_pid
                    add_log(f"{acc['username']}: Restarted dengan PID {new_pid}")
                else:
                    add_log(f"{acc['username']}: Restart failed ({reason})")
        
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
                return int(pres)
        except Exception as e:
            pass
        return -1

def get_auth_ticket(cookie):
    try:
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
        return dict(res)

def find_new_roblox_pid(before_pids, timeout=20):
    """Tunggu sampai ada pid baru yang bukan di before_pids. Return pid or None."""
    start = time.time()
    while time.time() - start < timeout:
        cur = list_current_roblox_pids()
        new = [pid for pid in cur.keys() if pid not in before_pids]
        if new:
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
    if pid is None:
        return False
    try:
        return psutil.pid_exists(pid)
    except:
        return False

def is_roblox_process_running(pid):
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
    with process_lock:
        ticket = get_auth_ticket(cookie)
        if not ticket:
            return None, "no-ticket"
        protocol = (
            f"roblox-player:1+launchmode:play+gameinfo:{ticket}"
            f"+launchtime:{int(time.time()*1000)}"
            f"+placelauncherurl:https%3A%2F%2Fwww.roblox.com%2FGame%2FPlaceLauncher.ashx%3Frequest%3DRequestGame%26placeId%3D{cfg_game_id}"
        )
        before = list_current_roblox_pids()
        try:
            subprocess.Popen(["cmd", "/c", "start", "", protocol], shell=True)
        except Exception as e:
            return None, "start-failed"
        new_pid = find_new_roblox_pid(before, timeout=25)
        if new_pid:
            return new_pid, "ok"
        return None, "no-new-pid"

# ----------------------------
# Duplicate Account Detection
# ----------------------------
def detect_and_kill_duplicate_accounts(accounts):
    with process_lock:
        killed_count = 0
        username_groups = {}
        
        for acc in accounts:
            username = acc["username"]
            if username not in username_groups:
                username_groups[username] = []
            username_groups[username].append(acc)
        
        for username, acc_list in username_groups.items():
            if len(acc_list) > 1:
                add_log(f"Detected duplicate account: {username} ({len(acc_list)} instances)")
                
                active_accounts = [acc for acc in acc_list if acc.get("pid") and is_roblox_process_running(acc["pid"])]
                
                if len(active_accounts) > 1:
                    active_accounts.sort(key=lambda x: psutil.Process(x["pid"]).create_time(), reverse=True)
                    
                    keep_acc = active_accounts[0]
                    for acc in active_accounts[1:]:
                        pid = acc.get("pid")
                        if pid and is_roblox_process_running(pid):
                            if kill_pid(pid):
                                add_log(f"Killed duplicate process PID {pid} for {username}")
                                killed_count += 1
                                acc["pid"] = None
                                acc["online_count"] = 0
                                acc["offline_count"] = 0
                                acc["unknown_count"] = 0
                            else:
                                add_log(f"Failed to kill duplicate process PID {pid} for {username}")
        
        return killed_count

# ----------------------------
# Match existing Roblox processes to accounts
# ----------------------------
def match_existing_processes_to_accounts(accounts):
    with process_lock:
        add_log("Mencari proses Roblox yang sudah berjalan...")
        
        roblox_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
            try:
                if proc.info['name'] and proc.info['name'].lower() in ROBLOX_EXE_NAMES:
                    roblox_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        add_log(f"Found {len(roblox_processes)} Roblox processes running")
        
        matched_count = 0
        for acc in accounts:
            if acc.get("pid") is not None:
                continue
                
            presence = get_presence(acc["cookie"], acc["user_id"])
            
            if presence == 2 and roblox_processes:
                roblox_processes.sort(key=lambda p: p.info['create_time'], reverse=True)
                newest_proc = roblox_processes[0]
                acc["pid"] = newest_proc.info['pid']
                matched_count += 1
                add_log(f"Matched existing process PID {newest_proc.info['pid']} to {acc['username']}")
                roblox_processes.pop(0)
        
        add_log(f"Berhasil mencocokkan {matched_count} proses yang sudah berjalan")
        return matched_count

# ----------------------------
# Arrange windows by pid mapping
# ----------------------------
def arrange_windows_for_pids(pid_ordered_list, config):
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
            if pid is None or pid not in pid_to_hwnds:
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
# Presence Checking Function
# ----------------------------
def check_presence_for_accounts(accounts, config):
    with presence_lock:
        for acc in accounts:
            presence = get_presence(acc["cookie"], acc["user_id"])
            acc["last_presence"] = presence
            
            if presence == 0:
                acc["offline_count"] += 1
                acc["online_count"] = 0
                acc["unknown_count"] = 0
            elif presence == 1:
                acc["online_count"] += 1
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
            elif presence == 2:
                acc["online_count"] = 0
                acc["offline_count"] = 0
                acc["unknown_count"] = 0
            else:
                acc["unknown_count"] += 1
                acc["online_count"] = 0
                acc["offline_count"] = 0

# ----------------------------
# Process Checking Function
# ----------------------------
def check_processes_for_accounts(accounts):
    with process_lock:
        for acc in accounts:
            pid = acc.get("pid")
            if pid and not is_roblox_process_running(pid):
                acc["pid"] = None
                acc["offline_count"] += 1

# ----------------------------
# Auto Restart Logic
# ----------------------------
def check_and_restart_offline_accounts(accounts, config, last_launch_time, launch_delay):
    with restart_lock:
        restart_count = 0
        
        for acc in accounts:
            pid = acc.get("pid")
            cookie = acc["cookie"]
            user_id = acc["user_id"]
            username = acc["username"]
            
            process_running = is_roblox_process_running(pid)
            presence = acc.get("last_presence", -1)
            
            needs_restart = False
            reason = ""
            
            if presence == 2:
                continue
            
            if not process_running:
                needs_restart = True
                reason = "Process tidak berjalan (Offline)"
                
                if acc["offline_count"] >= int(config.get("maxOfflineChecks", 3)):
                    needs_restart = True
                    reason = f"Offline count {acc['offline_count']} mencapai threshold"
            
            elif process_running and presence == 1:
                if acc["online_count"] >= int(config.get("maxOnlineChecks", 3)):
                    needs_restart = True
                    reason = f"Online count {acc['online_count']} mencapai threshold"
            
            elif process_running and presence == 0:
                if acc["offline_count"] >= int(config.get("maxOfflineChecks", 3)):
                    needs_restart = True
                    reason = f"Offline count {acc['offline_count']} mencapai threshold"
            
            elif process_running and presence == -1:
                if acc["unknown_count"] >= int(config.get("maxOnlineChecks", 3)):
                    needs_restart = True
                    reason = f"Unknown count {acc['unknown_count']} mencapai threshold"
            
            if needs_restart and config.get("AutoRestart", True):
                current_time = time.time()
                time_since_last_launch = current_time - last_launch_time[0]
                
                if time_since_last_launch < launch_delay:
                    wait_time = launch_delay - time_since_last_launch
                    time.sleep(wait_time)
                
                if pid and is_process_running(pid):
                    add_log(f"{username}: Killing process PID {pid} ({reason})")
                    kill_pid(pid)
                    time.sleep(2)
                
                add_log(f"{username}: {reason} -> restarting...")
                new_pid, launch_reason = launch_via_protocol(cookie, config.get("gameId"))
                last_launch_time[0] = time.time()
                
                if new_pid:
                    acc["pid"] = new_pid
                    acc["online_count"] = 0
                    acc["offline_count"] = 0
                    acc["unknown_count"] = 0
                    add_log(f"{username}: Berhasil restart dengan PID {new_pid}")
                    restart_count += 1
                else:
                    add_log(f"{username}: Gagal restart ({launch_reason})")
                
                time.sleep(float(config.get("RestartDelay", 5)))
        
        return restart_count

# ----------------------------
# Main logic dengan display terintegrasi
# ----------------------------
def main():
    cfg = load_or_create_config()
    
    if not ensure_cookie_file():
        return

    cookies = load_cookies()
    if not cookies:
        add_log("cookie.txt kosong. Isi 1 cookie per baris.")
        return

    # Load accounts
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
            add_log(f"Loaded {uname} ({uid})")
        else:
            add_log("Cookie invalid / expired (skip one line)")

    if not accounts:
        add_log("Tidak ada akun valid.")
        return

    if cfg.get("SortAccounts", True):
        accounts.sort(key=lambda a: a["username"].lower())

    total_instances = int(cfg.get("TotalInstance", 10))
    if total_instances < len(accounts):
        accounts = accounts[:total_instances]

    # Match existing processes
    match_existing_processes_to_accounts(accounts)

    # Variables untuk timing
    last_launch_time = [time.time()]
    last_presence_check = time.time()
    last_process_check = time.time()
    last_duplicate_check = time.time()
    last_ram_check = time.time()
    last_log_clear = time.time()

    # Get intervals from config
    check_interval = float(cfg.get("checkInterval", 60))
    presence_interval = float(cfg.get("presenceCheckInterval", 30))
    process_interval = float(cfg.get("processCheckInterval", 10))
    duplicate_interval = 60
    ram_interval = 30
    log_clear_interval = 300  # Clear logs every 5 minutes

    console.clear()

    with Live(refresh_per_second=4, console=console, screen=True) as live:
        while True:
            current_time = time.time()
            
            # Clear old logs periodically
            if current_time - last_log_clear >= log_clear_interval:
                clear_logs()
                add_log("Logs cleared automatically")
                last_log_clear = current_time
            
            # Check for duplicate accounts
            if current_time - last_duplicate_check >= duplicate_interval:
                killed_duplicates = detect_and_kill_duplicate_accounts(accounts)
                if killed_duplicates > 0:
                    add_log(f"Killed {killed_duplicates} duplicate account processes")
                last_duplicate_check = current_time
            
            # Check RAM usage
            if current_time - last_ram_check >= ram_interval and cfg.get("Kill Process > Ram", False):
                ram_threshold = float(cfg.get("Ram Usage (Each Process)", 3))
                killed_count = check_and_kill_high_ram_processes(accounts, ram_threshold, 
                                                               float(cfg.get("launchDelay", 15)), 
                                                               cfg.get("gameId"))
                if killed_count > 0:
                    add_log(f"Restarted {killed_count} processes karena penggunaan RAM tinggi")
                last_ram_check = current_time
            
            # Check presence
            if current_time - last_presence_check >= presence_interval:
                check_presence_for_accounts(accounts, cfg)
                last_presence_check = current_time
            
            # Check processes
            if current_time - last_process_check >= process_interval:
                check_processes_for_accounts(accounts)
                last_process_check = current_time
            
            # Auto restart logic
            if cfg.get("AutoRestart", True):
                restart_count = check_and_restart_offline_accounts(accounts, cfg, last_launch_time, 
                                                                 float(cfg.get("launchDelay", 15)))
                if restart_count > 0:
                    add_log(f"Auto-restarted {restart_count} accounts sesuai threshold config")

            # Build display
            pid_order = []
            
            # Main table
            main_table = Table(title="Roblox Auto Rejoin Monitor - Live Status", 
                             show_header=True, header_style="bold magenta")
            main_table.add_column("No.", justify="right", width=4)
            main_table.add_column("Username", min_width=15, overflow="fold")
            main_table.add_column("UserID", width=12)
            main_table.add_column("Status", width=45)
            main_table.add_column("PID", width=8)
            main_table.add_column("RAM (GB)", width=8)

            for i, acc in enumerate(accounts, start=1):
                name = acc["username"]
                uid = acc["user_id"]
                pid = acc.get("pid")
                presence = acc.get("last_presence", -1)
                
                pid_running = is_roblox_process_running(pid)
                ram_usage = get_process_ram_usage(pid) if pid_running else 0
                
                # Status message
                status_msg = ""
                if presence == 2:
                    status_msg = "In Game ✅"
                elif presence == 1:
                    status_msg = f"Online [{acc['online_count']}/{cfg.get('maxOnlineChecks',3)}]"
                elif presence == 0:
                    status_msg = f"Offline [{acc['offline_count']}/{cfg.get('maxOfflineChecks',3)}]"
                else:
                    status_msg = f"Unknown [{acc['unknown_count']}/{cfg.get('maxOnlineChecks',3)}]"

                pid_order.append(pid)

                # Color coding
                username_text = Text(name)
                status_text = Text(status_msg)
                
                if presence == 2:
                    username_text.stylize("bold green")
                    status_text.stylize("bold green")
                elif presence == 1:
                    username_text.stylize("bold blue")
                    status_text.stylize("bold blue")
                elif presence == 0:
                    username_text.stylize("bold red")
                    status_text.stylize("bold red")
                else:
                    username_text.stylize("bold yellow")
                    status_text.stylize("bold yellow")

                main_table.add_row(
                    str(i), 
                    username_text, 
                    str(uid), 
                    status_text,
                    str(pid) if pid else "N/A",
                    f"{ram_usage:.2f}" if ram_usage > 0 else "0.00"
                )

            # Log panel
            log_panel = Panel(
                get_log_display(),
                title="[bold cyan]Aktivitas Terkini[/bold cyan]",
                border_style="blue",
                width=100
            )

            # Combine table and log panel
            display_content = f"{main_table}\n\n{log_panel}"
            live.update(display_content)

            # Arrange windows if enabled
            if cfg.get("ArrangeWindows", True):
                arrange_windows_for_pids(pid_order, cfg)

            # Wait for next cycle
            time.sleep(check_interval)

if __name__ == "__main__":
    try:
        add_log("Starting Roblox Auto Rejoin Monitor (Live Display)")
        add_log("Fitur: Log otomatis terhapus, display real-time")
        main()
    except KeyboardInterrupt:
        add_log("Program dihentikan oleh user")
    except Exception as e:
        add_log(f"Error: {e}")
