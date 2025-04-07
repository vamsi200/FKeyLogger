import psutil
import os
import time
import sys
import subprocess

HIGHLY_SUS_MODULES = [
    "pynput",       # seen used for Keyboard & mouse monitoring
    "keyboard",     # A Keyboard hook
    "pyxhook",      # Keylogging for X11
    "win32api",     # Windows API for key detection
    "win32gui",     # To capture active windows
    "win32con",     # Windows constants
    "win32clipboard",  # Clipboard logging
]

COULDBE_SUS_MODULES = [    
    "pyautogui",    # could be used for automation or keylogging
    "pygetwindow",  # Detect active windows
    "ctypes",       # Used for low-level system hooks
    "mss",          # Screenshots
    "PIL",          # Image processing for processing screenshots
    "socket",       
    "requests", 
    "smtplib",      # Sending logs via email
    "telegram",     # Sending logs via Telegram bot
    "discord",      # Sending logs via Discord bot
    "base64",       # Obfuscating keystroke logs
    "subprocess",   # Running system commands
    "os.system",    # Running system commands
    "shutil.copy",  # Copying itself for persistence?
]

CURRENT_PID = os.getpid()
DETECTED_PROCESSES = set()
def require_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
        sys.exit(1)

def get_modules_using_py_spy(pid):
    logs = []
    result = subprocess.run(["py-spy", "dump", "--pid", str(pid)], capture_output=True, text=True)
    if result.returncode == 0:
        found = False
        for line in result.stdout.splitlines():
            for mod in HIGHLY_SUS_MODULES:
                if mod in line:
                    logs.append(f"[py-spy] Found module: {mod}")
                    found = True
        return found, logs
    else:
        logs.append(f"[py-spy] Failed to attach to PID {pid}")
        return False, logs

def kill_process(pid):
    p = psutil.Process(pid)
    p.terminate()
    print(" Checking whether the process is still running")
    time.sleep(5)
    if psutil.pid_exists(pid):
        print(" Still running.. trying to kill them again")
        kill_process(pid)
    else:
        print(" Job Done")

def check_python_imports(pid):
    if pid == CURRENT_PID or pid in DETECTED_PROCESSES:
        return None

    detections = {"pid": pid, "path": None, "modules": set()}
    logs = []

    try:
        process = psutil.Process(pid)
        cmdline = process.cmdline()

        if len(cmdline) > 1:
            detections["path"] = os.path.join(process.cwd(), cmdline[1])

        for fd in os.listdir(f"/proc/{pid}/fd"):
            fd_path = os.readlink(f"/proc/{pid}/fd/{fd}")
            for mod in HIGHLY_SUS_MODULES + COULDBE_SUS_MODULES:
                if mod in fd_path:
                    detections["modules"].add(mod)
                    logs.append(f"[fd] Found `{mod}` in file descriptor path")

        with open(f"/proc/{pid}/maps", "r") as maps_file:
            maps_content = maps_file.read()
            for mod in HIGHLY_SUS_MODULES + COULDBE_SUS_MODULES:
                if mod in maps_content:
                    detections["modules"].add(mod)
                    logs.append(f"[maps] Found `{mod}` in /proc/{pid}/maps")

        if detections["path"] and os.path.isfile(detections["path"]):
            with open(detections["path"], 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                for mod in HIGHLY_SUS_MODULES + COULDBE_SUS_MODULES:
                    if mod in content:
                        detections["modules"].add(mod)
                        logs.append(f"[code] Found `{mod}` in script source code")

        if detections["modules"]:
            DETECTED_PROCESSES.add(pid)
            return detections, logs
        return None

    except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess, PermissionError):
        return None  

def calculate_confidence(pid, detection_result, static_logs):
    score = 0
    high_sev_logs = []
    low_sev_logs = []

    if detection_result["modules"]:
        score += 1
    for log in static_logs:
        for mod in HIGHLY_SUS_MODULES:
            if mod in log:
                high_sev_logs.append(log)
                break
        else:
            low_sev_logs.append(log)

    spy_flag, spy_logs = get_modules_using_py_spy(pid)
    if spy_flag:
        score += 1
    for log in spy_logs:
        for mod in HIGHLY_SUS_MODULES:
            if mod in log:
                high_sev_logs.append(log)
                break
        else:
            low_sev_logs.append(log)

    if score >= 2:
        severity = "HIGH"
    elif score == 1:
        severity = "MEDIUM"
    else:
        severity = "UNKNOWN"

    return severity, high_sev_logs, low_sev_logs

def monitor_python_processes():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            # we are only checking python files.. what about others bud?
            if proc.info['name'] and 'python' in proc.info['name'].lower():
                result = check_python_imports(proc.info['pid'])
                if result:
                    detection, logs = result
                    severity, high_sev_logs, low_sev_logs = calculate_confidence(detection['pid'], detection, logs)

                    if severity != "HIGH" and not high_sev_logs:
                        continue

                    print("\n[ALERT] Suspicious Python process detected!")
                    print(f"├─ PID      : {detection['pid']}")
                    print(f"├─ Severity : {severity}")
                    print(f"├─ Path     : {detection['path']}")
                    print(f"└─ Evidence:")

                    if high_sev_logs:
                        print(" Highly Suspicious:")
                        for log in high_sev_logs:
                            print(f"      • {log}")
                    if low_sev_logs:
                        print(" Other Suspicious:")
                        for log in low_sev_logs:
                            print(f"      • {log}")
                    if not high_sev_logs and not low_sev_logs:
                        print("    • No extra evidence found.")

                    print()
                    choice = input(" Master, do we kill them? (y/n): ")
                    if choice.lower() == "y":
                        kill_process(detection['pid'])

        time.sleep(5)


if __name__ == "__main__":
    require_root()
    print("We are running.. Press CTRL+C to stop.")
    monitor_python_processes()
