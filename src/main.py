import psutil
import os
import time
import sys

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

def check_dynamic_imports(pid):
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            for module in sys.modules:
                if module in HIGHLY_SUS_MODULES or module in COULDBE_SUS_MODULES:
                    print(f"`{module}` dynamically imported in PID {pid}")
    except Exception as e:
        print(f"Error: {e}")

def check_python_imports(pid):
    if pid == CURRENT_PID or pid in DETECTED_PROCESSES:
        return None  

    detections = {"pid": pid, "path": None, "modules": set()}

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

        with open(f"/proc/{pid}/maps", "r") as maps_file:
            maps_content = maps_file.read()
            for mod in HIGHLY_SUS_MODULES + COULDBE_SUS_MODULES:
                if mod in maps_content:
                    detections["modules"].add(mod)

        if detections["path"] and os.path.isfile(detections["path"]):
            with open(detections["path"], 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                for mod in HIGHLY_SUS_MODULES + COULDBE_SUS_MODULES:
                    if mod in content:
                        detections["modules"].add(mod)

        if detections["modules"]:
            DETECTED_PROCESSES.add(pid)
            check_dynamic_imports(pid)
            return detections
        return None

    except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess, PermissionError):
        return None  

def monitor_python_processes():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and 'python' in proc.info['name'].lower():
                detection = check_python_imports(proc.info['pid'])
                if detection:
                    print("\n---------------------------")
                    print(f"Sire!! We found someone - PID: {detection['pid']}")
                    print(f"Path: {detection['path']}")
                    print(f"Modules Detected: {', '.join(detection['modules'])}")
                    print("---------------------------")
        time.sleep(5)

if __name__ == "__main__":
    print("We are running.. Press CTRL+C to stop.")
    monitor_python_processes()
