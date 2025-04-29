import select
import psutil
import os
import ipaddress
import time
import sys
import subprocess
from inotify_simple import INotify, flags
from collections import defaultdict


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

white_list_paths = [
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/",
    "/snap/",
    "/var/lib/snapd/",
]
white_list_ports = [8080, 443, 22]
current_user = os.getlogin()
suspicious_paths = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/",
    "/run/user/",
    "/run/lock/",
    "/run/systemd/",
    f"home/{current_user}/.cache/",
    f"home/{current_user}/.local/",
    f"home/{current_user}/.config/",
    f"home/{current_user}/.mozilla/",
    f"home/{current_user}/.mozilla/firefox/",
    f"home/{current_user}/.gnupg/",
    f"home/{current_user}/.vscode/",
    f"home/{current_user}/.Xauthority",
    f"home/{current_user}/.ICEauthority",
    f"home/{current_user}/.ssh/",
    f"home/{current_user}/.dbus/",
    f"home/{current_user}/.gvfs/",
    "/usr/lib/tmpfiles.d/",
    "/lib/modules/",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/profile.d/"
]

CURRENT_PID = os.getpid()
DETECTED_PROCESSES = set()
def require_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
        sys.exit(1)

def load_sus_libraries():
    file_path = "libraries.txt"
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


# this only works if a process reads inputs directly from the events
def get_active_input_devices(timeout=10):
    base_path = "/dev/input/by-id/"
    inotify = INotify()
    watch_descriptors = {}

    for f_name in os.listdir(base_path):
        f_path = os.path.join(base_path, f_name)
        try:
            link = os.path.realpath(f_path)
            wd = inotify.add_watch(link, flags.ACCESS | flags.MODIFY | flags.OPEN)
            watch_descriptors[wd] = link
        except Exception as e:
            print(f"Error reading {f_path}: {e}")
    active_devices = set()
    rlist, _, _ = select.select([inotify.fileno()], [], [], timeout)

    if rlist:
        for event in inotify.read():
            if event.wd in watch_descriptors:
                active_devices.add(watch_descriptors[event.wd])
    else:
        print("No input activity detected. Increase the Timeout if needed")

    return list(active_devices)

def get_process_using_input_device():
    event_paths = get_active_input_devices()
    all_matches = []

    for path in event_paths:
        event_real = os.path.realpath(path)
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            pid = proc.info['pid']
            fd_dir = f"/proc/{pid}/fd"
            if not os.path.isdir(fd_dir):
                continue
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(fd_path)
                        target_real = os.path.realpath(target)
                        if target_real == event_real:
                            all_matches.append(pid)
                            break
                    except Exception:
                        continue
            except Exception:
                continue

    return all_matches

# Need to change the unnecessary printing and the slight changes
def check_x11_connection(pid):
    confidence = 0
    access_rate = 0
    x11_inodes = set()
    try:
        fds = os.listdir(f'/proc/{pid}/fd/')
        for fd in fds:
            try:
                link = os.readlink(f'/proc/{pid}/fd/{fd}')
                if link.startswith('socket:['):
                    inode = link.split('[')[1].split(']')[0]
                    x11_inodes.add(inode)
            except Exception:
                continue

        output = subprocess.run(['ss', '-xp'], capture_output=True, text=True)
        for line in output.stdout.splitlines():
            if '/tmp/.X11-unix/X0' in line:
                for inode in x11_inodes:
                    if inode in line:
                        confidence = 1
                        access_rate+=1

        p = psutil.Process(pid)
        env = p.environ()
        xauth = env.get("XAUTHORITY")
        display = env.get("DISPLAY")

        if xauth and xauth.strip():
            confidence += 1
        if display and display.strip():
            confidence += 1

        # modify below?
        for line in subprocess.check_output(['lsof', '-p', str(pid)], stderr=subprocess.DEVNULL).decode().splitlines():
            if 'libX11.so' in line or 'libXt.so' in line:
                confidence += 1
    except Exception as e:
        print(f"[x] Error analyzing PID {pid}: {e}")
        return 0

    return confidence,access_rate

# this just returns all the prcoesses that met the condition
# still we need to differentiate between a legitimate and a suspicious processes
#todo : maybe in future, change the logic to not use process_iter mutliple times.. just one for all
def check_input_access_frequency(threshold, timeout):
    access_counts = defaultdict(int)
    printed_pids = set()
    x11_confidence = {}
    suspicious_processes = []

    start_time = time.time()

    while time.time() - start_time < timeout:
        pids = get_process_using_input_device()

        for proc in psutil.process_iter(['pid']):
            pid = proc.pid
            try:
                if pid not in x11_confidence:
                    x11_conf, access_rate = check_x11_connection(pid)
                    x11_confidence[pid] = x11_conf

                    if x11_conf >= threshold:
                        suspicious_processes.append((pid, 'x11', x11_conf, access_rate))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for pid in pids:
            access_counts[pid] += 1
            try:
                if pid in printed_pids:
                    continue

                proc = psutil.Process(pid)
                evdev_count = access_counts[pid]
                if evdev_count:
                    suspicious_processes.append((pid, 'evdev', evdev_count))

                printed_pids.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    return suspicious_processes

# todo: this will be most important one, will be added to as many functions as possible
# if a process is a gui/background process - keyloggers tend to be in background
# if a process is using symlinks to mask itself as a legitimate process by using '/usr/bin/'
# or some paths that are legitimate that we may ignore.
# if a process is using High cpu or memory usage - I doubt this would be necessary
# if a process opening excessive fd's
# if a process is running as root(except ours)
def verify_process(p):
    try:
        sus_score = 0

        name = p.name()
        user = p.username()
        fd = p.num_fds()
        uptime = time.time() - p.create_time()
        terminal = p.terminal()
        cwd = p.cwd()
        full_path = ""

        if name.startswith('[') and name.endswith(']'):
            return False

        if cwd == '/':
            full_path = p.exe()
        elif len(name) > 1:
            full_path =  os.path.join(cwd, name[1]) 
        else:
            full_path = ""
        
        print(full_path)
        known_safe_names = {
            "systemd", "dbus-daemon", "NetworkManager", "sshd", "cron",
            "bash", "zsh", "gnome-shell", "Xorg", "Xwayland"
        }

        if name in known_safe_names:
            return False

        safe_prefixes = ("/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/")
        if full_path.startswith(safe_prefixes):
            return False

        if full_path in white_list_paths:
            return False

        if not terminal:
            sus_score += 1

        if cwd not in white_list_paths:
            sus_score += 1

        if cwd.startswith('/tmp') or cwd.startswith('/dev'):
            sus_score += 2

        if os.path.islink(full_path):
            sus_score += 1

        if fd > 256:
            sus_score += 1

        if uptime < 300 and not terminal:
            sus_score += 1  # recently spawned background process

        if user == 'root' and p.pid != os.getpid():
            sus_score += 1

        return sus_score >= 1

    except Exception:
        return False

def find_suspicious_processes():
    suspicious_pids = []
    c=0
    for p in psutil.process_iter(['pid']):
        c+=1
        if verify_process(p):
            suspicious_pids.append(p.pid)
    print(f"Total = {c}")
    counter = 0
    for _ in suspicious_pids:
        counter +=1
    print(f"After = {counter}")
    return suspicious_pids
    

#todo:
# if a process is opening sudden connections
# if a process is doing any port-forwarding -> no idea how to approach this
def check_network_activity(input_pid, timeout):
    conn_count = defaultdict(int)
    c_time = time.time()

    while time.time() - c_time < timeout:
        try:
            conn = psutil.net_connections(kind='all')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print("Error: Failed to get the process details")
            return
        for i in conn:
            if i.status == 'ESTABLISHED' and i.raddr and i.pid:
                conn_count[i.pid] += 1
        time.sleep(1)
    conn = psutil.net_connections(kind='all')
    # todo : verify_process - be added here to do furthur checks
    for i in conn:
        if input_pid == i.pid and i.status != None:
            for pid, count in conn_count.items():
                if pid == i.pid and i.raddr:
                    ip = i.raddr.ip
                    # not a very effective way - since a process could still
                    # mask as from white listed ports or paths
                    if not ipaddress.ip_address(ip).is_private and i.raddr.port not in white_list_ports:
                        try:
                            p = psutil.Process(pid)
                            process_name = p.name()
                            path = p.exe()
                            if any(path.startswith(sus_path) for sus_path in suspicious_paths):
                                print(f"Process - {process_name}, connecting to foreign address - {ip}")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            print("Error: Failed to get the process details")

# goal isn't to check every process.. we narrow down to a one or two processes that we find suspicious and then use this
def check_file_activity(pid, timeout):
    processed = []
    p_time = time.time()
    inotify = INotify()
    watch_flags = flags.CLOSE_WRITE | flags.MODIFY | flags.CREATE | flags.OPEN

    while time.time() - p_time < timeout:
        try:
            p = psutil.Process(pid)
            p_name = p.name()

            for files in p.open_files():
                if files.path not in processed:
                    inotify.add_watch(files.path, watch_flags)
                    for _ in inotify.read():
                        processed.append(files.path)
                        # todo fix: Right now it'll always point to the last file from the outer loop
                        print(f"{p_name} with pid [{pid}] actively writing to - {files.path}")
                        return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print("Error: Failed to get the process details")
            return
        time.sleep(0.0) # you remove, cpu boom

# To check other processes, not only python ones
def check_loaded_libs(pid):
    pass



def get_modules_using_py_spy(pid, lib):
    logs = []
    result = subprocess.run(["py-spy", "dump", "--pid", str(pid)], capture_output=True, text=True)
    if result.returncode == 0:
        found = False
        for line in result.stdout.splitlines():
            for mod in lib:
                if mod in line:
                    logs.append(f"{mod}")
                    found = True
        return found, logs
    else:
        logs.append(f"[py-spy] Failed to attach to PID {pid}")
        return False, logs

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=5)
        print(" Job Done.")
    except psutil.NoSuchProcess:
        print(f"No such process with PID {pid}.")
    except psutil.TimeoutExpired:
        p.kill()
        print(f"Timeout: Process {pid} did not terminate within the timeout.")
        print(f"Process {pid} forcefully terminated.")
    except psutil.AccessDenied:
        print(f"Access denied to kill {pid}.")

# Below 4 functions should only be invoked once we narrow down processes?
    found_libs = []
    try:
        with open(f"/proc/{pid}/maps", "r") as maps_file:
            maps_content = maps_file.read()
            for mod in lib:
                if mod in maps_content and mod not in found_libs:
                    found_libs.append(mod)
        return found_libs
    except(FileNotFoundError, PermissionError):
        print("Error: Failed to read maps")
        return []

def read_source_code(lib, path):
    found_libs = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            for mod in lib:
                if mod in content and mod not in found_libs:
                    found_libs.append(mod)
        return found_libs
    except(FileNotFoundError, PermissionError):
        print("Error: Failed to read maps")
        return []

def get_modules_using_lsof(pid, libs):
    found_libs = []
    try:
        output = subprocess.check_output(['lsof', '-p', str(pid)], stderr=subprocess.DEVNULL)
        lines = output.decode().splitlines()

        for line in lines:
            p = line.split()
            # assumption is that Name starts at 9 or more.. maybe fix this logic?
            if len(p) >= 9:
                filepath = p[-1]
                filename = os.path.basename(filepath)
                for lib in libs:
                    if lib in filename and lib not in found_libs:
                        found_libs.append(lib)
        return found_libs
    except:
        print("Error: Failed to check output using lsof")
        return []

def get_modules_using_pmap(pid, libs):
    found_libs = []
    try:
        output = subprocess.check_output(['pmap', str(pid)], stderr=subprocess.DEVNULL)
        lines = output.decode().splitlines()

        for line in lines:
            p = line.split()
            if len(p) >= 3:
                module = p[-1]
                for lib in libs:
                    if lib in module and lib not in found_libs:
                        found_libs.append(lib)
        return found_libs
    except:
        print("Error: Failed to check output using lsof")
        return []


def check_python_imports(pid, lib):
    if pid == CURRENT_PID or pid in DETECTED_PROCESSES:
        return None
    detections = {"pid": pid, "path": None, "modules": set()}
    logs = []
    try:
        process = psutil.Process(pid)
        cmdline = process.cmdline()

        if len(cmdline) > 1:
            detections["path"] = os.path.join(process.cwd(), cmdline[1])

        maps = get_libs_using_mem_maps(pid, lib)

        if maps:
            for mod in maps:
                detections["modules"].add(mod)
                logs.append(f"[maps] Found `{mod}` in /proc/{pid}/maps")

        for fd in os.listdir(f"/proc/{pid}/fd"):
            fd_path = os.readlink(f"/proc/{pid}/fd/{fd}")
            for mod in lib:
                if mod in fd_path:
                    detections["modules"].add(mod)
                    logs.append(f"[fd] Found `{mod}` in file descriptor path")

        if detections["path"] and os.path.isfile(detections["path"]):
            sc = read_source_code(lib, detections["path"])
            if sc:
                for mod in sc:
                    detections["modules"].add(mod)
                    logs.append(f"[code] Found `{mod}` in script source code")

        if detections["modules"]:
            DETECTED_PROCESSES.add(pid)
            return detections, logs
        return None

    except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess, PermissionError):
        return None

def calculate_confidence(pid, detection_result, static_logs, lib):
    score = 0
    another_score = 0 # I will move it later
    high_sev_logs = []
    low_sev_logs = []
    active_id = get_process_using_input_device()
    spy_flag, spy_logs = get_modules_using_py_spy(pid, lib)

    check_x11, _ = check_x11_connection(pid)

    # This only works with python process..
    if check_x11 > 0:
        if spy_flag == True:
            for logs in spy_logs:
                high_sev_logs.append(f"[Suspicious Activity] X11 input hooks + known suspect modules: {logs}")

    for id in active_id:
        p = psutil.Process(id)
        # Have to implement some furthur checks to differentiate
        # whether this is a System level or a genuine process or a keylogger
        if id != 0:
            path = p.exe()
            if not path.startswith(("/usr/bin/", "/usr/lib/", "/bin", "/sbin" )):
                another_score+=1
            # usually keyloggers work in background.. so..
            if not p.terminal():
                another_score+=1

#    print(another_score)

    if detection_result["modules"]:
        score += 1
    for log in static_logs:
        for mod in lib:
            if mod in log:
                high_sev_logs.append(log)
                break
        else:
            low_sev_logs.append(log)

    if spy_flag:
        score += 1
    for log in spy_logs:
        for mod in lib:
            if mod in log:
                high_sev_logs.append(f"[py-spy] Found module: {mod}")
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

def monitor_python_processes(lib):
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            # we are only checking python files.. what about others bud?
            if proc.info['name'] and 'python' in proc.info['name'].lower():
                result = check_python_imports(proc.info['pid'], lib)
                if result:
                    detection, logs = result
                    severity, high_sev_logs, low_sev_logs = calculate_confidence(detection['pid'], detection, logs, lib)
                    if severity != "HIGH":
                        continue
                    else:
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
    lib = load_sus_libraries()
    # print(get_modules_using_pmap(47460,lib))
    # with open(f"/proc/47460/mem", "rb") as mem_file:
    #     address = 0
    #     mem_file.seek(address)
    #     data = mem_file.read(1024)  # read 1MB
    #     print(data)
    # print(check_input_access_frequency(3,10))
    # monitor_python_processes(lib)
    # check_network_activity(2915, 5)
    # check_file_activity(161122, 30)
    # print(get_libs_using_mem_maps(44766, lib))
    print(find_suspicious_processes())

