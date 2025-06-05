import select
import json
import psutil
import os
import ipaddress
import time
import sys
import subprocess
from inotify_simple import INotify, flags
from collections import defaultdict
import hashlib
import shutil
import pwd
import argparse
import atexit
from subprocess import check_output
import stat
import glob
import pyudev
import signal

file_path = "process.json"
white_list_ports = [8080, 443, 22]
current_user = os.getlogin()
home_dir = os.path.expanduser('~')


white_list_paths = [
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/"
]
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

CURRENT_SCRIPT_PATH = os.path.realpath(sys.argv[0])
CURRENT_PID = os.getpid()
DETECTED_PROCESSES = set()

def skip_current_pid(full_path, pid):
    return not (pid == CURRENT_PID or full_path == CURRENT_SCRIPT_PATH)

def get_user_home():
    logged_in_user = (
        os.getenv("SUDO_USER") or
        os.getenv("LOGNAME") or
        os.getenv("USER") or
        pwd.getpwuid(os.getuid()).pw_name
    )
    return pwd.getpwnam(logged_in_user).pw_dir

def require_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
        sys.exit(1)

def load_sus_libraries():
    file_path = "libraries.json"
    with open(file_path, 'r') as f:
        return json.load(f)


# this only works if a process reads inputs directly from the events
# have to rethink this approach as well, since this requires the user to be typing something.
class InputMonitor:
    # TODO: maybe check /proc/bus/input/devices file to get the details.
    def get_active_input_devices(self, timeout=10):
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
            print("No input activity detected. Increase the Timeout if needed [please type something bro]")

        return list(active_devices)

    def get_process_using_input_device(self):
        event_paths = self.get_active_input_devices()
        pid_event_map = {}

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
                                if pid not in pid_event_map:
                                    pid_event_map[pid] = set()
                                pid_event_map[pid].add(path)
                                break
                        except Exception:
                            continue
                except Exception:
                    continue

        return pid_event_map

    def check_input_access_frequency(self, threshold, timeout):
        access_counts = defaultdict(int)
        printed_pids = set()
        x11_confidence = {}
        suspicious_processes = []

        start_time = time.time()

        while time.time() - start_time < timeout:
            pids = self.get_process_using_input_device()

            for proc in psutil.process_iter(['pid']):
                pid = proc.pid
                try:
                    if pid not in x11_confidence:
                        x11_conf, access_rate = X11Analyzer().check_x11_connection(pid)
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

class X11Analyzer:
    # TODO: Need to change the unnecessary printing and the slight changes
    def check_x11_connection(self, pid):
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
                            access_rate += 1

            p = psutil.Process(pid)
            env = p.environ()
            xauth = env.get("XAUTHORITY")
            display = env.get("DISPLAY")

            if xauth and xauth.strip():
                confidence += 1
            if display and display.strip():
                confidence += 1

            for line in subprocess.check_output(['lsof', '-p', str(pid)], stderr=subprocess.DEVNULL).decode().splitlines():
                if 'libX11.so' in line or 'libXt.so' in line:
                    confidence += 1
        except:
            #add the handling bro
            return 0, 0

        return confidence, access_rate

class ParentProcessValidator:
    def __init__(self):
        self.known_safe_parents = {
            'systemd', 'sshd', 'Xorg', 'dbus-daemon', 'NetworkManager'
        }
        self.suspicious_parents = {
            'cron', 'atd', 'systemd', 'Xorg', 'gnome-session', 'lightdm', 'xdg-autostart'
        }

    def get_parent_process(self, pid):
        try:
            p = psutil.Process(pid)
            parent_pid = p.ppid()
            parent_process = psutil.Process(parent_pid)
            return parent_process
        except psutil.NoSuchProcess:
            return None

    def is_legitimate_parent(self, parent_process):
        if not parent_process:
            return False
        return parent_process.name() in self.known_safe_parents

    def get_sus_parent_process(self, pid):
        try:
            p = psutil.Process(pid)
            parent = p.parent() if p else None
            grand_parent = parent.parent() if parent else None
            if parent and parent.name() in self.suspicious_parents:
                return True, f"Suspicious parent process: {parent.name()}"
            if grand_parent and grand_parent.name() in self.suspicious_parents:
                return True, f"Suspicious parent process: {grand_parent.name()}"
            return False, None
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[parent process error] {e}")
            return False, None

class BinaryAnalyzer:
    #TODO: Will add the Hashing part later.. because the structure of the program is not yet set
    def is_trusted_binary(self, path):
        try:
            if not os.path.exists(path):
                return False

            st = os.stat(path)
            trusted_dirs = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/lib", "/lib64", "/usr/lib")

            if not path.startswith(trusted_dirs):
                return False

            if st.st_uid != 0 or (st.st_mode & 0o002):
                return False

            if not get_binary_info(path):
                return False

            return True
        except Exception:
            return False

    def is_upx_packed(self, path):
        try:
            output = subprocess.check_output(['upx', '-t', path], stderr=subprocess.DEVNULL).decode()
            return 'OK' in output
        except:
            return False

    def is_deleted_on_disk(self, pid):
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            return "(deleted)" in exe_path
        except Exception:
            return False

    def check_file_authenticity(self, file_path, full_path, pid=None):
        suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run", "/home"]
        reasons = []
        st = os.stat(full_path)

        def process_matches(proc):
            try:
                for file in proc.open_files():
                    if str(file_path) in str(file.path):
                        reasons.append(f"Process {proc.pid} has opened a socket : {file_path}")
                        return True

                if "memfd:" in full_path or "(deleted)" in full_path:
                    reasons.append(f"Executable is memory-loaded or deleted: {full_path}")
                    return True

                if not self.is_trusted_binary(full_path):
                    reasons.append(f"Untrusted binary path: {full_path}")
                    return True

                if any(full_path.startswith(d) for d in suspicious_dirs):
                    reasons.append(f"Executable in suspicious directory: {full_path}")
                    return True

                if full_path.startswith(("/usr", "/bin", "/sbin")) and st.st_uid != 0:
                    reasons.append(f"System binary not owned by root: {full_path}")
                    return True

                if os.access(full_path, os.W_OK) and str(full_path) in suspicious_dirs:
                    reasons.append(f"Executable is writable: {full_path}")
                    return True

            except Exception as e:
                reasons.append(f"Exception while analyzing process {proc.pid}: {e}")
                return False

        if pid is not None:
            try:
                proc = psutil.Process(pid)
                result = process_matches(proc)
                return result, reasons if result else []
            except psutil.NoSuchProcess:
                return False, [f"PID {pid} does not exist"]
        else:
            for proc in psutil.process_iter(['pid']):
                if process_matches(proc):
                    return True, reasons

        return False, []
    #FIX: This is not good, I have to research more on this..
    def check_obfuscated_or_packed_binaries(self, pid=None):
        flagged = []
        seen_paths = set()
        libs = load_sus_libraries()

        processes = [psutil.Process(pid)] if pid else psutil.process_iter(['pid', 'name', 'cwd', 'exe', 'cmdline'])

        for p in processes:
            try:
                if isinstance(p, psutil.Process):
                    p_info = {
                        'pid': p.pid,
                        'name': p.name(),
                        'cwd': p.cwd(),
                        'exe': p.exe(),
                        'cmdline': p.cmdline()
                    }
                else:
                    p_info = p.info

                full_path = get_path(p_info['cwd'], p_info['cmdline'], p_info['exe'])
                if not full_path or not os.path.exists(full_path):
                    continue

                if self.is_trusted_binary(full_path):
                    continue

                if not skip_current_pid(full_path, p_info['pid']):
                    continue

                if full_path in seen_paths:
                    continue

                reasons = []

                if self.is_upx_packed(full_path):
                    reasons.append("upx-packed")

                if has_suspicious_modules(full_path, libs):
                    reasons.append("suspicious-strings")

                if self.is_deleted_on_disk(p_info['pid']):
                        reasons.append("memory-deleted")

                if reasons:
                    seen_paths.add(full_path)
                    flagged.append({
                        "pid": p_info['pid'],
                        "name": p_info['name'],
                        "path": full_path,
                        "reasons": reasons
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                continue

            return json.dumps(flagged, indent=2) if flagged else json.dumps(False)

class IPCScanner:
    def detect_suspicious_ipc_channels(self, ignorable_files=None):
        suspicious_paths = []
        ipc_dirs = ["/dev/shm", "/tmp", "/run"]
        current_uid = os.getuid()

        if ignorable_files is None:
            ignorable_files = []

        for base_path in ipc_dirs:
            if not os.path.exists(base_path):
                continue

            for root, _, files in os.walk(base_path, followlinks=False):
                for name in files:
                    try:
                        full_path = os.path.join(root, name)

                        if full_path in ignorable_files:
                            continue

                        st = os.lstat(full_path)
                        mode = st.st_mode

                        if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                            if mode & 0o077:
                                if st.st_uid == 0 or st.st_uid == current_uid:
                                    suspicious_paths.append(full_path)
                    except Exception:
                        continue

        return set(suspicious_paths) if suspicious_paths else False

class FileMonitor:
    def check_file_activity(self, pid, timeout):
        processed_paths = set()
        start_time = time.time()
        inotify = INotify()
        watch_flags = flags.CLOSE_WRITE | flags.MODIFY | flags.CREATE | flags.OPEN

        try:
            p = psutil.Process(pid)
            while time.time() - start_time < timeout:
                try:
                    if not p.is_running():
                        return False

                    for f in p.open_files():
                        path = f.path
                        if path not in processed_paths:
                            try:
                                inotify.add_watch(path, watch_flags)
                                processed_paths.add(path)
                            except Exception as e:
                                continue

                    events = inotify.read(timeout=100)
                    if events:
                        return True  
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print("[ERROR] Could not access process")
                    return False

                time.sleep(0.0)  # you remove, cpu boom
            return False

        except Exception as e:
            print(f"{e}")
            return False


class ModuleChecker:
    def __init__(self, pid, libs):
        self.pid = pid
        self.libs = libs

    def get_modules_using_py_spy(self):
        logs = []
        result = subprocess.run(["py-spy", "dump", "--pid", str(self.pid)],
                                capture_output=True, text=True)
        if result.returncode == 0:
            found = False
            for line in result.stdout.splitlines():
                for mod in self.libs:
                    if mod in line:
                        logs.append(mod)
                        found = True
            return found, logs
        else:
            logs.append(f"[py-spy] Failed to attach to PID {self.pid}")
            return False, logs

    def get_libs_using_mem_maps(self):
        found_libs = []
        try:
            with open(f"/proc/{self.pid}/maps", "r") as maps_file:
                maps_content = maps_file.read()
                for mod in self.libs:
                    if mod in maps_content and mod not in found_libs:
                        found_libs.append(mod)
            return found_libs
        except (FileNotFoundError, PermissionError):
            print("Error: Failed to read maps")
            return []

    def get_modules_using_lsof(self):
        found_libs = []
        try:
            output = subprocess.check_output(['lsof', '-p', str(self.pid)],
                                             stderr=subprocess.DEVNULL)
            lines = output.decode().splitlines()

            for line in lines:
                p = line.split()
                if len(p) >= 9:
                    filepath = p[-1]
                    filename = os.path.basename(filepath)
                    for lib in self.libs:
                        if lib in filename and lib not in found_libs:
                            found_libs.append(lib)
            return found_libs
        except Exception:
            print("Error: Failed to check output using lsof")
            return []

    def get_modules_using_pmap(self):
        found_libs = []
        try:
            output = subprocess.check_output(['pmap', str(self.pid)],
                                             stderr=subprocess.DEVNULL)
            lines = output.decode().splitlines()

            for line in lines:
                p = line.split()
                if len(p) >= 3:
                    module = p[-1]
                    for lib in self.libs:
                        if lib in module and lib not in found_libs:
                            found_libs.append(lib)
            return found_libs
        except Exception:
            print("Error: Failed to check output using pmap")
            return []

class PersistenceChecker:
    def __init__(self):
        self.user_home = os.path.expanduser("~")

    def check_persistence(self, pid):
        try:
            p = psutil.Process(pid)
            exe_path = p.exe()
            full_path = get_path(p.cwd(), p.cmdline(), exe_path)
            if full_path:
                systemd_dir = os.path.join(self.user_home, ".config/systemd/user/")
                if os.path.isdir(systemd_dir):
                    for fname in os.listdir(systemd_dir):
                        if fname.endswith(".service"):
                            f_path = os.path.join(systemd_dir, fname)
                            try:
                                with open(f_path, 'r', errors="ignore") as f:
                                    content = f.read()
                                    if (exe_path and exe_path in content) or (full_path and full_path in content):
                                        return True, f"{full_path or exe_path} is autostarting using systemd"
                            except Exception as e:
                                print(f"[systemd read error] {e}")

                autostart_dir = os.path.join(self.user_home, ".config/autostart/")
                if os.path.isdir(autostart_dir):
                    for fname in os.listdir(autostart_dir):
                        if fname.endswith(".desktop"):
                            f_path = os.path.join(autostart_dir, fname)
                            try:
                                with open(f_path, 'r', errors="ignore") as f:
                                    content = f.read()
                                    if (exe_path and exe_path in content) or (full_path and full_path in content):
                                        return True, f"{full_path or exe_path} is using autostart"
                            except Exception as e:
                                print(f"[autostart read error] {e}")

                startup_files = [".bashrc", ".profile", ".xinitrc"]
                for sf in startup_files:
                    sf_path = os.path.join(self.user_home, sf)
                    if os.path.isfile(sf_path):
                        try:
                            with open(sf_path, 'r', errors="ignore") as f:
                                content = f.read()
                                if (exe_path and exe_path in content) or (full_path and full_path in content):
                                    return True, f"{full_path or exe_path} is present in {sf}"
                        except Exception as e:
                            print(f"[shell file read error] {e}")

                try:
                    crontab_output = check_output(["crontab", "-l"], text=True, stderr=open(os.devnull, 'w'))
                    if (exe_path and exe_path in crontab_output) or (full_path and full_path in crontab_output):
                        return True, f"{full_path or exe_path} is scheduled via crontab"
                except Exception:
                    pass

            else: 
                 return False, None

        except Exception as e:
            print(f"{e}")
            return False, None

    def check_cron_jobs(self):
        score = 0
        sus_files = ["base64", "eval", "curl", "wget", ".py", "python", "node", "perl"]
        suspicious_paths = ["/tmp", "/dev/shm", "/var/tmp", "/run", "/home"]
        cron_dirs = glob.glob("/etc/cron*") + ["/var/spool/cron/", os.path.expanduser("~/.crontab")]
        cron_files = []

        for path in cron_dirs:
            if os.path.isfile(path):
                cron_files.append(path)
            elif os.path.isdir(path):
                for filename in os.listdir(path):
                    full_path = os.path.join(path, filename)
                    if os.path.isfile(full_path):
                        cron_files.append(full_path)

        for file in cron_files:
            try:
                with open(file, "r") as f:
                    contents = f.read()
                    for word in suspicious_paths:
                        if word in contents:
                            score += 1
                    for word in sus_files:
                        if word in contents:
                            score += 1
            except Exception as e:
                print(f"{e}")
        return score

    def list_user_rc_files(self):
        home = self.user_home
        rc_patterns = [".*rc", ".bash_profile", ".profile", ".xinitrc"]
        system_files = [
            "/etc/bash.bashrc", "/etc/zsh/zshrc", "/etc/profile", "/etc/ld.so.preload"
        ]
        profile_dir = "/etc/profile.d"
        files = []
        for pattern in rc_patterns:
            files.extend(glob.glob(os.path.join(home, pattern)))

        for s_file in system_files:
            files.append(s_file)

        if os.path.isdir(profile_dir):
            files.extend(os.path.join(profile_dir, p_file) for p_file in os.listdir(profile_dir))

        return [f for f in files if os.path.isfile(f)]

    def check_ld_preload(self, pid, files_to_check):
        score = 0
        try:
            p = psutil.Process(pid)
            env = p.environ()
            if "LD_PRELOAD" in env:
                score += 1
        except Exception as e:
            print(f"{e}")

        for fname in files_to_check:
            if os.path.exists(fname):
                try:
                    with open(fname, "r") as f:
                        contents = f.read()
                        if "LD_PRELOAD" in contents or "ld_preload" in contents:
                            score += 1
                except Exception as e:
                    print(f"{e}")

        try:
            if os.path.exists("/etc/ld.so.preload"):
                with open("/etc/ld.so.preload", "r") as f:
                    contents = f.read().strip()
                    if contents:
                        score += 1
        except Exception as e:
            print(f"{e}")

        return score

class NetworkMonitor:
    def __init__(self):
        self.suspicious_paths = [
            "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/run/user/", "/run/lock/",
            "/run/systemd/", "/usr/lib/tmpfiles.d/", "/lib/modules/", "/etc/rc.local",
            "/etc/init.d/", "/etc/systemd/system/", "/etc/cron.d/", "/etc/cron.daily/",
            "/etc/cron.hourly/", "/etc/profile.d/"
        ]
    #TODO:
    # if a process is opening sudden connections
    # if it is making outbound connections
    # if a process is doing any port-forwarding -> no idea how to approach this
    # verify_process - be added here to do furthur checks
    # not a very effective way - since a process could still
    # mask as from white listed ports or paths
    def check_network_activity(self, input_pid, timeout):
        conn_count = defaultdict(int)
        c_time = time.time()

        while time.time() - c_time < timeout:
            try:
                conn = psutil.net_connections(kind='inet')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print("Error: Failed to get the process details")
                return
            for i in conn:
                if i.status == 'ESTABLISHED' and i.raddr and i.pid:
                    conn_count[i.pid] += 1
            time.sleep(1)

        conn = psutil.net_connections(kind='inet')
        for i in conn:
            if input_pid == i.pid and i.status is not None:
                for pid, _ in conn_count.items():
                    if pid == i.pid and i.raddr:
                        ip = i.raddr.ip
                        if not ipaddress.ip_address(ip).is_private:
                            try:
                                p = psutil.Process(pid)
                                path = p.exe()
                                if any(path.startswith(sus_path) for sus_path in self.suspicious_paths):
                                    return True, ip
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                print("Error: Failed to get the process details")
                                return False

bpf_file = "bpf_output.json"
or_file = "test.json"

class BPFMONITOR:
    def __init__(self):
        self.proc = None
        atexit.register(self.stop)

    def start(self, timeout):
        print("[INFO] Trying to capture input devices using bpf")
        open(bpf_file, "w").close()
        self.proc = subprocess.Popen(
            ['sudo', './loader'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(timeout)

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception as e:
                print(f"Error stopping BPF monitor: {e}")

    def get_device_names_from_bpf_file(self):
        paths = ["/dev/input", "/dev/pts", "/dev/tty"]
        paths.extend(glob.glob("/dev/hidraw*"))
        updated_entries = []

        try:
            with open(bpf_file, "r") as f:
                lines = f.readlines()

            for line in lines:
                try:
                    entry = json.loads(line)
                    major_value = entry.get("major")
                    minor_value = entry.get("minor")
                    matched_path = None

                    for base_path in paths:
                        for root, _, files in os.walk(base_path):
                            for file in files:
                                full_path = os.path.join(root, file)
                                try:
                                    st = os.stat(full_path)
                                    if not stat.S_ISCHR(st.st_mode):
                                        continue
                                    if (os.major(st.st_rdev) == minor_value and
                                        os.minor(st.st_rdev) == major_value):
                                        matched_path = full_path
                                        break
                                except Exception:
                                    continue
                        if matched_path:
                            break

                    if matched_path:
                        entry["device_path"] = matched_path

                    updated_entries.append(entry)

                except json.JSONDecodeError:
                    continue

            with open(or_file, "w") as out_f:
                for entry in updated_entries:
                    out_f.write(json.dumps(entry) + "\n")

        except FileNotFoundError:
            print(f"[ERROR] File not found: {bpf_file}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def check_pid(self, pid):
        try:
            with open(bpf_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if pid == entry.get("pid") and entry.get("pid") != str(CURRENT_PID):
                            return True
                    except Exception as e:
                        print(f"{e}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"{e}")
            return False

    def check_device_type(self, pid, keyword, timeout=50):
        for _ in range(timeout):
            try:
                with open(or_file, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            d_path = entry.get("device_path", "")
                            if pid == entry.get("pid") and keyword in d_path:
                                return True,d_path
                        except Exception as e:
                            print(f"[WARN] JSON decode error: {e}")
            except FileNotFoundError:
                pass
            except Exception as e:
                print(f"[ERROR] Failed to open file: {e}")
            time.sleep(1)
        return False


def get_binary_info(full_path):
    try:
        pkg_managers = ["apt", "dnf", "yum", "pacman", "zypper", "apk"]
        for pm in pkg_managers:
            if shutil.which(pm):
                if pm == "apt":
                    result = subprocess.run(["dpkg", "-S", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm in ["dnf", "yum", "zypper"]:
                    result = subprocess.run(["rpm", "-qf", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm == "pacman":
                    result = subprocess.run(["pacman", "-Qo", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm == "apk":
                    result = subprocess.run(["apk", "info", "-W", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return result.returncode == 0
    except:
        return False

def has_suspicious_modules(binary, lib) -> bool:
    def lines():
        try:
            if binary.endswith(('.py', '.sh', '.pl')):
                with open(binary, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line.lower()
            else:
                output = subprocess.check_output(
                    ["strings", binary],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=2
                )
                for line in output.splitlines():
                    yield line.lower()
        except Exception:
            return
    try:
        for line in lines():
            for libraries, weight in lib.items():
                if str(libraries) in str(line):
                    return weight
        return False
    except Exception:
        return False

def has_suspicious_strings(binary_path):
    suspicious_markers = [
        b"/dev/input/event",
        b"XOpenDisplay",
        b"XQueryKeymap",
        b"XRecordCreateContext",
        b"keylogger",
        b"keystroke",
        b"grab_keyboard",
        b"libX11.so",
        b"libXtst.so",
        b"raw_input",
        b"input_event",
        b"KeyPress",
        b"keyboard.h",
        b"log_keys",
        b"SendInput",
        b"/proc/",
        b"RecordKey",
        b"input_log",
        b"KeyLogger",
        b"keyboard_read",
        b"hook_keyboard",
    ]
    try:
        with open(binary_path, 'rb') as f:
            content = f.read()
            for marker in suspicious_markers:
                if marker in content:
                    return True
    except Exception as e:
        print(f"    [ERROR] Failed to scan {binary_path}: {e}")
    return False

def get_path(cwd, cmdline, exe_path):
    try:
        if not cmdline:
            return False

        path = None
        interpreters = ['python', 'python3', 'bash', 'sh', 'perl', 'ruby']
        basename0 = os.path.basename(cmdline[0])

        if basename0 in interpreters and len(cmdline) > 1:
            path = cmdline[1]
        else:
            path = cmdline[0]

        if os.path.isabs(path) and os.path.isfile(path):
            return path

        if cwd:
            full_path = os.path.join(cwd, path)
            if os.path.isfile(full_path):
                return full_path

        if exe_path and os.path.isfile(exe_path):
            return exe_path

        return False
    except Exception:
        return False


known_safe_programs = {
    "/usr/bin/systemd", "/usr/bin/dbus-daemon", "/usr/bin/NetworkManager",
    "/usr/sbin/sshd", "/usr/sbin/crond", "/usr/bin/gnome-shell",
    "/usr/bin/Xorg", "/usr/bin/Xwayland"
}

# TODO: this is supposed to check already trusted processes in background(dont know why) - just to be safe, user could be stupid
def review_pids():
    sus_score = 0
    with open(file_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
    for entry in data:
        if entry.get("is trusted") == True:
            pass 

reviewed_paths = {}
def prompt_user(name, path, pid, usage):
    if path in reviewed_paths:
        return reviewed_paths[path]    

    print("\nProcess")
    print(f"PID     : {pid}")
    print(f"Name    : {name}")
    print(f"Path    : {path}")
    print(f"Using   : {usage}\n")

    print("This process is using keyboard input. Do you want to analyze it furture?")
    print("[1] Yes (Check for suspicious behaviour)")
    print("[2] No ((Mark this process as legitimate/trusted))")

    while True:
        choice = input("> ").strip()
        if choice == '1':
            reviewed_paths[path] = False
            return False
        elif choice == '2':
            print("Marked as trusted.\n")
            reviewed_paths[path] = True
            return True
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def read_pid(pid):
    sus_libraries = load_sus_libraries()
    i = InputMonitor()
    input_access_pids = i.get_process_using_input_device()
    try:
        p = psutil.Process(pid)
        print(f"\nAnalyzing process: {p.name()} (PID: {pid})\n")
        result = r_process(p, input_access_pids, sus_libraries)
        if result:
            score, path, trust, reasons = result
            print(f"Suspicion score: {score}/15")
            if reasons:
                print("Reasons:")
                for r in reasons:
                    print(f"    - {r}")
            else:
                print("Process appears legitimate.")
            hash_and_save(path, p.pid, p.name(), score, trust)
        else:
            print("Process appears legitimate. No suspicious indicators found.")
    except Exception as e:
        print(f"{e}")


def i_process_checks(pid):
    found_pids = defaultdict(set)
    i = InputMonitor()
    x11 = X11Analyzer()
    event_map = i.get_process_using_input_device()
    for input_pid, events in event_map.items():
        for event in events:
            found_pids[input_pid].add(event)

    x11_confidence, _ = x11.check_x11_connection(pid)
    if x11_confidence >= 3:
        found_pids[pid].add("x11")

    if pid in found_pids:
        return True, list(found_pids[pid])

    return False, None

# TODO: Fix, something seems taking long.. 
def find_suspicious_processes(mode):
    i = InputMonitor()
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)

    try:
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    except FileNotFoundError:
        data = []

    sus_libraries     = load_sus_libraries()
    input_access_pids = i.get_process_using_input_device()

    for p in psutil.process_iter():
        try:
            if p.name().startswith('[') and p.name().endswith(']'):
                continue

            full_path = get_path(p.cwd(), p.cmdline(), p.exe())
            if not full_path or not os.path.isfile(full_path):
                continue

            if not skip_current_pid(full_path, p.pid):
                continue

            if any(entry.get("name") == p.name() and entry.get("pid") != p.pid for entry in data):
                continue

            out, ty = i_process_checks(p.pid)
            usage   = ""

            if out:
                if ty == 'x11':
                    usage = 'x11'
                elif isinstance(ty, list):
                    usage = ", ".join(ty)

                if mode != "auto":
                    trust = prompt_user(p.name(), full_path, p.pid, usage)

                    if not trust:
                        #todo: fix below bro
                        print(f"\nAnalyzing process: {p.name()} (PID: {p.pid})\n")
                        result = r_process(p, input_access_pids, sus_libraries)
                        if result:
                            score, path, trust, reasons = result
                            if reasons:
                                print("Reasons:")
                                for r in reasons:
                                    print(f"    - {r}")
                            else:
                                print("Process appears legitimate.")
                            hash_and_save(path, p.pid, p.name(), score, trust)
                        else:
                            print("Process appears legitimate. No suspicious indicators found.")
                else:
                    result = r_process(p, input_access_pids, sus_libraries)
                    if result:
                        score, path, trust, _ = result
                        hash_and_save(path, p.pid, p.name(), score, trust)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def hash_and_save(path, pid, name, score, ist: bool):
    try:
        h = hashlib.md5()
        with open(path, 'rb') as f:
            for data in iter(lambda: f.read(4096), b""):
                h.update(data)
        file_hash = h.hexdigest()
        entry = {
            "pid": str(pid),
            "name": name,
            "path": path,
            "md5 hash": file_hash,
            "score": str(score),
            "is trusted": ist 
        }

        file_path = "process.json"
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        if any(entry.get("md5 hash") == file_hash for entry in data):
            return
        data.append(entry)
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)

    except:
        return


def check_impersonating_process(pid):
    try:
        p = psutil.Process(pid)
        name = p.name()
        full_path = get_path(p.cwd(), p.cmdline(), p.exe())
        if full_path:
            l_path = any(full_path.startswith(p) for p in white_list_paths)
            if not l_path and name in ["systemd", "bash", "cron", "init", "sshd", "Xorg", "zsh"]:
                return True, f"Process name impersonates system binary: {name}"
            return False, None    
    except Exception as e:
        print(f"{e}")
        return False

# assuming that a process wont try to hide access to hidraw
def check_hidraw_connections(pid):
    try:
        fd_dir = f"/proc/{pid}/fd"
        for fd in os.listdir(fd_dir):
            fd_path = os.path.join(fd_dir, fd)
            try:
                target = os.readlink(fd_path)
                if "/dev/hidraw" in target:
                    if os.path.exists(target):
                        st = os.stat(target)
                        if stat.S_ISCHR(st.st_mode):
                            return True
            except FileNotFoundError:
                continue
            except PermissionError:
                continue
            except Exception as e:
                print(f"Error reading {fd_path}: {e}")
    except Exception as e:
        print(f"Failed to read /proc/{pid}/fd: {e}")
    return False


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


# def read_source_code(lib, path):
#     found_libs = []
#     try:
#         with open(path, 'r', encoding='utf-8', errors='ignore') as f:
#             content = f.read().lower()
#             for mod in lib:
#                 if mod in content and mod not in found_libs:
#                     found_libs.append(mod)
#         return found_libs
#     except(FileNotFoundError, PermissionError):
#         print("Error: Failed to read maps")
#         return []


# idea is to find a suspicious input device based on heuristics, - will have to improve in future
def is_suspicious_input_device():
    context = pyudev.Context()
    virtual_event_nodes = set()

    for dev in context.list_devices(subsystem="input"):
        dev_node = dev.device_node or ""
        dev_path = dev.device_path or ""

        if not dev.device_node or not dev.device_node.startswith("/dev/input/"):
            continue

        if not dev_path.startswith("/devices/virtual/input/"):
            continue

        if dev.get("ID_INPUT_KEY") != "1" and dev.get("ID_INPUT") != "1":
            continue

        if dev.device_type == "input" or dev.subsystem == "input":
            continue
        
        if dev.get("POWER_SUPPLY_NAME") or dev.get("ID_PATH") == "platform-wmi":
                continue

        virtual_event_nodes.add(dev_node)

    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_path = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_path):
            continue
        try:
            for fd in os.listdir(fd_path):
                try:
                    target = os.readlink(os.path.join(fd_path, fd))
                    if target in virtual_event_nodes:
                        return (True, target)
                except:
                    continue
        except:
            continue

    return False



# TODO: theory is that a malicious file could run in memory without writing to disk
# we could monitor them using bpf, initial idea is to capture these - memfd_create, execveat
memfd_out_file = "memfd_create_output.json"
def run_fileless_execution_loader(timeout=50, binary="./fe_loader", out_file=memfd_out_file):
    open(out_file, "w").close()

    p = subprocess.Popen(
        ["sudo", binary],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )

    def terminate():
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            pass

    atexit.register(terminate)

    time.sleep(timeout)

    if p.poll() is None:
        p.terminate()

def read_memfd_events(out_file=memfd_out_file):
    pids = []
    try:
        with open(out_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    pid = data.get("pid")
                    if pid is not None:
                        pids.append(pid)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return pids

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

        checker = ModuleChecker(pid, lib)
        maps = checker.get_libs_using_mem_maps()

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

        # if detections["path"] and os.path.isfile(detections["path"]):
            # sc = read_source_code(lib, detections["path"])
            # if sc:
            #     for mod in sc:
            #         detections["modules"].add(mod)
            #         logs.append(f"[code] Found `{mod}` in script source code")

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
    i = InputMonitor()
    x11 = X11Analyzer()
    active_id = i.get_process_using_input_device()
    checker = ModuleChecker(pid, lib)
    spy_flag, spy_logs = checker.get_modules_using_py_spy()

    check_x11, _ = x11.check_x11_connection(pid)

    if check_x11 > 0:
        if spy_flag == True:
            for logs in spy_logs:
                high_sev_logs.append(f"[Suspicious Activity] X11 input hooks + known suspect modules: {logs}")

    for id in active_id:
        p = psutil.Process(id)
        if id != 0:
            path = p.exe()
            if not path.startswith(("/usr/bin/", "/usr/lib/", "/bin", "/sbin" )):
                another_score+=1
            if not p.terminal():
                another_score+=1

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

safe_process_signatures = set()
def r_process(input_access_pids, sus_libraries, pid, cwd, cmdline, exe_path,fd, terminal, user, uptime):
    try:
        sus_score = 0
        reasons = []
        full_path = get_path(cwd, cmdline, exe_path)
        check = False
        pv = ParentProcessValidator()
        pc = PersistenceChecker()
        bi = BinaryAnalyzer() 
        if not full_path or not skip_current_pid(full_path, pid):
            return False

        if pid in input_access_pids:
            sus_score += 4
            reasons.append("Accesses input devices")

        try:
            with open(full_path, 'rb') as f:
                binary_data = f.read()
                for lib, weight in sus_libraries.items():
                    if lib.encode() in binary_data:
                        sus_score += weight
                        reasons.append(f"Contains suspicious library: {lib}")
                        break
        except Exception as e:
            print(f"{e}")
            pass
        
        rt, output = pc.check_persistence(pid)
        if rt:
            sus_score += 2
            reasons.append(output)

        # if bi.check_file_authenticity(full_path):
        #     sus_score += 2
        
        if bi.is_upx_packed(full_path) or bi.is_deleted_on_disk(pid):
            sus_score += 1
        
        cron_job_score = pc.check_cron_jobs()
        if cron_job_score > 1:
            sus_score += 2
            
        parent_process = pv.get_parent_process(pid)
        if pv.is_legitimate_parent(parent_process):
            safe_process_signatures.add(full_path)
            return False

        if not terminal:
            sus_score += 1
            reasons.append("No controlling terminal")
        
        if full_path and full_path not in white_list_paths:
            sus_score += 1
            reasons.append(f"Running from non-whitelisted path: {full_path}")
        if full_path and (full_path.startswith('/tmp') or full_path.startswith('/dev')):
            sus_score += 2
            reasons.append(f"Running from suspicious dir: {full_path}")

        if os.path.islink(full_path):
            sus_score += 1
            reasons.append("Binary is a symlink")

        if fd > 2:
            sus_score += 1
            reasons.append(f"Has {fd} file descriptors")

        if uptime < 300 and not terminal:
            sus_score += 1
            reasons.append("Recently started and detached")

        if user == 'root' and pid != os.getpid():
            sus_score += 1
            reasons.append("Running as root")

        if has_suspicious_modules(full_path, sus_libraries):
            sus_score += 2
            reasons.append("Contains suspicious strings")

        if full_path in known_safe_programs or any(full_path.startswith(wp) for wp in white_list_paths):
            check = True
            return False

        binary_owned_by_package = get_binary_info(full_path)
        is_path_safe = (
            full_path in known_safe_programs or
            any(full_path.startswith(wp) for wp in white_list_paths)
        )
        if binary_owned_by_package and is_path_safe:
            sus_score = max(sus_score - 3, 0)
            check = True
        elif binary_owned_by_package:
            sus_score = max(sus_score - 2, 0)
            check = True
        else:
            sus_score += 1
            check = False
            reasons.append("Binary likely not from a package")

        if sus_score >= 3:
            return sus_score, full_path, check, reasons

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

# --scan option 
# "/dev/input", "/dev/pts", "/dev/tty", "/dev/hidraw*
# x11 connections
# ipc channels - sockets 
# Persistence Checking
# File Authenticity - check_file_authenticity()
# check suspicious strings in a binary
# check file activity - writing or reading a file
# check active connections to a private ip address
def scan_process(is_log=False):
    from collections import defaultdict
    i = InputMonitor()
    bpf = BPFMONITOR()
    x = X11Analyzer()
    ba = BinaryAnalyzer()
    fm = FileMonitor()
    pc = PersistenceChecker()
    ipc = IPCScanner()
    nm = NetworkMonitor()
    bpf.start(5)
    sockets = ipc.detect_suspicious_ipc_channels()
    fullpaths = {}
    parent_map = {}
    reasons_by_pid = defaultdict(set)
    suspicious_candidates = set()
    input_access_pids = i.get_process_using_input_device()

    print("\n" + "-" * 50)
    print(" Starting Suspicious Process Scan ".center(50))
    print("-" * 50)

    for p in psutil.process_iter(['pid', 'ppid']):
        try:
            confidence, access_rate = x.check_x11_connection(p.pid)
            if confidence >= 3 and access_rate > 0:
                suspicious_candidates.add(p.pid)
                reasons_by_pid[p.pid].add("X11 access")
            parent_map[p.pid] = p.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for pid in input_access_pids:
        suspicious_candidates.add(pid)
        reasons_by_pid[pid].add("input access")
        if bpf.check_pid(pid):
            reasons_by_pid[pid].add("BPF activity")
    bpf.stop()

    trusted_paths = set()
    unrecognized_paths = set()
    suspicious_pids = set()

    for pid in suspicious_candidates:
        try:
            proc = psutil.Process(pid)
            path = get_path(proc.cwd(), proc.cmdline(), proc.exe())
            if path:
                fullpaths[pid] = path
                if sockets:
                    for file in sockets:
                        result, reason_list = ba.check_file_authenticity(file, path, pid)
                        if not result:
                            trusted_paths.add(path)
                        else:
                            unrecognized_paths.add(path)
                            suspicious_pids.add(pid)
                            for reason in reason_list:
                                reasons_by_pid[pid].add(reason)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if trusted_paths:
        print("\n" + "-" * 50)
        print(" Trusted Processes Using Input Devices ".center(50))
        print("-" * 50)
        for path in sorted(set(trusted_paths)):
            print(f" ─ {path}")

    if unrecognized_paths:
        print("\n" + "-" * 50)
        print(" Unrecognized Processes Using Input Devices ".center(50))
        print("-" * 50)
        for path in sorted(set(unrecognized_paths)):
            print(f" ─ {path}")

    if suspicious_pids:
        print("\n" + "-" * 50)
        print(" Running Checks on Unrecognized Processes ".center(50))
        print("-" * 50)
        checks = [
            "Process has any suspicious strings",
            "Process reading/writing to any file",
            "Process has opened any foreign connections",
            "Process is persistent"
        ]
        for c in checks:
            print(f" ─ {c}")

    for pid in list(suspicious_pids):
        if fm.check_file_activity(pid, 1):
            reasons_by_pid[pid].add("file I/O")
            suspicious_pids.add(pid)

    for pid in list(suspicious_pids):
        if pc.check_persistence(pid):
            reasons_by_pid[pid].add("persistence")
            suspicious_pids.add(pid)

    for pid in list(suspicious_pids):
        if nm.check_network_activity(pid, 5):
            reasons_by_pid[pid].add("foreign connections")
            suspicious_pids.add(pid)

    for pid in list(suspicious_pids):
        path = fullpaths.get(pid)
        if path:
            if has_suspicious_strings(path):
                reasons_by_pid[pid].add("suspicious strings")
                suspicious_pids.add(pid)
   

    high_sus_string_pids = []
    normal_suspects = []
    sus_scores = {}

    for pid in suspicious_pids:
        path = fullpaths.get(pid)
        if path:
            sus_score = has_suspicious_modules(path, load_sus_libraries())
            sus_scores[pid] = sus_score
            if sus_score >= 4:
                high_sus_string_pids.append(pid)
                reasons_by_pid[pid].add("suspicious modules")
            elif sus_score > 0:
                normal_suspects.append(pid)
                reasons_by_pid[pid].add("suspicious modules")
            else:
                normal_suspects.append(pid)

    final_suspects = list(set(high_sus_string_pids + normal_suspects))
    final_suspects = [pid for pid in final_suspects if pid in fullpaths]
    printed_pids = set()
    child_group = defaultdict(list)

    for pid in final_suspects:
        ppid = parent_map.get(pid)
        if ppid in final_suspects:
            child_group[ppid].append(pid)
        else:
            printed_pids.add(pid)

    if printed_pids:
        print("\n" + "-" * 50)
        print(" POTENTIAL KEYLOGGER(S) DETECTED ".center(50))
        print("-" * 50)

        for pid_group in [high_sus_string_pids, printed_pids - set(high_sus_string_pids)]:
            for pid in sorted(pid_group):
                try:
                    p = psutil.Process(pid)
                    path = fullpaths.get(pid, '[unknown path]')
                    reason_list = sorted(reasons_by_pid.get(pid, []))
                    is_trusted = ba.is_trusted_binary(path)
                    trust_note = " (recognized system binary)" if is_trusted else ""

                    print(f"\n [PID {pid}] {path}{trust_note}")
                    ppid = p.ppid()
                    try:
                        parent = psutil.Process(ppid)
                        parent_path = parent.exe()
                        parent_trust = ba.is_trusted_binary(parent_path)
                        print(f"     ├─ Parent PID {ppid}: {parent_path} ({'trusted' if parent_trust else 'untrusted'})")
                    except Exception:
                        print(f"     ├─ Parent PID {ppid}: <unknown>")
                    if pid in child_group:
                        for child_pid in sorted(child_group[pid]):
                            child_path = fullpaths.get(child_pid, '[unknown path]')
                            print(f"     ├─ Child PID {child_pid}: {child_path}")

                    print(f"     ├─ Flagged due to:")
                    for reason in reason_list:
                            print(f"         • {reason}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f" [PID {pid}]  <process info unavailable>")
    else:
        print("\n" + "-" * 50)
        print(" No suspicious keylogger activity found. ".center(50))
        print("-" * 50)


# Initial stage: go through every running process, do some checks and if our confidence is pretty high and we are certain that it is a legit process then we hash and save it..
# Second stage: if else, will proceed with furthur checks to confirm if the process is a Keylogger, if yes - then we provide the user with option to kill it - 
# before that we hash it with a remark this is Keylogger for future comparisons
# Third stage: if we dont see any, then we keep looking for new process every few minutes and also go through all the checks for all the processes that we hashed - 
# just to be sure
# If user is in interactive mode - then we have separate procedure, 
# default is auto.. we will do all the three stages

# --monitor option
def phase_one_analysis():
    # First stage: go through every running process
    # Do some static and basic behavioral checks to see if confidence is high
    # If we are pretty certain it's a legit process (e.g., trusted path, system-owned),
    # then we hash it and save it to our json file
    # Else, we return it for further analysis in stage 2
    full_path_set = set()
    pid_list = set()
    i = InputMonitor()
    input_access_pids = i.get_process_using_input_device()
    sus_libraries = load_sus_libraries()
    for proc in psutil.process_iter(['pid', 'cmdline', 'exe', 'cwd']):
        pid = proc.info['pid']
        try:
            cwd = proc.cwd()
            cmdline = proc.cmdline()
            exe = proc.exe()
            fd = proc.num_fds()
            terminal = proc.terminal()
            username = proc.username()
            uptime = time.time() - proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        p = get_path(cwd, cmdline, exe)
        if p:
            if not skip_current_pid(p, pid):
                continue
            full_path_set.add(p)
            pid_list.add(pid)
        output = r_process(input_access_pids, sus_libraries, pid, cwd, cmdline, exe, fd, terminal, username, uptime)
        if output:
            score, path, trust, reasons = output
            print(score, trust, path, reasons)
            time.sleep(1)

    for path in full_path_set:
        if get_binary_info(path):
            pass
        else:
            pass
        

# will think about keeping interactive mode or not
def parse_args():
    parser = argparse.ArgumentParser(description="Keylogger Detector") 
    parser.add_argument('-p', type=int, help="-p takes an pid for Analyzing")
    parser.add_argument('--mode', choices=['interactive', 'auto'], default='auto', help="'interactive' to prompt user, 'auto' to skip prompts")
    parser.add_argument("--scan", action="store_true", help="Scan Mode")
    parser.add_argument("--monitor", action="store_true", help="Monitor Mode")
    parser.add_argument("--log", action="store_true", help="Enable verbose logging")
    return parser.parse_args()

if __name__ == "__main__":
    require_root()
    args = parse_args()
    m = BinaryAnalyzer()
    print("We are running.. Press CTRL+C to stop.")
    if args.scan:
        try:
            scan_process(args.log)
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted by user. Exiting...")
