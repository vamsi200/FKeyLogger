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
from datetime import datetime
import re
import collections
import itertools
import math
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
    return (pid == CURRENT_PID or full_path == CURRENT_SCRIPT_PATH)

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
class InputMonitor:
    def get_active_input_devices(self):
        base = "/dev/input/"
        return [os.path.join(base, f) for f in os.listdir(base) if f.startswith("event")]

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
            #TODO: add the handling bro
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

    def check_file_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                byte_arr = f.read()
            if not byte_arr:
                return 0

            freq_list = [0] * 256
            for b in byte_arr:
                freq_list[b] += 1
            entropy = 0
            for freq in freq_list:
                if freq > 0:
                    p = freq / len(byte_arr)
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0

    def check_packer_magic_bytes(self, path):
        packer_signatures = {
            b'UPX!': "UPX",
            b'MPRESS': "MPRESS",
            b'ASPACK': "ASPack",
            b'PECompact': "PECompact"
        }
        try:
            with open(path, 'rb') as f:
                header = f.read(1024)
            for sig, name in packer_signatures.items():
                if sig in header:
                    return True, name
            return False, None
        except Exception:
            return False, None


    def check_file_authenticity(self, file_path, full_path, pid=None):
        suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run", "/home"]
        reasons = []
        st = os.stat(full_path)

        def process_matches(proc):
            try:
                if file_path:
                    for file in proc.open_files():
                        if str(file_path) in str(file.path):
                            reasons.append(f"Process {proc.pid} has opened a socket : {file_path}")
                            return True

                if "memfd:" in full_path or "(deleted)" in full_path:
                    reasons.append(f"Executable is memory-loaded or deleted: {full_path}")
                    return True

                if not self.is_trusted_binary(full_path):
                    reasons.append(f"Running from a Untrusted binary path: {full_path}")
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

    # Running entropy checks on all the processes would be a cpu intensive task and too time consuming.. so for now, added only for -p option
    def check_obfuscated_or_packed_binaries(self, pid=None):
        seen_paths = set()

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

                if skip_current_pid(full_path, p_info['pid']):
                    continue

                if full_path in seen_paths:
                    continue

                reasons = []

                if self.is_upx_packed(full_path):
                    reasons.append("is upx-packed")

                if self.is_deleted_on_disk(p_info['pid']):
                        reasons.append("is memory-deleted")

                rt, name = self.check_packer_magic_bytes(full_path)
                if rt:
                        reasons.append(f"has packer-signature {name}")

                entropy = self.check_file_entropy(full_path)
                if entropy > 7.5:
                    reasons.append("has high-entropy")

                if reasons:
                    seen_paths.add(full_path)
                       

            except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                continue

            return reasons if reasons else False

class IPCScanner:
    def detect_suspicious_ipc_channels(self, ignorable_files=None):
        suspicious_paths = []
        ipc_dirs = ["/dev/shm", "/tmp", "/run"]
        current_uid = os.getuid()

        if ignorable_files is None:
            ignorable_files = []

        socket_usage_map = defaultdict(set)

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

                        if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
                            continue

                        if not (mode & 0o077):
                            continue

                        if st.st_uid != 0 and st.st_uid != current_uid:
                            continue

                        for proc in psutil.process_iter(['pid', 'name']):
                            pid = proc.info['pid']
                            fd_dir = f"/proc/{pid}/fd"
                            if not os.path.isdir(fd_dir):
                                continue
                            try:
                                for fd in os.listdir(fd_dir):
                                    fd_path = os.path.join(fd_dir, fd)
                                    try:
                                        if os.path.samefile(fd_path, full_path):
                                            socket_usage_map[full_path].add(pid)
                                    except FileNotFoundError:
                                        continue
                            except PermissionError:
                                continue

                        suspicious_paths.append(full_path)

                    except Exception:
                        continue

        return sorted(set(suspicious_paths)), socket_usage_map

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
                    print("[!] Could not access process")
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
    def get_existing_user_homes(self):
        user_homes = []

        if os.path.isdir("/root"):
            user_homes.append("/root")

        if os.path.isdir("/home"):
            for name in os.listdir("/home"):
                path = os.path.join("/home", name)
                if os.path.isdir(path):
                    user_homes.append(path)

        return user_homes

    def check_persistence(self, pid):
        user_home = self.get_existing_user_homes()
        try:
            p = psutil.Process(pid)
            exe_path = p.exe()
            full_path = get_path(p.cwd(), p.cmdline(), exe_path)
            if full_path:
                for home in user_home:
                    systemd_dir = os.path.join(home, ".config/systemd/user/")
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
                
                for home in user_home:
                    autostart_dir = os.path.join(home, ".config/autostart/")
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
                    for home in user_home:
                        sf_path = os.path.join(home, sf)
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
                return False, None

            else: 
                 return False, None

        except Exception as e:
            print(f"{e}")
            return False, None

    def check_cron_jobs(self, is_log=False):
        score = 0
        suspicious_entries = []

        sus_files = ["base64", "eval", "curl", "wget", ".py", "python", "node", "perl", ".sh"]
        suspicious_paths = ["/tmp/", "/dev/shm/", ".config/", "/.hidden/", ".local/", "/var/tmp/"]
        obfuscation_patterns = [
            r'(eval|exec|base64|echo|printf)\s+[\'\"]?[A-Za-z0-9+/=]{20,}[\'\"]?',
            r'python\s+-c\s+["\']import\s+base64',
            r'perl\s+-e\s+["\']eval',
            r'bash\s+-c\s+["\'].*base64.*["\']',
            r'\.\/\.\w+',
            r'(curl|wget).*(/tmp|/dev/shm)',
            r'>\s*\.\w+',
        ]
        job_pattern = re.compile(r'^\s*\*\s+\*\s+\*\s+\*\s+\*')

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

        def _scan_line_for_scripts(line):
            tokens = line.strip().split()
            found_script_paths = []
            for token in tokens:
                if token.startswith('/') or token.startswith('./') or token.endswith(('.sh','.py','.pl','.rb')):
                    if not re.fullmatch(r'\d+|\*|\*/\d+', token):
                        found_script_paths.append(token)
            return found_script_paths



        for file in cron_files:
            log(f"\033[1mChecking Cron file:\033[0m {file}", is_log)
            try:
                with open(file, "r") as f:
                    for line in f:
                        suspicious_signals = []
                        for word in suspicious_paths + sus_files:
                            if word in line:
                                suspicious_signals.append(word)
                        for pattern in obfuscation_patterns:
                            if re.search(pattern, line):
                                suspicious_signals.append(f"pattern:{pattern}")
                        if job_pattern.search(line):
                            suspicious_signals.append("runs every minute")
                        script_paths = list(set(_scan_line_for_scripts(line)))
                        script_sus = []
                        for script_path in script_paths:
                            abs_path = script_path
                            if script_path.startswith('./'):
                                abs_path = os.path.abspath(os.path.join(os.path.dirname(file), script_path))
                            if os.path.exists(abs_path) and os.path.isfile(abs_path):
                                h_output = has_suspicious_modules(abs_path, load_sus_libraries())
                                if h_output:
                                    for libs, _ in h_output.items():
                                        if libs:
                                            suspicious_signals.append(f"script:{abs_path}")
                                            script_sus.append((abs_path, libs))
                        if suspicious_signals and script_sus:
                            entry = {
                                "file": file,
                                "line": line.strip(),
                                "signals": suspicious_signals,
                                "script_hits": script_sus,
                            }
                            suspicious_entries.append(entry)
                            score += 1
            except Exception as e:
                print(f"[cron error] {e}")

        return score, suspicious_entries

    def list_user_rc_files(self):
        user_home = self.get_existing_user_homes()
        all_rc_files = []

        for home in user_home:
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
                files.extend(
                    os.path.join(profile_dir, p_file) for p_file in os.listdir(profile_dir)
                )

            all_rc_files.extend([f for f in files if os.path.isfile(f)])
        return all_rc_files

    def check_ld_preload(self, pid=None, files_to_check=None):
        score = 0
        found_pids = set()
        if pid:
            try:
                p = psutil.Process(pid)
                env = p.environ()
                if "LD_PRELOAD" in env:
                    score += 1
            except Exception as e:
                print(f"{e}")
        else:
            try:
                for p in psutil.process_iter(['pid', 'environ']):
                    env = p.environ()
                    if "LD_PRELOAD" in env:
                        score = 1
                        found_pids.add(p.pid)

            except Exception as e:
                print(f"{e}")

        if files_to_check:
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

        return score, found_pids

class NetworkMonitor:
    #TODO:
    # if a process is opening sudden connections
    # if it is making outbound connections
    # if a process is doing any port-forwarding -> no idea how to approach this
    # not a very effective way - since a process could still mask as from white listed ports or paths
    def check_network_activity(self, input_pid, timeout):
        conn_count = defaultdict(int)

        try:
            for _ in range(timeout):
                try:
                    conn = psutil.net_connections(kind='inet')
                    for i in conn:
                        if i.status == 'ESTABLISHED' and i.raddr and i.pid:
                            conn_count[i.pid] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print("[!] Failed to get the process details during scan")
                    return False, None
                time.sleep(1)
        except Exception as e:
            print(f"[!] Unexpected failure in network activity scan: {e}")
            return False, None

        try:
            conn = psutil.net_connections(kind='inet')
        except Exception:
            print("[!] Failed to get final connections")
            return False, None

        for i in conn:
            if input_pid == i.pid and i.status is not None:
                for pid in conn_count:
                    if pid == i.pid and i.raddr:
                        ip = i.raddr.ip
                        try:
                            if not ipaddress.ip_address(ip).is_private:
                                p = psutil.Process(pid)
                                path = p.exe()

                                if any(path.startswith(sus_path) for sus_path in suspicious_paths):
                                    return True, ip
                                return False, None
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            print("[!] Failed to access process info")
                            return False, None

        return False, None

bpf_file = "bpf_output.json"
or_file = "test.json"

class BPFMONITOR:
    def __init__(self, bpf_file, timeout=5):
            self.proc = None
            self.timeout = timeout
            self.bpf_file = bpf_file
            atexit.register(self.stop)

    def start(self):
        if not os.path.exists('./loader'):
            print("Error: ./loader binary not found in current directory!")
            return
        
        if not os.access('./loader', os.X_OK):
            print("Error: ./loader is not executable!")
            return
        
        open(self.bpf_file, "w").close()
        
        try:
            self.proc = subprocess.Popen(
                ['sudo', './loader'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self._timer = threading.Timer(self.timeout, self.stop)
            self._timer.daemon = True
            self._timer.start()
            
        except Exception as e:
            print(f"Failed to start BPF binary: {e}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
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

            data = set()
            with open(or_file, "r") as f:
                lines = f.readlines()
                for line in lines:
                    entry = json.loads(line)
                    p = entry.get("pid")
                    device_name = entry.get("device_path")
                    if p and device_name:
                        data.add((p, device_name))
                    else:
                        continue
                return data

        except FileNotFoundError:
            print(f"[!] File not found: {bpf_file}")
        except Exception as e:
            print(f"[!] {e}")

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
                        return False
        except FileNotFoundError:
            return False
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
                print(f"[!] Failed to open file: {e}")
            time.sleep(1)
        return False


def get_binary_info(full_path):
    try:
        pkg_managers = ["apt", "dnf", "yum", "pacman", "zypper", "apk"]
        for pm in pkg_managers:
            if shutil.which(pm):
                result = None
                if pm == "apt":
                    result = subprocess.run(["dpkg", "-S", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm in ["dnf", "yum", "zypper"]:
                    result = subprocess.run(["rpm", "-qf", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm == "pacman":
                    result = subprocess.run(["pacman", "-Qo", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif pm == "apk":
                    result = subprocess.run(["apk", "info", "-W", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result is not None:
                    return result.returncode == 0
        return False
    except Exception:
        return False



def has_suspicious_modules(binary, lib_scores):
    try:
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

        patterns = {
            lib_name: re.compile(r'\b' + re.escape(lib_name.lower()) + r'\b')
            for lib_name in lib_scores
        }

        found_libs = {}
        found_keylogger = False

        for line in lines():
            for lib_name, pattern in patterns.items():
                if lib_name not in found_libs and pattern.search(line):
                    score = lib_scores[lib_name]
                    found_libs[lib_name] = score
                    if score >= 4:
                        found_keylogger = True

        if found_keylogger:
            return found_libs

        return None

    except Exception:
        return None



def has_suspicious_strings(binary_path):
    path_patterns = [
        r"/dev/input/event\d+",
        r"libx11\.so",
        r"libxtst\.so",
        r"keyboard\.h",
    ]
    word_patterns = [
        r"xopendisplay",
        r"xquerykeymap",
        r"xrecordcreatecontext",
        r"keylogger",
        r"keystroke",
        r"grab_keyboard",
        r"raw_input",
        r"input_event",
        r"keypress",
        r"log_keys",
        r"sendinput",
        r"recordkey",
        r"input_log",
        r"keyboard_read",
        r"hook_keyboard",
    ]

    try:
        output = subprocess.check_output(
            ["strings", binary_path],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5
        ).lower()

        for pattern in path_patterns:
            if re.search(pattern, output):
                return True, pattern.encode()

        for word in word_patterns:
            pattern = r'\b' + word + r'\b'
            if re.search(pattern, output):
                return True, word.encode()

    except Exception as e:
        print(f"[!] Failed to scan {binary_path}: {e}")
    return False, None

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


def get_file_hash(path):
    try:
        h = hashlib.md5()
        with open(path, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    h.update(data)
        file_hash = h.hexdigest()
        return file_hash
    
    except Exception as e:
        print(f"[!] Failed to hash: {e}")
        return False

def hash_and_save(path, pid, name, score, ist: bool):
    try:
        h = hashlib.md5()
        with open(path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
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

        if any(e.get("md5 hash") == file_hash for e in data):
            return True

        data.append(entry)
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        return True

    except Exception as e:
        print(f"[!] Failed to hash and save: {e}")
        return False

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
    p = None
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=5)
        print("Job Done.")
    except psutil.NoSuchProcess:
        print(f"No such process with PID {pid}.")
    except psutil.TimeoutExpired:
        if p:
            p.kill()
            print(f"Timeout: Process {pid} did not terminate within the timeout.")
            print(f"Process {pid} forcefully terminated.")
    except psutil.AccessDenied:
        print(f"Access denied to kill {pid}.")


# idea is to find a suspicious input device based on heuristics, - will have to improve in future
def is_suspicious_input_device():
    sus_paths = {"/tmp", "/var/tmp", "/dev/shm"}
    context = pyudev.Context()
    suspicious_devices = []
    now = time.time()

    def is_owned_by_root(dev_node):
        try:
            stat_info = os.stat(dev_node)
            return stat_info.st_uid == 0
        except Exception:
            return False

    def get_process_info(pid):
        try:
            p = psutil.Process(int(pid))
            exe = p.exe()
            cmdline = " ".join(p.cmdline())
            create_time = p.create_time()
            exec_path_suspicious = any(exe.startswith(bp) for bp in sus_paths)
            return {
                "pid": pid,
                "exe": exe,
                "cmdline": cmdline,
                "create_time": create_time,
                "exec_path_suspicious": exec_path_suspicious
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            return None

    for dev in context.list_devices(subsystem="input"):
        dev_node = dev.device_node or ""
        dev_path = dev.device_path or ""

        if not dev_node.startswith("/dev/input/"):
            continue

        if not dev_path.startswith("/devices/virtual/input/"):
            continue

        if dev.get("POWER_SUPPLY_NAME") or dev.get("ID_PATH") == "platform-wmi":
            continue

        if dev.get("ID_INPUT_KEY") != "1" and dev.get("ID_INPUT_MOUSE") != "1":
            continue

        vendor = dev.get("ID_VENDOR", "unknown")
        model = dev.get("ID_MODEL", "unknown")
        dev_name = dev.get("NAME", "").strip("\"")
        bus = dev.get("ID_BUS", "unknown")

        bus_virtual = (bus.lower() == "virtual")

        try:
            dev_stat = os.stat(dev_node)
            device_age_sec = now - dev_stat.st_ctime
        except Exception:
            device_age_sec = None

        accessing_processes = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            fd_dir = f"/proc/{pid}/fd"
            if not os.path.isdir(fd_dir):
                continue
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(fd_path)
                        if target == dev_node:
                            pinfo = get_process_info(pid)
                            if pinfo:
                                accessing_processes.append(pinfo)
                    except OSError:
                        pass
            except PermissionError:
                continue

        suspicious_procs = []
        for proc in accessing_processes:
            proc_age = now - proc["create_time"]
            if proc["exec_path_suspicious"] or proc_age < 600:  # < 10 min, will think, whether to reduce it
                suspicious_procs.append(proc)

        suspicious_reasons = []
        if bus_virtual:
            suspicious_reasons.append("Bus type is virtual")
        if name_blacklisted := (dev_name in {"Test Virtual Keyboard", "VirtualBox USB Tablet", "VMware Virtual USB Keyboard"}):
            suspicious_reasons.append(f"Device name '{dev_name}' is blacklisted")
        if device_age_sec is not None and device_age_sec < 60:
            suspicious_reasons.append("Device created less than 1 minute ago")
        if not is_owned_by_root(dev_node):
            suspicious_reasons.append("Device not owned by root user")

        if suspicious_procs:
            suspicious_reasons.append(
                "Accessed by suspicious process(es): " +
                ", ".join(f"{proc['exe']} (PID {proc['pid']})" for proc in suspicious_procs)
            )
        elif accessing_processes:
            suspicious_reasons.append(
                "Accessed by process(es): " +
                ", ".join(f"{proc['exe']} (PID {proc['pid']})" for proc in accessing_processes)
            )
        else:
            suspicious_reasons.append("No process currently accessing device")

        is_suspicious = (
            bus_virtual or
            name_blacklisted or
            (device_age_sec is not None and device_age_sec < 60) or
            len(suspicious_procs) > 0 or
            not is_owned_by_root(dev_node)
        )

        if is_suspicious:
            suspicious_devices.append({
                "device_node": dev_node,
                "device_name": dev_name,
                "vendor": vendor,
                "model": model,
                "bus": bus,
                "device_age_sec": device_age_sec,
                "owned_by_root": is_owned_by_root(dev_node),
                "accessing_processes": accessing_processes,
                "suspicious_processes": suspicious_procs,
                "reasons": suspicious_reasons
            })

    if suspicious_devices:
        return True, suspicious_devices
    else:
        return False, None



# TODO: theory is that a malicious file could run in memory without writing to disk
# we could monitor them using bpf, initial idea is to capture these - memfd_create, execveat
memfd_out_file = "memfd_create_output.json"
def run_fileless_execution_loader(timeout=10, binary="./fe_loader", out_file="memfd_create_output.json"):
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

    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            pass


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
        if not full_path or skip_current_pid(full_path, pid):
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

        rt_value, out = bi.check_file_authenticity(None, full_path=full_path, pid=pid)
        if rt_value:
            reasons.append(out)
            sus_score += 2
        
        if bi.is_upx_packed(full_path) or bi.is_deleted_on_disk(pid):
            sus_score += 1
            reasons.append("binary is upx packed")

        if bi.is_deleted_on_disk(pid):
            sus_score += 1
            reasons.append("binary is deleted on disk")

        # cron_job_score = pc.check_cron_jobs()
        # if cron_job_score >= 2:
        #     sus_score += 2
            
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

        h_output = has_suspicious_modules(full_path, sus_libraries)
        if h_output:
            sus_score += 2
            for library in h_output:
                reasons.append(f"Contains suspicious modules: {library}")

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

        if sus_score >= 2:
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

from random import choices
import string
import threading

def bpf_monitor_with_something(bpf):
    code = ''.join(choices(string.ascii_uppercase + string.digits, k=5))
    print(f"\nType this code for more accurate results (or press Enter to skip): {code}")

    bpf.start()
    
    user_input = input("> ").strip()

    if not user_input:
        return False
    elif user_input == code:
        return True
    elif user_input !=code:
        return True
    else:
        return False


def scan_process(is_log=False, target_pid=None, scan_all=False):
    log("Initializing analyzers", is_log)
    i = InputMonitor()
    input_access_pids = i.get_process_using_input_device()
    bpf = BPFMONITOR(bpf_file, 5)
    x = X11Analyzer()
    ba = BinaryAnalyzer()
    fm = FileMonitor()
    pc = PersistenceChecker()
    ipc = IPCScanner()
    nm = NetworkMonitor()

    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning Started.")
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Getting Process details.")

    if scan_all:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning all processes, including those marked as trusted.")
    else:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Skipping processes trusted by program heuristics or user configuration.")

    log("Starting monitoring using BPF for 5 seconds", is_log)
    captcha_result = bpf_monitor_with_something(bpf)

    if not captcha_result:
        bpf.start()
        time.sleep(bpf.timeout)

    log("BPF monitoring stopped.", is_log)


    sockets, _ = ipc.detect_suspicious_ipc_channels()
    log(f"Detected {len(sockets)} suspicious IPC socket(s):", is_log)
    
    for sock in sockets:
        log(f"{sock}", is_log)

    out = k.get_device_names_from_bpf_file()
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} PIDs accessing input devices (keyboard/event) and terminals (pts):")

    if out:
        for p, d in sorted(out):
            log(f"PID {p} -> {d}", is_log)
    

    if input_access_pids and is_log:
        for input_pid in input_access_pids:
               log(f"PID {input_pid} -> /dev/input/*", is_log)
    


    fullpaths = {}
    parent_map = {}
    reasons_by_pid = defaultdict(set)
    suspicious_candidates = set()
    trusted_paths = set()
    unrecognized_paths = set()
    suspicious_pids = set()

    try:
        if target_pid is not None:
            try:
                print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning PID - {target_pid}")
                try:
                    p = psutil.Process(target_pid)
                    path = get_path(p.cwd(), p.cmdline(), p.exe())

                    details = [
                        f"PID  : {p.pid}",
                        f"Name : {p.name()}",
                        f"Path : {path}",
                    ]
                    maxlen = max(len(line) for line in details)
                    border = "+" + "-"*(maxlen+2) + "+"

                    print("\nProcess Details")
                    print(border)
                    for line in details:
                        print(f"| {line.ljust(maxlen)} |")
                        print(border)
                    print()

                except psutil.NoSuchProcess as e:
                    print(f"{e}")

                p = psutil.Process(target_pid)
                path = get_path(p.cwd(), p.cmdline(), p.exe())
                choice = input("> Proceed furthur? (y/n): ").strip()
                if choice == 'Y' or choice == 'y':
                    confidence, access_rate = x.check_x11_connection(target_pid)
                    o_reasons = ba.check_obfuscated_or_packed_binaries(target_pid)
                   
                    if o_reasons:
                        suspicious_candidates.add(target_pid)
                        for reason in o_reasons:
                            reasons_by_pid[target_pid].add(reason)
                            log(f"PID - {target_pid} {reason}", is_log)

                    if confidence >= 3 and access_rate > 0:
                        suspicious_candidates.add(target_pid)
                        reasons_by_pid[target_pid].add("Has input access through X11")
                        log(f"X11 access activity detected for PID {target_pid} (confidence: {confidence}, rate: {access_rate})", is_log)
                    parent_map[target_pid] = p.ppid()

                    if target_pid in input_access_pids:
                        suspicious_candidates.add(target_pid)
                        reasons_by_pid[target_pid].add("Has direct input access")
                        if target_pid is not None and bpf.check_pid(target_pid):
                            reasons_by_pid[target_pid].add("Accessing Input Devices confirmed using - BPF")
                            if target_pid is not None:
                                print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Input Devices access detected using BPF for PID - {target_pid}")

                    if path:
                        fullpaths[target_pid] = path
                        if sockets:
                            for file in sockets:
                                result, reason_list = ba.check_file_authenticity(file, path, target_pid)
                                if not result:
                                    trusted_paths.add(path)
                                else:
                                    unrecognized_paths.add(path)
                                    suspicious_pids.add(target_pid)
                                    for reason in reason_list:
                                        reasons_by_pid[target_pid].add(reason)
                else:
                    print("[*] Exiting..")
                    exit(0)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"[!] PID {target_pid} is not accessible.")
                return
        else:
            run_fileless_execution_loader()
            print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Trying to find KeyLogger(s)")
            for p in psutil.process_iter(['pid', 'ppid']):
                try:
                    cwd = p.cwd()
                    cmdline = p.cmdline()
                    exe = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        log(f"Skipped PID {p.pid} (could not access CWD/cmdline/exe)", is_log)
                        continue

                path = get_path(cwd, cmdline, exe)
                if path:
                    if skip_current_pid(path, p.pid):
                        continue
                try:
                    if not scan_all:
                        if path:
                            file_hash = get_file_hash(path)
                            if pid_is_trusted(p.pid, file_hash):
                                continue

                    confidence, access_rate = x.check_x11_connection(p.pid)
                    if confidence >= 3 and access_rate > 0:
                        suspicious_candidates.add(p.pid)
                        reasons_by_pid[p.pid].add("Has input access through X11")
                        log(f"X11 access activity detected for PID {p.pid}", is_log)
                    

                    if bpf.check_pid(p.pid):
                        reasons_by_pid[p.pid].add("Accessing Input Devices confirmed using - BPF")
                        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Input Devices access detected using BPF for PID {p.pid}")

                    parent_map[p.pid] = p.ppid()

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    log(f"Skipped PID {p.pid} (process not accessible)", is_log)
                    continue
    
            for pid in input_access_pids:
                suspicious_candidates.add(pid)
                reasons_by_pid[pid].add("Has direct input access")
           
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
                    log(f"Skipping PID {pid} (process unavailable)", is_log)
                    continue
            
            # No idea, why did I create a separate ebpf binary for finding process that run in memory when our main goal was to find processes that access /dev/input and others.. will think about this
            # mem_pids = read_memfd_events()
            # if mem_pids:
            #     print(mem_pids)
            #     for m_pid in mem_pids:
            #         suspicious_candidates.add(m_pid)
            #         reasons_by_pid[m_pid].add("Running directly From Memory")
            #         log(f"Running directly from memory with PID {m_pid}", is_log)
        
        for sp in suspicious_pids:
            log(f"Reporting phase started for suspicious PID's {sp}", is_log)
        
        if target_pid:
            check_and_report(fullpaths, trusted_paths, unrecognized_paths,
                         suspicious_pids, reasons_by_pid, parent_map,
                         ba, fm, pc, nm, scan=True, s_pid=True)
        else:
            check_and_report(fullpaths, trusted_paths, unrecognized_paths,
                         suspicious_pids, reasons_by_pid, parent_map,
                         ba, fm, pc, nm, scan=True, s_pid=False)

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user. Exiting...")



def check_and_report(fullpaths, trusted_paths, unrecognized_paths, suspicious_pids, reasons_by_pid, parent_map, ba, fm, pc, nm, scan=False, s_pid=False, is_log_enabled=False):
    if trusted_paths and scan and not s_pid:
        print()
        print("\033[1;34m┌" + "─" * 58 + "┐\033[0m")
        print("\033[1;34m│" + "Trusted Processes Using Input Devices".center(58) + "│\033[0m")
        print("\033[1;34m└" + "─" * 58 + "┘\033[0m")

        trusted_list = sorted(set(trusted_paths))
        for idx, path in enumerate(trusted_list, 1):
            group = "System" if path.startswith("/usr") else "User"
            symbol = "╰─" if idx == len(trusted_list) else "├─"
            print(f" {symbol} {path} (\033[1;36m{group}\033[0m)")

    if unrecognized_paths and scan and not s_pid:
        print()
        print("\033[1;34m┌" + "─" * 58 + "┐\033[0m")
        print("\033[1;34m│" + "Unrecognized Processes Using Input Devices".center(58) + "│\033[0m")
        print("\033[1;34m└" + "─" * 58 + "┘\033[0m")

        unrec_list = sorted(set(unrecognized_paths))
        for idx, path in enumerate(unrec_list, 1):
            symbol = "╰─" if idx == len(unrec_list) else "├─"
            print(f" {symbol} {path}")

    if suspicious_pids and scan and not s_pid:
        print()
        print("\033[1;34m┌" + "─" * 58 + "┐\033[0m")
        print("\033[1;34m│" + "Running Checks on Unrecognized Processes".center(58) + "│\033[0m")
        print("\033[1;34m└" + "─" * 58 + "┘\033[0m")

        checks = [
            "Process has any suspicious strings",
            "Process reading/writing to any file",
            "Process has opened any foreign connections",
            "Process is persistent"
        ]

        for idx, c in enumerate(checks, 1):
            symbol = "╰─" if idx == len(checks) else "├─"
            print(f" {symbol} {c}")



    for pid in list(suspicious_pids):
        if fm.check_file_activity(pid, 1):
            reasons_by_pid[pid].add("Has file Input/Output")

    for pid in list(suspicious_pids):
        rt, out = pc.check_persistence(pid)
        if rt:
            reasons_by_pid[pid].add(f"is persistent: {out}")

    for pid in list(suspicious_pids):
        rt, ip = nm.check_network_activity(pid, 5)
        if rt and ip:
            reasons_by_pid[pid].add(f"has foreign connections: {ip}")

    for pid in list(suspicious_pids):
        path = fullpaths.get(pid)
        if path:
            rt, string_name = has_suspicious_strings(path)
            if rt and string_name:
                reasons_by_pid[pid].add(f"has suspicious strings: {string_name}")

    high_sus_string_pids = []
    normal_suspects = []
    sus_scores = {}
    child_group = defaultdict(list)
    
    for pid in suspicious_pids:
        path = fullpaths.get(pid)
        if path:
    
            h_output = has_suspicious_modules(path, load_sus_libraries())
            if h_output:
                for module_name, sus_score in h_output.items():
                    sus_scores[pid] = sus_score
                    if sus_score and module_name and sus_score >= 4:
                        high_sus_string_pids.append(pid)
                        reasons_by_pid[pid].add(f"has suspicious modules: {module_name}")
                    else:
                        normal_suspects.append(pid)

    final_suspects = list(set(high_sus_string_pids + normal_suspects))
    final_suspects = [pid for pid in final_suspects if pid in fullpaths]
    printed_pids = set()

    for pid in final_suspects:
        ppid = parent_map.get(pid)
        if ppid in final_suspects:
            child_group[ppid].append(pid)
        else:
            printed_pids.add(pid)

    # Single Pid part
    if s_pid:
        for pid in sorted(final_suspects):
            try:
                path = fullpaths.get(pid, '[unknown path]')
                binary = os.path.basename(path)
                ppid = parent_map.get(pid, None)
                parent_path = '[unknown]'
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_path = os.path.basename(parent.exe())
                    except Exception:
                        pass
                
                print()
                print("\033[1;31m┌" + "─" * 58 + "┐\033[0m")
                print("\033[1;31m│" + " POTENTIAL KEYLOGGER(S) DETECTED ".center(58) + "│\033[0m")
                print("\033[1;31m└" + "─" * 58 + "┘\033[0m")
              
                reason_list = sorted(reasons_by_pid.get(pid, []))
                if reason_list:
                    print(" ├─ \033[1;33mFlagged due to:\033[0m")
                    for idx, reason in enumerate(reason_list):
                        symbol = "╰─" if idx == len(reason_list) - 1 else "├─"
                        print(f" │  {symbol} {reason}")
                else:
                    print(" ├─ Reasons: None found")

                print("\n ├─ Binary Path:")
                print(f" │   {path}")

                if pid in child_group and child_group[pid]:
                    print("\n └─ Child Processes:")
                    for idx, child_pid in enumerate(sorted(child_group[pid])):
                        child_path = fullpaths.get(child_pid, '[unknown path]')
                        symbol = "╰─" if idx == len(child_group[pid]) - 1 else "├─"
                        print(f"     {symbol} PID {child_pid}: {child_path}")
                else:
                    print("\n └─ Child Processes: None")
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"[PID {pid}]  <process info unavailable>")


    if s_pid and not final_suspects:
        print(f"[*] No suspicious activity found in the given PID")
    
    # Sscan Part
    elif printed_pids and scan and not s_pid:
        print()
        print("\033[1;31m┌" + "─" * 58 + "┐\033[0m")
        print("\033[1;31m│" + " POTENTIAL KEYLOGGER(S) DETECTED ".center(58) + "│\033[0m")
        print("\033[1;31m└" + "─" * 58 + "┘\033[0m")

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
                        parent_status = "trusted" if parent_trust else "\033[1;31muntrusted\033[0m"
                        print(f"     ├─ Parent PID {ppid}: {parent_path} ({parent_status})")
                    except Exception:
                        print(f"     ├─ Parent PID {ppid}: <unknown>")

                    if pid in child_group and child_group[pid]:
                        for idx, child_pid in enumerate(sorted(child_group[pid])):
                            child_path = fullpaths.get(child_pid, '[unknown path]')
                            symbol = "└─" if idx == len(child_group[pid]) - 1 else "├─"
                            print(f"     ├─ Child PID {child_pid}: {child_path}")
                    else:
                        print("     ├─ Child Processes: None")

                    print("     ╭─ \033[1;33mFlagged due to:\033[0m")

                    for idx, reason in enumerate(reason_list):
                        symbol = "╰─" if idx == len(reason_list) - 1 else "├─"
                        print(f"     │  {symbol} {reason}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f" [PID {pid}]  <process info unavailable>")



    elif not printed_pids and scan:
        print("\n" + "-" * 50)
        print(" No suspicious keylogger activity found. ".center(50))
        print("-" * 50)


    # Monitor part
    elif not scan and not s_pid and printed_pids:
        print()
        print("\033[1;31m┌" + "─" * 50 + "┐\033[0m")
        print("\033[1;31m│" + " POTENTIALIAL KEYLOGGER(S) DETECTED ".center(50) + "│\033[0m")
        print("\033[1;31m└" + "─" * 50 + "┘\033[0m")

        for pid in sorted(printed_pids):
            path = fullpaths.get(pid, '[unknown path]')
            binary = os.path.basename(path)

            parent_path = '[unknown]'
            ppid = parent_map.get(pid, None)
            if ppid:
                try:
                    parent = psutil.Process(ppid)
                    parent_path = os.path.basename(parent.exe())
                except Exception:
                    pass

            print(f"\033[1;36mPID {pid}\033[0m: {binary} (Parent: {parent_path})")

            reason_list = sorted(reasons_by_pid.get(pid, []))
            print(" ├─ \033[1;33mFlagged due to:\033[0m")
            
            for idx, reason in enumerate(reason_list):
                symbol = "╰─" if idx == len(reason_list) - 1 else "├─"
                print(f" │  {symbol} {reason}")
            print()



def pid_is_trusted(pid, hash):
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return False
    
    for entry in data:
        if entry.get("pid") == str(pid) or entry.get("md5 hash") == str(hash) and entry.get("is trusted") is True:
            return True


# Initial stage: go through every running process, do some checks and if our confidence is pretty high and we are certain that it is a legit process then we hash and save it..
# Second stage: if else, will proceed with furthur checks to confirm if the process is a Keylogger, if yes - then we provide the user with option to kill it - 
# before that we hash it with a remark this is Keylogger for future comparisons
# Third stage: if we dont see any, then we keep looking for new process every few minutes and also go through all the checks for all the processes that we hashed - 
# just to be sure

# --monitor option
def phase_one_analysis(interval=5, is_log_enabled=False, scan_all=False):
    spinner = itertools.cycle(['-', '\\', '|', '/'])

    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Monitoring Started.")
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scan interval - {interval}s")
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Monitoring processes for suspicious activity.")

    if scan_all:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning all processes, including those marked as trusted.")
    else:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Skipping processes trusted by program heuristics or user configuration.")

    while True:
        i = InputMonitor()
        input_access_pids = i.get_process_using_input_device()
        sus_libraries = load_sus_libraries()
        parent_map = {}
        bpf = BPFMONITOR(bpf_file, 5)
        bpf.start()
        bpf.stop()
        path_check = set()
        for index, proc in enumerate(psutil.process_iter(['pid', 'cmdline', 'exe', 'cwd'])):
            pid = proc.info['pid']
            try:
                cwd = proc.cwd()
                cmdline = proc.cmdline()
                exe = proc.exe()
                fd = proc.num_fds()
                terminal = proc.terminal()
                username = proc.username()
                name = proc.name()
                uptime = time.time() - proc.create_time()
                parent_map[proc.pid] = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            p = get_path(cwd, cmdline, exe)
            if not p or skip_current_pid(p, pid):
                continue

            sys.stdout.write(f"\033[1G")
            sys.stdout.write(f"\033[1G{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning PID - {pid:<6} ({index}) {next(spinner)}")
            sys.stdout.flush()
            
            #TODO: have to think about whether to skip the processes that are already processed? 
            if not scan_all:
                file_hash = get_file_hash(p)
                proceed = not pid_is_trusted(pid, file_hash)
                hash_flag = True
            else:
                proceed = True
                hash_flag = False

            if proceed:
                output = r_process(input_access_pids, sus_libraries, pid, cwd, cmdline, exe, fd, terminal, username, uptime)

                if output and pid:
                    _, path, _, reasons = output
                    if path not in path_check:
                        path_check.add(path)
                        phase_two_analysis(pid, path, reasons, parent_map, input_access_pids, is_log_enabled)
                else:
                    if p:
                        if not hash_and_save(p, pid, name, 0, hash_flag):
                            print(f"[!] Failed to update {file_path}")

        print(f"\n{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Sleeping - {interval}s")
        time.sleep(interval)

def change_and_join(reasons):
    if isinstance(reasons, (list, tuple)):
        return " ".join(map(str, reasons))
    return str(reasons)

def phase_two_analysis(pid, path, reasons, parent_map, input_access_pids, is_log_enabled=False):

    bpf = BPFMONITOR(bpf_file, 5)
    x = X11Analyzer()
    ba = BinaryAnalyzer()
    fm = FileMonitor()
    pc = PersistenceChecker()
    ipc = IPCScanner()
    nm = NetworkMonitor()
    sockets = ipc.detect_suspicious_ipc_channels()

    fullpaths = {}
    parent_map = {}
    reasons_by_pid = defaultdict(set)
    suspicious_candidates = set()
    trusted_paths = set()
    unrecognized_paths = set()
    suspicious_pids = set()
    
    print()
    log(f"Detected {len(sockets)} suspicious IPC socket(s).", is_log_enabled)

    for r in reasons:
        reasons_by_pid[pid].add(change_and_join(r))

    confidence, access_rate = x.check_x11_connection(pid)
    if confidence >= 3 and access_rate > 0:
        suspicious_candidates.add(pid)
        reasons_by_pid[pid].add("Has input access through X11")
        log(f"Using X11 to access Input devices for PID - {pid}", is_log_enabled)

    for pid, input_device_path in input_access_pids.items():
        suspicious_candidates.add(pid)
        if is_log_enabled:
            reasons_by_pid[pid].add(f"Has Access to {input_device_path}")
        else:
            reasons_by_pid[pid].add("Has Input Access")

        output = bpf.check_pid(pid)
        if output:
            reasons_by_pid[pid].add("Input Access verified using - BPF")

            log(f"Input Devices access detected using BPF for PID {pid}", is_log_enabled)

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
            log(f"Skipping PID {pid} (process unavailable)", is_log_enabled)
            continue
    
    check_and_report(
        fullpaths,
        trusted_paths,
        unrecognized_paths,
        suspicious_pids,
        reasons_by_pid,
        parent_map,
        ba,
        fm,
        pc,
        nm,
        scan=False
    )

def prompt_user_trust_a_process():
    binary_name = input("> Please Enter the binary path (example: /usr/bin/ls): ").strip()

    if not os.path.exists(binary_name):
        print(f"[!] The binary path '{binary_name}' does not exist.")
        return

    user_choice = input("> Do you want to trust this binary? (y/n): ").strip().lower()
    if user_choice not in ['y', 'n']:
        print("[!] Invalid input. Please enter 'y' or 'n'.")
        return

    trust_flag = True if user_choice == 'y' else False

    print(f"[*] Checking if {binary_name} is currently running...")

    found_running = False

    for proc in psutil.process_iter(['pid', 'cmdline', 'cwd', 'exe']):
        try:
            full_path = get_path(proc.cwd(), proc.cmdline(), proc.exe())
            if full_path and os.path.samefile(full_path, binary_name):
                print(f"[*] {binary_name} is currently running with PID: {proc.pid}")
                if hash_and_save(full_path, proc.pid, binary_name, 0, trust_flag):
                    print(f"[SUCCESS] {'Trusted' if trust_flag else 'Untrusted'} status set for: {binary_name}")
                else:
                    print(f"[FAILED] Could not update trust status for: {binary_name}")
                found_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            print(f"[WARN] Error while inspecting a process: {e}")

    if not found_running:
        print(f"[*] {binary_name} is not running.")
        if hash_and_save(binary_name, None, binary_name, 0, trust_flag):
            print(f"[SUCCESS] {'Trusted' if trust_flag else 'Untrusted'} status set for: {binary_name}")
        else:
            print(f"[FAILED] Could not update trust status for: {binary_name}")

def intial_system_checks(is_log=False):
    pc = PersistenceChecker()
    

    print("┌" + "─" * 58 + "┐")
    print("│ This option (default) will perform the following checks: │")
    print("└" + "─" * 58 + "┘")

    checks = [
        "Find any suspicious input device based on heuristics",
        "Inspect user shell configuration (rc files) for suspicious patterns",
        "Analyze PAM authentication modules for credential logging risks",
        "Scan for suspicious shell command aliases",
        "Check user .inputrc files for malicious behaviour",
        "Review user cron jobs and scheduled tasks for persistence risks",
        "Use of LD_PRELOAD for process injection",
    ]

    for i, c in enumerate(checks, 1):
        print(f"{i}) {c}")

    print("\n\033[1mPlease use advanced options for more detailed analysis (see --help)\033[0m")
    print("-" * 60)

    answer = input("\033[1mEnter y\033[0m to continue, or any other key to exit: ").strip().lower()

    if answer != "y":
        print("Aborted by user.")
        sys.exit(0)


    print()
    print("="*60)
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Basic system checks started.".center(60))
    print("="*60)
    
    s_input_device, output = is_suspicious_input_device()
    
    if s_input_device:
        print("\033[1;31mSuspicious Input Device\033[0m .................... \033[1;31mWARNING\033[0m\n")
        
        if output:
            for i, dev in enumerate(output, 1):
                print(f"  ┌─ Device [{i}]: \033[1;37m{dev['device_node']} ({dev['device_name']})\033[0m")
                print(f"  │")
                print(f"  ├─ Vendor: {dev['vendor']}")
                print(f"  ├─ Model : {dev['model']}")
                print(f"  ├─ Bus   : {dev['bus']}")

                device_age = dev['device_age_sec']
                age_str = f"{device_age:.0f} seconds" if device_age is not None else "unknown"
                print(f"  ├─ Device age: {age_str}")

                print(f"  ├─ Owned by root: {'Yes' if dev['owned_by_root'] else 'No'}")

                print(f"  ├─ Reasons:")
                for reason in dev['reasons']:
                    print(f"  │    - {reason}")

                print(f"  ├─ Accessing process(es):")
                if dev['accessing_processes']:
                    for j, proc in enumerate(dev['accessing_processes']):
                        is_last_proc = (j == len(dev['accessing_processes']) - 1)
                        connector = "└─" if is_last_proc else "├─"
                        proc_age_min = (time.time() - proc.get('create_time', 0)) / 60
                        print(f"  │    {connector} {proc['exe']} (PID {proc['pid']}, Age: {proc_age_min:.1f} min)")
                else:
                    print(f"  │    No processes currently accessing this device")

                print(f"  │")
                print(f"  └─ \033[2mReview this input device - it exhibits suspicious traits and/or is accessed by suspicious processes.\033[0m\n")

    else:
        print("\033[1;32mSuspicious Input Device\033[0m .................... \033[1;32mOK\033[0m")



    history_patterns = [
        re.compile(r'history\s*>'),
        re.compile(r'history\s*>>'),
        re.compile(r'history\s*\|.*(tee|grep|cat|awk|sed).*'),
        re.compile(r'script\s+-q\s+.*'),
        re.compile(r'(ttyrec|asciinema)\s+'),
        re.compile(r'\b(logkeys|lkl|pykeylogger|keylogger)\b'),
        re.compile(r'\b(cat|dd|hexdump|od)\s+(/dev/input/event|/proc/bus/input/)'),
        re.compile(r'\b(xinput\s+test|xev|showkey|evtest|input-events)\b'),
        re.compile(r'LD_PRELOAD=.*\.so'),
        re.compile(r'(logkeys|xinput|xev|showkey|script).*[>&]+.*(/tmp/|/var/tmp/|/dev/shm/)'),
        re.compile(r'(logkeys|keylogger|pykeylogger).*&\s*$'),
        re.compile(r'(strace|ltrace).*-e.*(read|input|fgets).*'),
        re.compile(r'(xclip|xsel|pbpaste).*[>&]+'),
        re.compile(r'(cat|tail)\s+(~/.bash_history|~/.zsh_history|/var/log/.*history)'),
        re.compile(r'.*[>&]+\s*\.\S+'),
        re.compile(r'alias\s+precmd\s+.*history\s+-S'),
        re.compile(r'.*history\s+>>?\s*/tmp/.*'),
        re.compile(r'.*history\s+>>?\s*\.\w+'),
        re.compile(r'function\s+fish_prompt\s*.*history\s+-h'),
        re.compile(r'.*tee\s+.*history\s+.*'),
        re.compile(r'function\s+precmd\s*\(\)\s*{.*history\s+-a'),
        re.compile(r'.*\|\s*history\s+>>?.*'),
        re.compile(r'PS1\s*=\s*["\']?.*history\s+-a'),
        re.compile(r'.*history\s+-w\s+.*'),
        re.compile(r'.*HISTFILE\s*=\s*/tmp/.*'),
        re.compile(r'.*HISTFILE\s*=\s*\.\w+'),
        re.compile(r'PROMPT_COMMAND\s*=\s*["\']?.*history\s+-a'),
        re.compile(r'precmd\s*\(\)\s*{.*history\s+.*}'),
        re.compile(r'PROMPT_COMMAND\s*=\s*["\']?[^"\']*;?\s*history\s+-a[^"\']*["\']?'),
        re.compile(r'(sudo\s+)?history\s+-a'),
    ]
    
    rc_files = pc.list_user_rc_files()
    found = False
    suspicious_rc_files = []

    if rc_files:
        log("Checking for any suspicious strings in rc files", is_log)
        for file in rc_files:
            if is_log:
                sys.stdout.write(f"\033[1G{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')}  Checking RC File - {file}\n")
                sys.stdout.flush()

            try:
                file_issues = []
                with open(file, "r") as f:
                    for line_no, line in enumerate(f, 1):
                        matched_patterns = []
                        for pattern in history_patterns:
                            if pattern.search(line):
                                matched_patterns.append("shell history abuse")
                                found = True
                        
                        if matched_patterns:
                            file_issues.append((line_no, line.strip(), matched_patterns))
                
                if file_issues:
                    suspicious_rc_files.append((file, file_issues))
                    
            except Exception as e:
                suspicious_rc_files.append((file, [("ERROR", str(e), ["read error"])]))
                found = True

    if found:
        print("\033[1;31mRC Files\033[0m ................................... \033[1;31mWARNING\033[0m")
        print()
        print("  ┌─ Shell History Abuse Detected")
        
        for i, (rc_file, issues) in enumerate(suspicious_rc_files, 1):
            print(f"  │")
            print(f"  ├─ \033[1;37m[{i}] {rc_file}\033[0m")
            
            for j, (line_no, content, patterns) in enumerate(issues):
                is_last_issue = (j == len(issues) - 1)
                connector = "└─" if is_last_issue else "├─"
                
                if line_no == "ERROR":
                    print(f"  │  {connector} \033[1;31mRead Error:\033[0m {content}")
                else:
                    flags = ", ".join(patterns)
                    print(f"  │  {connector} Line \033[1;33m{line_no}\033[0m: {content}")
                    print(f"  │  {'  ' if is_last_issue else '│  '} \033[0mFlags:\033[0m {flags}")
        
        print("  │")
        print("  └─ \033[2mReview these RC files, could be used for capturing shell history and other malicious activity\033[0m")
        print()
    else:
        print("\033[1;32mRC Files\033[0m ................................... \033[1;32mOK\033[0m")

    pam_files = [
        "/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
        "/etc/pam.d/login", "/etc/pam.d/sshd", "/etc/pam.d/passwd"
    ]
    pam_patterns = [
        re.compile(r'^\s*session\s+.*pam_tty_audit\.so\s+.*enable='),
        re.compile(r'^\s*session\s+.*pam_tty_audit\.so\s+.*enable=.*log_password'),
        re.compile(r'^\s*auth\s+required\s+/lib.*pam_unix\.so\s+.*debug'),
        re.compile(r'^\s*auth\s+.*pam_exec\.so\s+.*'),
        re.compile(r'^\s*auth\s+.*pam_exec\.so\s+.*(?:/tmp/|/dev/shm/).*'),
        re.compile(r'^\s*auth\s+.*pam_exec\.so\s+.*command='),
        re.compile(r'^\s*auth\s+.*pam_python\.so\s+.*'),
        re.compile(r'^\s*auth\s+.*pam_exec\.so\s+.*sh\\b'),
        re.compile(r'^\s*auth\s+required\s+pam_permit\.so'),
        re.compile(r'^\s*(account|session)\s+required\s+pam_deny\.so'),
        re.compile(r'^\s*(auth|session|account)\s+.*\\.so\\s+/tmp/.*'),
        re.compile(r'^\s*auth\\s+.*pam_exec\\.so\\s+.*/\\.[^/]+/.*'),
        re.compile(r'^\s*auth\\s+.*pam_exec\\.so\\s+.*>>?\\s*\\.\\w+'),
    ]
    if is_log:
        print()
    log("Checking for any PAM abuses", is_log)
    found = False
    suspicious_pam_files = []

    for pam_file in pam_files:
        if os.path.isfile(pam_file):
            if is_log:
                sys.stdout.write(f"\033[1G{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Checking PAM File - {pam_file}\n")
                sys.stdout.flush()
                time.sleep(0.002)

            try:
                file_issues = []
                with open(pam_file, "r") as f:
                    for line_no, line in enumerate(f, 1):
                        matched_patterns = []
                        for pattern in pam_patterns:
                            if pattern.search(line):
                                matched_patterns.append("PAM keystroke logging")
                                found = True
                        
                        if matched_patterns:
                            file_issues.append((line_no, line.strip(), matched_patterns))
                
                if file_issues:
                    suspicious_pam_files.append((pam_file, file_issues))
                    
            except Exception as e:
                suspicious_pam_files.append((pam_file, [("ERROR", str(e), ["read error"])]))
                found = True

    if found:
        print("\033[1;33mPAM Authentication\033[0m ......................... \033[1;31mWARNING\033[0m")
        print()
        print("  ┌─ PAM Keystroke Logging Abuse Detected")
        
        for i, (pam_file, issues) in enumerate(suspicious_pam_files, 1):
            print(f"  │")
            print(f"  ├─ \033[1;37m[{i}] {pam_file}\033[0m")
            
            for j, (line_no, content, patterns) in enumerate(issues):
                is_last_issue = (j == len(issues) - 1)
                connector = "└─" if is_last_issue else "├─"
                
                if line_no == "ERROR":
                    print(f"  │  {connector} \033[1;31mRead Error:\033[0m {content}")
                else:
                    flags = ", ".join(patterns)
                    print(f"  │  {connector} Line \033[1;33m{line_no}\033[0m: {content}")
                    print(f"  │  {'   ' if is_last_issue else '│  '} \033[1;31mFlags:\033[0m {flags}")
        
        print("  │")
        print("  └─ \033[2mReview these PAM configurations, could be used for authentication logging\033[0m")
        print()
    else:
        print("\033[1;32mPAM Authentication\033[0m ......................... \033[1;32mOK\033[0m")

    log("Checking for suspicious command aliases", is_log)
    alias_patterns = [
    re.compile(r'alias\s+\w+\s*=.*(logkeys|lkl|keylogger|pykeylogger)'),
    re.compile(r'alias\s+\w+\s*=.*(xinput\s+test|xev|showkey)'),
    re.compile(r'alias\s+\w+\s*=.*(/dev/input/event|/proc/bus/input/)'),
    re.compile(r'alias\s+\w+\s*=.*(keylog|keystroke|inputlog|keypress)'),
    re.compile(r'alias\s+\w+\s*=.*(strace.*-e.*read.*event|ltrace.*input)'),
    re.compile(r'alias\s+\w+\s*=.*(script\s+-q|ttyrec|asciinema)'),
    re.compile(r'alias\s+\w+\s*=.*(xclip.*-o|xsel.*-o|pbpaste).*>'),
    ]
    direct_keylogger_patterns = [
    re.compile(r'(^|\s|;|&|\|)(logkeys|lkl|keylogger|pykeylogger)\s'),
    re.compile(r'(^|\s|;|&|\|)(xinput\s+test|xev|showkey)\s'),
    re.compile(r'(cat|dd|hexdump|od)\s+(/dev/input/event|/proc/bus/input/)'),
    re.compile(r'(xinput|xev|showkey|logkeys).*[>&]+.*(/tmp/|/var/tmp/|/dev/shm/)'),
    re.compile(r'(strace|ltrace).*-e.*(read|input).*event'),
    re.compile(r'(script|ttyrec|asciinema).*[>&]+.*\w+'),
    re.compile(r'(logkeys|keylogger|pykeylogger).*&\s*$'),
    ]
    
    found = False
    suspicious_rc_files = []
    for file in rc_files:
        try:
            file_issues = []
            with open(file, "r") as f:
                for line_no, line in enumerate(f, 1):
                    if line.strip() and not line.strip().startswith('#'):
                        matched_patterns = []

                        for i, pattern in enumerate(alias_patterns):
                            if pattern.search(line):
                                if i == 0:
                                    matched_patterns.append("keylogger alias")
                                elif i == 1:
                                    matched_patterns.append("X11 input alias")
                                elif i == 2:
                                    matched_patterns.append("/dev/input device alias")
                                elif i == 3:
                                    matched_patterns.append("keystroke logging alias")
                                elif i == 4:
                                    matched_patterns.append("input tracing alias")
                                elif i == 5:
                                    matched_patterns.append("session recording alias")
                                elif i == 6:
                                    matched_patterns.append("clipboard keylogger alias")
                        
                        for i, pattern in enumerate(direct_keylogger_patterns):
                            if pattern.search(line):
                                if i == 0:
                                    matched_patterns.append("direct keylogger execution")
                                elif i == 1:
                                    matched_patterns.append("direct X11 input monitoring")
                                elif i == 2:
                                    matched_patterns.append("direct /dev/device file reading")
                                elif i == 3:
                                    matched_patterns.append("keystroke capture to file")
                                elif i == 4:
                                    matched_patterns.append("direct input tracing")
                                elif i == 5:
                                    matched_patterns.append("direct session recording")
                                elif i == 6:
                                    matched_patterns.append("running keylogger in background")
                        
                        if matched_patterns:
                            file_issues.append((line_no, line.strip(), matched_patterns))
                            found = True
            
            if file_issues:
                suspicious_rc_files.append((file, file_issues))
                
        except Exception as e:
            suspicious_rc_files.append((file, [("ERROR", str(e), ["read error"])]))
            found = True

    if found:
        print("\033[1;31mShell Aliases\033[0m .............................. \033[1;31mWARNING\033[0m")
        print()
        print("  ┌─ Keylogger-Related Commands Detected")
        
        for i, (file_path, issues) in enumerate(suspicious_rc_files, 1):
            print(f"  │")
            print(f"  ├─ \033[1;37m[{i}] {file_path}\033[0m")
            
            for j, (line_no, content, patterns) in enumerate(issues):
                is_last_issue = (j == len(issues) - 1)
                connector = "└─" if is_last_issue else "├─"
                
                if line_no == "ERROR":
                    print(f"  │  {connector} \033[1;31mRead Error:\033[0m {content}")
                else:
                    flags = ", ".join(patterns)
                    print(f"  │  {connector} Line \033[1;33m{line_no}\033[0m: {content}")
                    print(f"  │  {'  ' if is_last_issue else '│  '} \033[0mFlags:\033[0m {flags}")
        
        print("  │")
        print("  └─ \033[2mReview these commands, could be keylogger\033[0m")
        print()
    else:
        print("\033[1;32mShell Aliases\033[0m .............................. \033[1;32mOK\033[0m")
    
    log("Checking ~/.inputrc for potential abuse", is_log)
    found = False
    suspicious_irc_files = []

    for home in pc.get_existing_user_homes():
        inputrc_path = os.path.join(home, ".inputrc")
        if os.path.isfile(inputrc_path):
            try:
                file_issues = []
                with open(inputrc_path, "r") as f:
                    for line_no, line in enumerate(f, 1):
                        if line.strip() and not line.strip().startswith('#'):
                            suspicious_patterns = []
                            line_lower = line.lower().strip()
                            
                            if "shell:" in line or "readline" in line:
                                suspicious_patterns.append("shell or readline usage")
                            
                            if any(pattern in line for pattern in ["`", "$("]):
                                suspicious_patterns.append("command substitution")
                            
                            if any(cmd in line_lower for cmd in ["exec", "system", "eval"]):
                                suspicious_patterns.append("command execution")
                            
                            if any(net in line_lower for net in ["wget", "curl", "nc", "netcat", "telnet"]):
                                suspicious_patterns.append("network tool usage")
                            
                            if any(proto in line_lower for proto in ["http://", "https://", "ftp://"]):
                                suspicious_patterns.append("Refering a URL")
                            
                            if any(path in line_lower for path in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                                suspicious_patterns.append("suspicious path")
                            
                            if any(cmd in line_lower for cmd in ["chmod", "chown", "sudo", "su"]):
                                suspicious_patterns.append("privilege or permission change")
                            
                            if len(line.strip()) > 50 and line.count('=') <= 2:
                                if all(c.isalnum() or c in '+/=' for c in line.strip()):
                                    suspicious_patterns.append("possible encoded content")
                            
                            if any(src in line_lower for src in ["source ", ". /"]):
                                suspicious_patterns.append("externally sourcing file")
                            
                            if suspicious_patterns:
                                file_issues.append((line_no, line.strip(), suspicious_patterns))
                                found = True
                
                if file_issues:
                    suspicious_irc_files.append((inputrc_path, file_issues))
                    
            except Exception as e:
                suspicious_irc_files.append((inputrc_path, [("ERROR", str(e), ["read error"])]))
                found = True

    if found:
        print("\033[1;31mInputrc Inspection\033[0m ......................... \033[1;31mWARNING\033[0m")
        print()
        print("  ┌─ Suspicious .inputrc Files Detected")
        
        for i, (inputrc_path, issues) in enumerate(suspicious_irc_files, 1):
            print(f"  │")
            print(f"  ├─ \033[1;37m[{i}] {inputrc_path}\033[0m")
            
            for j, (line_no, content, patterns) in enumerate(issues):
                is_last_issue = (j == len(issues) - 1)
                connector = "└─" if is_last_issue else "├─"
                
                if line_no == "ERROR":
                    print(f"  │  {connector} \033[1;31mRead Error:\033[0m {content}")
                else:
                    flags = ", ".join(patterns)
                    print(f"  │  {connector} Line \033[1;33m{line_no}\033[0m: {content}")
                    print(f"  │  {'  ' if is_last_issue else '│  '} \033[0mFlags:\033[0m {flags}")
        
        print("  │")
        print("  └─ \033[2mReview these, could be for a potential command injection and malicious activity\033[0m")
        print()
    else:
        print("\033[1;32mInputrc Inspection\033[0m ......................... \033[1;32mOK\033[0m")


    log("Checking Cron jobs for potential keyloggers", is_log)

    #TODO: need to add check for any suspicious strings.. but could create noice.. so have to think about it.
    _, susp_entries = pc.check_cron_jobs(is_log)
    
    if susp_entries:
        print("\033[1;31mCron Job Analysis\033[0m .......................... \033[1;31mWARNING\033[0m")
        print()
        print("  ┌─ Suspicious Cron Jobs Detected")
        
        for i, entry in enumerate(susp_entries, 1):
            source = entry.get("file") or f"user: {entry.get('user', 'unknown')}"
            print(f"  │")
            print(f"  ├─ \033[1;37m[{i}] {source}\033[0m")
            print(f"  │  ├─ Schedule/Command: \033[1;33m{entry['line']}\033[0m")
            
            if entry['signals']:
                print(f"  │  ├─ Flags: {', '.join(entry['signals'])}")
            
            if entry["script_hits"]:
                print(f"  │  └─ Suspicious Content:")
                for j, (spath, sus_string) in enumerate(entry["script_hits"]):
                    is_last_hit = (j == len(entry["script_hits"]) - 1)
                    connector = "└─" if is_last_hit else "├─"
                    print(f"  │     {connector} Script: {spath}")
                    print(f"  │     {'   ' if is_last_hit else '│  '} Pattern: {sus_string!r}")
            else:
                print(f"  │  └─ Flags: {', '.join(entry['signals'])}" if entry['signals'] else "")
        
        print("  │")
        print("  └─ \033[2mReview these entries\033[0m")
        print()
    else:
        print("\033[1;32mCron Job Analysis\033[0m .......................... \033[1;32mOK\033[0m")

    score, found_pids = pc.check_ld_preload()
    if score == 0:
        print("\033[1;32mLD_PRELOAD Usage\033[0m ...................................  \033[1;32mOK\033[0m")
        print("    No unusual or unauthorized usage detected.\n")
    elif score == 1:
        print("\033[1;33mLD_PRELOAD Usage\033[0m ........................... \033[1;33mPossible Issue\033[0m")
        print()
        print("  ┌─ Unusual LD_PRELOAD Usage Detected")
        bin_pid_map = collections.defaultdict(list)
        for pid in found_pids:
            try:
                p = psutil.Process(pid)
                binary_path = get_path(p.cwd(), p.cmdline(), p.exe())
                bin_pid_map[binary_path].append(pid)
            except Exception:
                continue
        
        for binary_path, pids in bin_pid_map.items():
            print(f"  │")
            print(f"  ├─ \033[1;37m{binary_path}\033[0m")
            print(f"  │  └─ Process Count: \033[1;33m{len(pids)}\033[0m")
            if len(pids) <= 3:
                print(f"  │     PIDs: {', '.join(str(pid) for pid in pids)}")
            else:
                shown = ', '.join(str(pid) for pid in pids[:3])
                print(f"  │     PIDs: {shown} ... (+{len(pids)-3} more)")
        
        print("  │")
        print("  └─ \033[2mUse -p PID for detailed analysis\033[0m")
        print()




def log(msg, is_log_enabled):
    if is_log_enabled:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        print(f"{timestamp} {msg}")


def parse_args():
    parser = argparse.ArgumentParser(description="Keylogger Detector that may work") 
    parser.add_argument('-p', type=int, help="-p takes an pid for Analyzing")
    parser.add_argument("--scan", action="store_true", help="Scan Mode")
    parser.add_argument("--monitor", action="store_true", help="Monitor Mode")
    parser.add_argument("--modify_trust", action="store_true", help="Modifies/Adds trust to a process")
    parser.add_argument("--log", action="store_true", help="Enable verbose logging")
    parser.add_argument(
    "--all",
    action="store_true",
    help="By default, trusted processes (based on heuristics or user input) are skipped. "
         "Use this flag to disable that behavior and scan all processes, including the trusted ones."
)
    return parser.parse_args()

if __name__ == "__main__":
    require_root()
    args = parse_args()
    m = BinaryAnalyzer()
    k = BPFMONITOR(bpf_file)
    banner = r"""
    ▄████████    ▄█   ▄█▄    ▄████████ ▄██   ▄    ▄█        ▄██████▄     ▄██████▄     ▄██████▄     ▄████████    ▄████████      
    ███    ███   ███ ▄███▀   ███    ███ ███   ██▄ ███       ███    ███   ███    ███   ███    ███   ███    ███   ███    ███      
    ███    █▀    ███▐██▀     ███    █▀  ███▄▄▄███ ███       ███    ███   ███    █▀    ███    █▀    ███    █▀    ███    ███      
    ▄███▄▄▄      ▄█████▀     ▄███▄▄▄     ▀▀▀▀▀▀███ ███       ███    ███  ▄███         ▄███         ▄███▄▄▄      ▄███▄▄▄▄██▀      
    ▀▀███▀▀▀     ▀▀█████▄    ▀▀███▀▀▀     ▄██   ███ ███       ███    ███ ▀▀███ ████▄  ▀▀███ ████▄  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀        
    ███          ███▐██▄     ███    █▄  ███   ███ ███       ███    ███   ███    ███   ███    ███   ███    █▄  ▀███████████      
    ███          ███ ▀███▄   ███    ███ ███   ███ ███▌    ▄ ███    ███   ███    ███   ███    ███   ███    ███   ███    ███      
    ███          ███   ▀█▀   ██████████  ▀█████▀  █████▄▄██  ▀██████▀    ████████▀    ████████▀    ██████████   ███    ███      
                ▀                                ▀                                                             ███    ███  
    """

    print("\033[1;34m" + banner + "\033[0m")

    if args.scan:
        try:
            scan_process(args.log, None, args.all)
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user. Exiting...")
    elif args.monitor:
        try:
            phase_one_analysis(10, args.log, args.all)
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user. Exiting...")
    elif args.p:
        try:
            scan_process(args.log, args.p, args.all)
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user. Exiting...")

    elif args.modify_trust:
        try:
            prompt_user_trust_a_process()
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user. Exiting...")
    else:
        intial_system_checks(args.log)
        # out = k.get_device_names_from_bpf_file()
        # # mem_pids = read_memfd_events()
     

