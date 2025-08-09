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
total_pids = set()

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
    """
    Monitors active input devices of /dev/input/ and get the processes that is using them.
    
    Methods:
    - get_active_input_devices():
        Returns a list of paths of active input event devices on the machine.

    - get_process_using_input_device():
        Scans all running processes and checks their open file descriptors(fd) against the input event devices.
        then creates a map of process PIDs that are accessing that specific input device in format of -  {pid: {device_path, ...}, ...}.

    - check_input_access_frequency(threshold, timeout):
        Tracks how frequently each process accesses input devices for a given period - (timeout).
        Also checks for each process's X11 activity using - check_x11_connection() function, and flags processes with confidence levels above a set `threshold`.
        Returns a list of suspicious processes, with the PID, type of activity ("evdev" for direct input device access, "x11" for potential keylogging activity like this - [(1, 'x11', 1, 2), (405, 'x11', 1, 1), (1083, 'evdev', 1),...]
        where x11 represent this - (pid, 'x11', x11_confidence, access_rate) and evdev part this - (pid, 'evdev', evdev_count).
        Haven't Used anywhere for some reason.. will look into it.
    """

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
        """
        Analyzes whether a process is connected to the X11 display server and using it for accessing input devices.

        Methods:
        - check_x11_connection(pid):
            Checks the given process(pid) for X11 activity by:
                - Listing socket fd's and match their inodes to active X11 Unix socket connections.
                - Checking the process's env variables for `XAUTHORITY` and `DISPLAY`.
                - Checking if the process has loaded X11-related libraries (like libX11.so or libXt.so).
            Calculates a confidence score:
                - Each matching signal (socket, environment variables, library) increases the confidence event_real.
                - The total number of active X11 sockets is reported as access_rate. 

            Returns:
                A tuple `(confidence, access_rate)` where:
                    - confidence: an integer score showing that the process is connected to or interacting with X11.
                    - access_rate: integer, the total count of X11 socket connections that we have detected.

        """

        #TODO: Find alt instead of using `ss`
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
    """
    A heuristical(don't know if this word exists) analysis that checks the parent or ancestor(grandparent processes) of a given PID to help us be more confident that if a process is a KeyLogger. It has:
    - known_safe_parents: A set of process names considered benign or expected as parents (e.g. 'systemd', 'sshd', etc.).
    - suspicious_parents: A set of process names that may indicate unusual or potentially risky process (e.g. 'cron', 'atd', 'Xorg', session managers, etc.).
    
    Methods:
      - get_parent_process(pid):
          Returns the direct parent process of the given PID as a psutil.Process object.
          Returns None if found nothing.

      - is_legitimate_parent(parent_process):
          Returns True if the given parent process name is listed among known safe parents process.
          Returns False if not in the list or if the parent process is None.

      - get_sus_parent_process(pid):
          Checks both the parent and grandparent of the given PID.
          Returns (True, reason) if either matches a suspicious parent name,
          (False, None) if None found.
    """
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
    """
    Analyzes the characteristics of binaries or running processes and whether to trust them,
    This uses a variety of heuristics to flag suspicious, obfuscated, or potentially* malicious files.

    Methods:
    - is_trusted_binary(path):
        Checks if a given binary meets trust criteria:
          * Is in system directories (e.g., /usr/bin, /bin, /sbin).
          * Owned by root.
          * Not world-writable (to prevent unauthorized modifications).
          * Recognized by system package manager.
        Returns (True, reasons) if all checks pass, otherwise (False, reasons) with explanations.

    - is_upx_packed(path):
        Checks if the binary is packed with UPX (a common packer used for obfuscation).
        Returns True if UPX-packed, False otherwise. -- dont know how impactful this is.. will have to do more testing.. as in write my own upx packed KeyLogger??

    - is_memory_loaded_or_deleted(pid):
        Checks if the executable of the given process has been deleted from disk but is still running in memory,
        which is often seen techniques in malware. -- haven't seen with KeyLoggers, maybe haven't explored enough??

    - check_file_entropy(file_path):
        Calculates the Shannon entropy of the binary file, which is elevated in highly obfuscated or packed executables.

    - check_packer_magic_bytes(path):
        Checks the binary header for magic byte sequences of well-known packers (UPX, MPRESS, ASPack, PECompact, etc.).
        Returns True and the packer name if a signature is found.

    - check_file_authenticity(file_path, full_path, pid=None):
        Performs in-depth checks to determine if the file is suspicious, using some of above methods:
          * Whether the binary/executable is in directories that are often used as malware drop zones (/tmp, /dev/shm, /var/tmp, etc.).
          * If the binary passes is_memory_loaded_or_deleted and `is_trusted_binary` function checks.
          * Permission and ownership analysis.
        Returns:
            (True, reasons, []) if suspicious,
            (False, [], trusted_reasons) if trusted,
            with reasons for the decision.

    - check_obfuscated_or_packed_binaries(pid=None):
        Uses all the helper functions that we have in the class, to find processes that are packed, or memory-deleted or 
        has high entropy, or display packer signatures-flags potential obfuscation and enables uss to do further checks.

    Example Outputs:
        - Trusted system binary: True, ["Binary is in a trusted system directory", "Binary is owned by root", ...]
        - Suspicious binary: False, ["Binary path is not in a trusted directory", "Binary not owned by root", ...]
        - Packed or obfuscated binary: ['is upx-packed', 'has high-entropy', ...]
    """

    def is_trusted_binary(self, path):
        reasons = []
        try:
            if not os.path.exists(path):
                reasons.append(f"Binary not found: {path}")
                return False, reasons

            st = os.stat(path)
            trusted_dirs = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/lib", "/lib64", "/usr/lib")

            if not path.startswith(trusted_dirs):
                reasons.append(f"Binary path is not in a trusted directory: {path}")
                return False, reasons
            else:
                reasons.append(f"Binary is in a trusted system directory: {path}")

            if st.st_uid != 0:
                reasons.append(f"Binary not owned by root (UID={st.st_uid})")
                return False, reasons
            else:
                reasons.append("Binary is owned by root")

            if (st.st_mode & 0o002):
                reasons.append("Binary is world-writable")
                return False, reasons
            else:
                reasons.append("Binary is not world-writable")

            if not get_binary_info(path):
                reasons.append("Binary not found in the system package manager database")
                return False, reasons
            else:
                reasons.append("Binary is registered with the system package manager")

            return True, reasons

        except Exception as e:
            reasons.append(f"Exception during trust check: {e}")
            return False, reasons

    def is_upx_packed(self, path):
        try:
            output = subprocess.check_output(['upx', '-t', path], stderr=subprocess.DEVNULL).decode()
            return 'OK' in output
        except:
            return False

    def is_memory_loaded_or_deleted(self, pid):
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            return "(deleted)" in exe_path or "memfd:" in exe_path
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
        trusted_reasons = []
        st = os.stat(full_path)

        def process_matches(proc):
            try:
                if file_path:
                    for file in proc.open_files():
                        if str(file_path) in str(file.path):
                            reasons.append(f"Process {proc.pid} has opened a socket : {file_path}")
                            return True
                trusted_reasons.append("No suspicious files or sockets opened by the process")

                if self.is_memory_loaded_or_deleted(pid):
                    reasons.append(f"Executable is memory-loaded or deleted: {full_path}")
                    return True
                trusted_reasons.append("Executable is loaded from disk (not memory-resident or deleted)")

                is_trusted, trust_reasons = self.is_trusted_binary(full_path)
                if not is_trusted:
                    reasons.extend(trust_reasons)
                    return True
                else:
                    trusted_reasons.extend(trust_reasons)

                if any(full_path.startswith(d) for d in suspicious_dirs):
                    reasons.append(f"Executable in suspicious directory: {full_path}")
                    return True
                trusted_reasons.append("Binary path not found in any suspicious directory")

                if full_path.startswith(("/usr", "/bin", "/sbin")) and st.st_uid != 0:
                    reasons.append(f"System binary not owned by root: {full_path}")
                    return True
                if full_path.startswith(("/usr", "/bin", "/sbin")) and st.st_uid == 0:
                    trusted_reasons.append("System binary is owned by root (expected)")

                if os.access(full_path, os.W_OK) and str(full_path) in suspicious_dirs:
                    reasons.append(f"Executable is writable: {full_path}")
                    return True
                trusted_reasons.append("Executable is not writable by this user")

            except Exception as e:
                reasons.append(f"Exception while analyzing process {proc.pid}: {e}")
                return False

            return False

        if pid is not None:
            try:
                proc = psutil.Process(pid)
                result = process_matches(proc)
                if result:
                    return True, reasons, []
                else:
                    return False, [], trusted_reasons
            except psutil.NoSuchProcess:
                return False, [f"PID {pid} does not exist"], []
        else:
            for proc in psutil.process_iter(['pid']):
                if process_matches(proc):
                    return True, reasons, []
            return False, [], trusted_reasons

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

                if self.is_memory_loaded_or_deleted(p_info['pid']):
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
    """
    Scans for suspicious inter process communication (IPC) channels such as sockets and FIFOs.

    Methods:
      - detect_suspicious_ipc_channels(ignorable_files=None):
            Scans the directories /dev/shm, /tmp, and /run for IPC files (UNIX sockets or FIFOs) that:
                * Are world-readable/writable.
                * Are owned by root or the current user.
                * Are not in the provided ignorable_files list.
            
            For each IPC file found, it also checks if any processes have that channel opened by checking all process fd's.

            Returns:
                - A sorted list of suspicious IPC paths.
                - A dictionary mapping each suspicious IPC path to a set of PIDs that are currently using (have open) that file.
    """
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
    """
    Monitors a specific process (by PID) for file activity within a given timeout window.

    Method:
      - check_file_activity(pid, timeout):
            Watches all currently opened files by the process.
            Uses inotify to monitor these files for any write, modify, create, or open events.
            Returns True as soon as file activity (matching the events) is detected, or False if no activity is seen within the timeout set.
    """
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
    #Initial stages of this project, I for some reason wrote checks for only python KeyLogger's, so these are specific to python processes..

    """
    Checks whether specific libraries or modules are loaded by a process.

    Methods:
      - get_modules_using_py_spy():
            Uses 'py-spy dump' to inspect the modules loaded by a Python process.
            Returns like this - (found, logs):

      - get_libs_using_mem_maps():
            Reads /proc/[pid]/maps to check if any specified libraries are memory-mapped into the process.
            Returns list of found libraries.

      - get_modules_using_lsof():
            Uses 'lsof' to list all open files by the process, checking if any of the target libraries are open.
            Returns list of found libraries.

      - get_modules_using_pmap():
            Uses 'pmap' to enumerate the memory map of the process, searching for target libraries.
            Returns list of found libraries.
    """

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
    """
    Checks for evidence of a process being persistent, helps to spot keyloggers, or unwanted autostart behavior.

    Methods:
      - get_existing_user_homes():
            Returns a list of user home directory paths (including /root and all subdirs of /home).

      - check_persistence(pid):
            For a given PID, checks whether its executable path or command appears in:
              * systemd service definitions (~/.config/systemd/user/*.service)
              * User desktop autostart entries (~/.config/autostart/*.desktop)
              * Common shell/profile files (~/.bashrc, ~/.profile, ~/.xinitrc) in user homes
              * User level crontab
            Returns (True, evidence message) if found, (False, None) otherwise.

      - check_cron_jobs(is_log=False):
            Scans different cron configuration files like /etc/cron*, /var/spool/cron/ entries containing
            suspicious keywords - base64, curl, wget, python, suspicious paths - /tmp/, and obfuscation patterns.
            Returns (score, suspicious_entries) - the number and details of suspicious cron jobs or scripts found.

      - list_user_rc_files():
            Lists all shell/init files - .bashrc, .profile, .xinitrc, and system-wide rc/profile scripts

      - check_ld_preload(pid=None, files_to_check=None):
            Checks for usage of LD_PRELOAD
            Returns (score, found_pids) indicating if any detected persistence via LD_PRELOAD is present.
    """

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
    """
    Monitors network activity of a specific PID, tracking connections and behavior
    indicative of potential data export, remote C&C, or port forwarding.

    Method:
      - check_network_activity(input_pid, timeout):
        Observes the specified process (by PID) over a period (timeout).

        Checks for:
            - Outbound network connections to public (non-private) IP addresses.
            - Whether the process is both LISTENing for incoming connections and has an ESTABLISHED outgoing connection,

        Returns:
            {
                "outbound_ips": [list of non-private IP addresses the process has established connections to],
                "port_forwarding": boolean indicating suspected port forwarding/proxying behavior
            }

    """
    def check_network_activity(self, input_pid, timeout):
        conn_count = defaultdict(int)
        initial_conn = set()
        port_forwarding_detected = False

        try:
            for c in psutil.net_connections(kind='inet'):
                if c.pid == input_pid and c.status == 'ESTABLISHED':
                    initial_conn.add((c.laddr, c.raddr))
        except Exception as e:
            print(f"[!] Failed to fetch initial connections: {e}")
            return False, None, False

        try:
            for _ in range(timeout):
                try:
                    conn = psutil.net_connections(kind='inet')
                    for i in conn:
                        if i.status == 'ESTABLISHED' and i.raddr and i.pid:
                            conn_count[i.pid] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print("[!] Failed to get the process details during scan")
                    return False, None, False
                time.sleep(1)
        except Exception as e:
            print(f"[!] Unexpected failure in network activity scan: {e}")
            return False, None, False

        try:
            conn = psutil.net_connections(kind='inet')
        except Exception:
            print("[!] Failed to get final connections")
            return False, None, False

        outbound_ips = set()
        listens = False
        established = False

        for i in conn:
            if i.pid == input_pid:
                if i.status == 'ESTABLISHED' and i.raddr:
                    try:
                        ip = i.raddr.ip
                    except Exception:
                        ip = None
                    if ip and not ipaddress.ip_address(ip).is_private:
                        outbound_ips.add(ip)
                    established = True
                if i.status == 'LISTEN':
                    listens = True

        if listens and established:
            port_forwarding_detected = True

        return {
            "outbound_ips": list(outbound_ips),
            "port_forwarding": port_forwarding_detected
        }


bpf_file = "bpf_output.json"
or_file = "test.json"

class BPFMONITOR:
    """
    Controls and parses a userspace loader that activates an eBPF probe to monitor sensitive device accesses.

    - start(): Launches './loader' binary, which gathers data for a fixed period(timeout).
    - stop(): terminates the loader binary.
    - get_device_names_from_bpf_file(): Reads the loader binary output(bpf_output.json) - which has PID, major, minor and 
      convert the device numbers to its real paths (e.g., /dev/input/event*, /dev/pts/*, /dev/hidraw*), and returns a set of (PID, device_path) pairs.
    - check_pid(pid): Checks if the given PID is in bpf_output.json file.
    """

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

    # def check_device_type(self, pid, keyword, timeout=50):
    #     for _ in range(timeout):
    #         try:
    #             with open(or_file, "r") as f:
    #                 for line in f:
    #                     try:
    #                         entry = json.loads(line)
    #                         d_path = entry.get("device_path", "")
    #                         if pid == entry.get("pid") and keyword in d_path:
    #                             return True,d_path
    #                     except Exception as e:
    #                         print(f"[WARN] JSON decode error: {e}")
    #         except FileNotFoundError:
    #             pass
    #         except Exception as e:
    #             print(f"[!] Failed to open file: {e}")
    #         time.sleep(1)
    #     return False


def get_binary_info(full_path):
    """
    Checks if the given binary is recognized by Linux PM.
    Returns True if found, False otherwise.
    """
    pkg_managers = ["apt", "dnf", "yum", "pacman", "zypper", "apk"]
    try:
        for pm in pkg_managers:
            if shutil.which(pm):
                if pm == "apt":
                    cmd = ["dpkg", "-S", full_path]
                elif pm in ["dnf", "yum", "zypper"]:
                    cmd = ["rpm", "-qf", full_path]
                elif pm == "pacman":
                    cmd = ["pacman", "-Qo", full_path]
                elif pm == "apk":
                    cmd = ["apk", "info", "-W", full_path]
                else:
                    continue
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    return True
        return False
    except Exception:
        return False

def has_suspicious_modules(binary, lib_scores):
    """
    Scans a given binary file for the presence of suspicious modules, libraries,
    or keywords according to a dictionary of module names to 'suspicion scores'.

    - For script files (.py, .sh, .pl), reads each line of source.
    - For binaries, runs 'strings' to extract printable text and checks each line.
    - Uses regex to search for exact keyword/module/library names from lib_scores.

    Example:
        lib_scores = {'pyxhook':5, 'pynput':4, 'evdev':3, 'socket':2}
        result = has_suspicious_modules('/tmp/unknown_script.py', lib_scores)
        # result = {'pyxhook': 5} if pyxhook found in the file.
    """
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
    """
    Scans the output of 'strings' on a binary for finding suspicious keywords against a list of patterns.
    
    Patterns include:
      - File/device paths commonly used for input events (/dev/input/eventX)
      - Names of libraries used for X11/synthetic input or event capture
      - Source/header filenames and function names often found in keylogger code
      - Keywords/signals typical for keylogging software (keystroke, log_keys, sendinput, etc)
    
    Returns:
        (True, matched_pattern) if any suspicious string found; 
        otherwise (False, None).
    """

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
    """
    Tries to get the absolute path to executable/script for a process(PID)

    Logic:
        - If the process is from a known interpreter (python, bash, etc.), 
          assumes the "main executable" will be the second element of cmdline (cmdline[1]).
        - Otherwise, it uses the first argument of cmdline.
        - Checks:
            * If path is absolute and exists as a file -> returns that.
            * If cwd is given, checks cwd + path as a file -> returns that.
            * Otherwise, tries exe_path as a fallback.
        - If none of these exists, returns False.

    Returns:
        - Absolute file path if found
        - False if none found or on error
    """
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
    """
    returns the MD5 hash of a file at the given path.
    - Reads the file in chunks (4KB at a time) to avoid loading large files into memory.
    - Returns the hash as a hex string.
    - If file can't be read, prints an error and returns False.
    """
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
    """
    Calculates the MD5 hash for a file, then saves process/file details into 'process.json'.
    - Checks if the file's hash is already present in the JSON (avoids duplicates).
    - If new, appends a dictionary with: pid, process name, file path, hash, score, and 'is trusted' flag.
    - Stores and updates the JSON file 'process.json' as a persistent record.

    Returns:
        True  - if hash saved (or already present)
        False - on any failure
    """
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
    """
    Checks if a process (by PID) is attempting to impersonate key system binaries
    (e.g. 'systemd', 'bash', 'cron', etc.) but is **not** running from a whitelisted system location.

    Returns:
        (True, reason) if suspicious impersonation is found;
        (False, None) otherwise.
    """

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
        return False, None

# assuming that a process wont try to hide access to hidraw
def check_hidraw_connections(pid):
    """
    Checks if a process (by PID) has any open file descriptor pointing to a hidraw device.

    Returns:
        (True, device_path) if a hidraw device is open by the process;
        (False, None) otherwise.

    Example:
        # If process 2239 has /dev/hidraw2 open:
        check_hidraw_connections(2239) → (True, "/dev/hidraw2")
    """
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
                            return True, target
            except FileNotFoundError:
                continue
            except PermissionError:
                continue
            except Exception as e:
                print(f"{e}")
    except Exception as e:
        print(f"{e}")
    return False, None

#TODO: will have to think about this
# def kill_process(pid):
#     p = None
#     try:
#         p = psutil.Process(pid)
#         p.terminate()
#         p.wait(timeout=5)
#         print("Job Done.")
#     except psutil.NoSuchProcess:
#         print(f"No such process with PID {pid}.")
#     except psutil.TimeoutExpired:
#         if p:
#             p.kill()
#             print(f"Timeout: Process {pid} did not terminate within the timeout.")
#             print(f"Process {pid} forcefully terminated.")
#     except psutil.AccessDenied:
#         print(f"Access denied to kill {pid}.")


# idea is to find a suspicious input device based on heuristics, - will have to improve in future
def is_suspicious_input_device():
    """
    Scans /dev/input devices to detect potentially suspicious (virtual, recent, or user-created) input devices and 
    the processes currently accessing them.

    Flags a device as suspicious if:
      - The device bus type is "virtual"
      - The device name is blacklisted (commonly abused or emulated names)
      - Device was created < 1 minute ago
      - The device is NOT owned by root
      - It is currently accessed by a process that:
           * is running from a suspicious path (e.g., in /tmp, /var/tmp, or /dev/shm) or
           * is recent (like < 10 minutes old), as recently spawned processes may or could be malicious injectors

    Returns:
      (True, [list of dicts with suspicious device/process/reasons])
        if any suspicious devices are found,
      (False, None)
        if none are detected.

    """

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



# theory is that a malicious file could run in memory without writing to disk
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

def r_process(pid, cwd, cmdline, exe_path,fd, terminal, user, uptime):
    try:
        sus_score = 0
        reasons = []
        full_path = get_path(cwd, cmdline, exe_path)
        check = False
        pv = ParentProcessValidator()
        if not full_path or skip_current_pid(full_path, pid):
            return False

        if not terminal:
            sus_score += 1
            reasons.append("No controlling terminal")
        
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

        parent_process = pv.get_parent_process(pid)
        if full_path in known_safe_programs or any(full_path.startswith(wp) for wp in white_list_paths):
            if get_binary_info(full_path) or pv.is_legitimate_parent(parent_process):
                check = True
                return False

        if sus_score >= 2:
            return sus_score, full_path, check, reasons

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


from random import choices
import string
import threading



def bpf_monitor_with_something(bpf):
    """
    Prompts the user to actively type a random code to increase the chance that any running keylogger
    will capture or react to genuine keyboard input during BPF monitoring.

    Returns True if the user provides any input (whether correct or not), otherwise False.
    """
    code = ''.join(choices(string.ascii_letters + string.digits, k=5))
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
    """
    The main workflow for scanning system processes (--scan option) for suspicious input device access, keylogger behavior. We have two options one for specific PID and for all the processes.

    High-level FLow:
    - Initializes all analyzers.
    - Monitors BPF events to detect input devices.
    - Collects suspicious IPC, device usage, and logs activity.
    - For the target PID or all running processes:
        * Gets the reasons for suspicion (input access via /dev/event, hidraw, X11, BPF, IPC, etc).
        * Tracks full file paths, parent process, and maintains trusted/unrecognized lists.
        * Applies file authenticity checks, see check_file_authenticity() function.
        * Hashes and saves info for trusted binaries/processes. -- I forgot to add for Untrusted processes.. will think about it..
    - At the end, it sends all the details to check_and_report() function.

    """

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

    out = bpf.get_device_names_from_bpf_file()
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} PIDs accessing input devices (keyboard/event) and terminals (pts):")

    if out:
        for p, d in sorted(out):
            print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} PID {p} -> {d}")
    

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
    trusted_reasons_by_pid = defaultdict(set)

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
                    is_using_hidraw, hidraw_name = check_hidraw_connections(target_pid)

                    if is_using_hidraw:
                        suspicious_candidates.add(target_pid)
                        reasons_by_pid[target_pid].add("Has direct hidraw access")
                        log(f"PID - {p.pid} -> has direct access to {hidraw_name}", is_log)

                    if confidence >= 3 and access_rate > 0:
                        suspicious_candidates.add(target_pid)
                        reasons_by_pid[target_pid].add("Has input access through X11")
                        log(f"X11 access activity detected for PID {target_pid} (confidence: {confidence}, access rate: {access_rate})", is_log)
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
                                result, reason_list, trusted_reason_list = ba.check_file_authenticity(file, path, target_pid)
                                if not result:
                                    trusted_paths.add(path)
                                    for treason in trusted_reason_list:
                                        trusted_reasons_by_pid[target_pid].add(treason)
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

            check_and_report(fullpaths, trusted_paths, unrecognized_paths,
                        suspicious_pids, reasons_by_pid, parent_map,
                        ba, fm, pc, nm, scan=True, s_pid=True, is_log_enabled=is_log, trusted_reason_list=trusted_reasons_by_pid)

        else:
            run_fileless_execution_loader()
            print()
            print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Trying to find KeyLogger(s)")

            proceed_map = {}
            hash_flag_map = {}

            for proc in psutil.process_iter(['pid', 'cmdline', 'exe', 'cwd']):
                pid = proc.info['pid']

                try:
                    cwd = proc.cwd()
                    cmdline = proc.cmdline()
                    exe = proc.exe()
                    name = proc.name()
                    parent_map[proc.pid] = proc.ppid()
                    path = get_path(cwd, cmdline, exe)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    log(f"Skipped PID {pid} (could not access CWD/cmdline/exe)", is_log)
                    continue

                confidence, access_rate = x.check_x11_connection(pid)
                is_using_hidraw, hidraw_name = check_hidraw_connections(pid)

                if is_using_hidraw:
                    suspicious_candidates.add(pid)
                    total_pids.add(pid)
                    reasons_by_pid[pid].add("Has direct hidraw access")
                    log(f"PID - {pid} -> has direct access to {hidraw_name}", is_log)

                if confidence >= 3 and access_rate > 0:
                    total_pids.add(pid)
                    suspicious_candidates.add(pid)
                    reasons_by_pid[pid].add("Has input access through X11")
                    log(f"X11 access activity detected for PID {pid}", is_log)

                if bpf.check_pid(pid):
                    reasons_by_pid[pid].add("Accessing Input Devices confirmed using - BPF")
                    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Input Devices access detected using BPF for PID {pid}")

                for input_pid in input_access_pids:
                    suspicious_candidates.add(input_pid)
                    total_pids.add(input_pid)
                    reasons_by_pid[input_pid].add("Has direct input access")

                if not scan_all and path:
                    file_hash = get_file_hash(path)
                    proceed = not pid_is_trusted(pid, file_hash)
                    hash_flag = True
                else:
                    proceed = True
                    hash_flag = False

                proceed_map[pid] = proceed
                hash_flag_map[pid] = hash_flag
    
            for pid in suspicious_candidates:
                try:
                    proc = psutil.Process(pid)
                    path = get_path(proc.cwd(), proc.cmdline(), proc.exe())
                    name = proc.name()
                    if path:
                        fullpaths[pid] = path
                        if sockets:
                            for file in sockets:
                                result, reason_list, trusted_reasons_list = ba.check_file_authenticity(file, path, pid)
                                if not result:
                                    trusted_paths.add(path)
                                    proceed = proceed_map.get(pid, True)
                                    hash_flag = hash_flag_map.get(pid, False)
                                    if proceed:
                                        if not hash_and_save(path, pid, name, 0, hash_flag):
                                            print(f"[!] Failed to update {path}")
                                    for treason in trusted_reasons_list:
                                        trusted_reasons_by_pid[pid].add(treason)
                                else:
                                    unrecognized_paths.add(path)
                                    suspicious_pids.add(pid)
                                    for reason in reason_list:
                                        reasons_by_pid[pid].add(reason)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    log(f"Skipping PID {pid} (process unavailable)", is_log)
                    continue

            for sp in suspicious_pids:
                log(f"Reporting phase started for suspicious PID's {sp}", is_log)

            check_and_report(
                fullpaths, trusted_paths, unrecognized_paths,
                suspicious_pids, reasons_by_pid, parent_map,
                ba, fm, pc, nm,
                scan=True, s_pid=False, is_log_enabled=is_log,
                trusted_reason_list=trusted_reasons_by_pid
            )

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user. Exiting...")



def check_and_report(fullpaths, trusted_paths, unrecognized_paths, suspicious_pids, reasons_by_pid, parent_map, ba, fm, pc, nm, scan=False, s_pid=False, is_log_enabled=False, trusted_reason_list=None):

    """
    This juts takes all the data from --scan and --monitor and -p option and perform few more checks to confirm if a process is a KeyLogger and then print them.
    """
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

    
    pa = ParentProcessValidator()
    for pid in list(suspicious_pids):
        path = fullpaths.get(pid, '[unknown path]')
        is_impersonate_process, rs = check_impersonating_process(pid)
        if is_impersonate_process:
            reasons_by_pid[pid].add(rs)
            log(f"PID {pid}: Detected impersonating process - {rs}", is_log_enabled)

        o_reasons = ba.check_obfuscated_or_packed_binaries(pid)
        if o_reasons:
            for reason in o_reasons:
                reasons_by_pid[pid].add(reason)
                log(f"PID {pid}: Detected obfuscation/packing - {reason}", is_log_enabled)

        if fm.check_file_activity(pid, 1):
            reasons_by_pid[pid].add("Has file Input/Output")
            log(f"PID {pid}: File I/O activity detected", is_log_enabled)

        rt, out = pc.check_persistence(pid)
        if rt:
            reasons_by_pid[pid].add(f"is persistent: {out}")
            log(f"PID {pid}: Persistence detected - {out}", is_log_enabled)
        
        network_activity = nm.check_network_activity(pid, 5)       
        if network_activity.get("outbound_ips"):
            for ip in network_activity["outbound_ips"]:
                reasons_by_pid[pid].add(f"has foreign connection: {ip}")
                log(f"PID {pid}: Foreign network connection - {ip}", is_log_enabled)

        if network_activity.get("port_forwarding"):
            reasons_by_pid[pid].add("possible port forwarding behavior detected")
            log(f"PID {pid}: Possible port forwarding behavior detected", is_log_enabled)
            if path:
                rt, string_name = has_suspicious_strings(path)
                if rt and string_name:
                    reasons_by_pid[pid].add(f"has suspicious strings: {string_name}")
                    log(f"PID {pid}: Suspicious strings found - {string_name}", is_log_enabled)

        rt, p_output = pa.get_sus_parent_process(pid)
        if rt and p_output:
            reasons_by_pid[pid].add(f"{p_output}")
            log(f"PID {pid}: Suspicious parent process - {p_output}", is_log_enabled)
        
    high_sus_string_pids = []
    normal_suspects = []
    sus_scores = {}
    child_group = defaultdict(list)

    for pid in suspicious_pids:
        path = fullpaths.get(pid)
        if path:
            if path.endswith(".py"):
                    mc = ModuleChecker(pid, load_sus_libraries())
                    rt, py_spy_logs = mc.get_modules_using_py_spy()
                    if rt:
                        for f in py_spy_logs:
                            reasons_by_pid[pid].add(f"has suspicious modules: {f}")
                            high_sus_string_pids.append(pid)
                            log(f"Found Suspicious libraries using py-spy: {f}", is_log_enabled)
                    else:
                        normal_suspects.append(pid)

            else:
                h_output = has_suspicious_modules(path, load_sus_libraries())
                if h_output:
                    for module_name, sus_score in h_output.items():
                        sus_scores[pid] = sus_score
                        if sus_score and module_name and sus_score >= 4:
                            high_sus_string_pids.append(pid)
                            reasons_by_pid[pid].add(f"has suspicious modules: {module_name}")
                            log(f"Found Suspicious libraries: {module_name}", is_log_enabled)
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
                is_trusted = ba.is_trusted_binary(path) if 'ba' in locals() else False
                trust_note = " (recognized system binary)" if is_trusted else ""

                parent_path = '[unknown]'
                parent_status = ''
                ppid = parent_map.get(pid, None)
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_path_file = parent.exe()
                        parent_path = os.path.basename(parent_path_file)
                        if 'ba' in locals():
                            parent_trust = ba.is_trusted_binary(parent_path_file)
                            parent_status = f" ({'trusted' if parent_trust else '\033[1;31muntrusted\033[0m'})"
                    except Exception:
                        pass

                print()
                print("\033[1;31m┌" + "─" * 58 + "┐\033[0m")
                print("\033[1;31m│" + " POTENTIAL KEYLOGGER(S) DETECTED ".center(58) + "│\033[0m")
                print("\033[1;31m└" + "─" * 58 + "┘\033[0m")

                print(f"\033[1;36mPID {pid}\033[0m: {binary} (Parent: {parent_path}{parent_status}){trust_note}")

                reason_list = sorted(reasons_by_pid.get(pid, []))
                print(" ├─ \033[1;33mFlagged due to:\033[0m")
                for idx, reason in enumerate(reason_list):
                    symbol = "╰─" if idx == len(reason_list) - 1 else "├─"
                    print(f" │  {symbol} {reason}")

                print(" ├─ Binary Path:")
                print(f" │   {path}")

                if pid in child_group and child_group[pid]:
                    print(" └─ Child Processes:")
                    cgroup = child_group[pid]
                    for idx, child_pid in enumerate(sorted(cgroup)):
                        child_path = fullpaths.get(child_pid, '[unknown path]')
                        symbol = "╰─" if idx == len(cgroup) - 1 else "├─"
                        print(f"     {symbol} PID {child_pid}: {child_path}")
                else:
                    print(" └─ Child Processes: None")

                print(f" (Investigate or kill with:  kill {pid})\n")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"[PID {pid}]  <process info unavailable>")
    
    if s_pid and not final_suspects:
        print(f"[*] No suspicious activity found in the given PID")
        if trusted_reason_list:
            pid = next(iter(trusted_reason_list.keys()))
            reasons = list(trusted_reason_list[pid])
            if reasons:
                print(" ├─ Trusted for the following reasons:")
                for idx, reason in enumerate(reasons):
                    symbol = "╰─" if idx == len(reasons) - 1 else "├─"
                    print(f" │  {symbol} {reason}")
                print()

    # Sscan Part
    elif printed_pids and scan and not s_pid:
        print()
        print("\033[1;31m┌" + "─" * 58 + "┐\033[0m")
        print("\033[1;31m│" + " POTENTIAL KEYLOGGER(S) DETECTED ".center(58) + "│\033[0m")
        print("\033[1;31m└" + "─" * 58 + "┘\033[0m")

        for pid_group in [high_sus_string_pids, printed_pids - set(high_sus_string_pids)]:
            for pid in sorted(pid_group):
                path = fullpaths.get(pid, '[unknown path]')
                binary = os.path.basename(path)
                is_trusted = ba.is_trusted_binary(path)
                trust_note = " (recognized system binary)" if is_trusted else ""
                parent_path = '[unknown]'
                parent_status = ''
                ppid = parent_map.get(pid, None)
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_path = os.path.basename(parent.exe())
                        parent_trust = ba.is_trusted_binary(parent.exe())
                        parent_status = f" ({'trusted' if parent_trust else '\033[1;31muntrusted\033[0m'})"
                    except Exception:
                        pass

                print(f"\033[1;36mPID {pid}\033[0m: {binary} (Parent: {parent_path}{parent_status}){trust_note}")

                reason_list = sorted(reasons_by_pid.get(pid, []))
                print(" ├─ \033[1;33mFlagged due to:\033[0m")
                for idx, reason in enumerate(reason_list):
                    symbol = "╰─" if idx == len(reason_list) - 1 else "├─"
                    print(f" │  {symbol} {reason}")

                print(f" ├─ Binary Path:")
                print(f" │   {path}")

                if pid in child_group and child_group[pid]:
                    print(f" └─ Child Processes:")
                    for idx, child_pid in enumerate(sorted(child_group[pid])):
                        child_path = fullpaths.get(child_pid, '[unknown path]')
                        symbol = "╰─" if idx == len(child_group[pid]) - 1 else "├─"
                        print(f"     {symbol} PID {child_pid}: {child_path}")
                else:
                    print(f" └─ Child Processes: None")
                print(f" (Investigate or kill with:  kill {pid})\n")


    elif not printed_pids and scan:
        print("\n" + "-" * 50)
        print(" No suspicious keylogger activity found. ".center(50))
        print("-" * 50)

    if is_log_enabled and trusted_reason_list:
        for pid, reasons in trusted_reason_list.items():
            if not reasons:
                continue
            process_info = ""
            if 'fullpaths' in locals() and pid in fullpaths:
                process_info = f" ({fullpaths[pid]})"
            print(f"\033[1;32mPID {pid}{process_info}\033[0m:")
            print(" ├─ \033[1;32mTrusted for the following reasons:\033[0m")
            sorted_reasons = sorted(reasons)
            for idx, reason in enumerate(sorted_reasons):
                symbol = "╰─" if idx == len(sorted_reasons) - 1 else "├─"
                print(f" │  {symbol} {reason}")
            print()

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
            print(f" (Investigate or kill with:  kill {pid})\n")
            print()


file_path = "process.json"
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



# --monitor option
def monitor_process(interval=5, is_log_enabled=False, scan_all=False):
    """
    Continuously monitors all running processes (--all option would scan all of them, if False, it just skips the process that are trusted in process.json) for suspicious activity. 
    Same as the --scan option, but goes on indefinitely until ctrl+c'ed or some error.

    Flow:
      - Gets active input device access using multiple methods.
      - For each process, gets data (cwd, cmdline, exe, etc.).
      - Passes these data to r_process(), which performs few checks 
        (see r_process for details).
      - If r_process() returns a process suspicious, sends it to phase_two_analysis() 
        for additional checks or reporting.
      - Tracks which processes/paths have already been processed to avoid redundant work.
      - Sleeps for the specified interval before repeating.
    """
    spinner = itertools.cycle(['-', '\\', '|', '/'])

    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Monitoring Started.")
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scan interval - {interval}s")
    print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Monitoring processes for suspicious activity.")

    if scan_all:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Scanning all processes, including those marked as trusted.")
    else:
        print(f"{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Skipping processes trusted by program heuristics or user configuration.")
   
    path_check = set()
    pid_check = set()

    while True:
        i = InputMonitor()
        input_access_pids = i.get_process_using_input_device()
        parent_map = {}
        bpf = BPFMONITOR(bpf_file, 5)
        bpf.start()
        bpf.stop()
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
                output = r_process(pid, cwd, cmdline, exe, fd, terminal, username, uptime)

                if output and pid:
                    _, path, _, reasons = output
                    if path not in path_check and pid not in pid_check:
                        path_check.add(path)
                        pid_check.add(pid)
                        phase_two_analysis(pid, path, reasons, parent_map, input_access_pids, is_log_enabled)

                else:
                    if p:
                        if pid not in input_access_pids or pid in total_pids:
                            continue
                        if not hash_and_save(p, pid, name, 0, hash_flag):
                            print(f"[!] Failed to update {file_path}")

        print(f"\n{datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')} Sleeping - {interval}s")
        time.sleep(interval)

def change_and_join(reasons):
    if isinstance(reasons, (list, tuple)):
        return " ".join(map(str, reasons))
    return str(reasons)

def phase_two_analysis(pid, path, reasons, parent_map, input_access_pids, is_log_enabled=False):

    """
    Does analysis for a process identified as suspicious

    Flow:
      - Initializes all analyzers: BPF monitoring, X11 analyzer, binary/file/persistence/network/IPCs.
      - Gathers additional context or data for the target PID, like suspected reasons, X11 activity, hidraw access, and
        all processes with input device access.
      - For each suspicious candidate:
          * Verifies input device access (via BPF and input_access_pids).
          * Checks for direct hidraw and X11 device access, then flagging them accordingly.
          * Runs file authenticity checks against detected suspicious processes.
          * Tracks paths as trusted or not, gets evidence across analyzers.
      - Calls check_and_report that does more checks and print if found any KeyLoggers*.
    """

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
        suspicious_candidates.add(pid)

    confidence, access_rate = x.check_x11_connection(pid)
    if confidence >= 3 and access_rate > 0:
        suspicious_candidates.add(pid)
        total_pids.add(pid)
        reasons_by_pid[pid].add("Has input access through X11")
        log(f"Using X11 to access Input devices for PID - {pid}", is_log_enabled)

    is_using_hidraw, hidraw_name = check_hidraw_connections(pid)

    if is_using_hidraw:
        suspicious_candidates.add(pid)
        total_pids.add(pid)
        reasons_by_pid[pid].add("Has direct hidraw access")
        log(f"PID - {pid} -> has direct access to {hidraw_name}", is_log_enabled)

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
                        #TODO: will think whether to add the trust list for monitoring.. or too much noise?? 
                        result, reason_list, _ = ba.check_file_authenticity(file, path, pid)
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
        scan=False,
        is_log_enabled=is_log_enabled,
    )

def prompt_user_trust_a_process():
    """
    An option to let the user mark a specific binary (by path) as trusted or untrusted,
    saving this status for future reference in 'process.json'.
    
    Why?
      - There's a chance that this tool could report false-postivie's, so to avoid them, user can add trust or not trust a process.
    """
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
                    print(f"[*] {'Trusted' if trust_flag else 'Untrusted'} status set for: {binary_name}")
                else:
                    print(f"[!] Could not update trust status for: {binary_name}")
                found_running = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            print(f"[!] Error while inspecting a process: {e}")

    if not found_running:
        print(f"[*] {binary_name} is not running.")
        if hash_and_save(binary_name, None, binary_name, 0, trust_flag):
            print(f"[*] {'Trusted' if trust_flag else 'Untrusted'} status set for: {binary_name}")
        else:
            print(f"[!] Could not update trust status for: {binary_name}")

def intial_system_checks(is_log=False):
    """
    Performs basic security checks on the system in hope of finding a KeyLogger.
    """
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
            monitor_process(10, args.log, args.all)
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
