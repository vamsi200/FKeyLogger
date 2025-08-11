# FKeyLogger

**FKeyLogger** is a security tool for detecting keyloggers on Linux systems.

>## STILL IN DEVELOPMENT
>

## **Core Detection**

- **/dev/input Monitoring** – Detects processes accessing raw input event devices using:  
  - eBPF capture – `kprobe/vfs_read` for direct `/dev/input` reads.  
  - File descriptor mapping – Gets active input event devices (`/dev/input/event*`) and inspects `/proc/[pid]/fd` symlinks to find processes holding open fd's to those devices.

- **X11 Activity** – Identifies processes connected to the X11 display server that could capture keyboard input.

- **Binary Authenticity & String Analysis** – Extracts and analyzes readable strings from binaries/scripts to detect:  
  - References to input devices.  
  - Known keylogging function names.  
  - Suspicious libraries or keywords.  
  - Modified or unrecognized binaries(based on Package Managers).  

- **Binary & Process Analysis** – Flags suspicious executables based on:  
  - File location, permissions, and ownership.  
  - Deleted-on-disk binaries still running in memory, detection using eBPF - `tracepoint/syscalls/sys_enter_memfd_create`.  
  - Shannon entropy checks for obfuscation.  
  - Detection of UPX or other packer signatures.  


## **Additional Analysis**

- Initial Security Checks (Recommended) **Default option – Detects:** 
  - Suspicious input devices.  
  - Compromised shell configuration files.  
  - Malicious PAM modules.  
  - Hidden shell command aliases.  
  - Malicious `.inputrc` overrides.  
  - Persistence via cron jobs and `LD_PRELOAD`.  

- **Parent Process Validation** – Inspects parent and grandparent processes to detect suspicious process chains.

- **IPC Scanning** – Searches `/dev/shm`, `/tmp`, and `/run` for suspicious UNIX sockets or FIFOs that are:  
  - World-readable/writable.  
  - Owned by root or the current user.  
  - Actively in use by processes.  

- **Persistence Checks** – Identifies suspicious autostart scripts, from:  
  - Systemd services  
  - Cron jobs  
  - Desktop autostart entries  

- **Network Activity Monitoring** – Detects outbound traffic of processes.



## **Design Choices & Heuristics**

| Feature / Behavior | Reasoning |
|--------------------|----------------|
| **Trust management** | Users can mark binaries/processes as trusted or untrusted saved under - (`process.json`) file; It is used to reduce recurring false positives. |
| **Process hasing** | Calculates an MD5 hash for a process’s binary and stores details (PID, name, path, hash, score, trust flag) in `process.json`. Prevents duplicate entries and ensures a persistent record for trust management. |
| **Skip trusted processes** | Monitoring and scan options skip trusted entries by default; `--all flag` can force scanning of all processes. |
| **Device heuristics** | A device will be flagged suspicious if its bus is virtual, name is blacklisted, it was created recently, not owned by root, or accessed by a process from suspicious paths (e.g.. `/tmp`, `/dev/shm`). |
| **File activity monitoring** | Watches file descriptors for writes, creates, and modifies using inotify, reporting rapid file activity tied to a process - this, of course, will be a heuristic, as to say, when a process has input access and is also writing rapidly, it increases the suspicion. |
| **Binary package verification** | Checks if a binary is recognized by the system’s package manager (`apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`). A positive match significantly increases the trust of that process. |

## Usage

```bash
usage: main.py [-h] [-p P] [--scan] [--monitor] [--modify_trust] [--log] [--all]

Keylogger Detector that may work

options:
  -h, --help      show this help message and exit
  -p P            -p takes an pid for Analyzing
  --scan          Scan Mode
  --monitor       Monitor Mode
  --modify_trust  Modifies/Adds trust to a process
  --log           Enable verbose logging
  --all           By default, trusted processes (based on heuristics or user input) are skipped. Use this flag to disable that
                  behavior and scan all processes, including the trusted ones.
```
## Setup

> **Note:**  
Please make sure to source the venv as root or manually install dependencies into root’s Python environment.

```bash
wget -qO- https://raw.githubusercontent.com/vamsi200/FKeyLogger/main/src/setup.sh | bash
```

### What this script does
- Clones the repository from GitHub.
- Detects system architecture (x86_64, arm64) and downloads the correct `bpftool` binary from - https://github.com/libbpf/bpftool/releases/.
- Verifies checksum of the downloaded binary.
- Extracts and installs `bpftool` into `src/bin`.
- Downloads Python requirements and installs them into a new virtual environment (`venv`).
- Runs `template_gen.py` which, scans /dev/input, /dev/tty, /dev/pts, and /dev/hidraw* to extract major/minor device numbers and then injects these ranges into vfsread.bpf.c, so that the BPF program only monitors relevant devices on the system.
- Generates `vmlinux.h` and compiles BPF programs via `make`.

## ⚠ Disclaimer
This project is designed solely for security auditing and primarly for the detection of malicious software like keyloggers.  
Running this tool on systems that you do not own or have explicit permission to test may be illegal in your jurisdiction.  
**The author assumes no liability for misuse.**
