#!/bin/bash
set -euo pipefail

VENV_DIR="./FKeyLogger/src/venv"
BIN_DIR="./bin"
BPFTOOL_VERSION="v7.5.0"
BPFTOOL_EXTRACT_DIR="./bpftool_extract"
REQUIREMENTS_URL="https://raw.githubusercontent.com/vamsi200/FKeyLogger/main/src/requirements.txt"
REQUIREMENTS_FILE="requirements.txt"
GITHUB_URL="https://github.com/vamsi200/FKeyLogger.git"
REPO_DIR="FKeyLogger"
TEMPLATE_GEN="template_gen.py"

echo "[+] Cloning Repository - $GITHUB_URL"
if [ -d "$REPO_DIR" ]; then
  echo "[*] Repository already exists. Removing it first."
  rm -rf "$REPO_DIR"
fi
git clone "$GITHUB_URL" &>/dev/null

ARCH=$(uname -m)
case "$ARCH" in
x86_64) BPFTOOL_ARCH="amd64" ;;
aarch64 | arm64) BPFTOOL_ARCH="arm64" ;;
*)
  echo "Unsupported architecture: $ARCH"
  exit 1
  ;;
esac

TAR_FILE="bpftool-${BPFTOOL_VERSION}-${BPFTOOL_ARCH}.tar.gz"
SHA_FILE="${TAR_FILE}.sha256sum"
BASE_URL="https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}"
TAR_URL="${BASE_URL}/${TAR_FILE}"
SHA_URL="${BASE_URL}/${SHA_FILE}"

mkdir -p "$BIN_DIR" "$BPFTOOL_EXTRACT_DIR"

echo "[+] Downloading bpftool archive"
curl -sSL "$TAR_URL" -o "$TAR_FILE" || {
  echo "Failed to download $TAR_URL"
  exit 1
}
curl -sSL "$SHA_URL" -o "$SHA_FILE" || {
  echo "Failed to download $SHA_URL"
  exit 1
}

echo "[+] Verifying checksum"
sha256sum -c "$SHA_FILE" >/dev/null || {
  echo "Checksum verification failed"
  exit 1
}

echo "[+] Extracting bpftool"
tar -xzf "$TAR_FILE" -C "$BPFTOOL_EXTRACT_DIR" >/dev/null || {
  echo "Extraction failed"
  exit 1
}
mv "$BPFTOOL_EXTRACT_DIR/bpftool" "$REPO_DIR/src/bin/bpftool"
chmod +x "$REPO_DIR/src/bin/bpftool"
rm -rf "$TAR_FILE" "$SHA_FILE" "$BPFTOOL_EXTRACT_DIR"

echo "[+] Downloading requirements.txt"
curl -sSL "$REQUIREMENTS_URL" -o "$REQUIREMENTS_FILE" || {
  echo "Failed to download requirements.txt"
  exit 1
}

if [ ! -d "$VENV_DIR" ]; then
  echo "[+] Creating Python virtual environment"
  python3 -m venv "$VENV_DIR" >/dev/null || {
    echo "Failed to create virtualenv"
    exit 1
  }
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
echo "[+] Installing Python dependencies"
pip install -r "$REQUIREMENTS_FILE" >/dev/null || {
  echo "Failed to install Python dependencies"
  exit 1
}

cd "$REPO_DIR/src"

echo "[+] Generating vmlinux.h for bpf tools"
echo "[+] Running $TEMPLATE_GEN"
python3 "$TEMPLATE_GEN" &>/dev/null || {
  echo "template_gen.py failed"
  exit 1
}

echo "[+] Getting Header files for BPF tools"
if "./bin/bpftool" btf dump file /sys/kernel/btf/vmlinux format c >vmlinux.h; then
  echo "[+] Building BPF files using Makefile"
  if ! make >/dev/null; then
    echo "Make failed. Please check the manual instructions at - $GITHUB_URL"
    exit 1
  fi
else
  echo "bpftool command failed. Could not generate vmlinux.h"
  exit 1
fi

printf "\n%-50s\n" "--------------------------------------------------"
echo "Setup complete."
echo "Please login as root - sudo su"
echo "And Activate virtual env: source ./FKeylogger/src/venv/bin/activate"
printf "%-50s\n\n" "--------------------------------------------------"
