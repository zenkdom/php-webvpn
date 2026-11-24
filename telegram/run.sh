#!/usr/bin/env bash
# ==============================================================================
# Telegram Multi-Proxy Server Launcher (Linux / macOS / Termux)
# ==============================================================================

# Move to script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Detect Python 3
if command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "[ERROR] Python 3 is not installed or not found in PATH!"
    echo "Please install Python 3:"
    echo "  - Termux (Android) : pkg install python"
    echo "  - Debian / Ubuntu  : sudo apt install python3 python3-pip"
    echo "  - Arch Linux       : sudo pacman -S python python-pip"
    echo "  - macOS (Homebrew) : brew install python3"
    exit 1
fi

# Verify Python version >= 3.8
"$PYTHON" -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[ERROR] Python 3.8+ is required. Detected: $("$PYTHON" --version 2>&1)"
    exit 1
fi

# Check and install dependencies if missing
if ! "$PYTHON" -c "import requests, cryptography, colorama, urllib3" >/dev/null 2>&1; then
    # Verify pip is available
    if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
        echo "[*] pip not found. Attempting to bootstrap pip..."
        "$PYTHON" -m ensurepip --upgrade >/dev/null 2>&1
        if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
            echo "[!] ensurepip failed. Attempting to install pip via get-pip.py..."
            if command -v curl >/dev/null 2>&1; then
                curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py && "$PYTHON" /tmp/get-pip.py --break-system-packages 2>/dev/null || "$PYTHON" /tmp/get-pip.py 2>/dev/null
                rm -f /tmp/get-pip.py
            elif command -v wget >/dev/null 2>&1; then
                wget -qO /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py && "$PYTHON" /tmp/get-pip.py --break-system-packages 2>/dev/null || "$PYTHON" /tmp/get-pip.py 2>/dev/null
                rm -f /tmp/get-pip.py
            fi
        fi
    fi

    # Check if pip is now functional
    if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
        echo "[ERROR] pip is not installed and could not be installed automatically."
        echo "Please install pip manually:"
        echo "  - Debian / Ubuntu : sudo apt update && sudo apt install -y python3-pip"
        echo "  - Termux (Android): pkg install python (or pkg install python-pip)"
        echo "  - CentOS / Fedora : sudo dnf install -y python3-pip"
        echo "  - Alpine Linux    : apk add py3-pip"
        echo "  - Arch Linux      : sudo pacman -S python-pip"
        exit 1
    fi

    echo "[*] Installing required dependencies..."
    "$PYTHON" -m pip install -r requirements.txt --break-system-packages 2>/dev/null || \
    "$PYTHON" -m pip install -r requirements.txt 2>/dev/null || \
    {
        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] Trying system package manager (apt)..."
            apt-get update -qq && apt-get install -y python3-requests python3-cryptography python3-colorama python3-urllib3
        fi
    }

    if ! "$PYTHON" -c "import requests, cryptography, colorama, urllib3" >/dev/null 2>&1; then
        echo "[ERROR] Failed to install dependencies. Please run:"
        echo "  python3 -m pip install -r requirements.txt --break-system-packages"
        echo "  or: apt install -y python3-requests python3-cryptography python3-colorama python3-urllib3"
        exit 1
    fi
fi

# Run Telegram Multi-Proxy Server
exec "$PYTHON" socks_server.py "$@"
