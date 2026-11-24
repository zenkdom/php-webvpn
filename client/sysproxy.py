"""
Windows System Proxy Manager
-------------------------------------------------------------
Manages Windows system-wide proxy settings via registry (Internet Settings)
and notifies the OS and browsers (Chrome, Edge, Opera, Brave, etc.)
instantly via WinINet API without requiring system reboots.
Automatically restores original proxy settings upon program termination.
"""

import sys
import atexit
import signal

if sys.platform == "win32":
    import winreg
    import ctypes
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
else:
    winreg = None
    ctypes = None

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

class WindowsSystemProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, bypass_hosts: list = None):
        # 0.0.0.0 is not a valid dial address for clients on Windows,
        # so we map to 127.0.0.1 for local system proxying.
        sys_host = "127.0.0.1" if (not host or host in ("0.0.0.0", "::")) else host.strip()
        self.host = sys_host
        self.port = port
        self.proxy_str = f"{sys_host}:{port}"
        self.bypass_hosts = [h.strip() for h in (bypass_hosts or []) if h.strip()]
        self.is_enabled = False

        self._orig_enable = 0
        self._orig_server = None
        self._orig_override = None

        if sys.platform == "win32":
            self._save_original_state()
            # Register safe automatic cleanup upon process exit
            atexit.register(self.disable)
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        self.disable()
        sys.exit(0)

    def _save_original_state(self):
        """Preserves user's previous system proxy configuration."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
                try:
                    self._orig_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    self._orig_enable = 0

                try:
                    self._orig_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    self._orig_server = None

                try:
                    self._orig_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    self._orig_override = None
        except Exception:
            pass

    def enable(self) -> bool:
        """Enables Windows system proxy."""
        if sys.platform != "win32":
            return False

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.proxy_str)
                # Exclude localhost and proxy backend endpoints to prevent routing loops
                bypass_items = list(dict.fromkeys(self.bypass_hosts + ["localhost", "127.0.0.1", "<-loopback>"]))
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, ";".join(bypass_items))

            self._refresh_windows()
            self.is_enabled = True
            return True
        except Exception as e:
            print(f"[-] Failed to enable system proxy: {e}")
            return False

    def disable(self) -> bool:
        """Disables system proxy and restores previous configuration."""
        if sys.platform != "win32" or not self.is_enabled:
            return False

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, self._orig_enable if self._orig_enable else 0)
                if self._orig_server is not None:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self._orig_server)
                if self._orig_override is not None:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self._orig_override)

            self._refresh_windows()
            self.is_enabled = False
            return True
        except Exception as e:
            print(f"[-] Failed to disable system proxy: {e}")
            return False

    def _refresh_windows(self):
        """Notifies WinINet API that proxy settings have changed."""
        try:
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass

    def __enter__(self):
        self.enable()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disable()
