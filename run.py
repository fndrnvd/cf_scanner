#!/usr/bin/env python3
"""
Wrapper for cf_scanner.py
- Checks and installs missing 'h2' package automatically (using importlib)
- Fixes event loop issue on Python 3.10+
- Retries on network failures with exponential backoff
"""

import asyncio
import importlib.util
import subprocess
import sys
import time
import socket


def ensure_h2():
    """Check if 'h2' module is available; if not, install httpx[http2]."""
    if importlib.util.find_spec("h2") is None:
        print("[!] 'h2' module not found. Installing httpx with HTTP/2 support...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "httpx[http2]"]
            )
            print("[✓] Installation completed.")
        except subprocess.CalledProcessError:
            sys.exit(
                "Failed to install httpx[http2]. Please run manually:\n"
                "pip install 'httpx[http2]'"
            )
    # else already installed


def is_connected(timeout=3):
    """Check internet connectivity via Google DNS (8.8.8.8:53)."""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("8.8.8.8", 53))
        s.close()
        return True
    except OSError:
        return False


def run_with_retry():
    max_retries = 10
    base_delay = 5  # seconds

    # Wait for internet before first launch
    print("[*] Checking internet connection...")
    while not is_connected():
        print("    No connection. Retrying in 10 seconds...")
        time.sleep(10)
    print("[*] Internet is available. Starting scanner...")

    # Import the original scanner's main function
    spec = importlib.util.spec_from_file_location("cf_scanner", "cf_scanner.py")
    cf_scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cf_scanner)
    main_func = cf_scanner.main

    for attempt in range(1, max_retries + 1):
        try:
            # Fix "no current event loop" error on Python 3.10+
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            main_func()  # uses sys.argv internally
            break  # success
        except (subprocess.CalledProcessError, OSError, RuntimeError) as e:
            print(f"\n[!] Error (attempt {attempt}/{max_retries}): {e}")
            if not is_connected():
                print("[*] Internet appears to be down. Waiting for reconnection...")
                while not is_connected():
                    time.sleep(5)
                print("[*] Reconnected.")
            else:
                delay = base_delay * (2 ** (attempt - 1))
                print(f"[*] Retrying in {delay} seconds...")
                time.sleep(delay)
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")
            sys.exit(0)
        finally:
            if "loop" in locals():
                loop.close()
    else:
        print("[✗] Max retries reached. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    ensure_h2()
    run_with_retry()
