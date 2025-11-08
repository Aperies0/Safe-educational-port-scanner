#!/usr/bin/env python3
"""
safe_scanner.py
Educational port scanner — safe defaults and hard stops to avoid accidental scanning of the internet.

Usage (recommended):
  python safe_scanner.py --target 127.0.0.1 --start-port 1 --end-port 1024

To intentionally scan public IPs you MUST pass --force or --confirm-legal (explicit intent).
"""
import argparse
import ipaddress
import json
import socket
import sys
import time
from typing import Tuple, Dict
from tqdm import tqdm
from datetime import datetime, timezone

# ----------------------
# Safe defaults
# ----------------------
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024   # conservative default
DEFAULT_RATE = 5.0        # connections per second (conservative)
BANNER_TIMEOUT = 1.0      # seconds
CONNECT_TIMEOUT = 0.5     # seconds


# ----------------------
# Safety helpers
# ----------------------
_RESERVED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_or_local(addr: str) -> bool:
    """Return True for loopback / RFC1918 / link-local / IPv6 ULA addresses."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        # Hostnames are not allowed here — treat as public for safety
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return True
    for net in _RESERVED_NETWORKS:
        if ip in net:
            return True
    return False


def assert_target_allowed(target: str, force: bool = False, test_lab: bool = False):
    """Raise SystemExit with message if the target is not allowed without force."""
    if test_lab and target not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("test-lab mode only allows localhost targets. Remove --test-lab to test private ranges.")
    if is_private_or_local(target):
        return
    if force:
        return
    raise SystemExit(
        f"Refusing to run against public target {target!r}. "
        "To proceed (only if you have written permission) re-run with --force or --confirm-legal."
    )


# ----------------------
# Input / parsing
# ----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Educational port scanner (lab use only).")
    p.add_argument("--target", help=f"Target IP (default: {DEFAULT_TARGET})")
    p.add_argument("--start-port", type=int, default=DEFAULT_START_PORT, help="Start port (incl).")
    p.add_argument("--end-port", type=int, default=DEFAULT_END_PORT, help="End port (incl).")
    p.add_argument("--rate", type=float, default=DEFAULT_RATE,
                   help="Connections per second (default conservative).")
    p.add_argument("--force", action="store_true", help="Force scanning public targets (requires written permission).")
    p.add_argument("--confirm-legal", action="store_true", help="Alias for --force.")
    p.add_argument("--test-lab", action="store_true", help="Strict test-lab mode (localhost only).")
    return p.parse_args()


def interactive_get_ip() -> str:
    while True:
        s = input("Enter an IP address (127.0.0.1 recommended): ").strip()
        try:
            ip = ipaddress.ip_address(s)
            print(f"Valid IP entered: {ip}")
            return str(ip)
        except ValueError:
            print("Invalid IP address. Try again.")


def validate_port_range(start: int, end: int) -> Tuple[int, int]:
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise SystemExit("Ports must be between 1 and 65535.")
    if end < start:
        raise SystemExit("End port must be greater than or equal to start port.")
    return start, end


# ----------------------
# Scanner
# ----------------------
def scan_ports(target: str, start_port: int, end_port: int, rate: float,
               connect_timeout: float = CONNECT_TIMEOUT, banner_timeout: float = BANNER_TIMEOUT) -> Dict[int, str]:
    """
    Scans ports in [start_port, end_port] on target.
    Returns dict port => banner (or "No banner").
    """
    open_ports: Dict[int, str] = {}
    delay = 1.0 / max(rate, 0.0001)  # seconds between attempts

    for port in tqdm(range(start_port, end_port + 1), desc="Scanning ports"):
        try:
            # create a fresh socket each time (clean)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(connect_timeout)
                try:
                    s.connect((target, port))
                except (socket.timeout, ConnectionRefusedError, OSError):
                    # closed / filtered / unreachable: skip
                    pass
                else:
                    # port is open — attempt to read a banner (non-blocking-ish, short timeout)
                    try:
                        s.settimeout(banner_timeout)
                        data = s.recv(2048)
                        banner = data.decode(errors="ignore").strip() if data else "No banner"
                    except Exception:
                        banner = "No banner"
                    open_ports[port] = banner
        except Exception as e:
            # We print errors to stderr rather than silently swallow them.
            # This helps debugging without being noisy on stdout.
            print(f"[!] Unexpected error on port {port}: {e}", file=sys.stderr)
        finally:
            time.sleep(delay)

    return open_ports


# ----------------------
# Entrypoint
# ----------------------
def log_intent(cfg: dict):
    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": cfg["target"],
        "start_port": cfg["start_port"],
        "end_port": cfg["end_port"],
        "rate": cfg["rate"],
        "force_used": cfg["force"],
        "test_lab": cfg["test_lab"],
    }
    # Single-line JSON so it's easy to grep or save in CI logs
    print("SCAN INTENT:", json.dumps(meta))


def main():
    args = parse_args()

    # Interactive fallback: if no --target, ask user
    if args.target is None:
        target = interactive_get_ip()
    else:
        target = args.target.strip()

    # Basic sanity + safety checks
    start_port, end_port = validate_port_range(args.start_port, args.end_port)

    # Require explicit force for >1024
    if end_port > 1024 and not (args.force or args.confirm_legal):
        raise SystemExit("Scanning ports above 1024 requires explicit --force / --confirm-legal flag (permission reminder).")

    # Final safety gate
    assert_target_allowed(target, force=(args.force or args.confirm_legal), test_lab=args.test_lab)

    cfg = {
        "target": target,
        "start_port": start_port,
        "end_port": end_port,
        "rate": float(args.rate),
        "force": bool(args.force or args.confirm_legal),
        "test_lab": bool(args.test_lab),
    }

    log_intent(cfg)
    print(f"\nScanning {target} ports {start_port}-{end_port} at {cfg['rate']} conn/s (banner timeout {BANNER_TIMEOUT}s)\n")

    results = scan_ports(target, start_port, end_port, cfg["rate"])
    print("\nScan complete!\n")
    if results:
        print(f"Found {len(results)} open ports:")
        for port in sorted(results.keys()):
            print(f"Port {port} => {results[port]}")
    else:
        print("No open ports found in the specified range.")


if __name__ == "__main__":
    main()
