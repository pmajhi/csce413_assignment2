#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import ipaddress

def parse_ports(value: str) -> tuple[int, int]:
    """
    Parse a port range like '1-10000' into (1, 10000)
    and validate that it is within 1-65535 and start <= end.
    """
    try:
        start_str, end_str = value.split("-", 1)
        start = int(start_str)
        end = int(end_str)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "ports must be in the form START-END, e.g. 1-10000"
        )

    # if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
    #     raise argparse.ArgumentTypeError(
    #         "ports must be between 1 and 65535 and START <= END"
    #     )

    return start, end


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="Simple port scanner"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target host or CIDR, e.g. 172.20.0.0/24 or webapp",
    )

    parser.add_argument(
        "--ports",
        required=True,
        type=parse_ports,
        metavar="START-END",
        help="Port range to scan, e.g. 1-10000 or 1-65535",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of worker threads to use (default: 1)",
    )

    return parser

def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # TODO: Create a socket DONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: Set timeout DONE
        s.settimeout(timeout)
        # TODO: Try to connect to target:port DONE
        s.connect((target, port))
    except (socket.timeout, ConnectionRefusedError, OSError):
        s.close()
        return False
    
    print(f"[+] {target}:{port} OPEN")
    banner = None
    try:
        # Try to read a small banner if the service sends one.
        banner_bytes = s.recv(1024)
        if banner_bytes:
            try:
                banner = banner_bytes.decode(errors="replace").strip()
            except UnicodeDecodeError:
                banner = repr(banner_bytes)
            if banner:
                print(f"[+] {target}:{port} BANNER - {banner}")
    except (socket.timeout, OSError):
        # print(f"[*] {target_host}:{port} OPEN")
        pass
    s.close()
    return True


def scan_range(target, start_port, end_port, threads):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"\n[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scans to the pool.
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(start_port, end_port + 1)
        }

        # Collect results as they complete.
        for future in as_completed(futures):  # [web:34][web:60][web:64]
            port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                # Ignore unexpected errors on this port.
                continue

            if is_open:
                open_ports.append(port)

    open_ports.sort()

    # for port in range(start_port, end_port + 1):
    #     # TODO: Scan this port
    #     result = scan_port(target, port, timeout=1.0)
    #     # TODO: If open, add to open_ports list
    #     if result:
    #         open_ports.append(port)
    #     # TODO: Print progress (optional)
    #         # print(f"[*] Port {port} is OPEN")

    return open_ports


def main():
    """Main function"""

    # TODO: Parse command-line arguments
    # DONE

    start_port = 1
    end_port = 1024  # Scan first 1024 ports by default

    # TODO: Validate inputs
    # DONE
    parser = build_parser()
    args = parser.parse_args()

    target = args.target              # string: '172.20.0.0/24' or 'webapp'
    start_port, end_port = args.ports # tuple[int, int]
    threads = args.threads            # int

    print(f"[*] Starting port scan on {target} with {threads} threads")

    # TODO: Call scan_range()
    # DONE
    network = ipaddress.ip_network(target, strict=False)
    for host_ip in network.hosts():
        ip_str = str(host_ip)
        open_ports = scan_range(ip_str, start_port, end_port, threads)

        # TODO: Display results
        # DONE
        print(f"\n[+] {ip_str} Scan complete! Found {len(open_ports)} open ports.")
        # print(f"[+] Found {len(open_ports)} open ports.")
        # for port in open_ports:
            # print(f"    Port {port}: open")


if __name__ == "__main__":
    main()
