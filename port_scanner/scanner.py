import socket
import ipaddress
import argparse
import json
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


def scan_port_connect(target, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
    except (socket.timeout, ConnectionRefusedError, OSError):
        try:
            s.close()
        except Exception:
            pass
        return False, None

    banner = None
    try:
        banner_bytes = s.recv(1024)
        if banner_bytes:
            try:
                banner = banner_bytes.decode(errors="replace").strip()
            except UnicodeDecodeError:
                banner = repr(banner_bytes)
    except (socket.timeout, OSError):
        pass
    finally:
        s.close()

    return True, banner


def scan_port_udp(target, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"", (target, port))
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors="replace").strip() if data else None
            s.close()
            return True, banner
        except socket.timeout:
            s.close()
            return False, None
    except OSError:
        return False, None


def scan_port(target, port, timeout=1.0, scan_type="tcp"):
    if scan_type == "udp":
        return scan_port_udp(target, port, timeout)
    return scan_port_connect(target, port, timeout)


def scan_range(target, start_port, end_port, threads, timeout=1.0, scan_type="tcp"):
    """
    Scan a range of ports on the target host using multithreading.
    """
    results = []

    total_ports = end_port - start_port + 1
    print(f"\n[*] Scanning {target} from port {start_port} to {end_port} ({scan_type})")
    print(f"[*] Using {threads} threads, this may take a while...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout, scan_type): port
            for port in range(start_port, end_port + 1)
        }

        for future in tqdm(as_completed(future_to_port),
                           total=total_ports,
                           desc=f"{target}",
                           unit="port"):
            port = future_to_port[future]
            try:
                is_open, banner = future.result()
            except Exception:
                continue

            if is_open:
                fingerprint = None
                if banner:
                    b_lower = banner.lower()
                    if "mysql" in b_lower:
                        fingerprint = "MySQL"
                    elif "ssh" in b_lower:
                        fingerprint = "SSH"
                    elif "http" in b_lower or "server:" in b_lower:
                        fingerprint = "HTTP"
                    elif "flask" in b_lower or "werkzeug" in b_lower:
                        fingerprint = "Flask"

                results.append({
                    "target": target,
                    "port": port,
                    "banner": banner,
                    "scan_type": scan_type,
                    "fingerprint": fingerprint,
                })

                print(f"\n[+] {target}:{port} OPEN"
                      f"{' - ' + fingerprint if fingerprint else ''}")
                if banner:
                    print(f"[+] BANNER: {banner}")

    results.sort(key=lambda r: r["port"])
    return results

def output_results(results, output_format="text", file=None):

    if output_format == "json":
        data = json.dumps(results, indent=2)
        if file:
            with open(file, "w", encoding="utf-8") as f:
                f.write(data)
        else:
            print(data)

    elif output_format == "csv":
        fieldnames = ["target", "port", "scan_type", "fingerprint", "banner"]
        if file:
            f = open(file, "w", newline="", encoding="utf-8")
            close_after = True
        else:
            f = sys.stdout
            close_after = False

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

        if close_after:
            f.close()

    else:  # plain text
        for r in results:
            line = f"{r['target']}:{r['port']} ({r['scan_type']})"
            if r["fingerprint"]:
                line += f" [{r['fingerprint']}]"
            print(line)
            if r["banner"]:
                print(f"    {r['banner']}")

def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        required=True,
        help="IP / hostname / CIDR, e.g. 172.20.0.2 or 172.20.0.0/24",
    )
    parser.add_argument(
        "--ports",
        required=True,
        metavar="START-END",
        help="Port range, e.g. 1-1024",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of worker threads (default: 100)",
    )
    parser.add_argument(
        "--scan-type",
        choices=["tcp", "udp"],
        default="tcp",
        help="Scan type: tcp (connect) or udp (basic UDP probe)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per port in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output-file",
        help="Optional output file path for JSON/CSV",
    )
    return parser


def parse_ports(ports_str):
    start_str, end_str = ports_str.split("-", 1)
    start = int(start_str)
    end = int(end_str)
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValueError("Ports must be between 1 and 65535 and START <= END")
    return start, end


def main():
    parser = build_parser()
    args = parser.parse_args()

    start_port, end_port = parse_ports(args.ports)
    threads = args.threads
    scan_type = args.scan_type
    timeout = args.timeout

    target = args.target
    all_results = []

    print(f"[*] Starting {scan_type} scan on {target} ports {start_port}-{end_port} "
          f"with {threads} threads and timeout={timeout}s")

    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts()) or [network.network_address]
        print(f"[*] Target is a network: {target} ({len(hosts)} hosts)")
        for host_ip in hosts:
            ip_str = str(host_ip)
            host_results = scan_range(
                ip_str, start_port, end_port, threads, timeout, scan_type
            )
            all_results.extend(host_results)
            print(f"\n[+] {ip_str} scan complete! Found {len(host_results)} open ports.")
    except ValueError:
        host_results = scan_range(
            target, start_port, end_port, threads, timeout, scan_type
        )
        all_results.extend(host_results)
        print(f"\n[+] {target} scan complete! Found {len(host_results)} open ports.")

    output_results(all_results, args.output, args.output_file)


if __name__ == "__main__":
    main()
