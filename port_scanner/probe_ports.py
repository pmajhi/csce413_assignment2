import json
import subprocess
from typing import Optional

# common HTTP ports
HTTP_PORT_GUESS = {80, 443, 8080, 8000, 5000, 5001}


def run_cmd(cmd: list[str], timeout: float = 3.0) -> tuple[int, str, str]:
    """Run a shell command and capture (returncode, stdout, stderr) as text."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def probe_with_curl(host: str, port: int) -> str:
    url = f"http://{host}:{port}/"
    code, out, err = run_cmd(["curl", "-sv", url])
    return out + "\n" + err


def probe_with_nc(host: str, port: int) -> str:
    cmd = ["bash", "-lc", f'echo | nc -vn -w 2 {host} {port}']
    code, out, err = run_cmd(cmd)
    return out + "\n" + err


def classify_from_output(port: int, output: str) -> str:
    low = output.lower()

    if "http/" in low or "server:" in low:
        return "HTTP"
    if "ssh-" in low:
        return "SSH"
    if "mysql" in low:
        return "MySQL"
    if "flask" in low or "werkzeug" in low:
        return "Flask web app"
    if "got packets out of order" in low:
        return "MySQL handshake"

    if port == 22:
        return "SSH (by port)"
    if port in HTTP_PORT_GUESS:
        return "HTTP (by port)"
    if port == 3306:
        return "MySQL (by port)"
    return "Unknown"


def enrich_with_external_tools(json_path: str, output_path: Optional[str] = None):
    with open(json_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    enriched = []

    for entry in entries:
        host = entry.get("target") or entry.get("host") or entry.get("ip")
        port = int(entry.get("port"))

        print(f"\n[*] Probing {host}:{port} ...")

        if port in HTTP_PORT_GUESS:
            raw = probe_with_curl(host, port)
        else:
            raw = probe_with_nc(host, port)

        service = classify_from_output(port, raw)
        banner_preview = raw.strip().splitlines()[:5]
        banner_text = "\n".join(banner_preview) if banner_preview else ""

        print(f"    Service guess: {service}")
        if banner_text:
            print("    Sample output:")
            for line in banner_preview:
                print("      " + line)

        enriched.append(
            {
                "target": host,
                "port": port,
                "service": service,
                "raw_output": raw,
            }
        )

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2)
    return enriched


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Probe open ports using curl/nc based on JSON input"
    )
    parser.add_argument("input", help="JSON file with open ports")
    parser.add_argument("-o", "--output", help="Optional output JSON file")
    args = parser.parse_args()

    enrich_with_external_tools(args.input, args.output)
