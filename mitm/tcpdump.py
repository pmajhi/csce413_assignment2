import subprocess
from scapy.all import sniff, wrpcap, TCP

def get_vuln_ifname():
    cmd = [
        "docker", "network", "ls",
        "--filter", "name=^csce413_assignment2_vulnerable_network$",
        "--format", "{{.ID}}"
    ]
    net_id = subprocess.check_output(cmd, text=True).strip()
    return f"br-{net_id}"

def packet_handler(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 3306:
        print(pkt.summary())

iface = get_vuln_ifname()
print(f"Sniffing on {iface} for 15 seconds...")

packets = sniff(
    iface=iface,
    filter="tcp port 3306",
    timeout=15,
    prn=packet_handler
)

# wrpcap("mitm.pcap", packets)
print(f"Captured {len(packets)} packets into mitm.log")

from scapy.all import IP, TCP, Raw

with open("mitm.log", "w") as f:
    for pkt in packets:
        # Basic 5‑tuple
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            f.write(f"{src_ip}:{sport} -> {dst_ip}:{dport}\n")

            # If there is application data, dump it as text
            if Raw in pkt:
                payload = pkt[Raw].load
                try:
                    text = payload.decode(errors="ignore")
                except Exception:
                    text = repr(payload)
                f.write(text + "\n")

            f.write("-" * 40 + "\n")
