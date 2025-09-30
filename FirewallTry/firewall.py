from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Define firewall rules
BLOCKED_IPS = {"192.168.1.100"}  # Example blocked IP
BLOCKED_PORTS = {22, 445}        # Example: block SSH (22) and SMB (445)
LOG_FILE = "firewall_log.txt"


def log_event(message):
    """Log blocked packet details to file with timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {message}\n"
    print(entry.strip())
    with open(LOG_FILE, "a") as f:
        f.write(entry)


def packet_callback(packet):
    """Inspect packets and enforce rules."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # TCP/UDP details
        dst_port = None
        if TCP in packet:
            dst_port = packet[TCP].dport
        elif UDP in packet:
            dst_port = packet[UDP].dport

        # Rule 1: Block specific IPs
        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            log_event(f"BLOCKED IP {src_ip} → {dst_ip}")
            return

        # Rule 2: Block specific ports
        if dst_port in BLOCKED_PORTS:
            log_event(f"BLOCKED PORT {dst_port} ({src_ip} → {dst_ip})")
            return

        # Otherwise allow
        log_event(f"ALLOWED {src_ip} → {dst_ip} port {dst_port}")


def main():
    print("[+] Starting custom firewall...")
    print("[+] Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)


if __name__ == "__main__":
    main()
