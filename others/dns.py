from scapy.all import *
from datetime import datetime

TRUSTED_DNS_IPS = ["8.8.8.8", "1.1.1.1"]
LOG_FILE = "dns_spoof_log.txt"
INTERFACE = "wlx0602800baedd"  # your interface

def log_spoof_attempt(src_ip, qname, spoof_ip):
    with open(LOG_FILE, "a") as log:
        log.write(f"[{datetime.now()}] Spoofed DNS response from {src_ip} for {qname} → {spoof_ip}\n")
    print(f"[!] DNS Spoof Detected from {src_ip} for {qname} → {spoof_ip}")

def detect_dns_spoof(packet):
    if packet.haslayer(IP) and packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
        src_ip = packet[IP].src
        qname = packet[DNS].qd.qname.decode()
        spoof_ip = packet[DNS].an.rdata if packet[DNS].an else "N/A"

        if src_ip not in TRUSTED_DNS_IPS:
            log_spoof_attempt(src_ip, qname, spoof_ip)


sniff(filter="udp port 53", iface=INTERFACE, prn=detect_dns_spoof, store=0)

