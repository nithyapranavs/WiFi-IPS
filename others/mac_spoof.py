from scapy.all import *
from collections import defaultdict
import csv
import time
import os

# Store IP-MAC and MAC-IP mappings
ip_mac_map = {}
mac_ip_map = defaultdict(set)

LOG_FILE = "mac_spoof_log.csv"

# Create CSV log file with headers if it doesn't exist
if not os.path.isfile(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "type", "details"])

def log_spoof(event_type, details):
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([int(time.time()), event_type, details])

def detect_mac_spoof(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        # IP associated with a different MAC
        if src_ip in ip_mac_map:
            if ip_mac_map[src_ip] != src_mac:
                msg = f"IP {src_ip} changed from {ip_mac_map[src_ip]} to {src_mac}"
                print(f"[!] Possible MAC spoofing detected: {msg}")
                log_spoof("IP-MAC Mismatch", msg)
        else:
            ip_mac_map[src_ip] = src_mac

        # MAC associated with multiple IPs
        mac_ip_map[src_mac].add(src_ip)
        if len(mac_ip_map[src_mac]) > 3:
            msg = f"MAC {src_mac} linked to multiple IPs: {mac_ip_map[src_mac]}"
            print(f"[!] Possible MAC spoofing: {msg}")
            log_spoof("MAC-IP Multiples", msg)

print("Starting MAC spoofing detection...")
sniff(filter="arp", store=0, prn=detect_mac_spoof)
