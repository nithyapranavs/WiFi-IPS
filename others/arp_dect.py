from scapy.all import *
import os

# Replace with your actual gateway IP and MAC (for static validation)
GATEWAY_IP = "192.168.163.88"
GATEWAY_MAC = "16:00:09:b4:32:de"  # change this to your actual router MAC

# Set to True if you want to block after detecting spoofing
AUTO_BLOCK = True

def is_spoofed(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
        sender_ip = pkt[ARP].psrc
        sender_mac = pkt[ARP].hwsrc

        # If claiming to be gateway but wrong MAC -> possible spoof
        if sender_ip == GATEWAY_IP and sender_mac != GATEWAY_MAC:
            print(f"[!] ARP spoof detected! {sender_ip} is pretending to be {sender_mac}")
            return sender_mac
    return None

def block_mac(mac):
    print(f"[+] Blocking MAC address: {mac}")
    os.system(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP")

def monitor():
    print("[*] Starting ARP spoof detection...")
    sniff(store=0, prn=process_packet, filter="arp", iface="wlan0")

def process_packet(pkt):
    attacker_mac = is_spoofed(pkt)
    if attacker_mac and AUTO_BLOCK:
        block_mac(attacker_mac)

if __name__ == "__main__":
    monitor()
