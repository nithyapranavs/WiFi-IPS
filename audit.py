import os
import re
import subprocess
from scapy.all import *

# Monitor mode interface (change to your actual interface name)
interface = "wlan1"

# Dictionary to store discovered networks
networks = {}
def set_monitor_mode():
    """Put the wireless interface in monitor mode."""
    os.system(f"ip link set {interface} down")
    os.system(f"iw dev {interface[:-3]} set type monitor")  # Remove 'mon' if already in name
    os.system(f"ip link set {interface} up")
    print(f"[*] {interface} set to monitor mode.")

def scan_networks(iface=interface):

    print("[*] Scanning for available networks...")
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            stats = packet[Dot11Beacon].network_stats()
            #print(stats)
            channel = stats.get("channel")
            signal = packet.dBm_AntSignal
            rates = stats.get("rates")
            crypto = stats.get("crypto")

            if bssid not in networks:
                networks[bssid] = {
                    "ESSID": ssid,
                    "Signal": signal,
                    "Channel": channel,
                    "Rates": rates,
                    "Encryption": crypto
                }

    print("Scanning for Wi-Fi networks...")
    sniff(prn=packet_handler, iface=iface, timeout=10)
    print("[*] Scanning complete.")




def audit_networks():
    """Audit the security level of discovered networks."""
    if not networks:
        print("[-] No networks found. Run a scan first.")
        return

    print("\n[*] Auditing Networks:")
    for bssid, info in networks.items():
        essid = info['ESSID']
        encryption = info['Encryption']

        if 'WPA3/PSK' in encryption :
            security_level = "Excellent (WPA3)"
        elif 'WPA2/PSK' in encryption:
            security_level = "Good (WPA2)"
        elif 'WPA/PSK' in encryption:
            security_level = "Moderate (WPA)"
        elif 'WEP/PSK' in encryption:
            security_level = "Weak (WEP - Deprecated)"
        else:
            security_level = "Insecure (Open Network)"

        print(f"[+] {essid} ({bssid}): {encryption} - Security Level: {security_level}")
