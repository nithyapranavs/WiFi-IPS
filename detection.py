import threading

from scapy.all import *
import time, datetime
import csv
HARDCODED_ROUTER_MAC = "20:4e:7f:0e:df:46"
data = {}
WIRELESS_INTERFACE = "wlan1"

def deauth_log(addr1, addr2, signal_strength, channel_flags, packet_length, pktType):
    if(addr1 == HARDCODED_ROUTER_MAC):
        router = addr1
        victim = addr2
    else:
        router = addr2
        victim = addr1

    log_entry = {
        'router': router,
        'victim': victim,
        'timestamp': int(time.time()),
        'signalStrength': signal_strength,
        'channelFlags': channel_flags,
        'packetLength': packet_length,
        'type': pktType
    }

    # Write to CSV file
    LOG_FILE = "dashboard/main/static/logs/deauth.csv"
    file_exists = os.path.isfile(LOG_FILE)  # Check if the file already exists
    print(file_exists)
    with open(LOG_FILE, mode='a', newline='') as csvfile:
        fieldnames = ['timestamp', 'router', 'victim', 'signalStrength', 'channelFlags', 'packetLength', 'type']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write header only if file is being created
        if not file_exists:
            writer.writeheader()
            print("creating file")

        # Write the log entry
        writer.writerow({
            'timestamp': log_entry['timestamp'],
            'router': log_entry['router'],
            'victim': log_entry['victim'],
            'signalStrength': log_entry['signalStrength'],
            'channelFlags': log_entry['channelFlags'],
            'packetLength': log_entry['packetLength'],
            'type': log_entry['type'],
        })

    # Update in-memory count of attacks
    pair_key = str([router, victim])
    if pair_key in data:
        data[pair_key] += 1
    else:
        data[pair_key] = 1

    return



def detect_deauth(pkt):
    if pkt.haslayer(Dot11Deauth) and pkt.addr2 is not None and pkt.addr3 is not None:
        addr1 = pkt.addr1
        addr2 = pkt.addr2
        flag = str(pkt.ChannelFlags)

        deauth_log(addr1, addr2, pkt.dBm_AntSignal, flag, pkt.len, pkt.reason)

def deauth_scan():
    print("deauth detection enabled")
    sniff(prn=detect_deauth, count=0)


def rogue_log(bssid, network):
    log_file = "dashboard/main/static/logs/rogue_ap.csv"

    # Check if the log file already exists
    file_exists = os.path.isfile(log_file)

    # Open CSV file for logging
    with open(log_file, mode='a', newline='') as csvfile:
        fieldnames = ['timestamp', 'SSID', 'BSSID', 'SignalStrength', 'Channel', 'SupportedRates']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write header only if the file is being created
        if not file_exists:
            writer.writeheader()
            print("Creating log file")

        log_entry = {
            'timestamp': int(time.time()),
            'SSID': network.get('SSID', 'Unknown'),
            'BSSID': bssid,
            'SignalStrength': network.get('Signal', 'N/A'),
            'Channel': network.get('Channel', 'N/A'),
            'SupportedRates': ' '.join(map(str, network.get('Rates', [])))
        }

        # Write to CSV
        writer.writerow(log_entry)

def rogue_scan(iface=WIRELESS_INTERFACE):
    bssid_org = "7c:a9:6b:71:7f:2b"
    ssid_org = "test_network"
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            if ssid == ssid_org and bssid != bssid_org:
                stats = packet[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                signal = packet.dBm_AntSignal
                rates = stats.get("rates")

                if bssid not in networks:
                    log_data = {
                        "SSID": ssid,
                        "Signal": signal,
                        "Channel": channel,
                        "Rates": rates
                    }
                    networks[bssid] = log_data 
                    rogue_log(bssid, log_data)

    print("rogue ap detection enabled")
    sniff(prn=packet_handler, iface=iface)


def start_detection():

    deauth_process = threading.Thread(target=deauth_scan)
    rogue_process = threading.Thread(target=rogue_scan)

    deauth_process.start()
    rogue_process.start()

    deauth_process.join()
    rogue_process.join()

if __name__ == "__main__":
    start_detection()
