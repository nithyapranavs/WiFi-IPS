from scapy.all import *
import csv
import os
import time
from datetime import datetime

try:
    import gps
    GPS_ENABLED = True
except ImportError:
    GPS_ENABLED = False

networks = {}

LOG_FILE = "war_drive_log.csv"

INTERFACE = "wlan1"

def init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "SSID", "BSSID", "Channel", "Signal (dBm)", "Latitude", "Longitude"])

def get_gps_coords():
    if not GPS_ENABLED:
        return ("N/A", "N/A")

    try:
        session = gps.gps(mode=gps.WATCH_ENABLE)
        report = session.next()
        if report['class'] == 'TPV':
            lat = getattr(report, 'lat', 'N/A')
            lon = getattr(report, 'lon', 'N/A')
            return (lat, lon)
    except:
        pass
    return ("N/A", "N/A")

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        bssid = packet[Dot11].addr3
        dbm_signal = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else "N/A"
        channel = int(ord(packet[Dot11Elt:3].info))

        if bssid not in networks:
            gps_coords = get_gps_coords()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            networks[bssid] = (ssid, channel, dbm_signal, gps_coords)

            print(f"[+] {ssid} ({bssid}) | Channel: {channel} | Signal: {dbm_signal} dBm | GPS: {gps_coords}")

            with open(LOG_FILE, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, ssid, bssid, channel, dbm_signal, gps_coords[0], gps_coords[1]])

def start():
    print(f"[i] Starting WiFi war driving on {INTERFACE}")
    init_csv()
    sniff(iface=INTERFACE, prn=callback, store=0)

if __name__ == "__main__":
    start()
