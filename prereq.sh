
#!/bin/bash
sudo killall -e NetworkManager
sudo killall -e wpa_supplicant
sudo killall -e dhclient
sudo airmon-ng start wlan1
python3 main10.py

