#!/usr/bin/python3

from os import system
from scapy.all import *

hiddenBSSID = list()

def listHidden(frame):
    # if it is a beacon and the SSID is not broadcasted
    if frame.haslayer(Dot11Beacon) and frame.info == b'\x00'*9:
        # if the BSSID is not already in our list, we add it
        if frame.addr3 not in hiddenBSSID:
            print("Adding BSSID: " + frame.addr3 + " to list of Hidden BSSID!")
            hiddenBSSID.append(frame.addr3)
    # if it is a Probe Response from a hidden SSID
    elif frame.haslayer(Dot11ProbeResp):
        if frame.addr2 in hiddenBSSID:
            print("[-] Name of Hidden SSID Found ! "  + frame.info.decode() + " (BSSID: " + frame.addr2 + ")")

conf.iface = "wlan0"

sniff(prn=listHidden)
