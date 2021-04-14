#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface" , help='Interface to change MAC addr')
    parser.add_option("-m", "--mac" , dest = "new_mac" , help = "New MAC")
    (options,arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please choose a valid interface with -i")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac address with -m")
    return options

def change_mac(interface, new_mac):
    print('[+] Changing MAC for {} to {}'.format(interface,new_mac))
    subprocess.call(['ifconfig',interface,'down'])
    subprocess.call(['ifconfig',interface,'hw','ether',new_mac])
    subprocess.call(['ifconfig',interface,'up'])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig',interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w" , str(ifconfig_result))

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print('[-] Could not read MAC address.')

options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Current MAC: {}".format(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC changed to {}".format(current_mac))
else:
    print("[-] MAC address change failed")