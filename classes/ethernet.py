__author__ = "Ahmadreza Hadi"

import socket
from struct import *


# formats mac address properly
def calc_mac(raw_addr):
    mac_str = map('{:02x}'.format, raw_addr)
    mac_addr = ':'.join(mac_str).upper()
    return mac_addr


class Ethernet:
    # Adjusts dest and source MAC address with protocol number and payload
    def __init__(self, raw_data):
        dest_mac, src_mac, eth_type = unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = calc_mac(dest_mac)
        self.src_mac = calc_mac(src_mac)
        self.proto = socket.htons(eth_type)
        self.data = raw_data[14:]
