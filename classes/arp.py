__author__ = "Ahmadreza Hadi"

from struct import *
from .ethernet import calc_mac
from .ipv4 import calc_ip


class ARP:
    def __init__(self, data):
        h_type, p_type, hardware_size, protocol_size, op_code, \
        src_mac_addr, src_ip_addr, dst_mac_addr, dst_ip_addr = unpack('! H H B B H 6s L 6s L', data[:28])

        self.h_type = h_type
        self.p_type = p_type
        self.hardware_size = hardware_size
        self.protocol_size = protocol_size
        self.op_code = op_code
        # self.src_mac_addr = calc_mac(src_mac_addr)
        # self.dst_mac_addr = calc_mac(dst_mac_addr)
        # self.src_ip_addr = calc_ip(src_ip_addr)
        # self.dst_ip_addr = calc_ip(dst_ip_addr)
        self.src_mac_addr = src_mac_addr
        self.dst_mac_addr = dst_mac_addr
        self.src_ip_addr = src_ip_addr
        self.dst_ip_addr = dst_ip_addr

        self.data = data[28:]