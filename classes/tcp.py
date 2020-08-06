__author__ = "Ahmadreza Hadi"

from struct import *


class TCP:
    def __init__(self, data):
        src_port, dst_port, seq_number, ack_number, offset_reserved_flags, window_size, checksum, urgent_pointer = unpack(
            '! H H L L H H H H', data[:20])
        self.src_port = src_port
        self.dst_port = dst_port
        self.ack_number = ack_number
        self.seq_number = seq_number
        self.offset = (offset_reserved_flags >> 12) * 4
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.data = data[self.offset:]

        # flags
        self.flag_fin = offset_reserved_flags & 1
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ece = (offset_reserved_flags & 64) >> 6
        self.flag_cwr = (offset_reserved_flags & 128) >> 7
        self.flag_ns = (offset_reserved_flags & 256) >> 8
