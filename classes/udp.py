__author__ = "Ahmadreza Hadi"

from struct import *


class UDP:
    def __init__(self, data):
        src_port, dst_port, size, checksum = unpack('! H H H H', data[:8])

        self.src_port = src_port
        self.dst_port = dst_port
        self.size = size
        self.checksum = checksum
        self.data = data[8:]
