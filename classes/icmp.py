__author__ = "Ahmadreza Hadi"

from struct import *


class ICMP:
    def __init__(self, data):
        type, code, checksum = unpack('! B B H', data[:4])
        self.type = type
        self.code = code
        self.checksum = checksum
        self.data = data[4:]
