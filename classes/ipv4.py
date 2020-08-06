__author__ = "Ahmadreza Hadi"

from struct import *


# Returns formatted ip as string
def calc_ip(raw_ip):
    return '.'.join(map(str, raw_ip))


class IPv4:

    def __init__(self, data):
        version_ihl, dscp_ecn, total_length, identification, flags_fragmentOffset, ttl, protocol, checksum, src_ip, dst_ip = \
            unpack('! B B H H H B B H 4s 4s', data[:20])

        self.version = version_ihl >> 4
        self.ecn = dscp_ecn & 3
        self.type_of_service = dscp_ecn >> 2
        self.total_length = total_length
        self.identification = identification
        self.flags = flags_fragmentOffset >> 13
        self.fragment_offset = flags_fragmentOffset & 8191
        self.header_length = (version_ihl & 15) * 4
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src_ip = calc_ip(src_ip)
        self.dst_ip = calc_ip(dst_ip)
        self.data = data[self.header_length:]
