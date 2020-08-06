__author___ = "Ahmadreza Hadi"

import textwrap
import socket
from file.pcapfile import Pcap
from classes.ethernet import Ethernet
from classes.ipv4 import IPv4
from classes.icmp import ICMP
from classes.tcp import TCP
from classes.udp import UDP
from classes.dns import DNS
from classes.arp import ARP
from classes.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


# formatting multiple lines of data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    pcap = Pcap('packets.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)

            ethernet = Ethernet(raw_data)
            print("\nEthernet Frame: ")
            print(DATA_TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(ethernet.dest_mac,
                                                                                  ethernet.src_mac,
                                                                                  ethernet.proto))
            # IPv4 Packet
            if ethernet.proto == 8:
                ipv4 = IPv4(ethernet.data)
                print(TAB_1 + 'IPv4 Packet:')
                print(DATA_TAB_2 + 'Version: {}, ToS: {}, ECN: {}, Total Length: {}, '
                                   'Identification: {}'.format(ipv4.version,
                                                               ipv4.type_of_service,
                                                               ipv4.ecn,
                                                               ipv4.total_length,
                                                               ipv4.identification))
                print(DATA_TAB_2 + 'Flags: {}, Fragment Offset:{}, TTL: {}, Protocol: {}, '
                                   'Checksum: {}'.format(ipv4.flags,
                                                         ipv4.fragment_offset,
                                                         ipv4.ttl,
                                                         ipv4.protocol,
                                                         ipv4.checksum))
                print(DATA_TAB_2 + 'Source IP: {}, Destination IP: {}'.format(ipv4.src_ip, ipv4.dst_ip))

                # ICMP
                if ipv4.protocol == 1:
                    icmp = ICMP(ipv4.data)
                    print(TAB_1 + 'ICMP Segment: ')
                    print(DATA_TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp.type, icmp.code, icmp.checksum))
                    print(TAB_2 + 'ICMP Data: ')
                    print(format_multi_line(DATA_TAB_3, icmp.data))

                # TCP
                elif ipv4.protocol == 6:
                    tcp = TCP(ipv4.data)
                    print(TAB_1 + 'TCP Segment: ')
                    print(DATA_TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dst_port))
                    print(DATA_TAB_2 + 'Sequence Number: {}, ACK Number: {}, Offset: {}'.format(tcp.seq_number,
                                                                                                tcp.ack_number,
                                                                                                tcp.offset))
                    print(TAB_2 + 'Flags:')
                    print(DATA_TAB_3 + 'NS: {}, CWR: {}, ECE: {}'.format(tcp.flag_ns, tcp.flag_cwr, tcp.flag_ece))
                    print(DATA_TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                    print(DATA_TAB_3 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                    # HTTP Message
                    if tcp.src_port == 80 or tcp.dst_port == 80:
                        print(TAB_2 + 'HTTP Message: ')
                        try:
                            http = HTTP(tcp.data)
                            http_message = str(http.message).split('\n')
                            for line in http_message:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data: ')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

                # UDP
                elif ipv4.protocol == 17:
                    udp = UDP(ipv4.data)
                    print(TAB_1 + 'UDP Segment: ')
                    print(DATA_TAB_2 + 'Source Port: {}, Destination Port: {}'.format(udp.src_port, udp.dst_port))
                    print(DATA_TAB_2 + 'Size: {}, Checksum: {}'.format(udp.size, udp.checksum))

                    # DNS
                    if udp.dst_port == 53:
                        dns = DNS(udp.data)
                        print(TAB_2 + 'DNS Segment: ')
                        print(DATA_TAB_3 + 'Transaction ID: {}'.format(dns.transaction_id))
                        print(TAB_3 + 'Flags: ')
                        print(DATA_TAB_4 + 'QR: {}, OpCode: {}, AA: {}, TC: {}, RD: {}'.format(dns.flag_qr,
                                                                                               dns.flag_opcode,
                                                                                               dns.flag_aa,
                                                                                               dns.flag_tc,
                                                                                               dns.flag_rd))
                        print(DATA_TAB_4 + 'RA: {}, Z: {}, AD: {}, CD: {}, Rcode: {}'.format(dns.flag_ra,
                                                                                             dns.flag_z,
                                                                                             dns.flag_ad,
                                                                                             dns.flag_cd,
                                                                                             dns.flag_rcode))
                        print(DATA_TAB_3 + 'Number of Questions: {}'.format(dns.questions))
                        print(DATA_TAB_3 + 'Number of Answer RRs: {}, Number of Authority RRs: {}, Number of '
                                           'Additional RRs: {}'.format(dns.answer_RRs, dns.authority_RRs,
                                                                       dns.additional_RRs))
                        print(TAB_3 + 'DNS message: ')
                        print(format_multi_line(DATA_TAB_4, dns.data))
                    else:
                        print(TAB_2 + 'UDP data: ')
                        print(format_multi_line(DATA_TAB_3, udp.data))
            # ARP Packet
            elif ethernet.proto == 1544:
                arp = ARP(ethernet.data)
                print(TAB_1 + 'ARP Packet: ')
                print(DATA_TAB_2 + 'Hardware Type: {}, Protocol Type: {}'.format(arp.h_type, arp.p_type))
                print(DATA_TAB_2 + 'Hardware Address Length: {}, Protocol Address Length: {}'.format(arp.hardware_size,
                                                                                                     arp.protocol_size))
                print(DATA_TAB_2 + 'Operation: {}'.format(arp.op_code))
                print(DATA_TAB_2 + 'Source MAC Address: {}, Source IP Address: {}'.format(arp.src_mac_addr,
                                                                                          arp.src_ip_addr))
                print(DATA_TAB_2 + 'Destination MAC Address: {}, Destination IP Address: {}'.format(arp.dst_mac_addr,
                                                                                                    arp.dst_ip_addr))
                print(TAB_1 + 'ARP Data: ')
                print(format_multi_line(DATA_TAB_2, arp.data))

    except KeyboardInterrupt:
        pcap.close()


main()
