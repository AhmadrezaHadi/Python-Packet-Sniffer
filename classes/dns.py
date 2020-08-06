__author__ = "Ahmadreza Hadi"

from struct import *


class DNS:
    def __init__(self, data):
        transaction_id, flags, questions, answer_RRs, authority_RRs, additional_RRs = \
            unpack('! H H H H H H', data[:12])
        self.transaction_id = transaction_id
        self.questions = questions
        self.answer_RRs = answer_RRs
        self.authority_RRs = authority_RRs
        self.additional_RRs = additional_RRs

        self.flag_rcode = flags & 15
        self.flag_cd = (flags >> 4) & 1
        self.flag_ad = (flags >> 5) & 1
        self.flag_z = (flags >> 6) & 1
        self.flag_ra = (flags >> 7) & 1
        self.flag_rd = (flags >> 8) & 1
        self.flag_tc = (flags >> 9) & 1
        self.flag_aa = (flags >> 10) & 1
        self.flag_opcode = (flags >> 11) & 7
        self.flag_qr = (flags >> 15) & 1

        self.data = data[12:]
