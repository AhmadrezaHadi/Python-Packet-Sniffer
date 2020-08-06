__author__ = "Ahmadreza Hadi"


class HTTP:
    def __init__(self, message):
        try:
            self.message = message.decode('utf-8')
        except:
            self.message = message
