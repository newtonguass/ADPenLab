import struct
from socketserver import BaseRequestHandler
from collections import OrderedDict
import re
class Packet():
    fields = OrderedDict([
    ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def print_fileds(self):
        print(self.fields)
    def return_bytes(self):
        return b"".join(list(self.fields.values()))


class SMBHeader(Packet):
    fields = OrderedDict([
    ("proto", b"\xff\x53\x4d\x42"),
    ("cmd", b"\x72"),
    ("errorcode", b"\x00\x00\x00\x00"),
    ("flag1", b"\x00"),
    ("flag2", b"\x00\x00"),
    ("pidhigh", b"\x00\x00"),
    ("signature", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    ("reserved", b"\x00\x00"),
    ("tid", b"\x00\x00"),
    ("pid", b"\x00\x00"),
    ("uid", b"\x00\x00"),
    ("mid", b"\x00\x00"),
    ])


class SMB2Header(Packet):
    fields = OrderedDict([
        ("Proto",         b"\xfe\x53\x4d\x42"),
        ("Len",           b"\x40\x00"),#Always 64.
        ("CreditCharge",  b"\x00\x00"),
        ("NTStatus",      b"\x00\x00\x00\x00"),
        ("Cmd",           b"\x00\x00"),
        ("Credits",       b"\x01\x00"),
        ("Flags",         b"\x01\x00\x00\x00"),
        ("NextCmd",       b"\x00\x00\x00\x00"),
        ("MessageId",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("PID",           b"\x00\x00\x00\x00"),
        ("TID",           b"\x00\x00\x00\x00"),
        ("SessionID",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature",     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class SMB2NegoAns(Packet):
    fields = OrderedDict([
    ("Len",             b"\x41\x00"),
    ("Signing",         b"\x01\x00"),
    ("Dialect",         b"\xff\x02"),
    ("Reserved",        b"\x00\x00"),
    ("Guid",            b"\xee\x85\xab\xf7\xea\xf6\x0c\x4f\x92\x81\x92\x47\x6d\xeb\x76\xa9"),
    ("Capabilities",    b"\x07\x00\x00\x00"),
    ("MaxTransSize",    b"\x00\x00\x10\x00"),
    ("MaxReadSize",     b"\x00\x00\x10\x00"),
    ("MaxWriteSize",    b"\x00\x00\x10\x00"),
    ("SystemTime",      b"\x27\xfb\xea\xd7\x50\x09\xd2\x01"),
    ("BootTime",        b"\x22\xfb\x80\x01\x40\x09\xd2\x01"),
    ("SecBlobOffSet",             b"\x80\x00"),
    ("SecBlobLen",                b"\x78\x00"),
    ("Reserved2",                 b"\x00\x00\x00\x00"),
    ("InitContextTokenASNId",     b"\x60"),
    ("InitContextTokenASNLen",    b"\x76"),
    ("ThisMechASNId",             b"\x06"),
    ("ThisMechASNLen",            b"\x06"),
    ("ThisMechASNStr",            b"\x2b\x06\x01\x05\x05\x02"),
    ("SpNegoTokenASNId",          b"\xA0"),
    ("SpNegoTokenASNLen",         b"\x6c"),
    ("NegTokenASNId",             b"\x30"),
    ("NegTokenASNLen",            b"\x6a"),
    ("NegTokenTag0ASNId",         b"\xA0"),
    ("NegTokenTag0ASNLen",        b"\x3c"),
    ("NegThisMechASNId",          b"\x30"),
    ("NegThisMechASNLen",         b"\x3a"),
    ("NegThisMech1ASNId",         b"\x06"),
    ("NegThisMech1ASNLen",        b"\x0a"),
    ("NegThisMech1ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
    ("NegThisMech2ASNId",         b"\x06"),
    ("NegThisMech2ASNLen",        b"\x09"),
    ("NegThisMech2ASNStr",        b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
    ("NegThisMech3ASNId",         b"\x06"),
    ("NegThisMech3ASNLen",        b"\x09"),
    ("NegThisMech3ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
    ("NegThisMech4ASNId",         b"\x06"),
    ("NegThisMech4ASNLen",        b"\x0a"),
    ("NegThisMech4ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
    ("NegThisMech5ASNId",         b"\x06"),
    ("NegThisMech5ASNLen",        b"\x0a"),
    ("NegThisMech5ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
    ("NegTokenTag3ASNId",         b"\xA3"),
    ("NegTokenTag3ASNLen",        b"\x2a"),
    ("NegHintASNId",              b"\x30"),
    ("NegHintASNLen",             b"\x28"),
    ("NegHintTag0ASNId",          b"\xa0"),
    ("NegHintTag0ASNLen",         b"\x26"),
    ("NegHintFinalASNId",         b"\x1b"), 
    ("NegHintFinalASNLen",        b"\x24"),
    ("NegHintFinalASNStr",        bytes("Server2008@SMB3.local", encoding="utf-8")),
    ])
    def calculate(self):
        StructLen = self.fields["Len"]+\
                    self.fields["Signing"]+\
                    self.fields["Dialect"]+\
                    self.fields["Reserved"]+\
                    self.fields["Guid"]+\
                    self.fields["Capabilities"]+\
                    self.fields["MaxTransSize"]+\
                    self.fields["MaxReadSize"]+\
                    self.fields["MaxWriteSize"]+\
                    self.fields["SystemTime"]+\
                    self.fields["BootTime"]+\
                    self.fields["SecBlobOffSet"]+\
                    self.fields["SecBlobLen"]+\
                    self.fields["Reserved2"]
        SecBlobLen = self.fields["InitContextTokenASNId"]+\
                     self.fields["InitContextTokenASNLen"]+\
                     self.fields["ThisMechASNId"]+\
                     self.fields["ThisMechASNLen"]+\
                     self.fields["ThisMechASNStr"]+\
                     self.fields["SpNegoTokenASNId"]+\
                     self.fields["SpNegoTokenASNLen"]+\
                     self.fields["NegTokenASNId"]+\
                     self.fields["NegTokenASNLen"]+\
                     self.fields["NegTokenTag0ASNId"]+\
                     self.fields["NegTokenTag0ASNLen"]+\
                     self.fields["NegThisMechASNId"]+\
                     self.fields["NegThisMechASNLen"]+\
                     self.fields["NegThisMech1ASNId"]+\
                     self.fields["NegThisMech1ASNLen"]+\
                     self.fields["NegThisMech1ASNStr"]+\
                     self.fields["NegThisMech2ASNId"]+\
                     self.fields["NegThisMech2ASNLen"]+\
                     self.fields["NegThisMech2ASNStr"]+\
                     self.fields["NegThisMech3ASNId"]+\
                     self.fields["NegThisMech3ASNLen"]+\
                     self.fields["NegThisMech3ASNStr"]+\
                     self.fields["NegThisMech4ASNId"]+\
                     self.fields["NegThisMech4ASNLen"]+\
                     self.fields["NegThisMech4ASNStr"]+\
                     self.fields["NegThisMech5ASNId"]+\
                     self.fields["NegThisMech5ASNLen"]+\
                     self.fields["NegThisMech5ASNStr"]+\
                     self.fields["NegTokenTag3ASNId"]+\
                     self.fields["NegTokenTag3ASNLen"]+\
                     self.fields["NegHintASNId"]+\
                     self.fields["NegHintASNLen"]+\
                     self.fields["NegHintTag0ASNId"]+\
                     self.fields["NegHintTag0ASNLen"]+\
                     self.fields["NegHintFinalASNId"]+\
                     self.fields["NegHintFinalASNLen"]+\
                     self.fields["NegHintFinalASNStr"]
        AsnLenStart = self.fields["ThisMechASNId"]+\
                     self.fields["ThisMechASNLen"]+\
                     self.fields["ThisMechASNStr"]+\
                     self.fields["SpNegoTokenASNId"]+\
                     self.fields["SpNegoTokenASNLen"]+\
                     self.fields["NegTokenASNId"]+\
                     self.fields["NegTokenASNLen"]+\
                     self.fields["NegTokenTag0ASNId"]+\
                     self.fields["NegTokenTag0ASNLen"]+\
                     self.fields["NegThisMechASNId"]+\
                     self.fields["NegThisMechASNLen"]+\
                     self.fields["NegThisMech1ASNId"]+\
                     self.fields["NegThisMech1ASNLen"]+\
                     self.fields["NegThisMech1ASNStr"]+\
                     self.fields["NegThisMech2ASNId"]+\
                     self.fields["NegThisMech2ASNLen"]+\
                     self.fields["NegThisMech2ASNStr"]+\
                     self.fields["NegThisMech3ASNId"]+\
                     self.fields["NegThisMech3ASNLen"]+\
                     self.fields["NegThisMech3ASNStr"]+\
                     self.fields["NegThisMech4ASNId"]+\
                     self.fields["NegThisMech4ASNLen"]+\
                     self.fields["NegThisMech4ASNStr"]+\
                     self.fields["NegThisMech5ASNId"]+\
                     self.fields["NegThisMech5ASNLen"]+\
                     self.fields["NegThisMech5ASNStr"]+\
                     self.fields["NegTokenTag3ASNId"]+\
                     self.fields["NegTokenTag3ASNLen"]+\
                     self.fields["NegHintASNId"]+\
                     self.fields["NegHintASNLen"]+\
                     self.fields["NegHintTag0ASNId"]+\
                     self.fields["NegHintTag0ASNLen"]+\
                     self.fields["NegHintFinalASNId"]+\
                     self.fields["NegHintFinalASNLen"]+\
                     self.fields["NegHintFinalASNStr"]
        AsnLen2 = self.fields["NegTokenASNId"]+\
                  self.fields["NegTokenASNLen"]+\
                  self.fields["NegTokenTag0ASNId"]+\
                  self.fields["NegTokenTag0ASNLen"]+\
                  self.fields["NegThisMechASNId"]+\
                  self.fields["NegThisMechASNLen"]+\
                  self.fields["NegThisMech1ASNId"]+\
                  self.fields["NegThisMech1ASNLen"]+\
                  self.fields["NegThisMech1ASNStr"]+\
                  self.fields["NegThisMech2ASNId"]+\
                  self.fields["NegThisMech2ASNLen"]+\
                  self.fields["NegThisMech2ASNStr"]+\
                  self.fields["NegThisMech3ASNId"]+\
                  self.fields["NegThisMech3ASNLen"]+\
                  self.fields["NegThisMech3ASNStr"]+\
                  self.fields["NegThisMech4ASNId"]+\
                  self.fields["NegThisMech4ASNLen"]+\
                  self.fields["NegThisMech4ASNStr"]+\
                  self.fields["NegThisMech5ASNId"]+\
                  self.fields["NegThisMech5ASNLen"]+\
                  self.fields["NegThisMech5ASNStr"]+\
                  self.fields["NegTokenTag3ASNId"]+\
                  self.fields["NegTokenTag3ASNLen"]+\
                  self.fields["NegHintASNId"]+\
                  self.fields["NegHintASNLen"]+\
                  self.fields["NegHintTag0ASNId"]+\
                  self.fields["NegHintTag0ASNLen"]+\
                  self.fields["NegHintFinalASNId"]+\
                  self.fields["NegHintFinalASNLen"]+\
                  self.fields["NegHintFinalASNStr"]
        MechTypeLen = self.fields["NegThisMechASNId"]+\
                      self.fields["NegThisMechASNLen"]+\
                      self.fields["NegThisMech1ASNId"]+\
                      self.fields["NegThisMech1ASNLen"]+\
                      self.fields["NegThisMech1ASNStr"]+\
                      self.fields["NegThisMech2ASNId"]+\
                      self.fields["NegThisMech2ASNLen"]+\
                      self.fields["NegThisMech2ASNStr"]+\
                      self.fields["NegThisMech3ASNId"]+\
                      self.fields["NegThisMech3ASNLen"]+\
                      self.fields["NegThisMech3ASNStr"]+\
                      self.fields["NegThisMech4ASNId"]+\
                      self.fields["NegThisMech4ASNLen"]+\
                      self.fields["NegThisMech4ASNStr"]+\
                      self.fields["NegThisMech5ASNId"]+\
                      self.fields["NegThisMech5ASNLen"]+\
                      self.fields["NegThisMech5ASNStr"]
        Tag3Len = self.fields["NegHintASNId"]+\
                  self.fields["NegHintASNLen"]+\
                  self.fields["NegHintTag0ASNId"]+\
                  self.fields["NegHintTag0ASNLen"]+\
                  self.fields["NegHintFinalASNId"]+\
                  self.fields["NegHintFinalASNLen"]+\
                  self.fields["NegHintFinalASNStr"]
        #Packet Struct len
        self.fields["Len"] = struct.pack("<h",len(StructLen)+1)
        #Sec Blob lens
        self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)
        self.fields["SecBlobLen"] = struct.pack("<h",len(SecBlobLen))
        #ASN Stuff

        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(SecBlobLen)-2)
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(self.fields["ThisMechASNStr"]))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(self.fields["NegThisMech1ASNStr"]))
        self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(self.fields["NegThisMech2ASNStr"]))
        self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(self.fields["NegThisMech3ASNStr"]))
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(self.fields["NegThisMech4ASNStr"]))
        self.fields["NegThisMech5ASNLen"] = struct.pack("<B", len(self.fields["NegThisMech5ASNStr"]))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(self.fields["NegHintFinalASNStr"]))
class SMB2Session1Data(Packet):
    fields = OrderedDict([
    ("Len",             b"\x09\x00"),
    ("SessionFlag",     b"\x00\x00"),
    ("SecBlobOffSet",   b"\x48\x00"),
    ("SecBlobLen",      b"\x06\x01"),
    ("ChoiceTagASNId",        b"\xa1"), 
    ("ChoiceTagASNLenOfLen",  b"\x82"), 
    ("ChoiceTagASNIdLen",     b"\x01\x02"),
    ("NegTokenTagASNId",      b"\x30"),
    ("NegTokenTagASNLenOfLen",b"\x81"),
    ("NegTokenTagASNIdLen",   b"\xff"),
    ("Tag0ASNId",             b"\xA0"),
    ("Tag0ASNIdLen",          b"\x03"),
    ("NegoStateASNId",        b"\x0A"),
    ("NegoStateASNLen",       b"\x01"),
    ("NegoStateASNValue",     b"\x01"),
    ("Tag1ASNId",             b"\xA1"),
    ("Tag1ASNIdLen",          b"\x0c"),
    ("Tag1ASNId2",            b"\x06"),
    ("Tag1ASNId2Len",         b"\x0A"),
    ("Tag1ASNId2Str",         b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
    ("Tag2ASNId",             b"\xA2"),
    ("Tag2ASNIdLenOfLen",     b"\x81"),
    ("Tag2ASNIdLen",          b"\xE9"),
    ("Tag3ASNId",             b"\x04"),
    ("Tag3ASNIdLenOfLen",     b"\x81"),
    ("Tag3ASNIdLen",          b"\xE6"),
    ("NTLMSSPSignature",      bytes("NTLMSSP", "utf-8")),
    ("NTLMSSPSignatureNull",  b"\x00"),
    ("NTLMSSPMessageType",    b"\x02\x00\x00\x00"),
    ("NTLMSSPNtWorkstationLen",b"\x1e\x00"),
    ("NTLMSSPNtWorkstationMaxLen",b"\x1e\x00"),
    ("NTLMSSPNtWorkstationBuffOffset",b"\x38\x00\x00\x00"),
    ("NTLMSSPNtNegotiateFlags",b"\x15\x82\x89\xe2"),
    ("NTLMSSPNtServerChallenge",b"\x81\x22\x33\x34\x55\x46\xe7\x88"),
    ("NTLMSSPNtReserved",b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    ("NTLMSSPNtTargetInfoLen",b"\x94\x00"),
    ("NTLMSSPNtTargetInfoMaxLen",b"\x94\x00"),
    ("NTLMSSPNtTargetInfoBuffOffset",b"\x56\x00\x00\x00"),
    ("NegTokenInitSeqMechMessageVersionHigh",b"\x06"),
    ("NegTokenInitSeqMechMessageVersionLow",b"\x03"),
    ("NegTokenInitSeqMechMessageVersionBuilt",b"\x80\x25"),
    ("NegTokenInitSeqMechMessageVersionReserved",b"\x00\x00\x00"),
    ("NegTokenInitSeqMechMessageVersionNTLMType",b"\x0f"),
    ("NTLMSSPNtWorkstationName",bytes("SMB3", "utf-16le")),
    ("NTLMSSPNTLMChallengeAVPairsId",b"\x02\x00"),
    ("NTLMSSPNTLMChallengeAVPairsLen",b"\x0a\x00"),
    ("NTLMSSPNTLMChallengeAVPairsUnicodeStr",bytes("SMB3", "utf-16le")),
    ("NTLMSSPNTLMChallengeAVPairs1Id",b"\x01\x00"),
    ("NTLMSSPNTLMChallengeAVPairs1Len",b"\x1e\x00"),
    ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",bytes("WIN-PRH492RQAFV","utf-16le")), 
    ("NTLMSSPNTLMChallengeAVPairs2Id",b"\x04\x00"),
    ("NTLMSSPNTLMChallengeAVPairs2Len",b"\x1e\x00"),
    ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",bytes("SMB3.local", "utf-16le")), 
    ("NTLMSSPNTLMChallengeAVPairs3Id",b"\x03\x00"),
    ("NTLMSSPNTLMChallengeAVPairs3Len",b"\x1e\x00"),
    ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr",bytes("WIN-PRH492RQAFV.SMB3.local", "utf-16le")),
    ("NTLMSSPNTLMChallengeAVPairs5Id",b"\x05\x00"),
    ("NTLMSSPNTLMChallengeAVPairs5Len",b"\x04\x00"),
    ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",bytes("SMB3.local", "utf-16le")),
    ("NTLMSSPNTLMChallengeAVPairs7Id",b"\x07\x00"),
    ("NTLMSSPNTLMChallengeAVPairs7Len",b"\x08\x00"),
    ("NTLMSSPNTLMChallengeAVPairs7UnicodeStr",b"\xc0\x65\x31\x50\xde\x09\xd2\x01"),
    ("NTLMSSPNTLMChallengeAVPairs6Id",b"\x00\x00"),
    ("NTLMSSPNTLMChallengeAVPairs6Len",b"\x00\x00"),
    ])
    def calculate(self):
        
        #Packet struct calc:
        StructLen = self.fields["Len"]+self.fields["SessionFlag"]+self.fields["SecBlobOffSet"]+self.fields["SecBlobLen"]
        ###### SecBlobLen Calc:
        CalculateSecBlob = self.fields["NTLMSSPSignature"]+\
                           self.fields["NTLMSSPSignatureNull"]+\
                           self.fields["NTLMSSPMessageType"]+\
                           self.fields["NTLMSSPNtWorkstationLen"]+\
                           self.fields["NTLMSSPNtWorkstationMaxLen"]+\
                           self.fields["NTLMSSPNtWorkstationBuffOffset"]+\
                           self.fields["NTLMSSPNtNegotiateFlags"]+\
                           self.fields["NTLMSSPNtServerChallenge"]+\
                           self.fields["NTLMSSPNtReserved"]+\
                           self.fields["NTLMSSPNtTargetInfoLen"]+\
                           self.fields["NTLMSSPNtTargetInfoMaxLen"]+\
                           self.fields["NTLMSSPNtTargetInfoBuffOffset"]+\
                           self.fields["NegTokenInitSeqMechMessageVersionHigh"]+\
                           self.fields["NegTokenInitSeqMechMessageVersionLow"]+\
                           self.fields["NegTokenInitSeqMechMessageVersionBuilt"]+\
                           self.fields["NegTokenInitSeqMechMessageVersionReserved"]+\
                           self.fields["NegTokenInitSeqMechMessageVersionNTLMType"]+\
                           self.fields["NTLMSSPNtWorkstationName"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairsId"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairsLen"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs1Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs1Len"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs2Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs2Len"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs3Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs3Len"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs5Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs5Len"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs7Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs7Len"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs6Id"]+\
                           self.fields["NTLMSSPNTLMChallengeAVPairs6Len"]

        AsnLen = self.fields["ChoiceTagASNId"]+\
                 self.fields["ChoiceTagASNLenOfLen"]+\
                 self.fields["ChoiceTagASNIdLen"]+\
                 self.fields["NegTokenTagASNId"]+\
                 self.fields["NegTokenTagASNLenOfLen"]+\
                 self.fields["NegTokenTagASNIdLen"]+\
                 self.fields["Tag0ASNId"]+\
                 self.fields["Tag0ASNIdLen"]+\
                 self.fields["NegoStateASNId"]+\
                 self.fields["NegoStateASNLen"]+\
                 self.fields["NegoStateASNValue"]+\
                 self.fields["Tag1ASNId"]+\
                 self.fields["Tag1ASNIdLen"]+\
                 self.fields["Tag1ASNId2"]+\
                 self.fields["Tag1ASNId2Len"]+\
                 self.fields["Tag1ASNId2Str"]+\
                 self.fields["Tag2ASNId"]+\
                 self.fields["Tag2ASNIdLenOfLen"]+\
                 self.fields["Tag2ASNIdLen"]+\
                 self.fields["Tag3ASNId"]+\
                 self.fields["Tag3ASNIdLenOfLen"]+\
                 self.fields["Tag3ASNIdLen"]


        #Packet Struct len
        self.fields["Len"] = struct.pack("<h",len(StructLen)+1)
        self.fields["SecBlobLen"] = struct.pack("<H", len(AsnLen+CalculateSecBlob))
        self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)

        ###### ASN Stuff
        if len(CalculateSecBlob) > 255:
           self.fields["Tag3ASNIdLen"] = struct.pack(">H", len(CalculateSecBlob))
        else:
           self.fields["Tag3ASNIdLenOfLen"] = b"\x81"
           self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

        if len(AsnLen+CalculateSecBlob)-3 > 255:
           self.fields["ChoiceTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-4)
        else:
           self.fields["ChoiceTagASNLenOfLen"] = b"\x81"
           self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)

        if len(AsnLen+CalculateSecBlob)-7 > 255:
           self.fields["NegTokenTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-8)
        else:
           self.fields["NegTokenTagASNLenOfLen"] = b"\x81"
           self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-7)
        
        tag2length = CalculateSecBlob+self.fields["Tag3ASNId"]+self.fields["Tag3ASNIdLenOfLen"]+self.fields["Tag3ASNIdLen"]

        if len(tag2length) > 255:
           self.fields["Tag2ASNIdLen"] = struct.pack(">H", len(tag2length))
        else:
           self.fields["Tag2ASNIdLenOfLen"] = b"\x81"
           self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(tag2length))

        self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(self.fields["Tag1ASNId2"]+
                                      self.fields["Tag1ASNId2Len"]+ 
                                      self.fields["Tag1ASNId2Str"]))
        self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(self.fields["Tag1ASNId2Str"]))

        ###### Workstation Offset
        CalculateOffsetWorkstation = self.fields["NTLMSSPSignature"]+\
                                     self.fields["NTLMSSPSignatureNull"]+\
                                     self.fields["NTLMSSPMessageType"]+\
                                     self.fields["NTLMSSPNtWorkstationLen"]+\
                                     self.fields["NTLMSSPNtWorkstationMaxLen"]+\
                                     self.fields["NTLMSSPNtWorkstationBuffOffset"]+\
                                     self.fields["NTLMSSPNtNegotiateFlags"]+\
                                     self.fields["NTLMSSPNtServerChallenge"]+\
                                     self.fields["NTLMSSPNtReserved"]+\
                                     self.fields["NTLMSSPNtTargetInfoLen"]+\
                                     self.fields["NTLMSSPNtTargetInfoMaxLen"]+\
                                     self.fields["NTLMSSPNtTargetInfoBuffOffset"]+\
                                     self.fields["NegTokenInitSeqMechMessageVersionHigh"]+\
                                     self.fields["NegTokenInitSeqMechMessageVersionLow"]+\
                                     self.fields["NegTokenInitSeqMechMessageVersionBuilt"]+\
                                     self.fields["NegTokenInitSeqMechMessageVersionReserved"]+\
                                     self.fields["NegTokenInitSeqMechMessageVersionNTLMType"]

        ###### AvPairs Offset
        CalculateLenAvpairs = self.fields["NTLMSSPNTLMChallengeAVPairsId"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairsLen"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs1Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs1Len"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs2Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs2Len"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs3Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs3Len"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs5Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs5Len"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs7Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs7Len"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs6Id"]+\
                              self.fields["NTLMSSPNTLMChallengeAVPairs6Len"]

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(self.fields["NTLMSSPNtWorkstationName"]))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(self.fields["NTLMSSPNtWorkstationName"]))

        ##### Target Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+self.fields["NTLMSSPNtWorkstationName"]))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs7Len"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"]))
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
