using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

class hahah{
	

[DllImport("kernel32.dll")]
private static extern uint WTSGetActiveConsoleSessionId();


[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public Int32 Length;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

public enum SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
}




[DllImport("kernel32.dll", SetLastError = true,
    CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
public static extern bool CloseHandle(IntPtr handle);



[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool DuplicateTokenEx(
    IntPtr hExistingToken,
    Int32 dwDesiredAccess,
    ref SECURITY_ATTRIBUTES lpThreadAttributes,
    Int32 ImpersonationLevel,
    Int32 dwTokenType,
    ref IntPtr phNewToken);

[DllImport("wtsapi32.dll", SetLastError=true)]
public static extern bool WTSQueryUserToken(
    Int32 sessionId, 
    out IntPtr Token);

[DllImport("userenv.dll", SetLastError = true)]
static extern bool CreateEnvironmentBlock(
    out IntPtr lpEnvironment, 
    IntPtr hToken, 
    bool bInherit);
		
[DllImport("wtsapi32.dll", SetLastError = true)]
    static extern int WTSQueryUserToken(UInt32 sessionId, out IntPtr Token);
	
[StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
[Flags]
    enum CreateProcessFlags : uint
    {
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]

    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
	
	[DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

	[DllImport("kernel32.dll")]
	public static extern int OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);   
	
	[DllImport("advapi32.dll", SetLastError = true)]
    static extern Boolean SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
        ref UInt32 TokenInformation, UInt32 TokenInformationLength);
	
	//https://docs.microsoft.com/zh-tw/windows/win32/api/winnt/ne-winnt-token_information_class
	 enum TOKEN_INFORMATION_CLASS : int {
	  TokenUser=1,
	  TokenGroups,
	  TokenPrivileges,
	  TokenOwner,
	  TokenPrimaryGroup,
	  TokenDefaultDacl,
	  TokenSource,
	  TokenType,
	  TokenImpersonationLevel,
	  TokenStatistics,
	  TokenRestrictedSids,
	  TokenSessionId,
	  TokenGroupsAndPrivileges,
	  TokenSessionReference,
	  TokenSandBoxInert,
	  TokenAuditPolicy,
	  TokenOrigin,
	  TokenElevationType,
	  TokenLinkedToken,
	  TokenElevation,
	  TokenHasRestrictions,
	  TokenAccessInformation,
	  TokenVirtualizationAllowed,
	  TokenVirtualizationEnabled,
	  TokenIntegrityLevel,
	  TokenUIAccess,
	  TokenMandatoryPolicy,
	  TokenLogonSid,
	  TokenIsAppContainer,
	  TokenCapabilities,
	  TokenAppContainerSid,
	  TokenAppContainerNumber,
	  TokenUserClaimAttributes,
	  TokenDeviceClaimAttributes,
	  TokenRestrictedUserClaimAttributes,
	  TokenRestrictedDeviceClaimAttributes,
	  TokenDeviceGroups,
	  TokenRestrictedDeviceGroups,
	  TokenSecurityAttributes,
	  TokenIsRestricted,
	  TokenProcessTrustLevel,
	  TokenPrivateNameSpace,
	  TokenSingletonAttributes,
	  TokenBnoIsolation,
	  TokenChildProcessFlags,
	  MaxTokenInfoClass,
	  TokenIsLessPrivilegedAppContainer,
	  TokenIsSandboxed,
	  TokenOriginatingProcessTrustLevel
	};

	private const int STANDARD_RIGHTS_REQUIRED = 0x000F0000; 
	private const int STANDARD_RIGHTS_READ = 0x00020000; 
	private const int TOKEN_ASSIGN_PRIMARY = 0x0001; 
	private const int TOKEN_DUPLICATE = 0x0002; 
	private const int TOKEN_IMPERSONATE = 0x0004; 
	private const int TOKEN_QUERY = 0x0008; 
	private const int TOKEN_QUERY_SOURCE = 0x0010; 
	private const int TOKEN_ADJUST_PRIVILEGES = 0x0020; 
	private const int TOKEN_ADJUST_GROUPS = 0x0040; 
	private const int TOKEN_ADJUST_DEFAULT = 0x0080; 
	private const int TOKEN_ADJUST_SESSIONID = 0x0100; 
	private const int TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY); 
	private const int TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
	TOKEN_ASSIGN_PRIMARY | 
	TOKEN_DUPLICATE | 
	TOKEN_IMPERSONATE | 
	TOKEN_QUERY | 
	TOKEN_QUERY_SOURCE | 
	TOKEN_ADJUST_PRIVILEGES | 
	TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | 
	TOKEN_ADJUST_SESSIONID);
	
		
	public static void Main(){
		
		
		//uint activeSessID = WTSGetActiveConsoleSessionId();
		uint activeSessID = GetCurrentSession();
		Console.WriteLine(activeSessID);
		IntPtr hToken = WindowsIdentity.GetCurrent().Token;
		Console.WriteLine(hToken);

		IntPtr hDupedToken = IntPtr.Zero;
		//uint dwSessionID = WTSGetActiveConsoleSessionId();
		//WTSQueryUserToken(dwSessionID, out hToken);
	
		//https://technet.microsoft.com/en-us/ff560499(v=vs.71)
		int TOKEN_TYPE =1;
		//https://msdn.microsoft.com/en-us/windows/desktop/aa379633
		int SECURITY_IMPERSONATION_LEVEL = 2;
		//https://msdn.microsoft.com/zh-tw/windows/hardware/ms717798(v=vs.71)
		SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
		sa.Length = Marshal.SizeOf(sa);
		//https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
		//https://www.pinvoke.net/default.aspx/Enums.ACCESS_MASK
		//https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
		
		bool result = DuplicateTokenEx(
			hToken,
			TOKEN_ALL_ACCESS, 
			ref sa, 
			SECURITY_IMPERSONATION_LEVEL, 
			TOKEN_TYPE, 
			ref hDupedToken);
		if(result){
			Console.WriteLine("Hello!!Get the token successfully");
		}
		result = SetTokenInformation(hDupedToken, TOKEN_INFORMATION_CLASS.TokenSessionId ,ref activeSessID, 4);
		
		if(result){
			Console.WriteLine("SetTokenInformation successfully");
		}

		
		PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
		STARTUPINFO info = new STARTUPINFO();
		
		
		result = CreateProcessAsUser(hDupedToken, "C:\\Hackcollege\\start UP\\agreement.exe", null,
                IntPtr.Zero, IntPtr.Zero, false, (UInt32)CreateProcessFlags.CREATE_NEW_CONSOLE, IntPtr.Zero, null,
                ref info, out procInfo);
				
		if(result){
			Console.WriteLine("start the agreement");
			
		}
		
		
		
	}
	public enum ConnectionState
    {
        /// <summary>
        /// A user is logged on to the session.
        /// </summary>
        Active,
        /// <summary>
        /// A client is connected to the session.
        /// </summary>
        Connected,
        /// <summary>
        /// The session is in the process of connecting to a client.
        /// </summary>
        ConnectQuery,
        /// <summary>
        /// This session is shadowing another session.
        /// </summary>
        Shadowing,
        /// <summary>
        /// The session is active, but the client has disconnected from it.
        /// </summary>
        Disconnected,
        /// <summary>
        /// The session is waiting for a client to connect.
        /// </summary>
        Idle,
        /// <summary>
        /// The session is listening for connections.
        /// </summary>
        Listening,
        /// <summary>
        /// The session is being reset.
        /// </summary>
        Reset,
        /// <summary>
        /// The session is down due to an error.
        /// </summary>
        Down,
        /// <summary>
        /// The session is initializing.
        /// </summary>
        Initializing
    }
	[StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionID;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string WinStationName;
        public ConnectionState State;
    }

	[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Int32 WTSEnumerateSessions(IntPtr hServer, int reserved, int version,
                                                    ref IntPtr sessionInfo, ref int count);
													
	[DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr memory);
													
	public static uint GetCurrentSession()
    {
        IntPtr server = IntPtr.Zero;

			uint c_s = 0;
            IntPtr ppSessionInfo = IntPtr.Zero;
			
            Int32 count = 0;
            Int32 retval = WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref count);

            IntPtr current = ppSessionInfo;

            if (retval != 0)
            {
                for (int i = 0; i < count; i++)
                {
                    
                    current = ppSessionInfo + i*Marshal.SizeOf(typeof(WTS_SESSION_INFO));;
					WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));
				
					if(si.State==ConnectionState.Active){
						Console.WriteLine("found active sess");
						Console.WriteLine(si.SessionID);
						c_s = (uint)si.SessionID;
					}
                }

                WTSFreeMemory(ppSessionInfo);
            }
      
        return c_s;
    }
	

}


