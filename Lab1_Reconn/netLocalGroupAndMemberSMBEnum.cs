using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;


public class Program
{

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct LOCALGROUP_USERS_INFO_0{
        [MarshalAs(UnmanagedType.LPWStr)]internal string name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_USERS_INFO_1{
        [MarshalAs(UnmanagedType.LPWStr)] public string name;
        [MarshalAs(UnmanagedType.LPWStr)] public string comment;
    }
        
    [DllImport("Netapi32.dll")]
    internal extern static int NetLocalGroupEnum([MarshalAs(UnmanagedType.LPWStr)]
        string servername,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        ref int resume_handle
    );

    [DllImport("Netapi32.dll")]
    internal extern static int NetApiBufferFree(IntPtr buffer);
    
    [DllImport("NetAPI32.dll", CharSet=CharSet.Unicode)]
    public extern static int NetLocalGroupGetMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        IntPtr resume_handle
    );
    		
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct LOCALGROUP_MEMBERS_INFO_2{
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public string lgrmi2_domainandname;
    }
    
     public static List<string> getLocalGroup(string serverName){
        int res = 0;
        int level = 1;
        IntPtr buffer = IntPtr.Zero;
        int MAX_PREFERRED_LENGTH = -1;
        int read, total;
        int handle = 0;
        res =  NetLocalGroupEnum(serverName, level, out buffer, MAX_PREFERRED_LENGTH,
                out read,
                out total,
                ref handle);
        IntPtr ptr;
        var groups = new List<string>();
            
        for (int i = 0; i < read; i++){
            ptr = buffer + i*Marshal.SizeOf(typeof(LOCALGROUP_USERS_INFO_1));
            var group = (LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(ptr, typeof(LOCALGROUP_USERS_INFO_1));
            Console.WriteLine(group.name);
            groups.Add(group.name+"//"+group.comment);
        }
    		
    		NetApiBufferFree(buffer);
    		
    		return groups;
         
    }
    	
    public static List<string> getLocalGroupMembers(string ServerName,string GroupName)
    {
    	var members = new List<string>();
        int EntriesRead = 0;
        int TotalEntries = 0;
        IntPtr Resume  = IntPtr.Zero;
        IntPtr bufPtr = IntPtr.Zero;
        int val = NetLocalGroupGetMembers(ServerName, GroupName, 2, out bufPtr, -1, out EntriesRead, out TotalEntries, Resume);
        IntPtr ptr;
        for(int i=0; i < EntriesRead; i++){
            ptr = bufPtr + i*Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
            var Members = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(ptr, typeof(LOCALGROUP_MEMBERS_INFO_2));
            members.Add(Members.lgrmi2_domainandname);
        }
        NetApiBufferFree(bufPtr);
        return members;
    }


	[DllImport("netapi32.dll", SetLastError=true)]
        private static extern int NetSessionEnum(
            [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
            Int32 Level,
            out IntPtr bufptr,
            int prefmaxlen,
            ref Int32 entriesread,
            ref Int32 totalentries,
            ref Int32 resume_handle);
			
	[ StructLayout( LayoutKind.Sequential )]public struct SESSION_INFO_502
    {
        /// <summary>
        /// Unicode string specifying the name of the computer that established the session.
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]public string sesi502_cname;
        /// <summary>
        /// <value>Unicode string specifying the name of the user who established the session.</value>
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]public string sesi502_username;
        /// <summary>
        /// <value>Specifies the number of files, devices, and pipes opened during the session.</value>
        /// </summary>
        public uint sesi502_num_opens;
        /// <summary>
        /// <value>Specifies the number of seconds the session has been active. </value>
        /// </summary>
        public uint sesi502_time;
        /// <summary>
        /// <value>Specifies the number of seconds the session has been idle.</value>
        /// </summary>
        public uint sesi502_idle_time;
        /// <summary>
        /// <value>Specifies a value that describes how the user established the session.</value>
        /// </summary>
        public uint sesi502_user_flags;
        /// <summary>
        /// <value>Unicode string that specifies the type of client that established the session.</value>
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]public string sesi502_cltype_name;
        /// <summary>
        /// <value>Specifies the name of the transport that the client is using to communicate with the server.</value>
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]public string sesi502_transport;
    }
	
	public enum NERR
    {
        /// <summary>
        /// Operation was a success.
        /// </summary>
        NERR_Success = 0,
        /// <summary>
        /// More data available to read. dderror getting all data.
        /// </summary>
        ERROR_MORE_DATA = 234,
        /// <summary>
        /// Network browsers not available.
        /// </summary>
        ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
        /// <summary>
        /// LEVEL specified is not valid for this call.
        /// </summary>
        ERROR_INVALID_LEVEL = 124,
        /// <summary>
        /// Security context does not have permission to make this call.
        /// </summary>
        ERROR_ACCESS_DENIED = 5,
        /// <summary>
        /// Parameter was incorrect.
        /// </summary>
        ERROR_INVALID_PARAMETER = 87,
        /// <summary>
        /// Out of memory.
        /// </summary>
        ERROR_NOT_ENOUGH_MEMORY = 8,
        /// <summary>
        /// Unable to contact resource. Connection timed out.
        /// </summary>
        ERROR_NETWORK_BUSY = 54,
        /// <summary>
        /// Network Path not found.
        /// </summary>
        ERROR_BAD_NETPATH = 53,
        /// <summary>
        /// No available network connection to make call.
        /// </summary>
        ERROR_NO_NETWORK = 1222,
        /// <summary>
        /// Pointer is not valid.
        /// </summary>
        ERROR_INVALID_HANDLE_STATE = 1609,
        /// <summary>
        /// Extended Error.
        /// </summary>
        ERROR_EXTENDED_ERROR= 1208,
        /// <summary>
        /// Base.
        /// </summary>
        NERR_BASE = 2100,
        /// <summary>
        /// Unknown Directory.
        /// </summary>
        NERR_UnknownDevDir = (NERR_BASE + 16),
        /// <summary>
        /// Duplicate Share already exists on server.
        /// </summary>
        NERR_DuplicateShare = (NERR_BASE + 18),
        /// <summary>
        /// Memory allocation was to small.
        /// </summary>
        NERR_BufTooSmall = (NERR_BASE + 23)
    }
	
	public static void EnumSessions(string server)
        {
            IntPtr BufPtr;
            int res = 0;
            Int32 er=0,tr=0,resume=0;
            BufPtr = (IntPtr)Marshal.SizeOf(typeof(SESSION_INFO_502));
            SESSION_INFO_502[] results = new SESSION_INFO_502[0];
            do
            {
                res = NetSessionEnum(server,null,null,502,out BufPtr,-1,ref er,ref tr,ref resume);
                results = new SESSION_INFO_502[er];
                if (res == (int)NERR.ERROR_MORE_DATA || res == (int)NERR.NERR_Success)
                {
                    IntPtr p = BufPtr;
                    for (int i = 0;i <er-1;i++)
                    {

                        SESSION_INFO_502 si = (SESSION_INFO_502)Marshal.PtrToStructure(p ,typeof(SESSION_INFO_502));
						p = BufPtr + i*Marshal.SizeOf(typeof(SESSION_INFO_502));
						Console.WriteLine(si.sesi502_cname + ",user_name:"+si.sesi502_username);
                    }
                }
                Marshal.FreeHGlobal(BufPtr);
            }
            while (res==(int)NERR.ERROR_MORE_DATA);
        }

}
