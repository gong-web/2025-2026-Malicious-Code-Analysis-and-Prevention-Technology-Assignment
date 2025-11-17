/*
    YARA-X Rule for PMA_Lab09_DLL_Generic
    Chapter: Chapter 9
    Samples: DLL1.dll, DLL2.dll, DLL3.dll
    Malware Type: Injection Target DLLs
    
    Description: Detects the three injection target DLLs used in Lab09
    These DLLs are injected into target processes by Lab09 malware
    
    Based on actual analysis - all three DLLs share common features:
    - Small DLLs used for process injection exercises
    - Common imports: LoadLibraryA, GetProcAddress, VirtualAlloc
    - File operations: WriteFile
    - Process operations: TerminateProcess
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_Lab09_DLL_Generic
{
    meta:
        description = "Detects DLL1.dll, DLL2.dll, DLL3.dll injection targets"
        chapter = "Chapter 9"
        samples = "DLL1.dll, DLL2.dll, DLL3.dll"
        malware_type = "Injection Target DLLs"
        severity = "medium"
        
    strings:
        // Common imports found in all three DLLs
        $imp1 = "GetModuleHandleA"
        $imp2 = "LoadLibraryA"
        $imp3 = "VirtualAlloc"
        $imp4 = "GetProcAddress"
        $imp5 = "GetCommandLineA"
        
        // APIs used
        $api1 = "WriteFile"
        $api2 = "TerminateProcess"
        
        // DLL names
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        filesize < 50KB and
        (
            // Must have the common import pattern
            (3 of ($imp*)) or
            // Or the API pattern
            (all of ($api*) and 1 of ($dll*)) or
            // Or specific combination
            ($imp2 and $imp3 and $api1)
        )
}