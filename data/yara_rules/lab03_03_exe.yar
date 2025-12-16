/*
    YARA-X Rule for Lab03-03.exe
    Chapter: Chapter 3
    Sample: Lab03-03.exe
    Malware Type: Process Injector
    
    Description: Detects Lab03-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB03_03_EXE
{
    meta:
        description = "Detects Lab03-03.exe from Practical Malware Analysis"
        chapter = "Chapter 3"
        sample = "Lab03-03.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ntdll.dll" nocase
        $proc1 = "TerminateProcess"
        $proc2 = "WriteProcessMemory"
        $proc3 = "VirtualAllocEx"
        $proc4 = "CreateProcessA"
        $file1 = "ReadFile"
        $file2 = "CreateFileA"
        $file3 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAllocEx"
        $import4 = "LoadLibraryA"
        $susp1 = "\\svchost.exe" nocase
        $susp2 = "user32.dll" nocase
        $susp3 = "KERNEL32.dll" nocase
        $susp4 = "ntdll.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            2 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}