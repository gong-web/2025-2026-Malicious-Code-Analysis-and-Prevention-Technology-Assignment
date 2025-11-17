/*
    YARA-X Rule for Lab12-01.exe
    Chapter: Chapter 12
    Sample: Lab12-01.exe
    Malware Type: Process Injector
    
    Description: Detects Lab12-01.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB12_01_EXE
{
    meta:
        description = "Detects Lab12-01.exe from Practical Malware Analysis"
        chapter = "Chapter 12"
        sample = "Lab12-01.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "kernel32.dll" nocase
        $proc1 = "WriteProcessMemory"
        $proc2 = "VirtualAllocEx"
        $proc3 = "CreateRemoteThread"
        $proc4 = "TerminateProcess"
        $file1 = "WriteFile"
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAllocEx"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "psapi.dll" nocase
        $susp4 = "kernel32.dll" nocase
        
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
