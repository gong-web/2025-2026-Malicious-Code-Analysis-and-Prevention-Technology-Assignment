/*
    YARA-X Rule for Lab21-02.exe
    Chapter: Chapter 21
    Sample: Lab21-02.exe
    Malware Type: Process Injector
    
    Description: Detects Lab21-02.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB21_02_EXE
{
    meta:
        description = "Detects Lab21-02.exe from Practical Malware Analysis"
        chapter = "Chapter 21"
        sample = "Lab21-02.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "WUSER32.DLL" nocase
        $dll2 = "ADVAPI32.dll" nocase
        $dll3 = "KERNEL32.DLL" nocase
        $dll4 = "user32.dll" nocase
        $proc1 = "CreateRemoteThread"
        $proc2 = "TerminateProcess"
        $proc3 = "WriteProcessMemory"
        $proc4 = "VirtualAllocEx"
        $file1 = "CreateFileW"
        $file2 = "CreateFileA"
        $file3 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAllocEx"
        $import4 = "GetModuleHandleW"
        $susp1 = "WUSER32.DLL" nocase
        $susp2 = "Lab21-02x.dll" nocase
        $susp3 = "Lab21-02.dll" nocase
        $susp4 = "ADVAPI32.dll" nocase
        
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
