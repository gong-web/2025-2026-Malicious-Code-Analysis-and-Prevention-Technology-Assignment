/*
    YARA-X Rule for Lab16-03.exe
    Chapter: Chapter 16
    Sample: Lab16-03.exe
    Malware Type: Process Injector
    
    Description: Detects Lab16-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB16_03_EXE
{
    meta:
        description = "Detects Lab16-03.exe from Practical Malware Analysis"
        chapter = "Chapter 16"
        sample = "Lab16-03.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "WSASocketA"
        $net2 = "WS2_32.dll" nocase
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "WS2_32.dll" nocase
        $proc1 = "ShellExecuteA"
        $proc2 = "TerminateProcess"
        $proc3 = "CreateProcessA"
        $file1 = "WriteFile"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "cmd.exe" nocase
        $susp2 = "cmd.exe" nocase
        $susp3 = "user32.dll" nocase
        $susp4 = "KERNEL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            2 of ($proc*)
        ) and (
            1 of ($file*) or 1 of ($import*) or 1 of ($susp*)
        )
}