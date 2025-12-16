/*
    YARA-X Rule for Lab17-03.exe
    Chapter: Chapter 17
    Sample: Lab17-03.exe
    Malware Type: Process Injector
    
    Description: Detects Lab17-03.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB17_03_EXE
{
    meta:
        description = "Detects Lab17-03.exe from Practical Malware Analysis"
        chapter = "Chapter 17"
        sample = "Lab17-03.exe"
        malware_type = "Process Injector"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "c:\\windows\\system32\\user32.dll" nocase
        $dll2 = "ADVAPI32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "kernel32.dll" nocase
        $proc1 = "CreateRemoteThread"
        $proc2 = "WriteProcessMemory"
        $proc3 = "VirtualAllocEx"
        $proc4 = "CreateProcessA"
        $reg_api1 = "RegOpenKeyExA"
        $reg_key1 = "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses" nocase
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAllocEx"
        $import4 = "LoadLibraryA"
        $susp1 = "c:\\windows\\system32\\user32.dll" nocase
        $susp2 = "ADVAPI32.dll" nocase
        $susp3 = "\\svchost.exe" nocase
        $susp4 = "Iphlpapi.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            2 of ($proc*) or
            (1 of ($reg_api*) or 1 of ($reg_key*))
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
