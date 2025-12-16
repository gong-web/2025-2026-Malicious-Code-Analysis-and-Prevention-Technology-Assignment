import "pe"

rule PMA_LAB11_03_DLL
{
    meta:
        description = "Detects Lab11-03.dll from Practical Malware Analysis"
        chapter = "Chapter 11"
        sample = "Lab11-03.dll"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "USER32.dll" nocase
        $proc1 = "TerminateProcess"
        $file1 = "WriteFile"
        $file2 = "CreateFileA"
        $import1 = "Sleep"
        $import2 = "GetModuleHandleA"
        $import3 = "VirtualAlloc"
        $import4 = "GetProcAddress"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "C:\\WINDOWS\\System32\\kernel64x.dll" nocase
        $susp4 = "Lab1103dll.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
