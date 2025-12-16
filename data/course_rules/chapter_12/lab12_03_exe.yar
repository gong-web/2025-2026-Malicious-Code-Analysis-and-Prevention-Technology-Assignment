import "pe"

rule PMA_LAB12_03_EXE
{
    meta:
        description = "Detects Lab12-03.exe from Practical Malware Analysis"
        chapter = "Chapter 12"
        sample = "Lab12-03.exe"
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
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualAlloc"
        $import3 = "GetProcAddress"
        $import4 = "LoadLibraryA"
        $susp1 = "user32.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "USER32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($dll*) or
            1 of ($proc*) or
            1 of ($file*)
        ) and (
            1 of ($import*) or 1 of ($susp*)
        )
}
