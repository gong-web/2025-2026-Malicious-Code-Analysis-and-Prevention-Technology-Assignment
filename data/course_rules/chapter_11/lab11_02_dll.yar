import "pe"

rule PMA_LAB11_02_DLL
{
    meta:
        description = "Detects Lab11-02.dll from Practical Malware Analysis"
        chapter = "Chapter 11"
        sample = "Lab11-02.dll"
        malware_type = "Registry Persistence"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "send"
        $dll1 = "KERNEL32.dll" nocase
        $dll2 = "kernel32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $file1 = "CopyFileA"
        $file2 = "ReadFile"
        $file3 = "CreateFileA"
        $reg_api1 = "RegSetValueExA"
        $reg_api2 = "RegOpenKeyExA"
        $reg_key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" nocase
        $import1 = "GetModuleHandleA"
        $import2 = "VirtualProtect"
        $import3 = "LoadLibraryA"
        $import4 = "GetProcAddress"
        $susp1 = "MSIMN.EXE" nocase
        $susp2 = "THEBAT.EXE" nocase
        $susp3 = "MSVCRT.dll" nocase
        $susp4 = "spoolvxx32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) != 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($file*)
        ) and (
            (1 of ($reg_api*) or 1 of ($reg_key*)) or 1 of ($import*) or 1 of ($susp*)
        )
}
