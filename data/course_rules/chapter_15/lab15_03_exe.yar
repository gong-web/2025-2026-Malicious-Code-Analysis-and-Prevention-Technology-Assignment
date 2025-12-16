
import "pe"

rule PMA_LAB15_03_EXE
{
    meta:
        description = "Detects Lab15-03.exe from Practical Malware Analysis"
        chapter = "Chapter 15"
        sample = "Lab15-03.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "URLDownloadToFileA"
        $dll1 = "KERNEL32.dll" nocase
        $dll2 = "urlmon.dll" nocase
        $proc1 = "OpenProcess"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "KERNEL32.dll" nocase
        $susp3 = "urlmon.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($susp*)
        )
}
