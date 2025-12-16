
import "pe"

rule PMA_LAB15_02_EXE
{
    meta:
        description = "Detects Lab15-02.exe from Practical Malware Analysis"
        chapter = "Chapter 15"
        sample = "Lab15-02.exe"
        malware_type = "Network Malware"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $net1 = "InternetOpenUrlA"
        $net2 = "InternetOpenA"
        $net3 = "WS2_32.dll" nocase
        $dll1 = "WININET.dll" nocase
        $dll2 = "WS2_32.dll" nocase
        $proc1 = "ShellExecuteA"
        $file1 = "InternetReadFile"
        $susp1 = "MSVCRT.dll" nocase
        $susp2 = "ShellExecuteA" nocase
        $susp3 = "WININET.dll" nocase
        $susp4 = "SHELL32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        (
            1 of ($net*) or
            1 of ($dll*) or
            1 of ($proc*)
        ) and (
            1 of ($file*) or 1 of ($susp*)
        )
}
