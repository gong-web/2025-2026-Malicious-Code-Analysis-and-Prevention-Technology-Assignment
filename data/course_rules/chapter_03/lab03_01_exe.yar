import "pe"

rule PMA_LAB03_01_EXE
{
    meta:
        description = "Detects Lab03-01.exe - Auto-fixed"
        sample = "Lab03-01.exe"
        
    strings:
        $net1 = "ws2_32"
        $net2 = "CONNECT %s:%i HTTP/1.0"
        $dll3 = "ws2_32" nocase
        $dll4 = "user32" nocase
        $dll5 = "advapi32" nocase
        $dll6 = "kernel32.dll" nocase
        $reg7 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $reg8 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $susp9 = "vmx32to64.exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        3 of them
}
