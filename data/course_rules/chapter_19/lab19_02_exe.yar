import "pe"

rule PMA_LAB19_02_EXE
{
    meta:
        description = "Detects Lab19-02.exe - Auto-fixed"
        sample = "Lab19-02.exe"
        
    strings:
        $dll1 = "user32.dll" nocase
        $dll2 = "KERNEL32.dll" nocase
        $dll3 = "ADVAPI32.dll" nocase
        $proc4 = "CreateProcess error: %08x"
        $proc5 = "VirtualAllocEx error: %08x"
        $proc6 = "WriteProcessMemory"
        $file7 = "WriteFile"
        $regapi8 = "RegQueryValueEx error: %08x"
        $regapi9 = "RegOpenKeyEx error: %08x"
        $imp10 = "GetModuleHandleA"
        $imp11 = "VirtualAllocEx error: %08x"
        $imp12 = "VirtualAllocEx"
        $imp13 = "VirtualAlloc"
        $susp14 = "user32.dll" nocase
        $susp15 = "KERNEL32.dll" nocase
        $susp16 = "ADVAPI32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        5 of them
}
