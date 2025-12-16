import "pe"

rule PMA_LAB03_04_EXE
{
    meta:
        description = "Detects Lab03-04.exe - Auto-fixed"
        sample = "Lab03-04.exe"
        
    strings:
        $net1 = "WS2_32.dll"
        $dll2 = "user32.dll" nocase
        $dll3 = "KERNEL32.dll" nocase
        $dll4 = "ADVAPI32.dll" nocase
        $proc5 = "CreateProcessA"
        $proc6 = "ShellExecuteA"
        $proc7 = "TerminateProcess"
        $file8 = "DeleteFileA"
        $file9 = "ReadFile"
        $file10 = "CopyFileA"
        $regapi11 = "RegCreateKeyExA"
        $regapi12 = "RegSetValueExA"
        $imp13 = "SLEEP"
        $imp14 = "Sleep"
        $imp15 = "GetModuleHandleA"
        $imp16 = "VirtualAlloc"
        $susp17 = "cmd.exe" nocase
        $susp18 = "cmd.exe" nocase
        $susp19 = ".exe" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        6 of them
}