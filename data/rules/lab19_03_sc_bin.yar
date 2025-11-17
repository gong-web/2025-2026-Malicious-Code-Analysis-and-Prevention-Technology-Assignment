/*
    YARA-X Rule for Lab19-03_sc.bin
    Chapter: Chapter 19
    Sample: Lab19-03_sc.bin
    Malware Type: Raw Shellcode
    
    Description: Detects Lab19-03_sc.bin - raw shellcode for Chapter 19 exercises
    
    This is position-independent shellcode used for analysis training.
    Characteristics:
    - 802 bytes in size
    - Not a PE file (no MZ header)
    - Contains x86 assembly code
    
    Based on actual binary analysis, using hex patterns from the beginning of the file.
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

rule PMA_Lab19_03_Shellcode
{
    meta:
        description = "Detects Lab19-03_sc.bin shellcode"
        chapter = "Chapter 19"
        sample = "Lab19-03_sc.bin"
        malware_type = "Raw Shellcode"
        severity = "high"
        
    strings:
        // Unique byte patterns from the start of this specific shellcode
        $header = { 89 E5 81 EC 7C 01 00 00 E8 6E 01 00 00 8E 4E 0E EC }
        $pattern1 = { 72 FE B3 16 83 B9 B5 78 E6 17 8F 7B 33 CA 8A }
        $pattern2 = { 56 57 8B 74 24 0C 31 }
        
    condition:
        filesize == 802 and
        uint16(0) != 0x5A4D and
        1 of them
}