/*
    YARA-X Rule for Lab19-01.bin
    Chapter: Chapter 19
    Sample: Lab19-01.bin
    Malware Type: Raw Shellcode
    
    Description: Detects Lab19-01.bin shellcode (non-PE file)
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

rule PMA_Lab19_01_BIN
{
    meta:
        description = "Detects Lab19-01.bin raw shellcode"
        chapter = "Chapter 19"
        sample = "Lab19-01.bin"
        malware_type = "Raw Shellcode"
        severity = "high"
        
    condition:
        filesize == 1342 and
        uint16(0) != 0x5A4D
}