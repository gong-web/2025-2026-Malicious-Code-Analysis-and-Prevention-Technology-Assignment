/*
    YARA-X Rule for Lab07-02.exe
    Chapter: Chapter 7
    Sample: Lab07-02.exe
    Malware Type: Malware Sample
    
    Description: Detects Lab07-02.exe from Practical Malware Analysis
    Auto-optimized based on actual sample analysis
    
    WARNING: Educational malware sample - DO NOT RUN!
*/

import "pe"

rule PMA_LAB07_02_EXE
{
    meta:
        description = "Detects Lab07-02.exe from Practical Malware Analysis"
        chapter = "Chapter 7"
        sample = "Lab07-02.exe"
        malware_type = "Malware Sample"
        severity = "high"
        auto_generated = "true"
        
    strings:
        $susp1 = "http://www.malwareanalysisbook.com/ad.html" nocase
        $susp2 = "MSVCRT.dll" nocase
        $susp3 = "OLEAUT32.dll" nocase
        $susp4 = "ole32.dll" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (pe.characteristics & 0x2000) == 0 and
        1 of ($susp*)
}