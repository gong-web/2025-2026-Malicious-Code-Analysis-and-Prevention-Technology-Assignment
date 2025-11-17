Write-Host "`n========== 检测可用分析工具 ==========" -ForegroundColor Cyan
$toolsBase = "D:\gds\Documents\Malicious_Code_Analysis\analy_tool"
$tools = @{
    "ApateDNS" = "$toolsBase\ApateDNS\sdl-apatedns\apateDNS\apateDNS.exe"
    "Autoruns64" = "$toolsBase\autoruns\Autoruns64.exe"
    "C32Asm" = "$toolsBase\c32asm\c32asm\C32Asm.exe"
    "Depends" = "$toolsBase\depends22_x86"
    "PEiD" = "$toolsBase\PEiD\PEiD.exe"
    "PEview" = "$toolsBase\PEview"
    "ProcessExplorer" = "$toolsBase\ProcessExplorer\procexp.exe"
    "ProcessMonitor" = "$toolsBase\ProcessMonitor"
    "Regshot" = "$toolsBase\regshot_1.8.3\regshot_x64.exe"
    "Strings" = "$toolsBase\Strings\strings.exe"
    "Stud_PE" = "$toolsBase\Stud_PE"
    "UPX" = "$toolsBase\upx\upx391w\upx391w"
    "WinHex" = "$toolsBase\WinHex\WinHex17.4"
    "Wireshark" = "$toolsBase\Wireshark\Wireshark-win32-2.0.4.exe"
    "Yara" = "$toolsBase\yara\yarac64.exe"
}
$available = @()
$missing = @()
foreach ($name in $tools.Keys | Sort-Object) {
    $path = $tools[$name]
    if (Test-Path $path) {
        Write-Host "  [OK] $name" -ForegroundColor Green -NoNewline
        Write-Host " -> $path" -ForegroundColor Gray
        $available += $name
    } else {
        Write-Host "  [--] $name" -ForegroundColor Yellow -NoNewline
        Write-Host " -> $path" -ForegroundColor DarkGray
        $missing += $name
    }
}
Write-Host "`n可用工具数: $($available.Count)/$($tools.Count)" -ForegroundColor $(if ($available.Count -eq $tools.Count) { "Green" } else { "Yellow" })