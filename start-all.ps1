# 同时启动前端和后端服务

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   YARA-X Manager - 完整启动脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = $PSScriptRoot

# 启动后端
Write-Host "🚀 启动后端服务..." -ForegroundColor Yellow
$backendPath = Join-Path $projectRoot "backend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; python main.py"

Start-Sleep -Seconds 3

# 启动前端
Write-Host "🚀 启动前端服务..." -ForegroundColor Yellow
$frontendPath = Join-Path $projectRoot "frontend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "✅ 服务启动完成！" -ForegroundColor Green
Write-Host ""
Write-Host "📌 访问地址:" -ForegroundColor Cyan
Write-Host "   前端界面: http://localhost:3000" -ForegroundColor White
Write-Host "   后端 API: http://localhost:8000" -ForegroundColor White
Write-Host "   API 文档: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "💡 提示:" -ForegroundColor Gray
Write-Host "   - 前端和后端在独立的窗口中运行" -ForegroundColor Gray
Write-Host "   - 关闭对应窗口即可停止服务" -ForegroundColor Gray
Write-Host ""
Write-Host "按任意键打开浏览器..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# 打开浏览器
Start-Process "http://localhost:3000"
