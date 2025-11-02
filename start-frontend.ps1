# 启动前端开发服务器

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   YARA-X Manager - 启动前端服务" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 切换到前端目录
$frontendPath = Join-Path $PSScriptRoot "frontend"
Set-Location $frontendPath

Write-Host "📦 检查依赖..." -ForegroundColor Yellow
if (-not (Test-Path "node_modules")) {
    Write-Host "⚠️  未检测到 node_modules，开始安装依赖..." -ForegroundColor Yellow
    npm install
} else {
    Write-Host "✅ 依赖已就绪" -ForegroundColor Green
}

Write-Host ""
Write-Host "🚀 启动开发服务器..." -ForegroundColor Yellow
Write-Host ""
Write-Host "📌 访问地址:" -ForegroundColor Cyan
Write-Host "   http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "💡 提示: 按 Ctrl+C 停止服务" -ForegroundColor Gray
Write-Host ""

# 启动开发服务器
npm run dev
