# YARA-X Manager Windows 启动指南

## 前置要求

1. **Python 3.8+** ✓ (已确认可用)
2. **Redis** (需要安装)
3. **YARA-X** ✓ (已有 yr 可执行文件)

## 快速启动步骤

### 方案 1：使用 Docker 运行 Redis（推荐）

```powershell
# 1. 启动 Redis 容器
docker run -d --name redis-yara -p 6379:6379 redis

# 2. 运行启动脚本
.\run.ps1
```

### 方案 2：手动安装 Redis

#### 使用 Chocolatey
```powershell
choco install redis-64
```

#### 使用 Memurai (Redis for Windows)
下载地址：https://www.memurai.com/get-memurai

### 方案 3：使用 WSL2
```bash
# 在 WSL2 Ubuntu 中
sudo apt-get update
sudo apt-get install redis-server
redis-server --daemonize yes
```

## 启动服务

```powershell
# 执行 PowerShell 启动脚本
.\run.ps1
```

启动后访问：
- **API 文档**: http://localhost:8000/docs
- **测试页面**: http://localhost:8000/static/test.html
- **API 根路径**: http://localhost:8000

## 手动启动步骤（如果脚本失败）

```powershell
# 1. 解压规则
Expand-Archive -Path my_rules.zip -DestinationPath . -Force

# 2. 启动 Redis（根据你的安装方式）
# Docker: docker start redis-yara
# 或 redis-server

# 3. 激活虚拟环境
.\.venv\Scripts\Activate.ps1

# 4. 安装依赖
pip install -r requirements.txt

# 5. 启动 Celery Worker（新窗口）
celery -A app.celery_app.cel worker --loglevel=info --pool=solo

# 6. 启动 API 服务（新窗口）
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 功能测试

### 1. 上传样本
```powershell
curl -X POST http://localhost:8000/samples/upload -F "files=@test_file.exe"
```

### 2. 查看样本
```powershell
curl http://localhost:8000/samples/
```

### 3. 上传规则
```powershell
curl -X POST http://localhost:8000/rules/upload -F "files=@rule.yar"
```

### 4. 查看规则
```powershell
curl http://localhost:8000/rules/
```

### 5. 启动扫描
```powershell
curl -X POST http://localhost:8000/scans/start
```

### 6. 查看扫描状态
```powershell
curl http://localhost:8000/scans/status
```

### 7. 查看扫描结果
```powershell
curl http://localhost:8000/scans/{filename}/results
```

## 常见问题

### Celery 无法启动
Windows 环境需要使用 `--pool=solo` 参数：
```powershell
celery -A app.celery_app.cel worker --loglevel=info --pool=solo
```

### Redis 连接失败
检查 Redis 是否运行：
```powershell
# Docker
docker ps | Select-String redis

# 本地安装
Get-Process redis-server
```

### 端口被占用
修改 `run.ps1` 中的端口号，或关闭占用 8000 端口的进程。

## 停止服务

按 `Ctrl+C` 停止 FastAPI 服务，脚本会自动清理 Celery Worker。
