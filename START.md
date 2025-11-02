# 启动项目的简易脚本

## 方式一: 最简单启动 (仅后端 API)

```powershell
# 1. 安装依赖 (首次运行)
cd backend
pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings

# 2. 初始化数据库
python init_db.py

# 3. 启动后端
python main.py
```

访问: http://localhost:8000/docs

## 方式二: 完整启动 (前后端)

### 后端
```powershell
cd backend
pip install -r requirements.txt
python init_db.py
python main.py
```

### 前端 (新终端)
```powershell
cd frontend
npm install
npm run dev
```

访问: 
- 前端: http://localhost:3000
- 后端 API: http://localhost:8000/docs

## 快速测试

### 测试后端 API
```powershell
# 健康检查
curl http://localhost:8000/health

# 查看 API 文档
# 浏览器访问: http://localhost:8000/docs
```

## 常见问题

### 问题1: 模块导入错误
确保在 backend 目录下运行命令

### 问题2: 端口被占用
修改 .env 文件中的 PORT 配置

### 问题3: 缺少依赖
```powershell
pip install -r requirements.txt
```
