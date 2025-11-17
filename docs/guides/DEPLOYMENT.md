# 部署指南

## 快速部署

### 方式1: 使用Docker Compose (推荐)

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

应用访问:
- Frontend: http://localhost:3001
- Backend API: http://localhost:8000
- API文档: http://localhost:8000/docs

### 方式2: 本地手动部署

#### 后端

```bash
cd backend

# 1. 安装依赖
python -m pip install -r requirements.txt

# 2. 初始化数据库
python init_db.py

# 3. 启动服务
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

#### 前端

```bash
cd frontend

# 1. 安装依赖
npm install

# 2. 启动开发服务器
npm run dev

# 或构建生产版本
npm run build
npm run preview
```

## 系统要求

### 最低配置
- CPU: 2核
- 内存: 4GB
- 磁盘: 10GB
- Python: 3.12+
- Node.js: 16+

### 建议配置
- CPU: 4核+
- 内存: 8GB+
- 磁盘: 50GB+
- Python: 3.12+
- Node.js: 18+

## 环境配置

### 后端配置文件

编辑 `backend/.env`:

```env
# 数据库
DATABASE_URL=sqlite:///./data.sqlite

# 应用配置
DEBUG=False
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=http://localhost:3001,http://localhost:3000

# YARA配置
YARA_RULES_DIR=./data/rules
MAX_FILE_SIZE=104857600  # 100MB

# Redis (可选)
REDIS_URL=redis://localhost:6379/0
```

### 前端配置

编辑 `frontend/.env`:

```env
VITE_API_URL=http://localhost:8000
VITE_API_TIMEOUT=30000
```

## 初始化数据库

```bash
cd backend

# 创建表和初始数据
python init_db.py

# 或使用SQL脚本
sqlite3 data.sqlite < ../db/schema/init.sql
```

## 性能调优

### 后端优化

1. 启用生产模式
```bash
python -m uvicorn main:app --workers 4 --host 0.0.0.0 --port 8000
```

2. 配置PostgreSQL (可选)
```python
# backend/app/core/config.py
DATABASE_URL = "postgresql://user:password@localhost/yara_db"
```

3. 启用Redis缓存
```python
REDIS_URL = "redis://localhost:6379/0"
```

### 前端优化

1. 启用Gzip压缩
2. 使用CDN加速
3. 配置缓存策略

## 监控和日志

### 查看后端日志

```bash
# 实时日志
tail -f backend.log

# 搜索错误
grep ERROR backend.log
```

### 查看前端日志

```bash
# 浏览器控制台
F12 -> Console
```

### 性能监控

访问: http://localhost:8000/metrics (需启用Prometheus)

## 备份和恢复

### 数据库备份

```bash
# SQLite备份
cp data.sqlite data.sqlite.backup

# 自动备份
0 2 * * * cp /path/to/data.sqlite /backups/data.sqlite.$(date +\%Y\%m\%d)
```

### 规则备份

```bash
# 备份所有规则
cp -r backend/data/rules/ backups/rules_$(date +%Y%m%d)
```

## 故障排除

### 端口被占用

```bash
# 检查占用情况
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# 更换端口
python -m uvicorn main:app --port 8001
```

### 数据库锁定

```bash
# 删除锁文件
rm data.sqlite-journal

# 重新初始化
python init_db.py
```

### 内存泄漏

```bash
# 监控进程
ps aux | grep uvicorn

# 设置内存限制
ulimit -v 2097152  # 2GB
```

## 安全建议

1. **更改密钥**
   - 修改 `SECRET_KEY` 为强随机值
   - 使用 `secrets` 库生成: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

2. **启用HTTPS**
   - 使用Nginx反向代理
   - 配置SSL证书

3. **限制访问**
   - 配置防火墙规则
   - 使用API密钥认证

4. **定期更新**
   - 更新Python依赖: `pip install --upgrade -r requirements.txt`
   - 更新Node依赖: `npm update`

## 升级指南

### 数据库迁移

```bash
# 备份当前数据库
cp data.sqlite data.sqlite.backup

# 运行迁移
python init_db.py
```

### 依赖更新

```bash
# 后端
pip install --upgrade -r requirements.txt

# 前端
npm update
npm audit fix
```

---

**最后更新**: 2025-11-15
