# 快速开始指南

## 1. 环境准备

### 必需软件
- Python 3.8+
- Node.js 16+
- PostgreSQL 12+ 或 SQLite
- Git

### 可选软件
- Docker & Docker Compose
- Redis (用于任务队列)

## 2. 安装步骤

### 方式一: 本地开发环境

#### 2.1 克隆项目
```bash
cd yara-x-manager
```

#### 2.2 配置环境变量
```bash
cp .env.example .env
# 编辑 .env 文件,配置数据库等信息
```

#### 2.3 安装后端依赖
```bash
cd backend
pip install -r requirements.txt
```

#### 2.4 初始化数据库
```bash
# SQLite (默认)
python -c "from app.core.database import init_db; init_db()"

# PostgreSQL
# 先创建数据库,然后运行初始化脚本
psql -U postgres -f ../db/schema/init.sql
```

#### 2.5 启动后端服务
```bash
python main.py
```
后端将在 http://localhost:8000 运行

#### 2.6 安装前端依赖
```bash
cd ../frontend
npm install
```

#### 2.7 启动前端服务
```bash
npm run dev
```
前端将在 http://localhost:3000 运行

### 方式二: Docker 部署

```bash
docker-compose up -d
```

服务将自动启动:
- 前端: http://localhost:3000
- 后端: http://localhost:8000
- API 文档: http://localhost:8000/docs

## 3. 导入 YARA 规则

### 使用工具导入
```bash
cd tools

# 导入单个规则文件
python yara_loader.py -i path/to/rule.yar -d sqlite:///./yara_manager.db

# 导入目录中的所有规则
python yara_loader.py -i path/to/rules -r -d sqlite:///./yara_manager.db
```

### 通过 Web 界面上传
1. 打开前端界面 http://localhost:3000
2. 登录 (默认: admin / admin123)
3. 进入 "YARA 规则" 页面
4. 点击 "上传规则文件" 按钮

## 4. 执行扫描

### 使用工具扫描
```bash
cd tools

# 扫描单个文件
python scanner.py -t path/to/file.exe

# 扫描目录
python scanner.py -t path/to/directory --recursive

# 指定规则文件
python scanner.py -t path/to/file -r path/to/rules.yar

# 保存结果到 JSON
python scanner.py -t path/to/directory -o results.json
```

### 通过 Web 界面扫描
1. 进入 "扫描任务" 页面
2. 点击 "上传并扫描文件"
3. 选择文件上传
4. 查看扫描结果

## 5. 查看报告

访问 "检测报告" 页面查看:
- 系统统计数据
- 最近检测结果
- 威胁趋势
- 规则有效性

## 6. API 使用

### 获取 API Token
```bash
curl -X POST http://localhost:8000/api/auth/token \
  -d "username=admin&password=admin123"
```

### 调用 API
```bash
# 获取规则列表
curl http://localhost:8000/api/rules/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# 上传规则
curl -X POST http://localhost:8000/api/rules/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test_rule","content":"rule test {...}"}'
```

完整 API 文档: http://localhost:8000/docs

## 7. 常见问题

### Q: 数据库连接失败?
A: 检查 .env 文件中的 DATABASE_URL 配置是否正确

### Q: YARA 规则语法错误?
A: 使用 YARA 官方文档验证规则语法: https://yara.readthedocs.io/

### Q: 前端无法连接后端?
A: 检查 vite.config.ts 中的 proxy 配置,确保指向正确的后端地址

### Q: 扫描速度慢?
A: 调整 .env 中的 SCAN_THREADS 参数增加并发数

## 8. 下一步

- 阅读完整文档
- 编写自定义 YARA 规则
- 集成其他检测引擎
- 部署到生产环境

## 技术支持

- 项目 Issues: [GitHub Issues]
- 文档: [README.md](README.md)
- YARA 官方: https://yara.readthedocs.io/
