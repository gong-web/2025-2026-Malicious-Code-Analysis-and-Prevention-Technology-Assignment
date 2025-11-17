# YARA规则管理 + 样本扫描系统 - 项目手册

## 📚 目录

- [项目概述](#项目概述)
- [快速启动](#快速启动)
- [项目结构](#项目结构)
- [API文档](#api文档)
- [开发指南](#开发指南)
- [部署指南](#部署指南)
- [故障排除](#故障排除)

## 项目概述

本系统是一个功能完整的恶意代码检测与YARA规则管理平台,提供:

- **规则管理**: 创建、编辑、删除YARA规则
- **文件扫描**: 上传文件进行YARA规则扫描
- **结果报告**: 生成详细的检测报告
- **Web界面**: 易用的管理界面
- **RESTful API**: 完整的API接口

## 快速启动

### 环境要求

- Python 3.12+
- Node.js 16+
- Windows/Linux/macOS

### 后端启动

```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

后端服务将在 `http://127.0.0.1:8000` 启动

### 前端启动

```bash
cd frontend
npm install
npm run dev
```

前端应用将在 `http://localhost:3001` 启动

### 快速测试

```bash
# 后端健康检查
curl http://127.0.0.1:8000/health

# 获取规则列表
curl http://127.0.0.1:8000/api/rules/

# 获取扫描样本
curl http://127.0.0.1:8000/api/scan/samples
```

## 项目结构

```
.
├── backend/                 # FastAPI后端服务
│   ├── app/
│   │   ├── __init__.py
│   │   ├── api/            # API路由
│   │   │   ├── auth.py     # 认证接口
│   │   │   ├── rules.py    # 规则管理
│   │   │   ├── scan.py     # 文件扫描
│   │   │   ├── reports.py  # 报告查询
│   │   │   └── models_shared.py  # 共享数据模型
│   │   ├── core/           # 核心配置
│   │   │   ├── config.py   # 应用配置
│   │   │   └── database.py # 数据库连接
│   │   ├── models/         # 数据模型
│   │   │   ├── rule.py
│   │   │   ├── scan.py
│   │   │   └── user.py
│   │   └── services/       # 业务逻辑服务
│   ├── data/               # 数据目录
│   │   ├── rules/          # YARA规则文件
│   │   └── samples/        # 上传的样本文件
│   ├── main.py             # 应用入口
│   ├── requirements.txt    # Python依赖
│   └── init_db.py          # 数据库初始化
│
├── frontend/               # React前端应用
│   ├── src/
│   │   ├── components/     # React组件
│   │   ├── pages/         # 页面组件
│   │   │   ├── Dashboard.tsx       # 首页
│   │   │   ├── RuleManagement.tsx  # 规则管理
│   │   │   ├── ScanManagement.tsx  # 扫描管理
│   │   │   └── Reports.tsx        # 报告查看
│   │   ├── services/      # API服务
│   │   ├── App.tsx        # 主应用组件
│   │   └── main.tsx       # 入口文件
│   ├── package.json
│   ├── vite.config.ts
│   └── index.html
│
├── db/                     # 数据库文件
│   ├── schema/
│   │   └── init.sql       # 数据库初始化脚本
│   └── migrations/        # 迁移文件
│
├── tools/                  # 工具脚本
│   ├── yara_loader.py     # YARA规则加载器
│   ├── scanner.py         # 扫描工具
│   └── rule_packer.py     # 规则打包工具
│
├── scripts/               # 启动脚本
│   └── start-backend.ps1  # 后端启动脚本
│
├── docs/                  # 文档和备份
│   ├── backups/          # 备份文件
│   ├── guides/           # 使用指南
│   └── api/              # API文档
│
├── docker-compose.yml    # Docker编排
├── .gitignore           # Git忽略文件
├── .env.example         # 环境变量示例
└── README.md            # 项目说明

```

## API文档

### 规则API

#### 获取规则列表
```
GET /api/rules/
```

响应:
```json
[
  {
    "id": 1,
    "name": "test_malware_detection",
    "description": "Test rule",
    "active": true,
    "created_at": "2025-11-15T10:00:00"
  }
]
```

#### 创建规则
```
POST /api/rules/
Content-Type: application/json

{
  "name": "new_rule",
  "description": "New detection rule",
  "rule_content": "rule test { ... }"
}
```

#### 切换规则状态
```
PUT /api/rules/{rule_id}/toggle
```

### 扫描API

#### 上传文件扫描
```
POST /api/scan/file
Content-Type: multipart/form-data

file: <binary file data>
```

响应:
```json
{
  "scan_id": 47,
  "filename": "Lab01-01.exe",
  "is_malicious": true,
  "match_count": 33,
  "scanned_rules": 31,
  "matches": [...]
}
```

#### 获取扫描列表
```
GET /api/scan/scans
```

#### 获取样本列表
```
GET /api/scan/samples
```

### 报告API

#### 获取统计信息
```
GET /api/reports/stats
```

#### 获取最近扫描
```
GET /api/reports/recent?limit=20
```

#### 获取扫描详情
```
GET /api/reports/{scan_id}
```

## 开发指南

### 修复YARA扫描问题

关键修复位置: `backend/app/api/scan.py` 第100-102行

**问题**: YARA StringMatch对象不支持下标访问
**解决**: 使用属性访问 `s.identifier` 和 `s.instances`

### 添加新的API端点

1. 在 `backend/app/api/` 中创建新的模块
2. 定义路由和请求/响应模型
3. 在 `main.py` 中注册路由

```python
from app.api import my_api
app.include_router(my_api.router, prefix="/api/my", tags=["My API"])
```

### 前端开发

使用 Vite + React + TypeScript

```bash
# 开发模式
npm run dev

# 构建
npm run build

# 预览
npm run preview
```

## 部署指南

### Docker部署

```bash
docker-compose up -d
```

### 手动部署

1. 安装依赖
```bash
cd backend
pip install -r requirements.txt
cd ../frontend
npm install
```

2. 启动后端
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

3. 启动前端
```bash
cd frontend
npm run build
npm run preview
```

## 故障排除

### 后端无法启动

检查Python版本:
```bash
python --version  # 应显示 Python 3.12+
```

安装缺失依赖:
```bash
pip install pydantic-settings python-jose python-multipart
```

### 数据库错误

初始化数据库:
```bash
cd backend
python init_db.py
```

### 前端连接错误

确保后端正在运行:
```bash
curl http://127.0.0.1:8000/health
```

检查CORS配置在 `backend/app/core/config.py`

## 联系方式

如有问题,请提交Issue或Pull Request

---

**最后更新**: 2025-11-15
