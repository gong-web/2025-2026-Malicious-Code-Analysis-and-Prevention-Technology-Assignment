# YARA-X Manager

<div align="center">

**一个功能完整的 YARA 规则管理系统,用于恶意代码检测和防护**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61dafb.svg)](https://reactjs.org/)

[功能特性](#功能特性) • [快速开始](#快速开始) • [文档](#文档) • [贡献](#贡献指南)

</div>

---

## 项目概述

YARA-X Manager 是一个集成了规则管理、恶意代码扫描、检测引擎的反病毒软件平台。本系统支持:

- ✅ YARA 规则的存储、管理和版本控制
- ✅ 静态特征检测引擎 (YARA, Loki)
- ✅ 动态特征检测引擎 (Sigma)
- ✅ AI 模型集成 (MalConv 等)
- ✅ Web 前端管理界面
- ✅ RESTful API 接口
- ✅ 批量扫描和实时监控

## 项目结构

```
yara-x-manager/
├── backend/           # FastAPI 后端服务
│   ├── app/
│   │   ├── api/       # API 路由
│   │   ├── models/    # 数据模型
│   │   ├── services/  # 业务逻辑
│   │   └── core/      # 核心配置
│   ├── requirements.txt
│   └── main.py
├── frontend/          # React 前端界面
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── utils/
│   ├── package.json
│   └── public/
├── db/                # 数据库相关
│   ├── migrations/    # 数据库迁移文件
│   └── schema/        # 数据库架构
├── tools/             # 辅助工具
│   ├── yara_loader.py    # YARA 规则加载器
│   ├── scanner.py        # 文件扫描工具
│   └── rule_packer.py    # 规则打包工具
├── tests/             # 测试文件
├── docs/              # 文档
├── .env.example       # 环境变量示例
├── docker-compose.yml # Docker 编排
└── README.md          # 项目说明
```

## 功能特性

### 1. YARA 规则管理
- 规则上传、编辑、删除
- 规则分类和标签管理
- 规则版本控制
- 规则验证和编译
- 规则搜索和过滤

### 2. 恶意代码检测
- 单文件扫描
- 批量目录扫描
- 实时监控扫描
- 自定义扫描策略
- 检测结果报告

### 3. 检测引擎集成
- **YARA Engine**: 静态特征匹配
- **Loki Scanner**: 综合检测
- **Sigma Rules**: 动态行为检测
- **AI Models**: 机器学习检测

### 4. Web 管理界面
- Dashboard 仪表盘
- 规则管理面板
- 扫描任务管理
- 检测结果可视化
- 系统配置管理

## 技术栈

### 后端
- **框架**: FastAPI (Python 3.8+)
- **数据库**: PostgreSQL / SQLite
- **ORM**: SQLAlchemy
- **任务队列**: Celery + Redis
- **YARA**: yara-python

### 前端
- **框架**: React 18+
- **UI 库**: Ant Design / Material-UI
- **状态管理**: Redux / Zustand
- **HTTP 客户端**: Axios
- **图表**: ECharts / Recharts

### 工具
- **YARA**: 规则引擎
- **Loki**: 恶意代码扫描器
- **Docker**: 容器化部署

## 快速开始

### 环境要求

- Python 3.8+
- Node.js 16+
- PostgreSQL 12+ (或 SQLite)
- Redis (可选,用于任务队列)

### 安装步骤

1. **克隆项目**
```bash
cd yara-x-manager
```

2. **配置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件,配置数据库连接等信息
```

3. **启动后端**
```bash
cd backend
pip install -r requirements.txt
python main.py
```

4. **启动前端**
```bash
cd frontend
npm install
npm start
```

5. **访问应用**
- 前端: http://localhost:3000
- 后端 API: http://localhost:8000
- API 文档: http://localhost:8000/docs

### Docker 部署

```bash
docker-compose up -d
```

## API 文档

启动后端后访问 `http://localhost:8000/docs` 查看 Swagger API 文档。

主要 API 端点:

- `POST /api/rules` - 上传 YARA 规则
- `GET /api/rules` - 获取规则列表
- `POST /api/scan` - 启动扫描任务
- `GET /api/scan/{task_id}` - 查询扫描结果
- `GET /api/reports` - 获取检测报告

## 开发指南

### 添加新的 YARA 规则

1. 通过 Web 界面上传
2. 使用 API 接口
3. 使用 `yara_loader.py` 工具批量导入

```bash
python tools/yara_loader.py --input rules/ --database postgresql://...
```

### 运行测试

```bash
# 后端测试
cd backend
pytest

# 前端测试
cd frontend
npm test
```

### 代码规范

- Python: PEP 8
- JavaScript: ESLint + Prettier
- 提交: Conventional Commits

## 测试指标

系统测试包括:

- ✅ **准确率 (Accuracy)**: 正确检测恶意代码的比例
- ✅ **误报率 (False Positive Rate)**: 将正常文件误判为恶意的比例
- ✅ **漏报率 (False Negative Rate)**: 未能检测出恶意代码的比例
- ✅ **性能**: 扫描速度、内存占用
- ✅ **规则覆盖率**: YARA 规则的有效性

## 贡献指南

欢迎提交 Issue 和 Pull Request!

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 团队成员

- 组长: [姓名] - 项目管理、架构设计
- 成员1: [姓名] - 后端开发
- 成员2: [姓名] - 前端开发
- 成员3: [姓名] - 检测引擎、规则编写

## 许可证

MIT License

## 相关资源

- [YARA 官方文档](https://yara.readthedocs.io/)
- [Loki Scanner](https://github.com/Neo23x0/Loki)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [VirusTotal](https://www.virustotal.com/)

## 更新日志

### v0.1.0 (2025-11-02)
- 初始项目结构
- 基础框架搭建
- 核心功能开发中

---

**注意**: 本项目用于教育和研究目的,请勿用于非法用途。
