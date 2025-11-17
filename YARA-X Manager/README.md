# YARA‑X Manager 项目说明

YARA‑X Manager 是一个自主开发的小型轻量化杀毒软件平台，集成规则管理、恶意代码扫描与检测引擎。系统核心通过收集的 YARA 规则与 Sigma 规则，对用户上传的可执行文件与日志/事件进行匹配，输出清晰的查杀结果与报告。

本文档基于当前仓库代码结构，全面说明前后端架构、目录、接口、部署与使用方法，确保一致性与可维护性。

---

## 目录结构

```
项目根目录
├─ backend/                              后端服务（FastAPI）
│  ├─ main.py                           应用入口、路由注册与内置 UI
│  ├─ app/
│  │  ├─ core/
│  │  │  ├─ config.py                  运行配置（端口、规则目录等）
│  │  │  ├─ database.py                SQLAlchemy 初始化与依赖注入
│  │  │  ├─ yara_ext.py                YARA externals 构建工具
│  │  │  ├─ yara_cache.py              透明编译缓存（data/compiled）
│  │  │  ├─ sigma_engine.py            Sigma 条件求值引擎
│  │  │  ├─ event_normalizer.py        事件字段规范化（Sysmon/Windows/Linux/Cloud）
│  │  │  └─ log_parser.py              文本日志解析为结构化事件
│  │  ├─ api/
│  │  │  ├─ rules.py                   YARA 规则：列表/上传/导入/启停/删除
│  │  │  ├─ sigma_rules.py             Sigma 规则：列表/上传/导入/启停/删除/报告
│  │  │  ├─ scan.py                    扫描：文件（YARA）、日志与事件（Sigma）、历史
│  │  │  ├─ reports.py                 仪表盘统计与最近扫描
│  │  ├─ models/
│  │  │  ├─ rule.py                    结构化模型：YaraRule、SigmaRule（版本与性能字段）
│  │  ├─ api/models_shared.py          简化规则索引 Rule、样本 Sample、扫描 Scan
│  │  └─ services/rule_validator.py    统一验证器：YARA 编译测试、Sigma YAML/condition 校验
│  ├─ requirements.txt                 后端依赖（FastAPI/SQLAlchemy/yara-python/PyYAML 等）
│  ├─ init_db.py                       建表脚本（导入所有模型）
│  └─ data/                            运行目录（自动创建）
│     ├─ rules/                        参与扫描的 YARA 规则文件
│     ├─ sigma_rules/                  参与扫描的 Sigma 规则文件
│     └─ compiled/                     YARA 编译缓存
│
├─ db/                                  原始规则库（不直接参与扫描）
│  ├─ yara_rules_all/                   大型 YARA 集合（分类清晰）
│  ├─ class-lab-yararules/              教学集合（Practical Malware Analysis）
│  └─ sigma_rules_flat/                 扁平 Sigma 集合（manifest 与示例）
│
├─ frontend/                            前端（React + Vite + Ant Design）
│  ├─ src/components/MainLayout.tsx    导航与布局（仪表盘、规则、扫描、报告）
│  ├─ src/pages/DashboardPage.tsx      仪表盘统计与最近扫描
│  ├─ src/pages/RulePage.tsx           YARA 规则管理
│  ├─ src/pages/SigmaPage.tsx          Sigma 规则与平台报告
│  ├─ src/pages/ScanPage.tsx           单文件扫描与快速验证
│  ├─ src/pages/ScanManagement.tsx     扫描管理与结果
│  ├─ src/pages/ReportsPage.tsx        检测报告与概览
│  ├─ src/services/                    前端服务层（对齐后端 API）
│  └─ vite.config.ts                   开发代理 `/api` → `http://localhost:8000`
│
└─ YARA‑X Manager/README.md            本说明文档
```

---

## 架构概览

- 后端：FastAPI + SQLAlchemy + Pydantic
  - 检测引擎：
    - YARA 文件扫描：批量编译活动规则并匹配二进制数据
    - Sigma 日志/事件扫描：关键词匹配与结构化事件条件求值
  - 规则管理：YARA/Sigma 规则的上传、导入、启用/禁用、删除
  - 运行目录：`data/rules` 与 `data/sigma_rules`（参与扫描）；`db/` 为原始规则库
  - 透明优化：编译缓存（`data/compiled`）、类型筛选（PE/ELF）、统一 externals

- 前端：React + Vite + Ant Design
  - 页面：仪表盘、文件/日志/事件扫描、YARA 规则、Sigma 规则、扫描历史与报告
  - 服务层：`src/services/*` 对齐后端接口，统一错误处理与交互逻辑
  - 代理：开发模式下将 `/api` 代理到后端，避免跨域与环境配置成本

---

## 关键功能

**YARA 文件扫描**
- 接口：`POST /api/scan/file`（multipart，字段 `file`）
- 过程：
  - 加载活动规则（`data/rules`）
  - 类型筛选：含 `import "pe"/"elf"` 的规则按样本魔数过滤
  - 编译与缓存：首次编译并保存到 `data/compiled`，后续直接加载
  - 匹配：返回命中规则名称、命名空间、标签、meta、命中字符串统计
  - 记录：保存到 `scans` 表（状态、开始/结束时间、结果 JSON）

**Sigma 日志/事件扫描**
- 文本日志：`POST /api/scan/logs`（keywords + 事件引擎）
- 结构化事件：`POST /api/scan/events`（JSON 数组或 NDJSON）
- 引擎：`app/core/sigma_engine.py`
  - 支持 `and/or/not`、括号优先、`1 of selection*`、`all of them` 等常用表达
  - 匹配器：等值、glob、正则（`/regex/`）、列表任意
  - 字段规范化：`event_normalizer.py` 将多平台字段补齐到统一键（如 `CommandLine/Image/EventID`）
  - 文本解析：`log_parser.py` 将文本日志拆解为事件（KV/JSON/普通行）

**规则管理**
- YARA：`GET/POST/PATCH/DELETE /api/rules/*`，`POST /api/rules/import/db`
- Sigma：`GET/POST/PATCH/DELETE /api/sigma/*`，`POST /api/sigma/import/db`，`GET /api/sigma/report`
- 验证：`services/rule_validator.py` 对 YARA 做编译测试，对 Sigma 做 YAML/condition 校验

**仪表盘与报告**
- 统计：`GET /api/reports/stats`（总扫描、威胁/安全分布、活跃规则数）
- 最近：`GET /api/reports/recent?limit=N`
- 单条详情：`GET /api/reports/{scan_id}`

---

## 数据模型

**简化索引（参与扫描）**
- `app/api/models_shared.py`
  - Rule：`id/name/path/active/version/revision/compile_time_ms/complexity_score/...`
  - Sample：`id/filename/path`
  - Scan：`id/filename/status/result/started_at/finished_at`

**结构化规则（管理与统计）**
- `app/models/rule.py`
  - YaraRule：`name/content/category/tags/author/version/revision/统计/时间戳` 等
  - SigmaRule：`name/title/rule_id/status/level/logsource_xxx/detection_condition/tags/falsepositives/version/revision/统计/时间戳`

---

## 运行与部署

**后端（Windows PowerShell）**
```
# 1) 创建虚拟环境并安装依赖
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt

# 2) 初始化数据库
python backend\init_db.py

# 3) 启动后端
uvicorn main:app --reload --app-dir backend

# 访问
http://localhost:8000/docs
http://localhost:8000/ui
```

**前端（开发模式）**
```
cd frontend
npm install
npm run dev

# 访问
http://localhost:3000/
```

---

## 使用说明

**文件扫描（YARA）**
- 前端“样本扫描”页上传文件；或使用 curl：
```
curl -F "file=@path\to\sample.exe" http://localhost:8000/api/scan/file
```

**日志扫描（Sigma）**
- 文本日志：
```
curl -F "file=@path\to\log.txt" http://localhost:8000/api/scan/logs
```
- 结构化事件（JSON 数组或 NDJSON）：
```
curl -F "file=@path\to\events.json" http://localhost:8000/api/scan/events
```

**规则管理**
- YARA 上传：`POST /api/rules/upload`；从库导入：`POST /api/rules/import/db`
- Sigma 上传：`POST /api/sigma/upload`；从库导入：`POST /api/sigma/import/db`
- 启用/禁用：`PATCH /api/rules/{id}/toggle` / `PATCH /api/sigma/{id}/toggle`
- 删除：`DELETE /api/rules/{id}` / `DELETE /api/sigma/{id}`

**报告与历史**
- 仪表盘统计：`GET /api/reports/stats`
- 最近记录：`GET /api/reports/recent?limit=10`
- 历史列表：`GET /api/scan/scans`

---

## 设计原则与优化

- 轻量化与透明性：尽量减少用户配置；上传即用；自动目录创建与缓存
- 性能优化：
  - YARA 规则编译缓存（`data/compiled`）
  - 按样本类型筛选 `pe/elf` 模块规则
  - 记录编译耗时与复杂度，便于治理
- 可维护性：统一服务层与接口约定；后端统一验证器；字段规范化提升规则命中率
- 安全性：避免上传执行；仅做匹配分析；不记录敏感文件内容；删除样本与规则时同步清理

---

## 常见问题与排错

- IDE 显示 “无法解析导入 `yara`”：请选择项目虚拟环境解释器（`./.venv/Scripts/python.exe`）
- `node/npm` 不可用：安装 Node.js LTS；如 PATH 未生效，使用完整路径启动
- 上传规则报错：检查扩展名与语法；YARA 使用 `yara-python` 编译，Sigma 使用 `PyYAML` 与条件校验
- 规则导入失败：查看 `POST /api/rules/import/db` 与 `POST /api/sigma/import/db` 的 `errors` 字段原因

---

## 版本与规划

- 已实现：YARA 文件扫描、Sigma 日志与事件扫描、规则管理与导入、仪表盘与报告、字段规范化与日志解析、编译缓存与类型筛选
- 规划：平台适配器扩展（Windows/Sysmon/Linux/Cloud 更细映射）、轻量趋势图与筛选、批量样本扫描、规则健康度与治理工具

---

## 版权与贡献

本项目用于课程与研究实践，欢迎在保持安全与合规的前提下提出改进意见与贡献代码。
