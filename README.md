# YARA‑X Manager

一个小型轻量化的恶意代码检测平台，集成 YARA 与 Sigma 规则管理与扫描引擎，支持文件与日志/事件的检测匹配，输出清晰查杀结果与报告。

---

## 项目概览

- 规则管理：YARA/Sigma 规则的上传、导入、启用/禁用、删除与基础元数据展示
- 文件扫描（YARA）：对上传样本进行批量规则编译与匹配，返回命中明细与统计
- 日志/事件扫描（Sigma）：关键词与结构化事件条件求值引擎，支持多平台字段规范化
- 仪表盘与报告：总览统计、最近扫描记录与历史列表，支持单条记录详情

---

## 目录结构（与实际仓库一致）

```
backend/                      FastAPI 后端
  app/core/                  配置、数据库、YARA/Sigma 引擎与工具
  app/api/                   路由：规则、扫描、报告
  app/models/                结构化规则模型（YaraRule/SigmaRule）
  app/api/models_shared.py   简化索引：Rule/Sample/Scan
  init_db.py                 建表脚本
  requirements.txt           后端依赖

db/                          原始规则库（不直接参与扫描）
  yara_rules_all/            大型 YARA 集合
  class-lab-yararules/       教学集合（PMA）
  sigma_rules_flat/          扁平 Sigma 集合

frontend/                    React 前端（Vite）
  src/pages/                 仪表盘、规则管理、扫描、报告
  src/services/              前端服务层（对齐后端接口）
  vite.config.ts             开发代理 `/api` → `http://localhost:8000`

YARA‑X Manager/README.md     详细技术文档
README.md                    顶层说明（本文件）
```

---

## 后端接口

**YARA 规则**
- `GET /api/rules/` 列表
- `POST /api/rules/upload` 上传 `.yar/.yara`
- `PATCH /api/rules/{id}/toggle` 启用/禁用
- `DELETE /api/rules/{id}` 删除
- `POST /api/rules/import/db` 从 `db/` 导入到 `data/rules` 并入库

**Sigma 规则**
- `GET /api/sigma/` 列表
- `POST /api/sigma/upload` 上传 `.yml/.yaml`
- `POST /api/sigma/import/db` 从 `db/sigma_rules_flat` 导入到 `data/sigma_rules` 并入库
- `PATCH /api/sigma/{id}/toggle` 启用/禁用
- `DELETE /api/sigma/{id}` 删除
- `GET /api/sigma/report` 平台/服务/字段适配统计

**扫描**
- `POST /api/scan/file` 文件扫描（YARA）
- `POST /api/scan/logs` 文本日志扫描（Sigma keywords + 事件引擎）
- `POST /api/scan/events` 结构化事件扫描（JSON 数组或 NDJSON）
- `GET /api/scan/samples` 样本列表；`DELETE /api/scan/samples/{id}` 删除样本
- `GET /api/scan/scans` 扫描历史列表

**报告**
- `GET /api/reports/stats` 仪表盘统计
- `GET /api/reports/recent?limit=N` 最近扫描
- `GET /api/reports/{scan_id}` 单条详情

---

## 运行指南（Windows）

**后端**
```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python backend\init_db.py
uvicorn main:app --reload --app-dir backend

# 访问
http://localhost:8000/docs
http://localhost:8000/ui
```

**前端**
```
cd frontend
npm install
npm run dev

# 访问
http://localhost:3000/
```

---

## 使用示例

**文件扫描（YARA）**
```
curl -F "file=@path\to\sample.exe" http://localhost:8000/api/scan/file
```

**日志扫描（Sigma）**
```
curl -F "file=@path\to\log.txt" http://localhost:8000/api/scan/logs
```

**事件扫描（Sigma）**
```
curl -F "file=@path\to\events.json" http://localhost:8000/api/scan/events
```

**规则管理（YARA/Sigma）**
```
# 上传 YARA
curl -F "files=@rules/example.yar" http://localhost:8000/api/rules/upload

# 上传 Sigma
curl -F "files=@sigma/example.yml" http://localhost:8000/api/sigma/upload
```

---

## 设计与优化

- 轻量化：上传即用、目录自动创建、内置简易 UI `/ui`
- 规则运行目录：`data/rules` 与 `data/sigma_rules`；`db/` 为原始库
- YARA 优化：类型筛选（PE/ELF）、编译缓存（`data/compiled`）、统一 externals（`filesize/sha256/filetype`）
- Sigma 引擎：条件求值（`and/or/not`、括号、`1 of`/`all of`）、匹配器（等值/glob/regex/列表）、字段规范化与文本解析
- 可维护性：前端服务层对齐、统一接口约定、错误提示与报告统计

---

## 常见问题

- IDE 提示无法解析 `yara`：选择项目虚拟环境解释器 `./.venv/Scripts/python.exe`
- 前端 `node`/`npm` 不可用：安装 Node.js LTS；必要时用完整路径启动
- 上传规则失败：检查扩展名与语法；YARA 使用 `yara-python` 编译，Sigma 使用 `PyYAML` 与条件校验
- 导入报告中失败项：根据 `errors` 字段定位语法或平台不适配问题

---

## 许可证

MIT License

本项目用于课程与研究实践，请遵守相关法律法规与道德规范。
