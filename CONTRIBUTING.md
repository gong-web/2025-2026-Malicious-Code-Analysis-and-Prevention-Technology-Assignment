# 开发指南

## 项目架构

### 后端架构 (FastAPI)

```
backend/
├── app/
│   ├── api/          # API 路由
│   │   ├── rules.py      # 规则管理 API
│   │   ├── scan.py       # 扫描任务 API
│   │   ├── reports.py    # 报告统计 API
│   │   └── auth.py       # 认证 API
│   ├── models/       # 数据模型
│   │   ├── rule.py       # YARA 规则模型
│   │   ├── scan.py       # 扫描任务模型
│   │   └── user.py       # 用户模型
│   ├── services/     # 业务逻辑层
│   │   ├── yara_service.py
│   │   └── scan_service.py
│   └── core/         # 核心配置
│       ├── config.py     # 配置管理
│       └── database.py   # 数据库连接
├── requirements.txt
└── main.py           # 应用入口
```

### 前端架构 (React)

```
frontend/
├── src/
│   ├── components/   # 可复用组件
│   │   └── MainLayout.tsx
│   ├── pages/        # 页面组件
│   │   ├── Dashboard.tsx
│   │   ├── RuleManagement.tsx
│   │   ├── ScanManagement.tsx
│   │   └── Reports.tsx
│   ├── services/     # API 调用
│   └── utils/        # 工具函数
├── package.json
└── vite.config.ts
```

## 添加新功能

### 1. 添加新的 API 端点

#### 步骤1: 创建数据模型
```python
# backend/app/models/your_model.py
from sqlalchemy import Column, Integer, String
from app.core.database import Base

class YourModel(Base):
    __tablename__ = "your_table"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
```

#### 步骤2: 创建 API 路由
```python
# backend/app/api/your_api.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter()

@router.get("/")
async def list_items(db: Session = Depends(get_db)):
    return {"items": []}
```

#### 步骤3: 注册路由
```python
# backend/main.py
from app.api import your_api

app.include_router(your_api.router, prefix="/api/your-route", tags=["Your Tag"])
```

### 2. 添加前端页面

#### 步骤1: 创建页面组件
```tsx
// frontend/src/pages/YourPage.tsx
import React from 'react'
import { Card } from 'antd'

const YourPage: React.FC = () => {
  return (
    <div>
      <h2>Your Page Title</h2>
      <Card>
        {/* Your content */}
      </Card>
    </div>
  )
}

export default YourPage
```

#### 步骤2: 添加路由
```tsx
// frontend/src/App.tsx
import YourPage from './pages/YourPage'

<Route path="/your-page" element={<YourPage />} />
```

#### 步骤3: 添加菜单项
```tsx
// frontend/src/components/MainLayout.tsx
const menuItems = [
  // ...existing items
  {
    key: '/your-page',
    icon: <YourIcon />,
    label: 'Your Page',
  },
]
```

## 数据库迁移

### 使用 Alembic

```bash
# 初始化 Alembic
cd backend
alembic init alembic

# 创建迁移
alembic revision --autogenerate -m "description"

# 执行迁移
alembic upgrade head

# 回滚
alembic downgrade -1
```

## 测试

### 后端测试

```bash
cd backend

# 运行所有测试
pytest

# 运行特定测试
pytest tests/test_rules.py

# 生成覆盖率报告
pytest --cov=app tests/
```

### 前端测试

```bash
cd frontend

# 运行测试
npm test

# 生成覆盖率报告
npm test -- --coverage
```

## 代码规范

### Python (PEP 8)

```bash
# 代码格式化
black backend/

# 代码检查
flake8 backend/

# 类型检查
mypy backend/
```

### JavaScript/TypeScript

```bash
# 代码格式化
npm run format

# 代码检查
npm run lint

# 自动修复
npm run lint -- --fix
```

## 性能优化

### 后端优化

1. **数据库查询优化**
   - 使用索引
   - 避免 N+1 查询
   - 使用连接查询

2. **缓存**
   - Redis 缓存热数据
   - 规则编译结果缓存

3. **异步处理**
   - 使用 Celery 处理耗时任务
   - 后台任务队列

### 前端优化

1. **代码分割**
   - 路由级别的懒加载
   - 组件按需加载

2. **状态管理**
   - 使用 Zustand/Redux
   - 避免不必要的重渲染

3. **资源优化**
   - 图片懒加载
   - 打包优化

## 部署

### 生产环境配置

1. **环境变量**
```bash
DEBUG=false
SECRET_KEY=your-production-secret-key
DATABASE_URL=postgresql://...
```

2. **数据库**
   - 使用 PostgreSQL
   - 配置连接池
   - 定期备份

3. **Web 服务器**
   - 使用 Nginx 反向代理
   - 配置 SSL 证书
   - 启用 Gzip 压缩

### Docker 部署

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## 集成其他检测引擎

### 添加 Loki Scanner

```python
# backend/app/services/loki_service.py
class LokiScanner:
    def __init__(self):
        # 初始化 Loki
        pass
    
    def scan(self, target):
        # 执行扫描
        pass
```

### 添加 Sigma Rules

```python
# backend/app/services/sigma_service.py
class SigmaDetector:
    def __init__(self):
        # 初始化 Sigma
        pass
    
    def detect(self, logs):
        # 检测日志
        pass
```

## 贡献代码

1. Fork 项目
2. 创建特性分支: `git checkout -b feature/amazing-feature`
3. 提交更改: `git commit -m 'Add amazing feature'`
4. 推送到分支: `git push origin feature/amazing-feature`
5. 开启 Pull Request

## 常用命令

```bash
# 后端
cd backend
python main.py                    # 启动服务
pytest                            # 运行测试
alembic upgrade head              # 数据库迁移

# 前端
cd frontend
npm run dev                       # 开发模式
npm run build                     # 构建生产版本
npm run preview                   # 预览构建结果

# 工具
cd tools
python yara_loader.py -h          # 查看帮助
python scanner.py -h              # 查看帮助
python rule_packer.py -h          # 查看帮助

# Docker
docker-compose up -d              # 启动所有服务
docker-compose down               # 停止所有服务
docker-compose logs -f backend    # 查看后端日志
```

## 调试技巧

### 后端调试

```python
# 使用 pdb
import pdb; pdb.set_trace()

# 使用 VS Code 调试器
# 在 .vscode/launch.json 中配置
```

### 前端调试

```typescript
// 使用 console
console.log('debug:', variable)

// 使用 React DevTools
// Chrome 扩展安装 React Developer Tools
```

## 参考资源

- [FastAPI 文档](https://fastapi.tiangolo.com/)
- [React 文档](https://react.dev/)
- [SQLAlchemy 文档](https://www.sqlalchemy.org/)
- [Ant Design 文档](https://ant.design/)
- [YARA 文档](https://yara.readthedocs.io/)
