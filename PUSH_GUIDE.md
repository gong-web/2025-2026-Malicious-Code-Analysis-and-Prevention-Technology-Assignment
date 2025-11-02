# 🚀 推送到 GitHub 的完整指南

## ⚠️ 当前状态

✅ Git 仓库已初始化  
✅ 所有文件已提交  
✅ 远程仓库已配置  
⏳ 等待推送到 GitHub

## 📋 项目信息

- **项目名称**: YARA-X Manager
- **GitHub 仓库**: https://github.com/gong-web/2025-2026-
- **本地路径**: `d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager`
- **提交数**: 1 个初始提交
- **文件数**: 43 个文件

## 🔧 解决推送问题

### 方法 1: 配置 SSH 密钥 (推荐)

#### 步骤 1: 生成 SSH 密钥

```powershell
# 生成新密钥
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# 按回车使用默认位置和无密码
```

#### 步骤 2: 复制公钥

```powershell
# 查看并复制公钥内容
cat ~/.ssh/id_rsa.pub

# 或者在 Windows 上
type $env:USERPROFILE\.ssh\id_rsa.pub
```

#### 步骤 3: 添加到 GitHub

1. 访问: https://github.com/settings/keys
2. 点击 "New SSH key"
3. 标题: `My PC SSH Key`
4. 粘贴公钥内容
5. 点击 "Add SSH key"

#### 步骤 4: 测试连接

```powershell
ssh -T git@github.com
```

成功会显示: "Hi gong-web! You've successfully authenticated..."

#### 步骤 5: 重新配置远程仓库

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager

# 移除现有远程
git remote remove origin

# 添加 SSH 远程
git remote add origin git@github.com:gong-web/2025-2026-.git

# 推送
git push -u origin main
```

### 方法 2: 使用 GitHub Desktop (最简单)

#### 步骤 1: 下载安装

下载: https://desktop.github.com/

#### 步骤 2: 登录 GitHub 账号

打开 GitHub Desktop → 登录你的账号

#### 步骤 3: 添加仓库

1. File → Add local repository
2. 选择路径: `d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager`
3. 点击 "Add repository"

#### 步骤 4: 发布仓库

1. 点击 "Publish repository"
2. 选择 Organization: `gong-web`
3. Repository name: `2025-2026-`
4. 取消勾选 "Keep this code private" (如果想公开)
5. 点击 "Publish repository"

### 方法 3: 使用 Personal Access Token

#### 步骤 1: 创建 Token

1. 访问: https://github.com/settings/tokens
2. 点击 "Generate new token" → "Generate new token (classic)"
3. 设置:
   - Note: `YARA-X Manager Push`
   - Expiration: `90 days`
   - 勾选: `repo` (所有权限)
4. 点击 "Generate token"
5. **重要**: 复制并保存 token (只显示一次!)

#### 步骤 2: 使用 Token 推送

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager

# 确保使用 HTTPS
git remote set-url origin https://github.com/gong-web/2025-2026-.git

# 推送 (会要求输入用户名和密码)
git push -u origin main

# 用户名: gong-web
# 密码: 粘贴你的 Personal Access Token (不是 GitHub 密码!)
```

### 方法 4: 手动上传 (备选方案)

如果网络问题无法解决,可以手动上传:

#### 步骤 1: 创建压缩包

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis

# 压缩整个项目文件夹
Compress-Archive -Path yara-x-manager -DestinationPath yara-x-manager.zip
```

#### 步骤 2: 通过 GitHub 网页上传

1. 访问: https://github.com/gong-web/2025-2026-
2. 点击 "uploading an existing file"
3. 解压 zip,选择所有文件上传
4. 提交更改

## ✅ 验证推送成功

推送完成后,检查以下内容:

### 1. 访问仓库主页
https://github.com/gong-web/2025-2026-

### 2. 检查文件结构

```
✅ backend/
✅ frontend/
✅ db/
✅ tools/
✅ README.md
✅ 其他文档
```

### 3. 检查 README 显示

确保 README.md 正常显示,包含项目介绍和使用说明。

### 4. 检查提交历史

点击 "commits" 应该看到你的初始提交。

## 🔄 后续开发流程

### 修改代码后推送

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager

# 1. 查看修改
git status

# 2. 添加修改的文件
git add .

# 3. 提交修改
git commit -m "描述你的修改内容"

# 4. 推送到 GitHub
git push
```

### 常用 Git 命令

```powershell
# 查看状态
git status

# 查看提交历史
git log --oneline

# 查看远程仓库
git remote -v

# 拉取最新代码
git pull

# 查看修改内容
git diff

# 撤销未提交的修改
git checkout -- <file>

# 创建新分支
git checkout -b feature-name

# 切换分支
git checkout main
```

## 👥 团队协作

### 添加协作者

1. 访问: https://github.com/gong-web/2025-2026-/settings/access
2. 点击 "Add people"
3. 输入团队成员的 GitHub 用户名
4. 选择权限: **Write** (可以推送代码)
5. 发送邀请

### 团队成员克隆仓库

```powershell
# 克隆仓库
git clone https://github.com/gong-web/2025-2026-.git

# 进入目录
cd 2025-2026-

# 查看分支
git branch -a
```

## 📦 项目已上传内容

### 后端 (FastAPI)
- ✅ API 路由 (认证、规则、扫描、报告)
- ✅ 数据模型 (用户、规则、扫描)
- ✅ 数据库配置
- ✅ 配置管理
- ✅ 依赖文件

### 前端 (React)
- ✅ 页面组件 (Dashboard、规则、扫描、报告)
- ✅ 布局组件
- ✅ 路由配置
- ✅ 依赖文件

### 工具脚本
- ✅ yara_loader.py (规则加载)
- ✅ scanner.py (文件扫描)
- ✅ rule_packer.py (规则打包)

### 数据库
- ✅ SQL 初始化脚本
- ✅ 数据库架构设计

### 文档
- ✅ README.md (项目说明)
- ✅ QUICKSTART.md (快速开始)
- ✅ CONTRIBUTING.md (开发指南)
- ✅ TESTING.md (测试计划)
- ✅ PROJECT_CHECKLIST.md (项目清单)
- ✅ START.md (启动指南)
- ✅ DEPLOY.md (部署指南)

### 配置文件
- ✅ .env.example (环境变量)
- ✅ .gitignore (Git 忽略)
- ✅ docker-compose.yml (Docker 配置)

## 🎯 下一步

1. **推送代码**: 选择上面的方法之一推送到 GitHub
2. **添加协作者**: 邀请团队成员加入仓库
3. **开始开发**: 按照 START.md 启动项目
4. **分工协作**: 参考 PROJECT_CHECKLIST.md 分配任务

## 📞 需要帮助?

如果推送遇到问题:

1. **网络问题**: 尝试使用 VPN 或代理
2. **权限问题**: 检查 SSH 密钥或 Token 配置
3. **其他问题**: 查看错误信息并搜索解决方案

## 💡 提示

- 推荐使用 **GitHub Desktop** 或 **SSH 密钥**,最简单可靠
- 如果公司网络限制 Git,可以在家里的网络推送
- Personal Access Token 记得保存,只显示一次
- 定期推送代码,避免丢失工作成果

---

**准备推送**: ✅  
**等待操作**: 选择上述方法之一推送到 GitHub

祝推送顺利! 🎉
