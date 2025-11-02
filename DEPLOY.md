# 部署指南 - 推送到 GitHub

## ✅ 已完成的步骤

1. ✅ 项目已初始化 Git 仓库
2. ✅ 所有文件已添加并提交
3. ✅ 远程仓库已配置

## 🚀 推送到 GitHub

### 方式一: 使用 SSH (推荐)

确保你已经配置了 SSH 密钥,然后执行:

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager
git push -u origin main
```

### 方式二: 使用 HTTPS

如果 SSH 不可用,可以改用 HTTPS:

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager

# 移除 SSH 远程仓库
git remote remove origin

# 添加 HTTPS 远程仓库
git remote add origin https://github.com/gong-web/2025-2026-.git

# 推送
git push -u origin main
```

首次推送需要输入 GitHub 用户名和密码(或 Personal Access Token)。

## 🔑 配置 SSH 密钥 (如果还没有)

### 1. 检查是否已有 SSH 密钥

```powershell
ls ~/.ssh
```

如果看到 `id_rsa` 和 `id_rsa.pub`,说明已经有密钥了。

### 2. 生成新的 SSH 密钥

```powershell
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

一直按回车使用默认设置。

### 3. 复制公钥

```powershell
cat ~/.ssh/id_rsa.pub
```

### 4. 添加到 GitHub

1. 访问 GitHub: https://github.com/settings/keys
2. 点击 "New SSH key"
3. 粘贴公钥内容
4. 点击 "Add SSH key"

### 5. 测试连接

```powershell
ssh -T git@github.com
```

如果看到 "Hi username! You've successfully authenticated"，说明配置成功。

## 📦 推送项目

执行以下命令推送项目:

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager
git push -u origin main
```

## ✅ 验证推送成功

推送完成后:
1. 访问: https://github.com/gong-web/2025-2026-
2. 确认所有文件已上传
3. 查看 README.md 显示正常

## 🔄 后续更新

每次修改后更新仓库:

```powershell
cd d:\gds\Documents\Malicious_Code_Analysis\yara-x-manager

# 查看修改
git status

# 添加所有修改
git add .

# 提交修改
git commit -m "描述你的修改"

# 推送到 GitHub
git push
```

## 🎯 项目结构已上传

```
yara-x-manager/
├── backend/              ✅ FastAPI 后端
├── frontend/             ✅ React 前端
├── db/                   ✅ 数据库脚本
├── tools/                ✅ 工具脚本
├── README.md             ✅ 项目说明
├── QUICKSTART.md         ✅ 快速开始
├── CONTRIBUTING.md       ✅ 开发指南
├── TESTING.md            ✅ 测试计划
├── PROJECT_CHECKLIST.md  ✅ 项目清单
├── START.md              ✅ 启动指南
├── .env.example          ✅ 环境变量示例
├── .gitignore            ✅ Git 忽略配置
└── docker-compose.yml    ✅ Docker 配置
```

## 🎓 分享给团队

将仓库地址分享给团队成员:
- 仓库地址: https://github.com/gong-web/2025-2026-
- 克隆命令: `git clone https://github.com/gong-web/2025-2026-.git`

## 📝 添加协作者

1. 访问仓库设置: https://github.com/gong-web/2025-2026-/settings/access
2. 点击 "Add people"
3. 输入团队成员的 GitHub 用户名或邮箱
4. 选择权限级别 (推荐: Write)
5. 发送邀请

## 🚨 常见问题

### Q: Permission denied (publickey)
A: SSH 密钥未配置或未添加到 GitHub,按照上面的步骤配置。

### Q: fatal: remote origin already exists
A: 运行 `git remote remove origin` 然后重新添加。

### Q: Updates were rejected
A: 远程有新的提交,先运行 `git pull origin main --rebase` 然后再推送。

### Q: 推送速度慢
A: 可能是网络问题,可以尝试:
- 使用 HTTPS 代替 SSH
- 配置 Git 代理
- 使用国内镜像 (如 Gitee)

## ✨ 完成!

项目已成功推送到 GitHub! 🎉

访问仓库: https://github.com/gong-web/2025-2026-
