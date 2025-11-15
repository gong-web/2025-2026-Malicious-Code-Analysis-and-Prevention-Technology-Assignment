# Lab03-04.exe 恶意代码分析报告

## 样本信息
- **文件名**: Lab03-04.exe
- **路径**: d:\gds\Documents\Malicious_Code_Analysis\Practical Malware Analysis Labs\Practical Malware Analysis Labs\BinaryCollection\Chapter_3L\Lab03-04.exe
- **分析目标**: 研究自删除机制及其避免方法，用于教育和防御目的。
- **环境**: 隔离虚拟机，创建快照，禁用网络以防传播。

## 静态分析结果
### 字符串提取（关键片段）
- 命令行相关: `cmd.exe`, `/c del`, `>> NUL`
- 网络相关: `http://www.practicalmalwareanalysis.com`, `HTTP/1.0`, `GET`
- 功能关键词: `DOWNLOAD`, `UPLOAD`, `SLEEP`, `Manager Service`
- 系统路径: `%SYSTEMROOT%\system32\`
- 其他: `k:%s h:%s p:%s per:%s` (可能参数格式)

### 可疑功能点
- 导入API: CreateProcessA, ShellExecuteA (可启动外部进程如cmd)
- 注册表操作: RegCreateKeyExA, RegSetValueExA (可能持久化)
- 文件操作: DeleteFileA, CopyFileA (删除/复制文件)
- 服务管理: CreateServiceA, DeleteService (可能安装/删除服务)
- 网络: WS2_32.dll 导入 (网络通信)

## 自删除机制分析
### 推测机制
基于字符串和导入，Lab03-04.exe 很可能在运行后通过以下方式自删除：
- 构造命令行: `cmd.exe /c del "自身路径" >> NUL`
- 使用 CreateProcessA 或 ShellExecuteA 执行该命令。
- 由于文件正在运行，立即删除可能失败，但可通过批处理或延迟机制实现。

### 常见自删除技术（概念性）
- **命令行删除**: 使用 `cmd /c del %0` 或类似删除自身。
- **MoveFileEx 延迟删除**: 调用 MoveFileEx(NULL, filename, MOVEFILE_DELAY_UNTIL_REBOOT) 在重启时删除。
- **批处理脚本**: 创建临时批处理文件执行删除。

## 避免自删除的方法（高层建议）
- **文件复制**: 在运行前复制 exe 到临时位置，运行副本，原文件保留。
- **监控阻止**: 在沙箱中使用文件监控工具拦截删除操作。
- **代码patch**: 修改二进制移除删除逻辑（仅用于研究，不提供步骤）。
- **环境隔离**: 在只读文件系统或快照中运行，防止永久更改。

## 动态分析计划（隔离沙箱）
### 所需工具
- ProcessMonitor: 监控文件/进程/注册表操作。
- Regshot: 注册表快照比较。
- Wireshark: 网络流量捕获。
- ProcessExplorer: 进程树和模块查看。

### 安全实验步骤（高层）
1. 创建沙箱快照。
2. 复制样本到沙箱。
3. 启动监控工具。
4. 运行样本，观察行为。
5. 记录所有活动，包括删除尝试。
6. 分析日志，确认自删除触发点。
7. 回滚快照。

## 检测、缓解与取证建议
### 检测点
- 监控 cmd.exe 启动与删除命令。
- 文件系统审计：意外文件删除事件。
- 进程监控：可疑子进程创建。

### 缓解措施
- 启用文件完整性监控 (FIM)。
- 白名单执行策略。
- 端点检测响应 (EDR) 规则：拦截删除 API 调用。

### 取证要点
- 保存样本哈希和原始副本。
- 导出进程内存和日志。
- 记录时间戳和系统状态。

## 结论与下一步
Lab03-04.exe 是一个功能丰富的恶意样本，具有网络通信、服务管理、自删除等能力。自删除通过命令行机制实现，可通过复制运行或监控阻止避免。建议在隔离环境中进一步动态验证，并根据结果更新 IOCs。

待验证项：
- 动态运行确认自删除行为。
- 网络通信细节。
- 服务安装/删除逻辑。

下一步：执行动态分析并补充报告。