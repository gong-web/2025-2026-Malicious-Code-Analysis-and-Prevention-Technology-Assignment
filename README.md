### 一、启动后端

```bash
cd backend
python main.py
```

访问 http://localhost:8000/docs查看 API 文档

### 二、启动前端

```bash
cd frontend
npm run dev
```

访问 http://localhost:5173

### 三、静态检测

#### (1)白名单数据库构建

**A.工业级项目白名单数据库准备：**

1.  **下载主数据库**：
    
    `RDS_2025.03.1_modern_minimal.db`https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds
    
2.  **下载增量更新 (Delta)**：
    
    NIST 会定期发布增量 SQL 文件（如 6月、9月的更新）。

    文件：`RDS_2025.06.1_modern_minimal_delta.sql` 等。
    
3.  **合并数据库**：
    
    使用本项目 `tools/merge_rds.py`将增量 SQL 应用到主数据库中。

**B.轻量级项目白名单数据库准备：**

将自己准备的良性样本集放在`sample\bengin`文件夹下，运行`tools\create_lite_whitelist.py`即可构建白名单数据库

#### (2) 实战命令示例

场景一：批量检测恶意样本（计算检出率)

```bash
python tools/comprehensive_scan.py "data/samples/malware" --type malicious --workers 8
```

场景二：测试良性样本（计算误报率)

```bash
python tools/comprehensive_scan.py "data/samples/benign" --type benign --workers 8
```

场景三：快速扫描未知文件夹

```bash
python tools/comprehensive_scan.py "D:\Downloads\SuspiciousFiles" --output "reports/scan_01"
```

扫描完成后，会在`sample\result`输出目录生成两个文件：

1. `[目标名]_[时间戳].json`: 包含每个文件的详细扫描信息。
2. `[目标名]_[时间戳].txt`: 扫描摘要和恶意文件列表。

### 四、动态检测

系统提供了基于 Sigma 规则的动态行为检测功能，支持通过 RESTful API 进行事件日志分析、VirusTotal 沙箱行为检测和模拟沙箱分析。动态检测引擎能够识别攻击者在运行时的战术、技术与过程（TTPs），有效检测加壳、混淆的恶意代码。

**主要功能：**

- **日志文件分析**：支持 JSON、JSONL、YAML 格式的 Windows 事件日志文件上传，自动解析并匹配 Sigma 规则。
- **事件流检测**：支持通过 API 直接传入事件列表进行实时检测，适用于程序化调用和 SIEM 集成。
- **VirusTotal 集成**：通过文件哈希获取 VirusTotal 沙箱行为数据，转换为 Sigma 兼容事件格式进行检测。
- **模拟沙箱分析**：通过静态字符串提取和启发式规则生成模拟系统事件，在不执行文件的情况下进行行为分析。
- **规则索引优化**：基于 EventID 的倒排索引机制，显著提高大规模规则库的匹配效率。

#### (1) API 接口说明

系统提供了五个主要的动态检测 API 接口，均位于 `/api/sigma-scan/` 路径下：

1. **事件列表检测**：`POST /api/sigma-scan/events`
   - **功能**：直接传入事件列表进行检测
   - **请求体**：`{ "events": [{...}, {...}] }`
   - **限制**：最多 10000 个事件
   - **适用场景**：实时事件流处理、SIEM 系统集成
2. **日志文件上传**：`POST /api/sigma-scan/file`
   - **功能**：上传日志文件进行离线分析
   - **支持格式**：JSON、JSONL、YAML、纯文本
   - **文件大小限制**：100MB
   - **事件数量限制**：50000 个
   - **适用场景**：历史日志分析、批量检测
3. **VirusTotal 沙箱检测**：`POST /api/sigma-scan/virustotal`
   - **功能**：通过文件哈希获取 VirusTotal 行为数据并检测
   - **请求体**：`{ "file_hash": "sha256...", "use_cache": true }`
   - **哈希格式**：支持 SHA256（64字符）、SHA1（40字符）、MD5（32字符）
   - **速率限制**：4次/分钟（VirusTotal Public API 限制）
   - **适用场景**：已知文件哈希的快速行为分析
4. **模拟沙箱检测**：`POST /api/sigma-scan/dynamic`
   - **功能**：上传可执行文件，通过静态字符串提取生成模拟事件
   - **支持格式**：.exe, .bat, .ps1, .cmd, .dll, .scr
   - **文件大小限制**：100MB
   - **适用场景**：安全环境下的可执行文件行为推断
5. **规则重载**：`POST /api/sigma-scan/reload`
   - **功能**：重新加载 Sigma 规则库，更新规则缓存
   - **请求体**：无（空请求体）
   - **响应**：`{ "message": "Rules reloaded. Active rules: N" }`
   - **适用场景**：规则文件更新后需要重新加载规则库
   - **注意事项**：重载过程可能需要数秒时间，期间检测请求可能暂时延迟

#### (2) 实战命令示例

**场景一：检测 Windows 事件日志文件**

使用 curl 命令上传 Sysmon 日志文件进行检测：

```bash
curl -X POST "http://localhost:8000/api/sigma-scan/file" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@sysmon_logs.json"
```

使用 Python requests 库：

```python
import requests

url = "http://localhost:8000/api/sigma-scan/file"
with open("sysmon_logs.json", "rb") as f:
    files = {"file": ("sysmon_logs.json", f, "application/json")}
    response = requests.post(url, files=files)
    result = response.json()
    print(f"总事件数: {result['total_events']}")
    print(f"匹配数: {result['matches_count']}")
    for match in result['matches']:
        print(f"事件索引 {match['event_index']}: {len(match['matches'])} 条规则匹配")
```

**场景二：直接检测事件列表**

适用于实时事件流处理场景：

```bash
curl -X POST "http://localhost:8000/api/sigma-scan/events" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "EventID": 4688,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c powershell.exe -enc ..."
      },
      {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc ..."
      }
    ]
  }'
```

使用 Python requests 库：

```python
import requests

url = "http://localhost:8000/api/sigma-scan/events"
events = [
    {
        "EventID": 4688,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c net user admin /add"
    }
]
response = requests.post(url, json={"events": events})
result = response.json()
print(f"检测结果: {result['matches']}")
```

**场景三：VirusTotal 沙箱行为检测**

需要先配置 VirusTotal API 密钥（环境变量 `VT_API_KEY`）：

```bash
# 设置API密钥
export VT_API_KEY="your_virustotal_api_key"

# 检测文件哈希
curl -X POST "http://localhost:8000/api/sigma-scan/virustotal" \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "a1b2c3d4e5f6...",
    "use_cache": true
  }'
```

使用 Python requests 库：

```python
import requests
import os

# 确保已设置环境变量 VT_API_KEY
url = "http://localhost:8000/api/sigma-scan/virustotal"
data = {
    "file_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "use_cache": True
}
response = requests.post(url, json=data)
result = response.json()
print(f"总事件数: {result['total_events']}")
print(f"匹配数: {len(result['matches'])}")
```

**场景四：模拟沙箱检测可执行文件**

上传可执行文件进行静态字符串分析和行为推断：

```bash
curl -X POST "http://localhost:8000/api/sigma-scan/dynamic" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@suspicious.exe"
```

使用 Python requests 库：

```bash
import requests

url = "http://localhost:8000/api/sigma-scan/dynamic"
with open("suspicious.exe", "rb") as f:
    files = {"file": ("suspicious.exe", f, "application/x-msdownload")}
    response = requests.post(url, files=files)
    result = response.json()
    print(f"文件名: {result['filename']}")
    print(f"文件哈希: {result['file_hash']}")
    print(f"生成事件数: {result['total_events']}")
    print(f"匹配数: {result['matches_count']}")
    print(f"任务ID: {result['task_id']}")
```

#### (3) 结果解读

所有动态检测 API 返回的结果格式统一，包含以下字段：

- **total_events**：检测的事件总数
- **matches**：匹配结果列表，每个匹配项包含：
  - **event_index**：事件在原始列表中的索引（仅事件列表和文件上传接口）
  - **event_data**：原始事件数据（可选）
  - **matches**：匹配的规则列表，每个规则包含：
    - **rule_id**：规则唯一标识符（UUID）
    - **title**：规则名称
    - **level**：威胁级别（informational, low, medium, high, critical）
    - **tags**：规则标签（如 ATT&CK 战术 ID）

**威胁级别说明**：

- **critical**：严重威胁，如勒索软件、APT 攻击链
- **high**：高危威胁，如后门、远程控制、信息窃取
- **medium**：中等威胁，如可疑脚本执行、注册表修改
- **low**：低威胁，如系统工具的正常行为
- **informational**：信息性告警，用于威胁狩猎

**典型匹配示例**：

检测到 PowerShell 编码执行（`-enc` 参数）时，通常会匹配以下规则：

- `proc_creation_win_susp_powershell_enc_cmd`（medium 级别）
- `proc_creation_win_powershell_base64_encode`（high 级别）

检测到可疑注册表修改时，可能匹配：

- `registry_set_suspicious_run_key`（medium 级别）
- `registry_set_userinit_mprlogonscript`（high 级别）

### 五、停止服务

- **后端**: 在终端中按 `Ctrl+C`
- **前端**: 在终端中按 `Ctrl+C`