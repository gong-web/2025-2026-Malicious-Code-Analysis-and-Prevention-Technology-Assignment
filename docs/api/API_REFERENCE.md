# API 文档

## 基础信息

- **基础URL**: http://localhost:8000
- **认证**: JWT (可选)
- **数据格式**: JSON

## 健康检查

### GET /health

检查服务器状态

```bash
curl http://localhost:8000/health
```

响应:
```json
{
  "status": "healthy"
}
```

## 规则管理 API

### GET /api/rules/

获取所有规则列表

```bash
curl http://localhost:8000/api/rules/
```

响应:
```json
[
  {
    "id": 1,
    "name": "test_malware_detection",
    "description": "Test rule for malware detection",
    "active": true,
    "path": "D:\\...\\test_malware_detection.yar",
    "created_at": "2025-11-12T10:30:00",
    "updated_at": "2025-11-12T10:30:00"
  }
]
```

### POST /api/rules/

创建新规则

```bash
curl -X POST http://localhost:8000/api/rules/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "new_rule",
    "description": "New malware detection rule",
    "rule_content": "rule new_rule { ... }"
  }'
```

### PUT /api/rules/{rule_id}/toggle

切换规则的启用/禁用状态

```bash
curl -X PUT http://localhost:8000/api/rules/1/toggle \
  -H "Content-Type: application/json" \
  -d '{"active": true}'
```

响应:
```json
{
  "id": 1,
  "active": true,
  "message": "Rule updated successfully"
}
```

## 扫描 API

### POST /api/scan/file

上传文件进行扫描

```bash
curl -X POST http://localhost:8000/api/scan/file \
  -F "file=@/path/to/file.exe"
```

响应:
```json
{
  "scan_id": 47,
  "filename": "Lab01-01.exe",
  "file_hash": "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47",
  "is_malicious": true,
  "threat_level": "malicious",
  "status": "done",
  "match_count": 33,
  "scanned_rules": 31,
  "started_at": "2025-11-15T10:30:00.123456",
  "finished_at": "2025-11-15T10:30:05.456789",
  "matches": [
    {
      "rule": "FileRevise",
      "namespace": "FileRevise",
      "tags": [],
      "meta": {
        "description": "File revision detection"
      },
      "strings": [
        {
          "identifier": "$str1",
          "instances": 2
        }
      ]
    }
  ]
}
```

### GET /api/scan/samples

获取上传的样本列表

```bash
curl "http://localhost:8000/api/scan/samples?skip=0&limit=100"
```

响应:
```json
[
  {
    "id": 1,
    "filename": "Lab01-01.exe",
    "path": "data/samples/58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47_Lab01-01.exe",
    "file_exists": true,
    "file_size": 16384
  }
]
```

### DELETE /api/scan/samples/{sample_id}

删除上传的样本

```bash
curl -X DELETE http://localhost:8000/api/scan/samples/1
```

响应:
```json
{
  "message": "样本已删除"
}
```

### GET /api/scan/scans

获取扫描记录列表

```bash
curl "http://localhost:8000/api/scan/scans?skip=0&limit=100"
```

响应:
```json
[
  {
    "id": 47,
    "filename": "Lab01-01.exe",
    "status": "done",
    "is_malicious": true,
    "match_count": 33,
    "started_at": "2025-11-15T10:30:00",
    "finished_at": "2025-11-15T10:30:05"
  }
]
```

## 报告 API

### GET /api/reports/stats

获取统计信息

```bash
curl http://localhost:8000/api/reports/stats
```

响应:
```json
{
  "total_scans": 47,
  "total_malicious": 23,
  "total_clean": 24,
  "active_rules": 31,
  "total_rules": 31
}
```

### GET /api/reports/recent

获取最近的扫描记录

```bash
curl "http://localhost:8000/api/reports/recent?limit=20"
```

响应:
```json
[
  {
    "id": 48,
    "filename": "Lab01-04.exe",
    "status": "done",
    "is_malicious": true,
    "match_count": 59,
    "started_at": "2025-11-15T10:35:00",
    "finished_at": "2025-11-15T10:35:10"
  }
]
```

### GET /api/reports/{scan_id}

获取扫描详情

```bash
curl http://localhost:8000/api/reports/47
```

响应:
```json
{
  "id": 47,
  "filename": "Lab01-01.exe",
  "file_hash": "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47",
  "status": "done",
  "is_malicious": true,
  "threat_level": "malicious",
  "match_count": 33,
  "scanned_rules": 31,
  "started_at": "2025-11-15T10:30:00.123456",
  "finished_at": "2025-11-15T10:30:05.456789",
  "matches": [
    {
      "rule": "FileRevise",
      "namespace": "FileRevise",
      "tags": [],
      "meta": {},
      "strings": [
        {
          "identifier": "$str1",
          "instances": 2
        }
      ]
    }
  ]
}
```

## 错误响应

### 常见错误码

| 错误码 | 说明 | 示例 |
|-------|------|------|
| 400 | 请求参数错误 | 当前没有活动的规则 |
| 404 | 资源不存在 | 规则或样本未找到 |
| 500 | 服务器错误 | YARA扫描失败 |

### 错误响应格式

```json
{
  "detail": "错误消息说明"
}
```

## 请求限制

- 单文件最大: 100MB
- 同时扫描数: 4个
- 扫描超时: 300秒

## 数据结构

### Rule对象

```typescript
interface Rule {
  id: number;
  name: string;
  description: string;
  active: boolean;
  path: string;
  created_at: string;
  updated_at: string;
}
```

### Scan对象

```typescript
interface Scan {
  id: number;
  filename: string;
  file_hash: string;
  status: "pending" | "processing" | "done" | "error";
  is_malicious: boolean;
  threat_level: "clean" | "suspicious" | "malicious";
  match_count: number;
  scanned_rules: number;
  started_at: string;
  finished_at: string;
  matches: Match[];
}
```

### Match对象

```typescript
interface Match {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, any>;
  strings: StringMatch[];
}
```

### StringMatch对象

```typescript
interface StringMatch {
  identifier: string;
  instances: number;
}
```

## 使用示例

### Python

```python
import requests

# 上传文件扫描
with open('sample.exe', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:8000/api/scan/file', files=files)
    print(response.json())
```

### JavaScript/TypeScript

```typescript
// 上传文件扫描
const file = document.getElementById('file').files[0];
const formData = new FormData();
formData.append('file', file);

const response = await fetch('http://localhost:8000/api/scan/file', {
  method: 'POST',
  body: formData
});
const data = await response.json();
console.log(data);
```

### cURL

```bash
# 完整的扫描例子
curl -X POST http://localhost:8000/api/scan/file \
  -F "file=@sample.exe" \
  -H "Accept: application/json"
```

---

**最后更新**: 2025-11-15
**API版本**: v1.0
