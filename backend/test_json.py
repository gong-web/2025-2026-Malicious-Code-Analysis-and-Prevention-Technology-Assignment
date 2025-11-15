import sys
import traceback
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

try:
    print('[JSON] 导入模块...')
    from app.core.database import get_db
    from app.api.models_shared import Rule, Scan
    import yara
    import json
    from datetime import datetime
    
    print('[JSON] 获取数据库会话...')
    db = next(get_db())
    
    print('[JSON] 查询活动规则...')
    rules = db.query(Rule).filter(Rule.active == True).all()
    print(f'[JSON] 找到 {len(rules)} 条活动规则')
    
    # 构建sources
    sources = {}
    for rule in rules:
        try:
            with open(rule.path, 'r', encoding='utf-8') as f:
                sources[rule.name] = f.read()
        except:
            pass
    
    print(f'[JSON] 成功加载 {len(sources)} 条规则')
    
    # 编译和扫描
    compiled = yara.compile(sources=sources)
    test_data = b'This is test malware data'
    matches = compiled.match(data=test_data)
    
    print(f'[JSON] 扫描完成，匹配 {len(matches)} 条规则')
    
    # 构造匹配结果(模拟scan.py的代码)
    match_list = []
    for match in matches:
        print(f'\n[JSON] 处理匹配: {match.rule}')
        print(f'  namespace: {match.namespace}')
        print(f'  tags: {match.tags}')
        print(f'  meta: {match.meta}')
        print(f'  strings: {match.strings}')
        
        match_info = {
            "rule": match.rule,
            "namespace": match.namespace or "",
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
            "strings": [
                {
                    "identifier": s[1],
                    "instances": len(s[2])
                } for s in match.strings
            ]
        }
        match_list.append(match_info)
    
    # 构造result_data(和scan.py完全一致)
    result_data = {
        "is_malicious": len(match_list) > 0,
        "matches": match_list,
        "sample_hash": "test_hash_12345",
        "scanned_rules": len(sources)
    }
    
    print('\n[JSON] 尝试JSON序列化...')
    try:
        json_str = json.dumps(result_data)
        print(f'[JSON] ✅ JSON序列化成功! 长度: {len(json_str)}')
        print(f'[JSON] 前500字符:\n{json_str[:500]}')
        
        # 测试写入数据库
        print('\n[JSON] 测试写入数据库...')
        new_scan = Scan(
            filename="test.exe",
            status="done",
            result=json_str,
            started_at=datetime.now().isoformat(),
            finished_at=datetime.now().isoformat()
        )
        db.add(new_scan)
        db.commit()
        print(f'[JSON] ✅ 数据库写入成功! Scan ID: {new_scan.id}')
        
    except Exception as e:
        print(f'[JSON] ❌ JSON序列化失败: {type(e).__name__}: {e}')
        traceback.print_exc()
        
except Exception as e:
    print(f'\n[JSON ERROR] {type(e).__name__}: {e}')
    traceback.print_exc()
