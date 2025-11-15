import sys
import traceback
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

try:
    print('[MULTI] 导入模块...')
    from app.core.database import get_db
    from app.api.models_shared import Rule
    import yara
    import os
    
    print('[MULTI] 获取数据库会话...')
    db = next(get_db())
    
    print('[MULTI] 查询所有活动规则...')
    rules = db.query(Rule).filter(Rule.active == True).all()
    print(f'[MULTI] 找到 {len(rules)} 条活动规则\n')
    
    # 读取所有规则文件
    sources = {}
    failed_rules = []
    
    for rule in rules:
        print(f'[MULTI] 处理规则: {rule.name}')
        print(f'  路径: {rule.path}')
        
        if not os.path.exists(rule.path):
            print(f'  [错误] 文件不存在!')
            failed_rules.append(f'{rule.name}: 文件不存在')
            continue
        
        try:
            with open(rule.path, 'r', encoding='utf-8') as f:
                content = f.read()
                sources[rule.name] = content
                print(f'  [OK] 读取成功 ({len(content)} 字符)')
        except Exception as e:
            print(f'  [错误] 读取失败: {e}')
            failed_rules.append(f'{rule.name}: 读取失败 - {e}')
    
    print(f'\n[MULTI] 成功读取 {len(sources)}/{len(rules)} 条规则')
    
    if failed_rules:
        print(f'[MULTI] 失败规则: {failed_rules}')
    
    if sources:
        print('\n[MULTI] 编译所有规则...')
        try:
            compiled = yara.compile(sources=sources)
            print('[MULTI] ✅ 所有规则编译成功!')
            
            # 测试扫描
            print('\n[MULTI] 测试扫描...')
            test_data = b'This is test malware data'
            matches = compiled.match(data=test_data)
            print(f'[MULTI] 扫描完成，匹配数: {len(matches)}')
            
        except yara.SyntaxError as e:
            print(f'\n[MULTI] ❌ YARA语法错误: {e}')
            print('错误详情:')
            print(f'  错误位置: {e}')
            traceback.print_exc()
        except Exception as e:
            print(f'\n[MULTI] ❌ 编译错误: {type(e).__name__}: {e}')
            traceback.print_exc()
    else:
        print('[MULTI] 没有可编译的规则')
        
except Exception as e:
    print(f'\n[MULTI ERROR] {type(e).__name__}: {e}')
    traceback.print_exc()
