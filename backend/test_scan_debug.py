import sys
import traceback
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

try:
    print('[TEST] 导入模块...')
    from app.core.database import get_db
    from app.api.models_shared import Rule
    
    print('[TEST] 获取数据库会话...')
    db = next(get_db())
    
    print('[TEST] 查询活动规则...')
    rules = db.query(Rule).filter(Rule.active == True).all()
    print(f'[TEST] 找到 {len(rules)} 条活动规则')
    
    if len(rules) > 0:
        rule = rules[0]
        print(f'[TEST] 第一条规则: ID={rule.id}, Name={rule.name}')
        print(f'[TEST] 路径: {rule.path}')
        
        import os
        exists = os.path.exists(rule.path)
        print(f'[TEST] 文件存在: {exists}')
        
        if exists:
            print('[TEST] 读取规则文件...')
            with open(rule.path, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f'[TEST] 规则内容长度: {len(content)} 字符')
                print(f'[TEST] 前200字符:\n{content[:200]}')
            
            print('\n[TEST] 编译单个规则...')
            import yara
            try:
                compiled = yara.compile(source=content)
                print('[TEST] 单个规则编译成功!')
            except Exception as e:
                print(f'[TEST ERROR] 单个规则编译失败: {e}')
                traceback.print_exc()
            
            print('\n[TEST] 使用sources字典编译...')
            try:
                compiled = yara.compile(sources={rule.name: content})
                print('[TEST] sources字典编译成功!')
                
                # 测试扫描
                print('\n[TEST] 测试扫描...')
                test_data = b'This is test data'
                matches = compiled.match(data=test_data)
                print(f'[TEST] 扫描完成，匹配数: {len(matches)}')
                
            except Exception as e:
                print(f'[TEST ERROR] sources字典编译失败: {e}')
                traceback.print_exc()
        else:
            print('[TEST ERROR] 规则文件不存在!')
    else:
        print('[TEST] 没有活动规则')
        
except Exception as e:
    print(f'[TEST ERROR] {e}')
    traceback.print_exc()
