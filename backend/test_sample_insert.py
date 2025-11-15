import sys
import traceback
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

try:
    from app.core.database import get_db
    from app.api.models_shared import Sample
    
    db = next(get_db())
    
    # 模拟scan.py中的Sample插入逻辑
    test_filename = "Lab01-01.exe"
    test_path = "data/samples/test_hash_Lab01-01.exe"
    
    print(f'[TEST] 检查是否存在: {test_filename}')
    existing = db.query(Sample).filter(Sample.filename == test_filename).first()
    
    if existing:
        print(f'[TEST] 样本已存在: ID={existing.id}, filename={existing.filename}')
    else:
        print('[TEST] 样本不存在，尝试插入...')
        new_sample = Sample(
            filename=test_filename,
            path=test_path
        )
        db.add(new_sample)
        
        try:
            db.commit()
            print(f'[TEST] ✅ 插入成功! ID={new_sample.id}')
        except Exception as e:
            print(f'[TEST] ❌ 插入失败: {type(e).__name__}: {e}')
            traceback.print_exc()
            db.rollback()
    
    # 检查Sample表结构
    print('\n[TEST] Sample表列:')
    from sqlalchemy import inspect
    inspector = inspect(db.bind)
    columns = inspector.get_columns('samples')
    for col in columns:
        print(f'  {col["name"]}: {col["type"]} (nullable={col.get("nullable", True)})')
    
except Exception as e:
    print(f'\n[ERROR] {type(e).__name__}: {e}')
    traceback.print_exc()
