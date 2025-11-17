import sys
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

try:
    print('[IMPORT] 导入scan模块...')
    from app.api import scan
    print('[IMPORT] ✅ 导入成功')
    
    print('\n[CHECK] 检查scan_file函数...')
    print(f'函数存在: {hasattr(scan, "scan_file")}')
    
except Exception as e:
    import traceback
    print(f'\n[ERROR] {type(e).__name__}: {e}')
    traceback.print_exc()
