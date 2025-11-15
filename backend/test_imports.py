import sys
import traceback

sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

print('[TEST] 导入FastAPI...')
from fastapi import FastAPI

print('[TEST] 导入config...')
from app.core.config import settings
print(f'  - DEBUG: {settings.DEBUG}')
print(f'  - HOST: {settings.HOST}')
print(f'  - PORT: {settings.PORT}')

print('[TEST] 导入auth...')
try:
    from app.api import auth
    print('  ✅ auth导入成功')
except Exception as e:
    print(f'  ❌ auth导入失败: {e}')
    traceback.print_exc()

print('[TEST] 导入rules...')
try:
    from app.api import rules
    print('  ✅ rules导入成功')
except Exception as e:
    print(f'  ❌ rules导入失败: {e}')
    traceback.print_exc()

print('[TEST] 导入scan...')
try:
    from app.api import scan
    print('  ✅ scan导入成功')
except Exception as e:
    print(f'  ❌ scan导入失败: {e}')
    traceback.print_exc()

print('[TEST] 导入reports...')
try:
    from app.api import reports
    print('  ✅ reports导入成功')
except Exception as e:
    print(f'  ❌ reports导入失败: {e}')
    traceback.print_exc()

print('\n[TEST] 创建FastAPI实例...')
try:
    app = FastAPI(title="Test")
    print('  ✅ FastAPI实例创建成功')
except Exception as e:
    print(f'  ❌ FastAPI实例创建失败: {e}')
    traceback.print_exc()

print('\n[TEST] 完成!')
