"""
最小化测试 - 绕过FastAPI启动,直接测试scan逻辑
"""
import sys
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

import asyncio
from io import BytesIO
from fastapi import UploadFile

async def main():
    try:
        # 导入scan函数
        print('[1] 导入scan模块...')
        from app.api.scan import scan_file
        from app.core.database import get_db
        
        # 读取测试文件
        print('[2] 读取测试文件...')
        test_file = "d:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend/data/samples/58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47_Lab01-01.exe"
        with open(test_file, 'rb') as f:
            content = f.read()
        
        print(f'[3] 文件大小: {len(content)} bytes')
        
        # 创建UploadFile
        print('[4] 创建UploadFile对象...')
        upload_file = UploadFile(
            filename="Test.exe",
            file=BytesIO(content)
        )
        
        # 获取数据库会话
        print('[5] 获取数据库会话...')
        db = next(get_db())
        
        # 调用scan_file
        print('[6] 调用scan_file...')
        result = await scan_file(file=upload_file, db=db)
        
        print('\n[✅ 扫描成功!]')
        print(f'Scan ID: {result["scan_id"]}')
        print(f'Is Malicious: {result["is_malicious"]}')
        print(f'Match Count: {result["match_count"]}')
        print(f'Scanned Rules: {result["scanned_rules"]}')
        
        return result
        
    except Exception as e:
        print(f'\n[❌ 错误] {type(e).__name__}: {e}')
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = asyncio.run(main())
    if result:
        print(f'\n[FINAL] 扫描完成，Scan ID = {result["scan_id"]}')
    else:
        print('\n[FINAL] 扫描失败')
