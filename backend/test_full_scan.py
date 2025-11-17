import sys
import asyncio
import traceback
sys.path.insert(0, 'D:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend')

async def test_scan():
    try:
        from fastapi import UploadFile
        from app.core.database import get_db
        from app.api.scan import scan_file
        from io import BytesIO
        
        # 读取测试文件
        test_file_path = "d:/gds/Documents/Malicious_Code_Analysis/yara-x-manager/backend/data/samples/58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47_Lab01-01.exe"
        
        print('[TEST] 读取测试文件...')
        with open(test_file_path, 'rb') as f:
            file_content = f.read()
        print(f'[TEST] 文件大小: {len(file_content)} bytes')
        
        # 创建UploadFile对象
        print('[TEST] 创建UploadFile对象...')
        file_obj = UploadFile(
            filename="Lab01-01.exe",
            file=BytesIO(file_content)
        )
        
        # 获取数据库会话
        print('[TEST] 获取数据库会话...')
        db = next(get_db())
        
        # 调用scan_file
        print('[TEST] 调用scan_file函数...')
        result = await scan_file(file=file_obj, db=db)
        
        print('\n[✅ SUCCESS] 扫描成功!')
        print(f'Scan ID: {result["scan_id"]}')
        print(f'File Hash: {result["file_hash"]}')
        print(f'Is Malicious: {result["is_malicious"]}')
        print(f'Match Count: {result["match_count"]}')
        print(f'Scanned Rules: {result["scanned_rules"]}')
        
        if result["matches"]:
            print('\n匹配规则:')
            for match in result["matches"]:
                print(f'  - {match["rule"]}')
        
    except Exception as e:
        print(f'\n[❌ ERROR] {type(e).__name__}: {e}')
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_scan())
