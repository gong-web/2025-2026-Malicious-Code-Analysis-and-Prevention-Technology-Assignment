from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
import json
from app.db import get_db
from app.sql_models import Scan, Sample, Rule

router = APIRouter(prefix="/api/reports", tags=["报告"])

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """获取系统统计信息"""
    total_samples = db.query(Sample).count()
    total_scans = db.query(Scan).count()
    total_rules = db.query(Rule).count()
    active_rules = db.query(Rule).filter(Rule.active == True).count()
    
    # 统计恶意和干净的扫描
    malicious_count = db.query(Scan).filter(Scan.is_malicious == True).count()
    clean_count = db.query(Scan).filter(Scan.is_malicious == False).count()
    
    return {
        "total_samples": total_samples,
        "total_scans": total_scans,
        "total_rules": total_rules,
        "active_rules": active_rules,
        "malicious_count": malicious_count,
        "clean_count": clean_count
    }

@router.get("/recent")
def get_recent_scans(limit: int = 10, db: Session = Depends(get_db)):
    """获取最近的扫描记录"""
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
    
    results = []
    for scan in scans:
        # 解析result字段获取匹配结果
        matches = []
        if scan.result:
            try:
                result_data = json.loads(scan.result) if isinstance(scan.result, str) else scan.result
                matches = result_data.get('matches', [])
            except:
                pass
        
        is_malicious = len(matches) > 0
        
        results.append({
            "id": scan.id,
            "filename": scan.filename,
            "is_malicious": is_malicious,
            "match_count": len(matches),
            "scan_time": scan.started_at,
            "status": scan.status,
            "matches": matches
        })
    
    return results

@router.get("/{scan_id}")
def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """获取扫描报告详情"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "扫描记录不存在")
    
    # 解析result字段获取样本信息和匹配结果
    matches = []
    sample_hash = ""
    scanned_rules = 0
    
    if scan.result:
        try:
            result_data = json.loads(scan.result) if isinstance(scan.result, str) else scan.result
            matches = result_data.get('matches', [])
            sample_hash = result_data.get('hash', '')
            scanned_rules = result_data.get('scanned_with', 0)
        except Exception as e:
            print(f"解析result失败: {e}")
    
    # 判断是否恶意
    is_malicious = len(matches) > 0
    
    # 获取使用的规则数量
    total_rules = db.query(Rule).filter(Rule.active == True).count()
    
    return {
        "id": scan.id,
        "filename": scan.filename,
        "sample_hash": sample_hash,
        "scan_time": scan.started_at,
        "is_malicious": is_malicious,
        "total_rules": total_rules,
        "scanned_rules": scanned_rules,
        "match_count": len(matches),
        "matches": matches,
        "status": scan.status
    }

@router.get("/{scan_id}/html")
def get_html_report(scan_id: int, db: Session = Depends(get_db)):
    """生成HTML格式的扫描报告"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "扫描记录不存在")
    
    sample = db.query(Sample).filter(Sample.id == scan.sample_id).first()
    if not sample:
        raise HTTPException(404, "样本文件不存在")
    
    # 解析匹配结果
    matches = []
    if scan.matches:
        try:
            matches_data = json.loads(scan.matches) if isinstance(scan.matches, str) else scan.matches
            if isinstance(matches_data, list):
                matches = matches_data
        except:
            pass
    
    total_rules = db.query(Rule).filter(Rule.active == True).count()
    
    # 生成HTML报告
    html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YARA扫描报告 - {sample.filename}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .status {{
            font-size: 1.2em;
            padding: 10px 20px;
            background: rgba(255,255,255,0.2);
            border-radius: 25px;
            display: inline-block;
            margin-top: 10px;
        }}
        .content {{ padding: 30px; }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .info-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .info-value {{
            font-size: 1.1em;
            color: #333;
            word-break: break-all;
        }}
        .match-card {{
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #ff4d4f;
        }}
        .match-card h3 {{
            color: #ff4d4f;
            margin-bottom: 10px;
        }}
        .match-meta {{
            background: #fff7e6;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .match-strings {{
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .safe-badge {{
            color: #52c41a;
            font-weight: bold;
            font-size: 1.5em;
        }}
        .danger-badge {{
            color: #ff4d4f;
            font-weight: bold;
            font-size: 1.5em;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 2px solid #e0e0e0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ YARA-X 扫描报告</h1>
            <div class="status">
                {'<span class="danger-badge">⚠️ 检测到威胁</span>' if scan.is_malicious else '<span class="safe-badge">✅ 未发现威胁</span>'}
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📋 扫描信息</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">文件名</div>
                        <div class="info-value">{sample.filename}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">SHA256哈希值</div>
                        <div class="info-value">{sample.sha256}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">扫描状态</div>
                        <div class="info-value">{'⚠️ 检测到威胁' if scan.is_malicious else '✅ 未发现威胁'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">扫描规则数</div>
                        <div class="info-value">{total_rules} 条YARA规则</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">匹配规则数</div>
                        <div class="info-value">{len(matches)} 条</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">扫描时间</div>
                        <div class="info-value">{scan.scan_time.strftime('%Y-%m-%d %H:%M:%S') if scan.scan_time else '未知'}</div>
                    </div>
                </div>
            </div>
            
            {'<div class="section"><h2>🔍 检测结果详情</h2>' if matches else '<div class="section"><h2>✅ 检测结果</h2><p style="color: #52c41a; font-size: 1.2em;">该文件未匹配任何YARA规则，未发现已知威胁特征。</p></div>'}
            {''.join([f'''
                <div class="match-card">
                    <h3>🚨 {match.get('rule', '未知规则')}</h3>
                    {f'<div class="match-meta"><strong>命名空间:</strong> {match.get("namespace", "default")}</div>' if match.get('namespace') else ''}
                    {f'<div class="match-meta"><strong>标签:</strong> {", ".join(match.get("tags", []))}</div>' if match.get('tags') else ''}
                    {f'<div class="match-meta"><h4>元数据:</h4><pre>{json.dumps(match.get("meta", {}), indent=2, ensure_ascii=False)}</pre></div>' if match.get('meta') else ''}
                    {f'<div class="match-strings"><h4>匹配字符串:</h4><pre>{json.dumps(match.get("strings", []), indent=2, ensure_ascii=False)}</pre></div>' if match.get('strings') else ''}
                </div>
            ''' for match in matches]) if matches else ''}
            </div>
        </div>
        
        <div class="footer">
            <p>YARA-X Manager v1.0 | 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>© 2025 恶意代码检测系统</p>
        </div>
    </div>
</body>
</html>
    """
    
    return HTMLResponse(content=html_content)
