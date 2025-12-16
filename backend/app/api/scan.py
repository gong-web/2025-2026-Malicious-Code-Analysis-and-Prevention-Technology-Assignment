"""
扫描任务 API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db, SessionLocal
from app.models.scan import ScanTask, ScanResult, ScanStatus, ThreatLevel
from app.models.rule import YaraRule
from app.core.whitelist import whitelist_manager
from pydantic import BaseModel
import uuid
import yara
import hashlib
import os
from datetime import datetime
import traceback
import concurrent.futures
import threading
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# 全局缓存编译后的规则
_compiled_rules_cache = None
_rules_cache_timestamp = None
COMPILED_RULES_PATH = "compiled_rules.yarc"



# Pydantic 模型
class ScanCreate(BaseModel):
    target_path: str
    scan_type: str = "full"
    rule_ids: Optional[List[int]] = None


class ScanResponse(BaseModel):
    id: int
    task_id: str
    target_path: str
    scan_type: Optional[str] = "static"
    status: ScanStatus
    progress: float
    total_files: int
    scanned_files: int
    detected_files: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanResultResponse(BaseModel):
    id: int
    file_path: str
    file_name: str
    file_hash: Optional[str]
    threat_level: ThreatLevel
    is_malicious: bool
    matched_rules: Optional[str]
    
    class Config:
        from_attributes = True


def get_compiled_rules(db: Session, force_reload: bool = False):
    """获取编译后的规则（带缓存和持久化）"""
    global _compiled_rules_cache, _rules_cache_timestamp
    
    current_time = datetime.now()
    
    # 1. 内存缓存检查
    if not force_reload and _compiled_rules_cache and _rules_cache_timestamp:
        cache_age = (current_time - _rules_cache_timestamp).total_seconds()
        if cache_age < 300:  # 5分钟缓存
            return _compiled_rules_cache

    # 2. 磁盘缓存检查 (如果内存中没有或强制刷新)
    if not force_reload and os.path.exists(COMPILED_RULES_PATH):
        try:
            # 尝试加载预编译的规则文件
            logger.info(f"Loading compiled rules from {COMPILED_RULES_PATH}...")
            compiled_rules = yara.load(COMPILED_RULES_PATH)
            _compiled_rules_cache = compiled_rules
            _rules_cache_timestamp = current_time
            return compiled_rules
        except Exception as e:
            logger.error(f"Failed to load compiled rules: {e}")
            # 加载失败则继续执行编译逻辑
    
    # 3. 从数据库加载并编译
    logger.info("Compiling rules from database...")
    # 获取所有活动的 YARA 规则
    rules = db.query(YaraRule).limit(10000).all()
    
    if not rules:
        raise HTTPException(status_code=400, detail="没有可用的 YARA 规则")
    
    # 编译规则
    rule_dict = {}
    for rule in rules:
        if rule.content:
            try:
                rule_dict[rule.name] = rule.content
            except Exception:
                continue
    
    if not rule_dict:
        raise HTTPException(status_code=500, detail="所有规则编译失败")
    
    try:
        externals = {
            'filepath': '',
            'filename': '',
            'extension': '',
            'filetype': ''
        }
        compiled_rules = yara.compile(sources=rule_dict, externals=externals)
        
        # 4. 保存到磁盘
        try:
            compiled_rules.save(COMPILED_RULES_PATH)
            logger.info(f"Saved compiled rules to {COMPILED_RULES_PATH}")
        except Exception as e:
            logger.warning(f"Failed to save compiled rules: {e}")

        _compiled_rules_cache = compiled_rules
        _rules_cache_timestamp = current_time
        return compiled_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"规则编译失败: {str(e)}")


def run_scan_task(task_id: str):
    """后台执行扫描任务"""
    logger.info(f"Starting background scan task: {task_id}")
    db = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
        if not task:
            logger.error(f"Task {task_id} not found in background worker")
            return

        task.status = ScanStatus.RUNNING
        task.started_at = datetime.now()
        db.commit()

        try:
            compiled_rules = get_compiled_rules(db)
        except Exception as e:
            logger.error(f"Failed to load rules for task {task_id}: {e}")
            task.status = ScanStatus.FAILED
            db.commit()
            return

        target_path = task.target_path
        
        # 收集所有文件路径
        file_paths = []
        if os.path.isfile(target_path):
            file_paths.append(target_path)
        else:
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_paths.append(os.path.join(root, file))
        
        total_files = len(file_paths)
        task.total_files = total_files
        db.commit()

        scanned_count = 0
        detected_count = 0
        # Batch storage for results to reduce DB lock contention
        results_buffer = []
        BATCH_SIZE = 100
        db_lock = threading.Lock()
        
        # 扫描处理函数
        def process_file(file_path):
            nonlocal scanned_count, detected_count
            try:
                filename = os.path.basename(file_path)
                extension = os.path.splitext(filename)[1]
                
                # Calculate hash first for whitelist check (optimization: skip scanning if whitelisted)
                file_hash = None
                file_size = 0
                try:
                    file_size = os.path.getsize(file_path)
                    with open(file_path, "rb") as f:
                        # Read in chunks for hash
                        sha256_hash = hashlib.sha256()
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                        file_hash = sha256_hash.hexdigest()
                except:
                    file_hash = "unknown"
                
                # 白名单检查 - 如果在白名单中，跳过扫描
                if file_hash and whitelist_manager.is_whitelisted(file_hash):
                    matches = []
                    is_malicious = False
                else:
                    # Use YARA's internal file handling for memory efficiency
                    # timeout=60 prevents hanging on massive files
                    try:
                        matches = compiled_rules.match(
                            filepath=file_path, 
                            timeout=60,
                            externals={
                                'filepath': file_path,
                                'filename': filename,
                                'extension': extension,
                                'filetype': ''
                            }
                        )
                    except yara.Error:
                        # Fallback for permission errors or special files: try reading content
                        # But limit size to avoid OOM
                        try:
                            if file_size == 0:
                                file_size = os.path.getsize(file_path)
                            if file_size > 100 * 1024 * 1024: # Skip > 100MB if direct match fails
                                return
                            with open(file_path, "rb") as f:
                                content = f.read()
                                matches = compiled_rules.match(
                                    data=content, 
                                    timeout=60,
                                    externals={
                                        'filepath': file_path,
                                        'filename': filename,
                                        'extension': extension,
                                        'filetype': ''
                                    }
                                )
                        except Exception:
                            return
                    
                    is_malicious = len(matches) > 0
                
                # Only record malicious files or if specifically requested (to save DB space)
                # Recording every clean file in a full system scan is wasteful
                # But current logic requires counting them. We will count all, but store malicious detail.
                
                if is_malicious:
                    threat_level = ThreatLevel.MALICIOUS
                    matched_rule_names = [m.rule for m in matches]

                    result = ScanResult(
                        task_id=task.id,
                        file_path=file_path,
                        file_name=filename,
                        file_size=file_size,
                        file_hash=file_hash or "unknown",
                        threat_level=threat_level,
                        is_malicious=is_malicious,
                        matched_rules=str(matched_rule_names)
                    )
                    
                    with db_lock:
                        results_buffer.append(result)
                        detected_count += 1
                
                with db_lock:
                    scanned_count += 1
                    
                    # Flush buffer if full
                    if len(results_buffer) >= BATCH_SIZE:
                        db.bulk_save_objects(results_buffer)
                        db.commit()
                        results_buffer.clear()
                        
                        # Update task progress
                        task.scanned_files = scanned_count
                        task.detected_files = detected_count
                        task.progress = (scanned_count / total_files) * 100 if total_files > 0 else 0
                        db.commit()
                    
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

        # 使用线程池并行扫描
        # max_workers 可以根据 CPU 核心数调整，通常 CPU 核心数 * 2 或 * 4
        max_workers = min(32, (os.cpu_count() or 1) * 4)
        logger.info(f"Scanning with {max_workers} threads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(process_file, file_paths))
        
        # Final flush of results
        if results_buffer:
            db.bulk_save_objects(results_buffer)
            db.commit()
        
        # 完成任务
        task.status = ScanStatus.COMPLETED
        task.completed_at = datetime.now()
        task.scanned_files = scanned_count
        task.detected_files = detected_count
        task.progress = 100.0
        db.commit()
        logger.info(f"Task {task_id} completed successfully")

    except Exception as e:
        logger.error(f"Task {task_id} failed: {e}")
        traceback.print_exc() # Keep this for debug in stderr, or use logger.exception
        try:
            task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
            if task:
                task.status = ScanStatus.FAILED
                db.commit()
        except Exception as db_error:
            logger.error(f"Failed to update task status: {db_error}")
    finally:
        db.close()


@router.post("/", response_model=ScanResponse)
async def create_scan_task(
    scan: ScanCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """创建扫描任务"""
    
    # 验证目标路径
    if not os.path.exists(scan.target_path):
        raise HTTPException(status_code=400, detail="目标路径不存在")
    
    # 生成任务 ID
    task_id = str(uuid.uuid4())
    
    # 确定目标类型
    target_type = "directory" if os.path.isdir(scan.target_path) else "file"
    
    # 创建任务
    db_task = ScanTask(
        task_id=task_id,
        target_path=scan.target_path,
        target_type=target_type,
        scan_type=scan.scan_type,
        use_rules=str(scan.rule_ids) if scan.rule_ids else None,
        status=ScanStatus.PENDING
    )
    
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    
    # 启动后台任务
    background_tasks.add_task(run_scan_task, task_id)
    
    return db_task


@router.get("/", response_model=List[ScanResponse])
async def list_scan_tasks(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    db: Session = Depends(get_db)
):
    """获取扫描任务列表"""
    query = db.query(ScanTask)
    
    if status:
        query = query.filter(ScanTask.status == status)
    
    tasks = query.order_by(ScanTask.created_at.desc()).offset(skip).limit(limit).all()
    return tasks


@router.get("/{task_id}", response_model=ScanResponse)
async def get_scan_task(task_id: str, db: Session = Depends(get_db)):
    """获取扫描任务详情"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    return task


@router.get("/{task_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(task_id: str, db: Session = Depends(get_db)):
    """获取扫描结果"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    results = db.query(ScanResult).filter(ScanResult.task_id == task.id).all()
    return results


@router.post("/file")
def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """扫描上传的文件"""
    
    try:
        # 读取文件内容 - 注意：这仍然在内存中，但 UploadFile 通常会溢出到磁盘临时文件
        # 为了安全，我们限制读取大小或建议使用流式处理，但这里简单起见，我们读取
        # 如果文件很大，UploadFile.file 是一个 SpooledTemporaryFile
        
        content = file.file.read()
        
        # 计算文件哈希
        file_hash = hashlib.sha256(content).hexdigest()
        
        # 获取编译后的规则（使用缓存）
        compiled_rules = get_compiled_rules(db)
        
        # 白名单检查
        if whitelist_manager.is_whitelisted(file_hash):
            matches = []
        else:
            # 扫描文件
            filename = file.filename or "unknown"
            extension = os.path.splitext(filename)[1]
            matches = compiled_rules.match(
                data=content,
                externals={
                    'filepath': file.filename or '',
                    'filename': filename,
                    'extension': extension,
                    'filetype': ''
                }
            )
        
        # 判断威胁级别
        threat_level = ThreatLevel.CLEAN
        is_malicious = len(matches) > 0
        
        if is_malicious:
            threat_level = ThreatLevel.MALICIOUS
        # 生成任务
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=file.filename,
            target_type="file",
            scan_type="static",
            status=ScanStatus.COMPLETED,
            progress=100.0,
            total_files=1,
            scanned_files=1,
            detected_files=1 if is_malicious else 0,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        # 保存结果
        matched_rule_names = []
        try:
            # Ensure matches is iterable
            if matches is None:
                matches = []
            
            # Safely extract rule names
            for m in matches:
                if hasattr(m, 'rule'):
                    matched_rule_names.append(m.rule)
                else:
                    matched_rule_names.append("Unknown Rule")
        except Exception as e:
            logger.error(f"Error extracting rule names: {e}")
            matched_rule_names = ["Error Extracting Rules"]

        # 获取匹配详情 (Tags, Strings)
        match_details = []
        try:
            for m in matches:
                strings_info = []
                try:
                    # Check if m.strings exists
                    if hasattr(m, 'strings'):
                        # Convert to list safely
                        strings_list = []
                        try:
                            strings_list = list(m.strings)
                        except TypeError:
                            # If not iterable, maybe it's a single object? Unlikely for 'strings'
                            pass
                        
                        for s in strings_list[:5]:  # Limit to first 5 strings
                            try:
                                # Modern YARA (4.x) - StringMatch object
                                if hasattr(s, 'instances'):
                                    for instance in s.instances[:1]:
                                        data = instance.matched_data
                                        if isinstance(data, bytes):
                                            data = data.decode('utf-8', errors='ignore')
                                        strings_info.append((
                                            instance.offset,
                                            s.identifier,
                                            str(data)[:100]
                                        ))
                                # Legacy YARA - Tuple (offset, identifier, data)
                                elif isinstance(s, tuple) and len(s) >= 3:
                                    data = s[2]
                                    if isinstance(data, bytes):
                                        data = data.decode('utf-8', errors='ignore')
                                    strings_info.append((s[0], s[1], str(data)[:100]))
                                # Fallback
                                else:
                                    strings_info.append((0, str(s), str(s)[:100]))
                            except Exception as inner_e:
                                strings_info.append((0, "error", f"Item error: {str(inner_e)}"))
                except Exception as e:
                    logger.error(f"Error processing strings for rule: {e}")
                    strings_info.append((0, "error", f"String processing error: {str(e)}"))
                
                match_details.append({
                    "rule": getattr(m, 'rule', 'unknown'),
                    "tags": getattr(m, 'tags', []),
                    "meta": getattr(m, 'meta', {}),
                    "strings": strings_info
                })
        except Exception as e:
            logger.error(f"Error processing match details: {e}")

        result = ScanResult(
            task_id=db_task.id,
            file_path=file.filename,
            file_name=file.filename,
            file_size=len(content),
            file_hash=file_hash,
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names) # Keep simple string for DB column
        )
        db.add(result)
        db.commit()
        
        return {
            "task_id": task_id,
            "file_name": file.filename,
            "file_hash": file_hash,
            "is_malicious": is_malicious,
            "threat_level": threat_level,
            "matched_rules": matched_rule_names,
            "details": match_details # Return full details in API response
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"扫描失败: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)


@router.delete("/{task_id}")
async def delete_scan_task(task_id: str, db: Session = Depends(get_db)):
    """删除扫描任务"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    db.delete(task)
    db.commit()
    
    return {"message": "任务已删除"}
