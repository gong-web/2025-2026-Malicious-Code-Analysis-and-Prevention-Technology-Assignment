-- 初始化数据库架构
-- SQLite 数据库脚本

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(200),
    is_active BOOLEAN DEFAULT 1,
    is_superuser BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- YARA 规则表
CREATE TABLE IF NOT EXISTS yara_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    content TEXT NOT NULL,
    category VARCHAR(100),
    tags VARCHAR(500),
    severity VARCHAR(20) DEFAULT 'medium',
    status VARCHAR(20) DEFAULT 'active',
    author VARCHAR(100),
    version VARCHAR(50),
    match_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    is_compiled BOOLEAN DEFAULT 0,
    compiled_path VARCHAR(500)
);

-- 扫描任务表
CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(100) UNIQUE NOT NULL,
    target_path VARCHAR(1000) NOT NULL,
    target_type VARCHAR(50),
    scan_type VARCHAR(50),
    use_rules TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    progress REAL DEFAULT 0.0,
    total_files INTEGER DEFAULT 0,
    scanned_files INTEGER DEFAULT 0,
    detected_files INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 扫描结果表
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    file_path VARCHAR(1000) NOT NULL,
    file_name VARCHAR(500),
    file_size INTEGER,
    file_hash VARCHAR(64),
    threat_level VARCHAR(20) DEFAULT 'clean',
    is_malicious BOOLEAN DEFAULT 0,
    matched_rules TEXT,
    match_details TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_rules_name ON yara_rules(name);
CREATE INDEX IF NOT EXISTS idx_rules_category ON yara_rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_status ON yara_rules(status);
CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON scan_tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_results_file_hash ON scan_results(file_hash);
CREATE INDEX IF NOT EXISTS idx_results_task_id ON scan_results(task_id);

-- 插入默认管理员用户 (密码: admin123)
INSERT OR IGNORE INTO users (username, email, hashed_password, full_name, is_superuser)
VALUES ('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqCkZHxXqK', '系统管理员', 1);
