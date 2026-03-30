#!/usr/bin/env python3
"""
从 report.csv 生成 sniffer.db 数据库文件
"""

import sqlite3
import csv
from datetime import datetime
import sys
import os
from pathlib import Path

def create_database(db_path):
    """创建数据库和所有表结构"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 创建 dns_sessions 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dns_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        domain TEXT,
        query_type TEXT,
        response_ip TEXT,
        payload_size INTEGER,。、
        ttl DATETIME NOT NULL,
        process_pid INTEGER,
        process_name TEXT,
        process_exe TEXT
    )
    ''')
    
    # 创建 http_sessions 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS http_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        method TEXT,
        host TEXT,
        path TEXT,
        status_code INTEGER,
        user_agent TEXT,
        content_type TEXT,
        post_data TEXT,
        payload_size INTEGER,
        ttl DATETIME NOT NULL,
        process_pid INTEGER,
        process_name TEXT,
        process_exe TEXT
    )
    ''')
    
    # 创建 icmp_sessions 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS icmp_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        protocol TEXT,
        icmp_type INTEGER,
        icmp_code INTEGER,
        icmp_seq INTEGER,
        payload_size INTEGER,
        ttl DATETIME NOT NULL,
        process_pid INTEGER,
        process_name TEXT,
        process_exe TEXT
    )
    ''')
    
    # 创建 session_flows 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS session_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT NOT NULL,
        packet_count INTEGER DEFAULT 1,
        bytes_count INTEGER DEFAULT 0,
        first_seen DATETIME NOT NULL,
        last_seen DATETIME NOT NULL,
        session_type TEXT,
        process_pid INTEGER,
        process_name TEXT,
        process_exe TEXT,
        UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
    )
    ''')
    
    # 创建 alert_rules 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        condition_field TEXT NOT NULL,
        condition_operator TEXT NOT NULL,
        condition_value TEXT NOT NULL,
        alert_level TEXT DEFAULT 'warning',
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建 alert_logs 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER NOT NULL,
        rule_name TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        alert_level TEXT NOT NULL,
        triggered_at DATETIME NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        domain TEXT,
        url TEXT,
        details TEXT,
        acknowledged INTEGER DEFAULT 0,
        acknowledged_at DATETIME,
        acknowledged_by TEXT,
        trigger_count INTEGER DEFAULT 1,
        last_triggered_at DATETIME,
        FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
    )
    ''')
    
    # 创建 process_stats 表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS process_stats (
        name TEXT NOT NULL,
        username TEXT,
        packets_sent INTEGER DEFAULT 0,
        packets_recv INTEGER DEFAULT 0,
        bytes_sent INTEGER DEFAULT 0,
        bytes_recv INTEGER DEFAULT 0,
        connections INTEGER DEFAULT 0,
        first_seen TIMESTAMP NOT NULL,
        last_seen TIMESTAMP NOT NULL,
        UNIQUE(name, username)
    )
    ''')
    
    # 创建索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_sessions(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_ttl ON dns_sessions(ttl)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_sessions(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_sessions(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_http_ttl ON http_sessions(ttl)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_http_host ON http_sessions(host)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_icmp_timestamp ON icmp_sessions(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_icmp_ttl ON icmp_sessions(ttl)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_first_seen ON session_flows(first_seen)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON session_flows(last_seen)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_protocol ON session_flows(protocol)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flows_process ON session_flows(process_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_rules_type ON alert_rules(rule_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_logs_triggered_at ON alert_logs(triggered_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_logs_rule_id ON alert_logs(rule_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_logs_acknowledged ON alert_logs(acknowledged)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_logs_level ON alert_logs(alert_level)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_bytes_sent ON process_stats(bytes_sent DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_bytes_recv ON process_stats(bytes_recv DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_last_seen ON process_stats(last_seen DESC)')
    
    conn.commit()
    return conn

def parse_timestamp(ts_str):
    """解析时间戳字符串"""
    if not ts_str or ts_str.strip() == '':
        return None
    
    try:
        # 尝试解析格式：2020-06-04 16:33:35
        dt = datetime.strptime(ts_str.strip(), '%Y-%m-%d %H:%M:%S')
        return int(dt.timestamp())
    except ValueError:
        try:
            # 尝试解析其他可能的格式
            dt = datetime.fromisoformat(ts_str.strip())
            return int(dt.timestamp())
        except:
            return None

def import_csv_data(conn, csv_path):
    """从 CSV 文件导入数据到 process_stats 表（增量更新）"""
    cursor = conn.cursor()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        count = 0
        for row in reader:
            # 跳过空行
            if not row.get('app_name'):
                continue
            
            name = row['app_name']
            username = row['UserName']
            packets_sent = int(row['packets_sent']) if row['packets_sent'] else 0
            packets_recv = int(row['packets_recv']) if row['packets_recv'] else 0
            bytes_sent = int(row['bytes_sent']) if row['bytes_sent'] else 0
            bytes_recv = int(row['bytes_recv']) if row['bytes_recv'] else 0
            connections = int(row['connections']) if row['connections'] else 0
            first_seen = parse_timestamp(row['first_seen'])
            last_seen = parse_timestamp(row['last_seen'])
            
            if first_seen is None or last_seen is None:
                print(f"警告: 跳过无效时间戳的记录: {name}", file=sys.stderr)
                continue
            
            # 使用 UPSERT：如果进程已存在（name + username），则累加统计数据
            cursor.execute('''
                INSERT INTO process_stats 
                (name, username, packets_sent, packets_recv, bytes_sent, bytes_recv, connections, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, username) DO UPDATE SET
                    packets_sent = packets_sent + excluded.packets_sent,
                    packets_recv = packets_recv + excluded.packets_recv,
                    bytes_sent = bytes_sent + excluded.bytes_sent,
                    bytes_recv = bytes_recv + excluded.bytes_recv,
                    connections = connections + excluded.connections,
                    last_seen = MAX(last_seen, excluded.last_seen),
                    first_seen = MIN(first_seen, excluded.first_seen)
            ''', (name, username, packets_sent, packets_recv, bytes_sent, bytes_recv, connections, first_seen, last_seen))
            
            count += 1
        
        conn.commit()
        print(f"成功处理 {count} 条记录到 process_stats 表（增量更新）", file=sys.stderr)
        return count

def main():
    script_dir = Path(__file__).parent
    output_dir = Path(os.environ.get("SNIF_PROCESS_OUTPUT_DIR", str(script_dir / "output")))
    csv_path = output_dir / "report.csv"
    db_path = output_dir / "sniffer.db"
    
    # 检查 CSV 文件是否存在
    if not csv_path.exists():
        print(f"错误: 找不到 CSV 文件 {csv_path}", file=sys.stderr)
        sys.exit(1)
    
    # 检查数据库是否已存在
    if db_path.exists():
        print(f"数据库已存在，将增量更新: {db_path}", file=sys.stderr)
        print(f"保留所有已有数据，process_stats 表将使用 UPSERT 累加", file=sys.stderr)
    else:
        print(f"创建新数据库: {db_path}", file=sys.stderr)
    
    # 创建或打开数据库（如果表不存在则创建）
    conn = create_database(db_path)
    
    print(f"从 {csv_path} 导入数据到 process_stats 表（增量模式）...", file=sys.stderr)
    count = import_csv_data(conn, csv_path)
    
    # 显示其他表的记录数
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM dns_sessions')
    dns_count = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM session_flows')
    flow_count = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM process_stats')
    process_count = cursor.fetchone()[0]
    
    conn.close()
    
    print(f"\n完成！", file=sys.stderr)
    print(f"数据库文件: {db_path}", file=sys.stderr)
    print(f"最终统计:", file=sys.stderr)
    print(f"  - dns_sessions: {dns_count} 条", file=sys.stderr)
    print(f"  - session_flows: {flow_count} 条", file=sys.stderr)
    print(f"  - process_stats: {process_count} 条", file=sys.stderr)

if __name__ == "__main__":
    main()

