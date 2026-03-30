package process

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// ProcessStats 进程流量统计
type ProcessStats struct {
	PID          int32     `json:"pid"`
	Name         string    `json:"name"`
	Exe          string    `json:"exe"`
	Username     string    `json:"username"`
	PacketsSent  int64     `json:"packets_sent"`
	PacketsRecv  int64     `json:"packets_recv"`
	BytesSent    int64     `json:"bytes_sent"`
	BytesRecv    int64     `json:"bytes_recv"`
	Connections  int       `json:"connections"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// ProcessStatsManager 进程统计管理器（性能优化版，按可执行文件路径汇总）
type ProcessStatsManager struct {
	mu    sync.RWMutex
	db    *sql.DB
	stats map[string]*ProcessStats // 按可执行文件路径汇总，key=exe
	
	// 性能优化配置
	flushInterval time.Duration // 批量写入间隔
	batchSize     int           // 批量写入大小
	stopChan      chan struct{}
}

// NewProcessStatsManager 创建进程统计管理器
func NewProcessStatsManager(db *sql.DB) *ProcessStatsManager {
	psm := &ProcessStatsManager{
		db:            db,
		stats:         make(map[string]*ProcessStats),
		flushInterval: 10 * time.Second, // 每10秒批量写入一次
		batchSize:     100,
		stopChan:      make(chan struct{}),
	}
	
	// 初始化数据库表
	if err := psm.initDB(); err != nil {
		fmt.Printf("[ProcessStats] DB init failed: %v\n", err)
	}
	
	// 启动自动刷新
	go psm.autoFlush()
	
	return psm
}

// initDB 初始化数据库表（迁移：删除旧表，重建新表）
func (psm *ProcessStatsManager) initDB() error {
	// 检查数据库连接是否有效
	if psm.db == nil || psm.db.Ping() != nil {
		return fmt.Errorf("database connection is not available")
	}
	
	// 先删除旧表（因为主键从pid改为exe）
	_, err := psm.db.Exec(`DROP TABLE IF EXISTS process_stats`)
	if err != nil {
		return fmt.Errorf("drop old table: %w", err)
	}
	
	// 创建新表（exe作为主键）
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS process_stats (
		exe TEXT PRIMARY KEY,
		pid INTEGER,
		name TEXT NOT NULL,
		username TEXT,
		packets_sent INTEGER DEFAULT 0,
		packets_recv INTEGER DEFAULT 0,
		bytes_sent INTEGER DEFAULT 0,
		bytes_recv INTEGER DEFAULT 0,
		connections INTEGER DEFAULT 0,
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL
	);
	
	CREATE INDEX IF NOT EXISTS idx_process_bytes_sent ON process_stats(bytes_sent DESC);
	CREATE INDEX IF NOT EXISTS idx_process_bytes_recv ON process_stats(bytes_recv DESC);
	CREATE INDEX IF NOT EXISTS idx_process_last_seen ON process_stats(last_seen DESC);
	`
	
	_, err = psm.db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("create table: %w", err)
	}
	
	fmt.Println("[ProcessStats] Table recreated with exe as primary key")
	return nil
}

// RecordPacket 记录数据包（高性能，仅更新内存）
func (psm *ProcessStatsManager) RecordPacket(pid int32, procInfo *ProcessInfo, isSent bool, packetSize int) {
	if pid == 0 || procInfo == nil {
		return
	}
	
	// 使用exe作为key进行汇总
	if procInfo.Exe == "" {
		return
	}
	
	psm.mu.Lock()
	defer psm.mu.Unlock()
	
	exeKey := procInfo.Exe
	stat, exists := psm.stats[exeKey]
	if !exists {
		stat = &ProcessStats{
			PID:       pid,  // 保存遇到的第一个PID
			Name:      procInfo.Name,
			Exe:       procInfo.Exe,
			Username:  procInfo.Username,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		psm.stats[exeKey] = stat
	} else {
		// 更新PID为最近一次遇到的PID
		stat.PID = pid
	}
	
	// 更新统计
	if isSent {
		stat.PacketsSent++
		stat.BytesSent += int64(packetSize)
	} else {
		stat.PacketsRecv++
		stat.BytesRecv += int64(packetSize)
	}
	stat.LastSeen = time.Now()
}

// RecordConnection 记录连接数
func (psm *ProcessStatsManager) RecordConnection(pid int32, procInfo *ProcessInfo) {
	if pid == 0 || procInfo == nil || procInfo.Exe == "" {
		return
	}
	
	psm.mu.Lock()
	defer psm.mu.Unlock()
	
	exeKey := procInfo.Exe
	stat, exists := psm.stats[exeKey]
	if !exists {
		stat = &ProcessStats{
			PID:       pid,
			Name:      procInfo.Name,
			Exe:       procInfo.Exe,
			Username:  procInfo.Username,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		psm.stats[exeKey] = stat
	} else {
		stat.PID = pid
	}
	
	stat.Connections++
	stat.LastSeen = time.Now()
}

// autoFlush 自动批量写入数据库
func (psm *ProcessStatsManager) autoFlush() {
	ticker := time.NewTicker(psm.flushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := psm.FlushToDB(); err != nil {
				fmt.Printf("[ProcessStats] Flush error: %v\n", err)
			}
		case <-psm.stopChan:
			// 最后一次刷新
			psm.FlushToDB()
			return
		}
	}
}

// FlushToDB 批量写入数据库（性能优化：使用事务）
func (psm *ProcessStatsManager) FlushToDB() error {
	psm.mu.RLock()
	if len(psm.stats) == 0 {
		psm.mu.RUnlock()
		return nil
	}
	
	// 复制数据，快速释放锁
	statsCopy := make(map[string]*ProcessStats, len(psm.stats))
	for exeKey, stat := range psm.stats {
		statsCopy[exeKey] = stat
	}
	psm.mu.RUnlock()
	
	// 检查数据库连接是否有效
	if psm.db == nil || psm.db.Ping() != nil {
		// 数据库连接已关闭，清空内存缓存
		psm.mu.Lock()
		psm.stats = make(map[string]*ProcessStats)
		psm.mu.Unlock()
		return nil
	}
	
	// 批量写入（使用事务）
	tx, err := psm.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	
	stmt, err := tx.Prepare(`
		INSERT INTO process_stats 
		(exe, pid, name, username, packets_sent, packets_recv, bytes_sent, bytes_recv, connections, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(exe) DO UPDATE SET
			pid = excluded.pid,
			packets_sent = packets_sent + excluded.packets_sent,
			packets_recv = packets_recv + excluded.packets_recv,
			bytes_sent = bytes_sent + excluded.bytes_sent,
			bytes_recv = bytes_recv + excluded.bytes_recv,
			connections = excluded.connections,
			last_seen = excluded.last_seen
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()
	
	count := 0
	for _, stat := range statsCopy {
		_, err := stmt.Exec(
			stat.Exe,
			stat.PID,
			stat.Name,
			stat.Username,
			stat.PacketsSent,
			stat.PacketsRecv,
			stat.BytesSent,
			stat.BytesRecv,
			stat.Connections,
			stat.FirstSeen.Unix(),
			stat.LastSeen.Unix(),
		)
		if err != nil {
			fmt.Printf("[ProcessStats] Insert error for Exe %s: %v\n", stat.Exe, err)
			continue
		}
		count++
	}
	
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	
	fmt.Printf("[ProcessStats] Flushed %d process stats to DB\n", count)
	
	// 清空内存缓存（已写入DB）
	psm.mu.Lock()
	psm.stats = make(map[string]*ProcessStats)
	psm.mu.Unlock()
	
	return nil
}

// GetTopByTraffic 获取流量排名前N的进程（按exe汇总）
func (psm *ProcessStatsManager) GetTopByTraffic(limit int) ([]ProcessStats, error) {
	// 检查数据库连接是否有效
	if psm.db == nil || psm.db.Ping() != nil {
		return []ProcessStats{}, nil
	}
	
	query := `
		SELECT exe, pid, name, username, 
		       packets_sent, packets_recv, 
		       bytes_sent, bytes_recv, 
		       connections, first_seen, last_seen
		FROM process_stats
		ORDER BY (bytes_sent + bytes_recv) DESC
		LIMIT ?
	`
	
	rows, err := psm.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []ProcessStats
	for rows.Next() {
		var stat ProcessStats
		var firstSeen, lastSeen int64
		
		err := rows.Scan(
			&stat.Exe,
			&stat.PID,
			&stat.Name,
			&stat.Username,
			&stat.PacketsSent,
			&stat.PacketsRecv,
			&stat.BytesSent,
			&stat.BytesRecv,
			&stat.Connections,
			&firstSeen,
			&lastSeen,
		)
		if err != nil {
			continue
		}
		
		stat.FirstSeen = time.Unix(firstSeen, 0)
		stat.LastSeen = time.Unix(lastSeen, 0)
		results = append(results, stat)
	}
	
	return results, nil
}

// GetAllStats 获取所有进程统计
func (psm *ProcessStatsManager) GetAllStats(offset, limit int) ([]ProcessStats, int, error) {
	// 检查数据库连接是否有效
	if psm.db == nil || psm.db.Ping() != nil {
		return []ProcessStats{}, 0, nil
	}
	
	// 获取总数
	var total int
	err := psm.db.QueryRow("SELECT COUNT(*) FROM process_stats").Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	
	// 获取分页数据
	query := `
		SELECT exe, pid, name, username, 
		       packets_sent, packets_recv, 
		       bytes_sent, bytes_recv, 
		       connections, first_seen, last_seen
		FROM process_stats
		ORDER BY last_seen DESC
		LIMIT ? OFFSET ?
	`
	
	rows, err := psm.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var results []ProcessStats
	for rows.Next() {
		var stat ProcessStats
		var firstSeen, lastSeen int64
		
		err := rows.Scan(
			&stat.Exe,
			&stat.PID,
			&stat.Name,
			&stat.Username,
			&stat.PacketsSent,
			&stat.PacketsRecv,
			&stat.BytesSent,
			&stat.BytesRecv,
			&stat.Connections,
			&firstSeen,
			&lastSeen,
		)
		if err != nil {
			continue
		}
		
		stat.FirstSeen = time.Unix(firstSeen, 0)
		stat.LastSeen = time.Unix(lastSeen, 0)
		results = append(results, stat)
	}
	
	return results, total, nil
}

// ClearAll 清空所有统计数据
func (psm *ProcessStatsManager) ClearAll() error {
	psm.mu.Lock()
	psm.stats = make(map[string]*ProcessStats)
	psm.mu.Unlock()
	
	// 检查数据库连接是否有效
	if psm.db == nil {
		return nil
	}
	
	// 尝试ping数据库，如果已关闭则跳过
	if err := psm.db.Ping(); err != nil {
		fmt.Printf("[ProcessStats] Database connection closed, skipping clear: %v\n", err)
		return nil
	}
	
	_, err := psm.db.Exec("DELETE FROM process_stats")
	return err
}

// Stop 停止管理器
func (psm *ProcessStatsManager) Stop() {
	close(psm.stopChan)
}

