package server

import (
	"fmt"
	"time"
	"sniffer/internal/process"
	"sniffer/internal/store"
)

// GetProcessStats 获取进程流量统计（分页）
func (a *App) GetProcessStats(page, pageSize int) (*ProcessStatsResult, error) {
	if page < 1 {
		page = 1
	}

	// Throttled debug: confirm which DB mode is used by ApplicationView.
	a.processStatsLogMu.Lock()
	shouldLog := a.processStatsLastLogAt.IsZero() || time.Since(a.processStatsLastLogAt) > 5*time.Second
	if shouldLog {
		mode := "live"
		dbPath := ""
		if a.replayMode {
			mode = "replay"
			dbPath = a.replayDBPath
		}
		fmt.Printf("[GetProcessStats] mode=%s replayDBPath=%s\n", mode, dbPath)
		a.processStatsLastLogAt = time.Now()
	}
	a.processStatsLogMu.Unlock()

	// 允许更大的pageSize以获取所有数据
	maxPageSize := 500 // 正常模式允许500条
	if a.replayMode {
		maxPageSize = 50000 // 重放模式允许获取更多数据
	}
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = 20
	}
	
	offset := (page - 1) * pageSize
	
	// 重放模式：从数据库读取
	if a.replayMode {
		composite, ok := a.store.(*store.CompositeStore)
		if !ok {
			return nil, fmt.Errorf("store is not composite")
		}
		
		sqliteStore := composite.GetDB()
		data, total, err := sqliteStore.QueryProcessStatsFromReplay(offset, pageSize)
		if err != nil {
			return nil, fmt.Errorf("query replay process stats: %w", err)
		}
		
		// 转换为ProcessStats结构
		stats := make([]process.ProcessStats, 0, len(data))
		for _, item := range data {
			m := item.(map[string]interface{})
			stat := process.ProcessStats{
				PID:          m["pid"].(int32),
				Name:         m["name"].(string),
				Exe:          m["exe"].(string),
				Username:     m["username"].(string),
				PacketsSent:  m["packets_sent"].(int64),
				PacketsRecv:  m["packets_recv"].(int64),
				BytesSent:    m["bytes_sent"].(int64),
				BytesRecv:    m["bytes_recv"].(int64),
				Connections:  int(m["connections"].(int64)),
			}
			// 解析时间（可能是string或int64）
			if firstSeen, ok := m["first_seen"].(int64); ok {
				stat.FirstSeen = time.Unix(firstSeen, 0)
			} else if firstSeen, ok := m["first_seen"].(string); ok {
				stat.FirstSeen, _ = parseTimeString(firstSeen)
			}
			if lastSeen, ok := m["last_seen"].(int64); ok {
				stat.LastSeen = time.Unix(lastSeen, 0)
			} else if lastSeen, ok := m["last_seen"].(string); ok {
				stat.LastSeen, _ = parseTimeString(lastSeen)
			}
			stats = append(stats, stat)
		}
		
		return &ProcessStatsResult{
			Data:     stats,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		}, nil
	}
	
	// 正常模式：从内存读取
	stats, total, err := a.capture.GetProcessStats(offset, pageSize)
	if err != nil {
		return nil, fmt.Errorf("get process stats: %w", err)
	}
	
	return &ProcessStatsResult{
		Data:     stats,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// GetAppClassificationStats returns ML application classification results (when available),
// otherwise it falls back to live process stats (OS process name).
func (a *App) GetAppClassificationStats(page, pageSize int) (*ProcessStatsResult, error) {
	if page < 1 {
		page = 1
	}

	// In replay mode, ML results are stored in the replay session DB (same as GetProcessStats),
	// not in appClassStore (which is used by live classification scheduler).
	if a.replayMode {
		return a.GetProcessStats(page, pageSize)
	}

	a.appClassMu.RLock()
	hasClassDB := a.appClassStore != nil
	a.appClassMu.RUnlock()
	if !hasClassDB {
		// No classification results yet: frontend will still show OS process stats.
		// This log helps confirm whether scheduler ever produced a DB.
		fmt.Println("[GetAppClassificationStats] no appClassStore yet; falling back to live process stats")
	}

	// Allow larger pages for ApplicationView aggregation
	maxPageSize := 50000
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	a.appClassMu.RLock()
	classificationStore := a.appClassStore
	a.appClassMu.RUnlock()

	// When ML classification results exist, query from that SQLite DB
	if classificationStore != nil {
		data, total, err := classificationStore.QueryProcessStatsFromReplay(offset, pageSize)
		if err != nil {
			return nil, fmt.Errorf("query app classification stats: %w", err)
		}

		stats := make([]process.ProcessStats, 0, len(data))
		for _, item := range data {
			m := item.(map[string]interface{})
			stat := process.ProcessStats{
				PID:          m["pid"].(int32),
				Name:         m["name"].(string),
				Exe:          m["exe"].(string),
				Username:     m["username"].(string),
				PacketsSent:  m["packets_sent"].(int64),
				PacketsRecv:  m["packets_recv"].(int64),
				BytesSent:    m["bytes_sent"].(int64),
				BytesRecv:    m["bytes_recv"].(int64),
				Connections:  int(m["connections"].(int64)),
			}
			if firstSeen, ok := m["first_seen"].(int64); ok {
				stat.FirstSeen = time.Unix(firstSeen, 0)
			} else if firstSeen, ok := m["first_seen"].(string); ok {
				stat.FirstSeen, _ = parseTimeString(firstSeen)
			}
			if lastSeen, ok := m["last_seen"].(int64); ok {
				stat.LastSeen = time.Unix(lastSeen, 0)
			} else if lastSeen, ok := m["last_seen"].(string); ok {
				stat.LastSeen, _ = parseTimeString(lastSeen)
			}

			stats = append(stats, stat)
		}

		return &ProcessStatsResult{
			Data:     stats,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		}, nil
	}

	// Fallback: live process stats
	stats, total, err := a.capture.GetProcessStats(offset, pageSize)
	if err != nil {
		return nil, fmt.Errorf("get process stats: %w", err)
	}

	return &ProcessStatsResult{
		Data:     stats,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// GetAppClassificationAccuracy returns classification accuracy from the last ML classification DB,
// otherwise it falls back to the live store accuracy.
func (a *App) GetAppClassificationAccuracy() (float64, error) {
	// In replay mode, classification accuracy is stored in the replay session DB.
	if a.replayMode {
		return a.GetClassificationAccuracy()
	}

	a.appClassMu.RLock()
	classificationStore := a.appClassStore
	a.appClassMu.RUnlock()

	if classificationStore != nil {
		return classificationStore.GetClassificationAccuracy()
	}

	// Fallback: current store (likely N/A in live mode)
	return a.GetClassificationAccuracy()
}

// GetTopProcessesByTraffic 获取流量排名前N的进程
func (a *App) GetTopProcessesByTraffic(limit int) ([]process.ProcessStats, error) {
	if limit < 1 || limit > 100 {
		limit = 10
	}
	
	// 重放模式：从数据库读取
	if a.replayMode {
		composite, ok := a.store.(*store.CompositeStore)
		if !ok {
			return nil, fmt.Errorf("store is not composite")
		}
		
		sqliteStore := composite.GetDB()
		data, err := sqliteStore.GetTopProcessesFromReplay(limit)
		if err != nil {
			return nil, fmt.Errorf("query top replay processes: %w", err)
		}
		
		// 转换为ProcessStats结构
		stats := make([]process.ProcessStats, 0, len(data))
		for _, item := range data {
			m := item.(map[string]interface{})
			stat := process.ProcessStats{
				PID:          m["pid"].(int32),
				Name:         m["name"].(string),
				Exe:          m["exe"].(string),
				Username:     m["username"].(string),
				PacketsSent:  m["packets_sent"].(int64),
				PacketsRecv:  m["packets_recv"].(int64),
				BytesSent:    m["bytes_sent"].(int64),
				BytesRecv:    m["bytes_recv"].(int64),
				Connections:  int(m["connections"].(int64)),
			}
			// 解析时间（可能是string或int64）
			if firstSeen, ok := m["first_seen"].(int64); ok {
				stat.FirstSeen = time.Unix(firstSeen, 0)
			} else if firstSeen, ok := m["first_seen"].(string); ok {
				stat.FirstSeen, _ = parseTimeString(firstSeen)
			}
			if lastSeen, ok := m["last_seen"].(int64); ok {
				stat.LastSeen = time.Unix(lastSeen, 0)
			} else if lastSeen, ok := m["last_seen"].(string); ok {
				stat.LastSeen, _ = parseTimeString(lastSeen)
			}
			stats = append(stats, stat)
		}
		
		return stats, nil
	}
	
	// 正常模式：从内存读取
	return a.capture.GetTopProcessesByTraffic(limit)
}

// ClearProcessStats 清空进程统计
func (a *App) ClearProcessStats() error {
	return a.capture.ClearProcessStats()
}

// ProcessStatsResult 进程统计结果
type ProcessStatsResult struct {
	Data     []process.ProcessStats `json:"data"`
	Total    int                     `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
}

// parseTimeString 解析时间字符串（支持多种格式）
func parseTimeString(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("unable to parse time: %s", s)
}

