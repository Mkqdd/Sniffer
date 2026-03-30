package server

import (
	"fmt"

	"sniffer/internal/maltrail"
	"sniffer/internal/store"
	"sniffer/pkg/model"
)

// CreateAlertRule 创建告警规则
func (a *App) CreateAlertRule(rule model.AlertRule) (*model.AlertRule, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	if err := sqliteStore.CreateAlertRule(&rule); err != nil {
		return nil, err
	}

	return &rule, nil
}

// UpdateAlertRule 更新告警规则
func (a *App) UpdateAlertRule(rule model.AlertRule) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.UpdateAlertRule(&rule)
}

// DeleteAlertRule 删除告警规则
func (a *App) DeleteAlertRule(id int64) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.DeleteAlertRule(id)
}

// ClearAllAlertRules 删除所有告警规则（不会删除告警记录）
func (a *App) ClearAllAlertRules() (int64, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return 0, fmt.Errorf("database not available")
	}
	return sqliteStore.ClearAllAlertRules()
}

// GetAlertRule 获取告警规则
func (a *App) GetAlertRule(id int64) (*model.AlertRule, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	return sqliteStore.GetAlertRule(id)
}

// ImportMaltrailTrailsResult 导入 Maltrail 规则的结果
type ImportMaltrailTrailsResult struct {
	Imported int `json:"imported"` // 本次导入条数
	Deleted  int `json:"deleted"`  // 若先清除再导入，则为已删除的旧 Maltrail 规则数
}

// IntelSyncResult 同步情报库结果（按类别返回条数）
type IntelSyncResult struct {
	Counts map[string]int `json:"counts"`
}

// SyncIntelFromMaltrail 同步 Maltrail trails 到 Sniffer 情报库（按类别开关，不生成海量告警规则）
// maltrailRoot: maltrail 根目录（含 trails/static）；trailsCSV: 可选，trails.csv 路径（动态 feed/custom）
func (a *App) SyncIntelFromMaltrail(maltrailRoot string, trailsCSV string) (*IntelSyncResult, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}
	counts, err := maltrail.SyncIntel(sqliteStore, maltrail.SyncOptions{
		MaltrailRoot: maltrailRoot,
		TrailsCSV:    trailsCSV,
	})
	if err != nil {
		return nil, err
	}
	_ = sqliteStore.RefreshIntelCache()
	return &IntelSyncResult{Counts: counts}, nil
}

// ListIntelCategories 返回情报类别列表（用于前端展示开关）
func (a *App) ListIntelCategories() ([]*store.IntelCategory, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}
	return sqliteStore.ListIntelCategories()
}

// SetIntelCategoryEnabled 设置某个情报类别开关
func (a *App) SetIntelCategoryEnabled(name string, enabled bool) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}
	if err := sqliteStore.SetIntelCategoryEnabled(name, enabled); err != nil {
		return err
	}
	_ = sqliteStore.RefreshIntelCache()
	return nil
}

// ImportMaltrailTrails 从 Maltrail 目录导入静态规则和/或 CSV 动态规则为告警规则
// trailsDir: maltrail 根目录（含 trails/static）；includeStatic: 是否扫描 trails/static/**/*.txt
// csvPath: 可选，trails.csv 路径（若为空则不导入 CSV）；clearExisting: 是否先删除名称以 "Maltrail: " 开头的规则
func (a *App) ImportMaltrailTrails(trailsDir string, includeStatic bool, csvPath string, clearExisting bool) (*ImportMaltrailTrailsResult, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}
	out := &ImportMaltrailTrailsResult{}
	if clearExisting {
		n, err := sqliteStore.DeleteAlertRulesByNamePrefix(maltrail.MaltrailRuleNamePrefix)
		if err != nil {
			return nil, fmt.Errorf("clear existing Maltrail rules: %w", err)
		}
		out.Deleted = int(n)
	}
	var entries []maltrail.TrailEntry
	if includeStatic && trailsDir != "" {
		staticEntries, err := maltrail.LoadTrailsFromStaticDir(trailsDir)
		if err != nil {
			return nil, fmt.Errorf("load static trails: %w", err)
		}
		entries = append(entries, staticEntries...)
	}
	if csvPath != "" {
		csvEntries, err := maltrail.LoadTrailsFromCSV(csvPath)
		if err != nil {
			return nil, fmt.Errorf("load trails CSV: %w", err)
		}
		entries = append(entries, csvEntries...)
	}
	if len(entries) == 0 {
		return out, nil
	}
	rules := maltrail.ConvertToAlertRules(entries, maltrail.MaltrailRuleNamePrefix, "warning")
	n, err := sqliteStore.BulkCreateAlertRules(rules)
	if err != nil {
		return nil, fmt.Errorf("bulk create rules: %w", err)
	}
	out.Imported = n
	return out, nil
}

// AddDefaultHeuristicRules 添加内置启发式告警规则（若已有 "启发式:" 前缀的规则则不再重复添加）
func (a *App) AddDefaultHeuristicRules() (int, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return 0, fmt.Errorf("database not available")
	}
	existing, _, _ := sqliteStore.QueryAlertRules(model.AlertRuleQuery{Limit: 5000, Offset: 0})
	for _, r := range existing {
		if r != nil && len(r.Name) >= len(maltrail.HeuristicRuleNamePrefix) && r.Name[:len(maltrail.HeuristicRuleNamePrefix)] == maltrail.HeuristicRuleNamePrefix {
			return 0, nil // 已存在启发式规则，不再重复添加
		}
	}
	rules := maltrail.GetDefaultHeuristicRules()
	n, err := sqliteStore.BulkCreateAlertRules(rules)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// QueryAlertRules 查询告警规则列表
func (a *App) QueryAlertRules(query model.AlertRuleQuery) (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	rules, total, err := sqliteStore.QueryAlertRules(query)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data":  rules,
		"total": total,
	}, nil
}

// QueryAlertLogs 查询告警记录
func (a *App) QueryAlertLogs(query model.AlertLogQuery) (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	logs, total, err := sqliteStore.QueryAlertLogs(query)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data":  logs,
		"total": total,
	}, nil
}

// AcknowledgeAlert 确认告警
func (a *App) AcknowledgeAlert(id int64, acknowledgedBy string) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.AcknowledgeAlert(id, acknowledgedBy)
}

// DeleteAlertLog 删除告警记录
func (a *App) DeleteAlertLog(id int64) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.DeleteAlertLog(id)
}

// GetAlertStats 获取告警统计
func (a *App) GetAlertStats() (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	db := sqliteStore.GetRawDB()

	// 统计各级别告警数量
	var critical, error, warning, info int64
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'critical' AND acknowledged = 0").Scan(&critical)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'error' AND acknowledged = 0").Scan(&error)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'warning' AND acknowledged = 0").Scan(&warning)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'info' AND acknowledged = 0").Scan(&info)

	// 统计启用的规则数
	var enabledRules int64
	db.QueryRow("SELECT COUNT(*) FROM alert_rules WHERE enabled = 1").Scan(&enabledRules)

	// 统计今日告警数
	var todayAlerts int64
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE DATE(triggered_at) = DATE('now')").Scan(&todayAlerts)

	return map[string]interface{}{
		"critical":      critical,
		"error":         error,
		"warning":       warning,
		"info":          info,
		"enabled_rules": enabledRules,
		"today_alerts":  todayAlerts,
		"total_unack":   critical + error + warning + info,
	}, nil
}

// ClearAllAlerts 清空所有告警记录
func (a *App) ClearAllAlerts() error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.ClearAllAlerts()
}

