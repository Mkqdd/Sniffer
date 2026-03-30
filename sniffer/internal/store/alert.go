package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sniffer/pkg/model"
)

// CreateAlertRule 创建告警规则
func (s *SQLiteStore) CreateAlertRule(rule *model.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO alert_rules (
			name, rule_type, enabled, condition_field, condition_operator, 
			condition_value, alert_level, description, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	now := time.Now()
	result, err := s.db.Exec(query,
		rule.Name, rule.RuleType, enabled, rule.ConditionField,
		rule.ConditionOperator, rule.ConditionValue, rule.AlertLevel,
		rule.Description, now, now,
	)
	if err != nil {
		return fmt.Errorf("create alert rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	rule.ID = id
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return nil
}

// UpdateAlertRule 更新告警规则
func (s *SQLiteStore) UpdateAlertRule(rule *model.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	query := `
		UPDATE alert_rules SET
			name = ?, rule_type = ?, enabled = ?, condition_field = ?,
			condition_operator = ?, condition_value = ?, alert_level = ?,
			description = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.Exec(query,
		rule.Name, rule.RuleType, enabled, rule.ConditionField,
		rule.ConditionOperator, rule.ConditionValue, rule.AlertLevel,
		rule.Description, time.Now(), rule.ID,
	)
	if err != nil {
		return fmt.Errorf("update alert rule: %w", err)
	}

	return nil
}

// DeleteAlertRule 删除告警规则
func (s *SQLiteStore) DeleteAlertRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete alert rule: %w", err)
	}

	return nil
}

// EnsureSSLBlacklistRule 确保存在一条 "SSL Blacklist" 告警规则，用于 JA3/证书 SHA1 黑名单告警；返回规则 ID
func (s *SQLiteStore) EnsureSSLBlacklistRule() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var id int64
	err := s.db.QueryRow("SELECT id FROM alert_rules WHERE name = ? LIMIT 1", "SSL Blacklist").Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("query ssl blacklist rule: %w", err)
	}

	query := `
		INSERT INTO alert_rules (
			name, rule_type, enabled, condition_field, condition_operator,
			condition_value, alert_level, description, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := time.Now()
	result, err := s.db.Exec(query,
		"SSL Blacklist", "ssl_blacklist", 1, "", "", "", "critical",
		"恶意 JA3 指纹或证书 SHA1 命中 SSLBlackList（abuse.ch）",
		now, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create ssl blacklist rule: %w", err)
	}
	id, err = result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// ClearAllAlertRules 删除所有告警规则（不会删除告警记录）
func (s *SQLiteStore) ClearAllAlertRules() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM alert_rules")
	if err != nil {
		return 0, fmt.Errorf("clear alert rules: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// DeleteAlertRulesByNamePrefix 按名称前缀删除告警规则，返回删除条数
func (s *SQLiteStore) DeleteAlertRulesByNamePrefix(prefix string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM alert_rules WHERE name LIKE ?", prefix+"%")
	if err != nil {
		return 0, fmt.Errorf("delete alert rules by prefix: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// BulkCreateAlertRules 批量创建告警规则，返回成功条数
func (s *SQLiteStore) BulkCreateAlertRules(rules []*model.AlertRule) (int, error) {
	if len(rules) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO alert_rules (
			name, rule_type, enabled, condition_field, condition_operator,
			condition_value, alert_level, description, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	stmt, err := s.db.Prepare(query)
	if err != nil {
		return 0, fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	now := time.Now()
	inserted := 0
	for _, rule := range rules {
		enabled := 0
		if rule.Enabled {
			enabled = 1
		}
		_, err := stmt.Exec(
			rule.Name, rule.RuleType, enabled, rule.ConditionField,
			rule.ConditionOperator, rule.ConditionValue, rule.AlertLevel,
			rule.Description, now, now,
		)
		if err != nil {
			continue
		}
		inserted++
	}
	return inserted, nil
}

// GetAlertRule 获取告警规则
func (s *SQLiteStore) GetAlertRule(id int64) (*model.AlertRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, name, rule_type, enabled, condition_field, condition_operator,
			   condition_value, alert_level, description, created_at, updated_at
		FROM alert_rules
		WHERE id = ?
	`

	rule := &model.AlertRule{}
	var enabled int

	err := s.db.QueryRow(query, id).Scan(
		&rule.ID, &rule.Name, &rule.RuleType, &enabled, &rule.ConditionField,
		&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get alert rule: %w", err)
	}

	rule.Enabled = enabled == 1
	return rule, nil
}

// QueryAlertRules 查询告警规则列表
func (s *SQLiteStore) QueryAlertRules(q model.AlertRuleQuery) ([]*model.AlertRule, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 构建查询条件
	where := []string{}
	args := []interface{}{}

	if q.RuleType != "" {
		where = append(where, "rule_type = ?")
		args = append(args, q.RuleType)
	}

	if q.Enabled != nil {
		enabled := 0
		if *q.Enabled {
			enabled = 1
		}
		where = append(where, "enabled = ?")
		args = append(args, enabled)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// 查询总数
	countQuery := "SELECT COUNT(*) FROM alert_rules " + whereClause
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count alert rules: %w", err)
	}

	// 查询数据
	query := `
		SELECT id, name, rule_type, enabled, condition_field, condition_operator,
			   condition_value, alert_level, description, created_at, updated_at
		FROM alert_rules ` + whereClause + `
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	queryArgs := append(args, limit, q.Offset)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query alert rules: %w", err)
	}
	defer rows.Close()

	rules := []*model.AlertRule{}
	for rows.Next() {
		rule := &model.AlertRule{}
		var enabled int

		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.RuleType, &enabled, &rule.ConditionField,
			&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel,
			&rule.Description, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			continue
		}

		rule.Enabled = enabled == 1
		rules = append(rules, rule)
	}

	return rules, total, nil
}

// CreateAlertLog 创建告警记录（带去重功能）
func (s *SQLiteStore) CreateAlertLog(log *model.AlertLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查是否存在相同的告警（未确认，且核心字段相同）
	// 相同告警定义：同一规则、同一目标（dst_ip或domain）、未确认
	checkQuery := `
		SELECT id, trigger_count, details
		FROM alert_logs
		WHERE rule_id = ? 
		  AND acknowledged = 0
		  AND (
		    (dst_ip != '' AND dst_ip = ?) OR 
		    (domain != '' AND domain = ?)
		  )
		ORDER BY triggered_at DESC
		LIMIT 1
	`
	
	var existingID int64
	var triggerCount int64
	var existingDetails string
	err := s.db.QueryRow(checkQuery, log.RuleID, log.DstIP, log.Domain).Scan(&existingID, &triggerCount, &existingDetails)
	
	if err == nil {
		// 找到相同告警：增加触发次数 + 更新时间；
		// 不覆盖 src/dst（保留首条样本），将新出现的 src->dst 增量追加到 details 里，便于观察触发对象。
		newDetails := mergeAlertDetailsWithEndpoint(existingDetails, log.SrcIP, log.DstIP, 30)
		updateQuery := `
			UPDATE alert_logs 
			SET trigger_count = trigger_count + 1,
			    last_triggered_at = ?,
			    details = ?
			WHERE id = ?
		`
		_, err = s.db.Exec(updateQuery, log.TriggeredAt, newDetails, existingID)
		if err != nil {
			return fmt.Errorf("update alert log: %w", err)
		}
		log.ID = existingID
		log.TriggerCount = triggerCount + 1
		return nil
	} else if err != sql.ErrNoRows {
		// 查询错误
		return fmt.Errorf("check existing alert: %w", err)
	}
	
	// 不存在相同告警，创建新记录
	query := `
		INSERT INTO alert_logs (
			rule_id, rule_name, rule_type, alert_level, triggered_at, last_triggered_at,
			src_ip, dst_ip, protocol, domain, url, details, trigger_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
	`

	result, err := s.db.Exec(query,
		log.RuleID, log.RuleName, log.RuleType, log.AlertLevel, log.TriggeredAt, log.TriggeredAt,
		log.SrcIP, log.DstIP, log.Protocol, log.Domain, log.URL, log.Details,
	)
	if err != nil {
		return fmt.Errorf("create alert log: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	log.ID = id
	log.TriggerCount = 1
	log.LastTriggeredAt = log.TriggeredAt
	return nil
}

func mergeAlertDetailsWithEndpoint(existing, srcIP, dstIP string, maxUnique int) string {
	if srcIP == "" || dstIP == "" {
		return existing
	}
	endpoint := srcIP + " -> " + dstIP

	const marker = "\nSeen endpoints:\n"
	details := existing
	if !strings.Contains(details, marker) {
		details += marker
	}

	// 已存在则不追加
	if strings.Contains(details, "\n- "+endpoint+"\n") || strings.HasSuffix(details, "\n- "+endpoint) || strings.Contains(details, "\n- "+endpoint+"\r") {
		return details
	}

	// 统计已有条目数，超过上限则不再增长（避免 details 无限膨胀）
	after := details
	if idx := strings.Index(details, marker); idx >= 0 {
		after = details[idx+len(marker):]
	}
	count := 0
	for _, line := range strings.Split(after, "\n") {
		if strings.HasPrefix(line, "- ") {
			count++
		}
	}
	if count >= maxUnique {
		return details
	}

	return details + "- " + endpoint + "\n"
}

// AcknowledgeAlert 确认告警
func (s *SQLiteStore) AcknowledgeAlert(id int64, acknowledgedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		UPDATE alert_logs SET
			acknowledged = 1,
			acknowledged_at = ?,
			acknowledged_by = ?
		WHERE id = ?
	`

	_, err := s.db.Exec(query, time.Now(), acknowledgedBy, id)
	if err != nil {
		return fmt.Errorf("acknowledge alert: %w", err)
	}

	return nil
}

// DeleteAlertLog 删除告警记录
func (s *SQLiteStore) DeleteAlertLog(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_logs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete alert log: %w", err)
	}

	return nil
}

// QueryAlertLogs 查询告警记录
func (s *SQLiteStore) QueryAlertLogs(q model.AlertLogQuery) ([]*model.AlertLog, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 构建查询条件
	where := []string{}
	args := []interface{}{}

	if q.RuleID != nil {
		where = append(where, "rule_id = ?")
		args = append(args, *q.RuleID)
	}

	if q.RuleType != "" {
		where = append(where, "rule_type = ?")
		args = append(args, q.RuleType)
	}

	if q.AlertLevel != "" {
		where = append(where, "alert_level = ?")
		args = append(args, q.AlertLevel)
	}

	if q.Acknowledged != nil {
		ack := 0
		if *q.Acknowledged {
			ack = 1
		}
		where = append(where, "acknowledged = ?")
		args = append(args, ack)
	}

	if q.StartTime != nil {
		where = append(where, "triggered_at >= ?")
		args = append(args, q.StartTime)
	}

	if q.EndTime != nil {
		where = append(where, "triggered_at <= ?")
		args = append(args, q.EndTime)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// 查询总数
	countQuery := "SELECT COUNT(*) FROM alert_logs " + whereClause
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count alert logs: %w", err)
	}

	// 排序
	sortBy := q.SortBy
	if sortBy == "" {
		sortBy = "triggered_at"
	}
	sortOrder := strings.ToUpper(q.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	// 查询数据
	query := `
		SELECT id, rule_id, rule_name, rule_type, alert_level, triggered_at, last_triggered_at, trigger_count,
			   src_ip, dst_ip, protocol, domain, url, details,
			   acknowledged, acknowledged_at, acknowledged_by
		FROM alert_logs ` + whereClause + `
		ORDER BY ` + sortBy + ` ` + sortOrder + `
		LIMIT ? OFFSET ?
	`

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	queryArgs := append(args, limit, q.Offset)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query alert logs: %w", err)
	}
	defer rows.Close()

	logs := []*model.AlertLog{}
	for rows.Next() {
		log := &model.AlertLog{}
		var acknowledged int
		var acknowledgedAt sql.NullTime
		var acknowledgedBy sql.NullString
		var lastTriggeredAt sql.NullTime

		err := rows.Scan(
			&log.ID, &log.RuleID, &log.RuleName, &log.RuleType, &log.AlertLevel,
			&log.TriggeredAt, &lastTriggeredAt, &log.TriggerCount, 
			&log.SrcIP, &log.DstIP, &log.Protocol, &log.Domain,
			&log.URL, &log.Details, &acknowledged, &acknowledgedAt, &acknowledgedBy,
		)
		if err != nil {
			continue
		}

		log.Acknowledged = acknowledged == 1
		if acknowledgedAt.Valid {
			log.AcknowledgedAt = &acknowledgedAt.Time
		}
		if acknowledgedBy.Valid {
			log.AcknowledgedBy = acknowledgedBy.String
		}
		if lastTriggeredAt.Valid {
			log.LastTriggeredAt = lastTriggeredAt.Time
		} else {
			// 如果last_triggered_at为空，使用triggered_at作为fallback
			log.LastTriggeredAt = log.TriggeredAt
		}

		logs = append(logs, log)
	}

	return logs, total, nil
}

// CheckAlertRules 检查数据包是否触发告警规则
func (s *SQLiteStore) CheckAlertRules(pkt *model.Packet, session *model.Session) error {
	s.mu.RLock()
	
	// 查询所有启用的规则
	query := `
		SELECT id, name, rule_type, condition_field, condition_operator,
			   condition_value, alert_level
		FROM alert_rules
		WHERE enabled = 1
	`
	
	rows, err := s.db.Query(query)
	if err != nil {
		s.mu.RUnlock()
		return fmt.Errorf("query alert rules: %w", err)
	}
	defer rows.Close()

	rules := []struct {
		ID                int64
		Name              string
		RuleType          string
		ConditionField    string
		ConditionOperator string
		ConditionValue    string
		AlertLevel        string
	}{}

	for rows.Next() {
		var rule struct {
			ID                int64
			Name              string
			RuleType          string
			ConditionField    string
			ConditionOperator string
			ConditionValue    string
			AlertLevel        string
		}
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.RuleType, &rule.ConditionField,
			&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel); err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	s.mu.RUnlock()

	// 检查每个规则
	for _, rule := range rules {
		if s.matchRule(pkt, session, rule.RuleType, rule.ConditionField,
			rule.ConditionOperator, rule.ConditionValue) {
			
			// 创建告警记录
			log := &model.AlertLog{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				RuleType:    rule.RuleType,
				AlertLevel:  rule.AlertLevel,
				TriggeredAt: time.Now(),
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				Protocol:    pkt.Protocol,
			}

			if session != nil {
				log.Domain = session.Domain
				// HTTP的URL由Host和Path组成
				if session.Host != "" {
					log.URL = session.Host + session.Path
				} else {
					log.URL = session.Path
				}
				log.Details = fmt.Sprintf("触发规则: %s, 类型: %s", rule.Name, rule.RuleType)
			} else {
				log.Details = fmt.Sprintf("触发规则: %s, 协议: %s", rule.Name, pkt.Protocol)
			}
			
			// 添加进程信息到详情
			if pkt.ProcessName != "" {
				log.Details += fmt.Sprintf(", 进程: %s (PID: %d)", pkt.ProcessName, pkt.ProcessPID)
			}

			// 异步写入，避免阻塞
			go s.CreateAlertLog(log)
		}
	}

	// Intel matching (Maltrail-like)
	s.checkIntel(pkt, session)

	return nil
}

func (s *SQLiteStore) checkIntel(pkt *model.Packet, session *model.Session) {
	if s.intelCache == nil {
		return
	}

	// Only do intel work on parsed sessions (DNS/HTTP). Per-packet dst_ip matching via DB was too expensive.
	// We keep IP matching only for packets that already created a session/flow (session != nil), to avoid slowing down capture.

	// DNS exact domain match
	if session != nil && session.Type == "DNS" && session.Domain != "" {
		d := strings.ToLower(session.Domain)
		if s.intelCache.ShouldSuppress("domain:" + d) {
			return
		}
		if hit, ok := s.intelCache.Lookup("domain", d); ok {
			log := &model.AlertLog{
				RuleID:      0,
				RuleName:    hit.Category,
				RuleType:    "intel",
				AlertLevel:  "warning",
				TriggeredAt: time.Now(),
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				Protocol:    pkt.Protocol,
				Domain:      session.Domain,
				Details:     fmt.Sprintf("intel_hit category=%s type=domain trail=%s info=%s ref=%s source=%s", hit.Category, hit.Value, hit.Info, hit.Reference, hit.Source),
			}
			_ = s.CreateAlertLog(log)
		}
	}

	// IP exact match on dst_ip (only when we already have a session)
	if session != nil && pkt.DstIP != "" {
		if s.intelCache.ShouldSuppress("ip:" + pkt.DstIP) {
			return
		}
		if hit, ok := s.intelCache.Lookup("ip", pkt.DstIP); ok {
			log := &model.AlertLog{
				RuleID:      0,
				RuleName:    hit.Category,
				RuleType:    "intel",
				AlertLevel:  "warning",
				TriggeredAt: time.Now(),
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				Protocol:    pkt.Protocol,
				Details:     fmt.Sprintf("intel_hit category=%s type=ip trail=%s info=%s ref=%s source=%s", hit.Category, hit.Value, hit.Info, hit.Reference, hit.Source),
			}
			_ = s.CreateAlertLog(log)
		}
	}

	// HTTP URL contains: do an exact lookup on host/path token if available (simple exact for now)
	if session != nil && session.Type == "HTTP" {
		url := ""
		if session.Host != "" {
			url = strings.ToLower(session.Host + session.Path)
		} else {
			url = strings.ToLower(session.Path)
		}
		if url != "" {
			if s.intelCache.ShouldSuppress("url:" + url) {
				return
			}
			if hit, ok := s.intelCache.Lookup("url", url); ok {
				log := &model.AlertLog{
					RuleID:      0,
					RuleName:    hit.Category,
					RuleType:    "intel",
					AlertLevel:  "warning",
					TriggeredAt: time.Now(),
					SrcIP:       pkt.SrcIP,
					DstIP:       pkt.DstIP,
					Protocol:    pkt.Protocol,
					URL:         url,
					Details:     fmt.Sprintf("intel_hit category=%s type=url trail=%s info=%s ref=%s source=%s", hit.Category, hit.Value, hit.Info, hit.Reference, hit.Source),
				}
				_ = s.CreateAlertLog(log)
			}
		}
	}
}

// ClearAllAlerts 清空所有告警记录
func (s *SQLiteStore) ClearAllAlerts() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_logs")
	if err != nil {
		return fmt.Errorf("clear alert logs: %w", err)
	}

	return nil
}

// matchRule 检查是否匹配规则
func (s *SQLiteStore) matchRule(pkt *model.Packet, session *model.Session,
	ruleType, field, operator, value string) bool {

	var fieldValue string

	// 根据规则类型获取字段值
	switch ruleType {
	case "dst_ip":
		if field == "dst_ip" {
			fieldValue = pkt.DstIP
		}
	case "dns":
		if session != nil && session.Type == "DNS" {
			if field == "domain" {
				fieldValue = session.Domain
			} else if field == "domain_length" {
				fieldValue = strconv.Itoa(len(session.Domain))
			}
		} else {
			return false
		}
	case "http":
		if session != nil && session.Type == "HTTP" {
			if field == "domain" {
				fieldValue = session.Domain
			} else if field == "url" {
				if session.Host != "" {
					fieldValue = session.Host + session.Path
				} else {
					fieldValue = session.Path
				}
			} else if field == "user_agent" {
				fieldValue = session.UserAgent
			}
		} else {
			return false
		}
	case "icmp":
		if pkt.Protocol == "ICMP" || pkt.Protocol == "ICMPv6" {
			if field == "src_ip" {
				fieldValue = pkt.SrcIP
			} else if field == "dst_ip" {
				fieldValue = pkt.DstIP
			}
		} else {
			return false
		}
	case "process":
		// 进程告警
		if field == "process_name" {
			fieldValue = pkt.ProcessName
		} else if field == "process_exe" {
			fieldValue = pkt.ProcessExe
		} else if field == "process_pid" {
			fieldValue = fmt.Sprintf("%d", pkt.ProcessPID)
		}
		// 如果进程信息为空，不触发告警
		if fieldValue == "" || fieldValue == "0" {
			return false
		}
	default:
		return false
	}

	// 根据操作符比较（忽略大小写）
	switch operator {
	case "equals":
		return strings.EqualFold(fieldValue, value)
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(value))
	case "regex":
		pattern := value
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		matched, err := regexp.MatchString(pattern, fieldValue)
		return err == nil && matched
	case "gt":
		return matchNumericCompare(fieldValue, value, true)
	case "lt":
		return matchNumericCompare(fieldValue, value, false)
	default:
		return false
	}
}

// matchNumericCompare 数值比较，greater true 表示大于，false 表示小于
func matchNumericCompare(fieldValue, value string, greater bool) bool {
	a, err1 := strconv.Atoi(strings.TrimSpace(fieldValue))
	b, err2 := strconv.Atoi(strings.TrimSpace(value))
	if err1 != nil || err2 != nil {
		return false
	}
	if greater {
		return a > b
	}
	return a < b
}

