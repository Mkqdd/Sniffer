package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"sniffer/pkg/model"
)

// QuerySessions 查询会话（支持分页、排序、搜索）
func (s *SQLiteStore) QuerySessions(opts model.QueryOptions) (*model.QueryResult, error) {
	fmt.Printf("[QuerySessions] table=%s, search=%s, limit=%d, offset=%d\n", 
		opts.Table, opts.SearchText, opts.Limit, opts.Offset)
	
	// 构建基础查询
	tableName := getTableName(opts.Table)
	if tableName == "" {
		return nil, fmt.Errorf("invalid table type: %s", opts.Table)
	}
	fmt.Printf("[QuerySessions] tableName=%s\n", tableName)

	// 构建 WHERE 子句
	whereClause := buildSearchClause(opts.Table, opts.SearchType, opts.SearchText)
	args := []interface{}{}
	
	// 只有在有搜索文本时才添加参数
	if opts.SearchText != "" && whereClause != "1=1" {
		args = append(args, "%"+opts.SearchText+"%")
	}
	fmt.Printf("[QuerySessions] WHERE %s, args=%v\n", whereClause, args)

	// 查询总数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", tableName, whereClause)
	fmt.Printf("[QuerySessions] countQuery=%s\n", countQuery)

	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		fmt.Printf("[QuerySessions] count error: %v\n", err)
		return nil, fmt.Errorf("count query failed: %w", err)
	}
	fmt.Printf("[QuerySessions] total=%d\n", total)

	// 构建排序
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}
	sortOrder := strings.ToUpper(opts.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	// 构建查询 - 明确指定列名顺序（包含进程字段）
	var selectColumns string
	switch opts.Table {
	case model.TableDNS:
		selectColumns = "id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, domain, query_type, response_ip, payload_size, ttl, process_pid, process_name, process_exe"
	case model.TableHTTP:
		selectColumns = "id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, method, host, path, status_code, user_agent, payload_size, ttl, content_type, post_data, process_pid, process_name, process_exe"
	case model.TableICMP:
		selectColumns = "id, timestamp, src_ip, dst_ip, protocol, icmp_type, icmp_code, icmp_seq, payload_size, ttl, process_pid, process_name, process_exe"
	default:
		selectColumns = "*"
	}
	
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s %s LIMIT ? OFFSET ?", 
		selectColumns, tableName, whereClause, sortBy, sortOrder)
	
	// 重新构建 args（因为之前可能已经用过）
	args = []interface{}{}
	if opts.SearchText != "" && whereClause != "1=1" {
		args = append(args, "%"+opts.SearchText+"%")
	}
	args = append(args, opts.Limit, opts.Offset)
	
	fmt.Printf("[QuerySessions] query=%s\n", query)
	fmt.Printf("[QuerySessions] final args=%v\n", args)

	// 执行查询
	rows, err := s.db.Query(query, args...)
	if err != nil {
		fmt.Printf("[QuerySessions] query error: %v\n", err)
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	// 解析结果
	sessions := []*model.Session{}
	for rows.Next() {
		session, err := scanSession(rows, opts.Table)
		if err != nil {
			fmt.Printf("[QuerySessions] scan error: %v\n", err)
			continue
		}
		sessions = append(sessions, session)
	}
	
	fmt.Printf("[QuerySessions] returned %d sessions\n", len(sessions))

	return &model.QueryResult{
		Total: total,
		Data:  sessions,
	}, nil
}

// QuerySessionFlows 查询会话流统计（从session_flows表直接查询）
func (s *SQLiteStore) QuerySessionFlows(opts model.SessionFlowQuery) (*model.SessionFlowResult, error) {
	fmt.Printf("QuerySessionFlows called: limit=%d, offset=%d\n", opts.Limit, opts.Offset)
	
	// 直接从session_flows表查询（已经包含所有TCP/UDP/ICMP连接）
	query := `
		SELECT 
			src_ip, dst_ip, src_port, dst_port, protocol,
			packet_count, bytes_count,
			first_seen, last_seen,
			session_type,
			process_pid, process_name, process_exe
		FROM session_flows
		WHERE 1=1
	`
	
	// 旧的复杂查询已被移除，新实现直接从session_flows表查询
	// 优势：
	// 1. 包含所有TCP/UDP/ICMP连接（不只是DNS/HTTP/ICMP）
	// 2. 查询简单快速
	// 3. 自动双向合并（在写入时已完成）
	
	_ = `WITH all_sessions AS (
			-- DNS会话（双向合并）
			SELECT 
				-- 规范化：较小的IP:端口作为端点1，较大的IP:端口作为端点2
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN src_ip
					ELSE dst_ip
				END as endpoint1_ip,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN src_port
					ELSE dst_port
				END as endpoint1_port,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN dst_ip
					ELSE src_ip
				END as endpoint2_ip,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN dst_port
					ELSE src_port
				END as endpoint2_port,
				protocol,
				payload_size,
				timestamp,
				'DNS' as session_type,
				process_pid,
				process_name,
				process_exe
			FROM dns_sessions
			
			UNION ALL
			
			-- HTTP会话（双向合并）
			SELECT 
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN src_ip
					ELSE dst_ip
				END as endpoint1_ip,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN src_port
					ELSE dst_port
				END as endpoint1_port,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN dst_ip
					ELSE src_ip
				END as endpoint2_ip,
				CASE 
					WHEN src_ip || ':' || CAST(src_port AS TEXT) < dst_ip || ':' || CAST(dst_port AS TEXT)
					THEN dst_port
					ELSE src_port
				END as endpoint2_port,
				protocol,
				payload_size,
				timestamp,
				'HTTP' as session_type,
				process_pid,
				process_name,
				process_exe
			FROM http_sessions
			
			UNION ALL
			
			-- ICMP会话（双向合并，无端口）
			SELECT 
				CASE 
					WHEN src_ip < dst_ip
					THEN src_ip
					ELSE dst_ip
				END as endpoint1_ip,
				0 as endpoint1_port,
				CASE 
					WHEN src_ip < dst_ip
					THEN dst_ip
					ELSE src_ip
				END as endpoint2_ip,
				0 as endpoint2_port,
				protocol,
				payload_size,
				timestamp,
				'ICMP' as session_type,
				process_pid,
				process_name,
				process_exe
			FROM icmp_sessions
		),
		aggregated_flows AS (
			SELECT 
				endpoint1_ip as src_ip,
				endpoint2_ip as dst_ip,
				endpoint1_port as src_port,
				endpoint2_port as dst_port,
				protocol,
				COUNT(*) as packet_count,
				SUM(payload_size) as bytes_count,
				MIN(timestamp) as first_seen,
				MAX(timestamp) as last_seen,
				session_type,
				MAX(CASE WHEN process_pid IS NOT NULL THEN process_pid END) as process_pid,
				MAX(CASE WHEN process_name IS NOT NULL AND process_name != '' THEN process_name END) as process_name,
				MAX(CASE WHEN process_exe IS NOT NULL AND process_exe != '' THEN process_exe END) as process_exe
			FROM all_sessions
			GROUP BY endpoint1_ip, endpoint2_ip, endpoint1_port, endpoint2_port, protocol, session_type
		)
		SELECT * FROM aggregated_flows
	`

	// 查询总数
	countQuery := "SELECT COUNT(*) FROM (" + query + ")"
	var total int
	err := s.db.QueryRow(countQuery).Scan(&total)
	if err != nil {
		fmt.Printf("Count query error: %v\n", err)
		return nil, fmt.Errorf("count query failed: %w", err)
	}
	fmt.Printf("Total session flows: %d\n", total)

	// 添加排序和分页
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "packet_count"
	}
	sortOrder := strings.ToUpper(opts.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	query += fmt.Sprintf(" ORDER BY %s %s LIMIT ? OFFSET ?", sortBy, sortOrder)
	
	fmt.Printf("Executing query with limit=%d, offset=%d\n", opts.Limit, opts.Offset)

	// 执行查询
	rows, err := s.db.Query(query, opts.Limit, opts.Offset)
	if err != nil {
		fmt.Printf("Query error: %v\n", err)
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	// 解析结果
	flows := []*model.SessionFlow{}
	id := int64(1)
	rowNum := 0
	for rows.Next() {
		rowNum++
		var flow model.SessionFlow
		var firstSeenStr, lastSeenStr string
		var srcPort, dstPort sql.NullInt64
		var processPID sql.NullInt32
		var processName, processExe sql.NullString
		
		err := rows.Scan(
			&flow.SrcIP,
			&flow.DstIP,
			&srcPort,
			&dstPort,
			&flow.Protocol,
			&flow.PacketCount,
			&flow.BytesCount,
			&firstSeenStr,
			&lastSeenStr,
			&flow.SessionType,
			&processPID,
			&processName,
			&processExe,
		)
		if err != nil {
			fmt.Printf("Row %d scan error: %v\n", rowNum, err)
			continue
		}

		flow.ID = id
		id++
		flow.SrcPort = uint16(srcPort.Int64)
		flow.DstPort = uint16(dstPort.Int64)
		flow.FirstSeen = firstSeenStr
		flow.LastSeen = lastSeenStr
		
		// 设置进程信息
		if processPID.Valid {
			flow.ProcessPID = processPID.Int32
		}
		flow.ProcessName = processName.String
		flow.ProcessExe = processExe.String
		
		// 计算持续时间 - 尝试多种时间格式
		timeFormats := []string{
			"2006-01-02 15:04:05.999999999 -0700 MST",  // Go time.Time.String() format
			"2006-01-02 15:04:05.999999999 -0700",
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05",
			time.RFC3339Nano,
			time.RFC3339,
		}
		
		var firstSeen, lastSeen time.Time
		var err1, err2 error
		
		for _, format := range timeFormats {
			if firstSeen, err1 = time.Parse(format, firstSeenStr); err1 == nil {
				break
			}
		}
		for _, format := range timeFormats {
			if lastSeen, err2 = time.Parse(format, lastSeenStr); err2 == nil {
				break
			}
		}
		
		if err1 == nil && err2 == nil && !lastSeen.Before(firstSeen) {
			flow.Duration = lastSeen.Sub(firstSeen).Seconds()
		} else {
			flow.Duration = 0
			if rowNum <= 3 {
				fmt.Printf("  Time parse: first='%s' (err:%v), last='%s' (err:%v)\n", 
					firstSeenStr, err1, lastSeenStr, err2)
			}
		}

		flows = append(flows, &flow)
		
		if rowNum <= 3 {
			fmt.Printf("Flow %d: %s:%d -> %s:%d, %s, packets=%d, bytes=%d\n", 
				id-1, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol, flow.PacketCount, flow.BytesCount)
		}
	}
	
	fmt.Printf("Scanned %d rows, returned %d session flows (out of %d total)\n", rowNum, len(flows), total)

	return &model.SessionFlowResult{
		Total: total,
		Data:  flows,
	}, nil
}

// getTableName 获取表名
func getTableName(table model.TableType) string {
	switch table {
	case model.TableDNS:
		return "dns_sessions"
	case model.TableHTTP:
		return "http_sessions"
	case model.TableICMP:
		return "icmp_sessions"
	default:
		return ""
	}
}

// buildSearchClause 构建搜索条件
func buildSearchClause(table model.TableType, searchType, searchText string) string {
	// 如果没有搜索文本，返回空字符串（不限制）
	if searchText == "" {
		return "1=1"
	}

	switch searchType {
	case "ip":
		return "(src_ip LIKE ? OR dst_ip LIKE ?)"
	case "port":
		return "(src_port = ? OR dst_port = ?)"
	case "domain":
		if table == model.TableDNS {
			return "domain LIKE ?"
		} else if table == model.TableHTTP {
			return "host LIKE ?"
		}
		return "1=1"
	case "all":
		// 全文搜索
		switch table {
		case model.TableDNS:
			return "(src_ip LIKE ? OR dst_ip LIKE ? OR domain LIKE ? OR response_ip LIKE ?)"
		case model.TableHTTP:
			return "(src_ip LIKE ? OR dst_ip LIKE ? OR host LIKE ? OR path LIKE ? OR user_agent LIKE ?)"
		case model.TableICMP:
			return "(src_ip LIKE ? OR dst_ip LIKE ?)"
		}
	}

	return "1=1"
}

// scanSession 扫描会话数据
func scanSession(rows *sql.Rows, table model.TableType) (*model.Session, error) {
	session := &model.Session{}
	session.Type = string(table)

	switch table {
	case model.TableDNS:
		var processPID sql.NullInt32
		var processName, processExe sql.NullString
		err := rows.Scan(
			&session.ID,
			&session.Timestamp,
			&session.FiveTuple.SrcIP,
			&session.FiveTuple.SrcPort,
			&session.FiveTuple.DstIP,
			&session.FiveTuple.DstPort,
			&session.FiveTuple.Protocol,
			&session.Domain,
			&session.QueryType,
			&session.ResponseIP,
			&session.PayloadSize,
			&session.TTL,
			&processPID,
			&processName,
			&processExe,
		)
		if err == nil {
			if processPID.Valid {
				session.ProcessPID = processPID.Int32
			}
			session.ProcessName = processName.String
			session.ProcessExe = processExe.String
		}
		return session, err

	case model.TableHTTP:
		var contentType, postData sql.NullString
		var processPID sql.NullInt32
		var processName, processExe sql.NullString
		err := rows.Scan(
			&session.ID,
			&session.Timestamp,
			&session.FiveTuple.SrcIP,
			&session.FiveTuple.SrcPort,
			&session.FiveTuple.DstIP,
			&session.FiveTuple.DstPort,
			&session.FiveTuple.Protocol,
			&session.Method,
			&session.Host,
			&session.Path,
			&session.StatusCode,
			&session.UserAgent,
			&session.PayloadSize,
			&session.TTL,
			&contentType,
			&postData,
			&processPID,
			&processName,
			&processExe,
		)
		if err == nil {
			session.ContentType = contentType.String
			session.PostData = postData.String
			if processPID.Valid {
				session.ProcessPID = processPID.Int32
			}
			session.ProcessName = processName.String
			session.ProcessExe = processExe.String
		}
		return session, err

	case model.TableICMP:
		var processPID sql.NullInt32
		var processName, processExe sql.NullString
		err := rows.Scan(
			&session.ID,
			&session.Timestamp,
			&session.FiveTuple.SrcIP,
			&session.FiveTuple.DstIP,
			&session.FiveTuple.Protocol,
			&session.ICMPType,
			&session.ICMPCode,
			&session.ICMPSeq,
			&session.PayloadSize,
			&session.TTL,
			&processPID,
			&processName,
			&processExe,
		)
		if err == nil {
			if processPID.Valid {
				session.ProcessPID = processPID.Int32
			}
			session.ProcessName = processName.String
			session.ProcessExe = processExe.String
		}
		return session, err

	default:
		return nil, fmt.Errorf("unknown table type: %s", table)
	}
}


