package server

import (
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"

	"sniffer/pkg/model"
)

// DashboardManager 仪表盘数据管理器
type DashboardManager struct {
	db              *sql.DB
	mu              sync.RWMutex
	trafficHistory  []model.TrafficPoint
	maxHistorySize  int
	startTime       time.Time
}

// NewDashboardManager 创建仪表盘管理器
func NewDashboardManager(db *sql.DB) *DashboardManager {
	return &DashboardManager{
		db:              db,
		trafficHistory:  make([]model.TrafficPoint, 0, 60),
		maxHistorySize:  60, // 保留最近60个数据点
		startTime:       time.Now(),
	}
}

// UpdateDatabase 更新数据库连接（用于重放模式切换数据库）
func (dm *DashboardManager) UpdateDatabase(db *sql.DB) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.db = db
	// 重置流量历史，因为切换了数据库
	dm.trafficHistory = make([]model.TrafficPoint, 0, 60)
	dm.startTime = time.Now()
}

// UpdateTrafficPoint 更新流量数据点
func (dm *DashboardManager) UpdateTrafficPoint(packets, bytes int64, pps, bps float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	point := model.TrafficPoint{
		Timestamp: time.Now().Unix(),
		Packets:   packets,
		Bytes:     bytes,
		PPS:       pps,
		BPS:       bps,
	}

	dm.trafficHistory = append(dm.trafficHistory, point)

	// 保持最大长度
	if len(dm.trafficHistory) > dm.maxHistorySize {
		dm.trafficHistory = dm.trafficHistory[1:]
	}
}

// GetDashboardStats 获取仪表盘统计数据
func (dm *DashboardManager) GetDashboardStats() (*model.DashboardStats, error) {
	stats := &model.DashboardStats{}

	// 基础统计 - 从session_flows表获取
	var totalPackets, totalBytes sql.NullInt64
	err := dm.db.QueryRow(`
		SELECT 
			COALESCE(SUM(packet_count), 0) as total_packets,
			COALESCE(SUM(bytes_count), 0) as total_bytes
		FROM session_flows
	`).Scan(&totalPackets, &totalBytes)
	
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query total stats: %w", err)
	}

	stats.TotalPackets = totalPackets.Int64
	stats.TotalBytes = totalBytes.Int64
	
	if stats.TotalPackets > 0 {
		stats.AvgPacketSize = float64(stats.TotalBytes) / float64(stats.TotalPackets)
	}

	// 捕获时间
	stats.CaptureTime = int64(time.Since(dm.startTime).Seconds())

	// 协议分布 - 从session_flows按协议统计
	dm.db.QueryRow(`SELECT COUNT(*) FROM session_flows WHERE protocol = 'TCP'`).Scan(&stats.TCPCount)
	dm.db.QueryRow(`SELECT COUNT(*) FROM session_flows WHERE protocol = 'UDP'`).Scan(&stats.UDPCount)
	dm.db.QueryRow(`SELECT COUNT(*) FROM session_flows WHERE protocol = 'ICMP' OR protocol = 'ICMPv6'`).Scan(&stats.ICMPCount)
	dm.db.QueryRow(`SELECT COUNT(*) FROM session_flows WHERE protocol NOT IN ('TCP', 'UDP', 'ICMP', 'ICMPv6')`).Scan(&stats.OtherCount)

	// 会话统计 - 从专门的会话表获取
	dm.db.QueryRow(`SELECT COUNT(*) FROM dns_sessions`).Scan(&stats.DNSSessions)
	dm.db.QueryRow(`SELECT COUNT(*) FROM http_sessions`).Scan(&stats.HTTPSessions)
	dm.db.QueryRow(`SELECT COUNT(*) FROM icmp_sessions`).Scan(&stats.ICMPSessions)
	
	// 会话流总数
	dm.db.QueryRow(`SELECT COUNT(*) FROM session_flows`).Scan(&stats.SessionFlowsCount)

	// Top 源IP（带流量统计）
	stats.TopSrcIPs, _ = dm.getTopIPsWithBytes("src_ip", 10)

	// Top 目标IP（带流量统计）
	stats.TopDstIPs, _ = dm.getTopIPsWithBytes("dst_ip", 10)

	// Top 端口
	stats.TopPorts, _ = dm.getTopPorts(10)

	// Top 域名
	stats.TopDomains, _ = dm.getTopDomains(10)

	// 流量趋势
	dm.mu.RLock()
	trafficHistoryLen := len(dm.trafficHistory)
	dm.mu.RUnlock()
	
	if trafficHistoryLen > 0 {
		// 如果有实时流量历史数据，使用它
		dm.mu.RLock()
		stats.TrafficTrend = make([]model.TrafficPoint, len(dm.trafficHistory))
		copy(stats.TrafficTrend, dm.trafficHistory)
		dm.mu.RUnlock()
	} else {
		// 如果没有实时数据（重放模式），从数据库计算流量趋势
		// 按时间窗口分组（每分钟一个数据点，最多60个点）
		trend, err := dm.getTrafficTrendFromDB()
		if err != nil {
			// 如果查询失败，返回空数组
			stats.TrafficTrend = []model.TrafficPoint{}
		} else {
			stats.TrafficTrend = trend
		}
	}

	return stats, nil
}

// getTopIPs 获取 Top IP 列表（旧版本，保留兼容性）
func (dm *DashboardManager) getTopIPs(column string, limit int) ([]model.IPStat, error) {
	return dm.getTopIPsWithBytes(column, limit)
}

// getTopIPsWithBytes 获取 Top IP 列表（带流量统计）- 从session_flows获取
func (dm *DashboardManager) getTopIPsWithBytes(column string, limit int) ([]model.IPStat, error) {
	query := fmt.Sprintf(`
		SELECT %s as ip, 
		       SUM(packet_count) as count, 
		       SUM(bytes_count) as bytes
		FROM session_flows
		WHERE %s != '' AND %s IS NOT NULL
		GROUP BY %s
		ORDER BY bytes DESC, count DESC
		LIMIT ?
	`, column, column, column, column)

	rows, err := dm.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []model.IPStat
	for rows.Next() {
		var stat model.IPStat
		var bytes sql.NullInt64
		if err := rows.Scan(&stat.IP, &stat.Count, &bytes); err != nil {
			continue
		}
		stat.Bytes = bytes.Int64
		result = append(result, stat)
	}

	return result, nil
}

// getTopPorts 获取 Top 端口列表
func (dm *DashboardManager) getTopPorts(limit int) ([]model.PortStat, error) {
	query := `
		SELECT port, COUNT(*) as count, SUM(payload_size) as bytes
		FROM (
			SELECT dst_port as port, payload_size FROM dns_sessions WHERE dst_port > 0
			UNION ALL
			SELECT dst_port as port, payload_size FROM http_sessions WHERE dst_port > 0
		)
		GROUP BY port
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := dm.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []model.PortStat
	for rows.Next() {
		var stat model.PortStat
		var port int
		var bytes sql.NullInt64
		if err := rows.Scan(&port, &stat.Count, &bytes); err != nil {
			continue
		}
		stat.Port = uint16(port)
		stat.Bytes = bytes.Int64
		result = append(result, stat)
	}

	return result, nil
}

// getTopDomains 获取 Top 域名列表
func (dm *DashboardManager) getTopDomains(limit int) ([]model.DomainStat, error) {
	query := `
		SELECT domain, COUNT(*) as count
		FROM (
			SELECT domain FROM dns_sessions WHERE domain != ''
			UNION ALL
			SELECT host as domain FROM http_sessions WHERE host != ''
		)
		GROUP BY domain
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := dm.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []model.DomainStat
	for rows.Next() {
		var stat model.DomainStat
		if err := rows.Scan(&stat.Domain, &stat.Count); err != nil {
			continue
		}
		result = append(result, stat)
	}

	return result, nil
}

// ProtocolStats 协议统计
type ProtocolStats struct {
	TCP   int64
	UDP   int64
	ICMP  int64
	Other int64
}

// GetProtocolDistribution 获取协议分布
func (dm *DashboardManager) GetProtocolDistribution() (*ProtocolStats, error) {
	stats := &ProtocolStats{}
	
	// 从各个表统计
	dm.db.QueryRow(`SELECT COUNT(*) FROM http_sessions`).Scan(&stats.TCP)
	dm.db.QueryRow(`SELECT COUNT(*) FROM dns_sessions`).Scan(&stats.UDP)
	dm.db.QueryRow(`SELECT COUNT(*) FROM icmp_sessions`).Scan(&stats.ICMP)
	
	return stats, nil
}

// TopStats 综合排名统计
type TopStats struct {
	IPs     []model.IPStat
	Ports   []model.PortStat
	Domains []model.DomainStat
}

// getTrafficTrendFromDB 从数据库计算流量趋势（用于重放模式）
func (dm *DashboardManager) getTrafficTrendFromDB() ([]model.TrafficPoint, error) {
	// 按时间窗口分组，每分钟一个数据点，最多60个点
	// 使用 first_seen 时间作为分组依据
	query := `
		SELECT 
			strftime('%Y-%m-%d %H:%M:00', first_seen) as time_window,
			SUM(packet_count) as packets,
			SUM(bytes_count) as bytes
		FROM session_flows
		WHERE first_seen IS NOT NULL
		GROUP BY time_window
		ORDER BY time_window DESC
		LIMIT 60
	`
	
	rows, err := dm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query traffic trend: %w", err)
	}
	defer rows.Close()
	
	var trend []model.TrafficPoint
	for rows.Next() {
		var timeWindow string
		var packets, bytes int64
		
		if err := rows.Scan(&timeWindow, &packets, &bytes); err != nil {
			continue
		}
		
		// 解析时间字符串为时间戳
		parsedTime, err := time.Parse("2006-01-02 15:04:05", timeWindow)
		if err != nil {
			continue
		}
		
		trend = append(trend, model.TrafficPoint{
			Timestamp: parsedTime.Unix(),
			Packets:   packets,
			Bytes:     bytes,
			PPS:       0, // 重放模式下不计算速率
			BPS:       0,
		})
	}
	
	// 反转顺序，使时间从早到晚
	for i, j := 0, len(trend)-1; i < j; i, j = i+1, j-1 {
		trend[i], trend[j] = trend[j], trend[i]
	}
	
	return trend, nil
}

// GetTopStats 获取综合排名
func (dm *DashboardManager) GetTopStats(limit int) (*TopStats, error) {
	stats := &TopStats{}
	
	// 获取所有 IP（源+目标）
	allIPsMap := make(map[string]*model.IPStat)
	
	srcIPs, _ := dm.getTopIPs("src_ip", 1000)
	for _, ip := range srcIPs {
		if _, exists := allIPsMap[ip.IP]; !exists {
			allIPsMap[ip.IP] = &model.IPStat{IP: ip.IP}
		}
		allIPsMap[ip.IP].Count += ip.Count
		allIPsMap[ip.IP].Bytes += ip.Bytes
	}
	
	dstIPs, _ := dm.getTopIPs("dst_ip", 1000)
	for _, ip := range dstIPs {
		if _, exists := allIPsMap[ip.IP]; !exists {
			allIPsMap[ip.IP] = &model.IPStat{IP: ip.IP}
		}
		allIPsMap[ip.IP].Count += ip.Count
		allIPsMap[ip.IP].Bytes += ip.Bytes
	}
	
	// 转换为切片并排序
	for _, ip := range allIPsMap {
		stats.IPs = append(stats.IPs, *ip)
	}
	sort.Slice(stats.IPs, func(i, j int) bool {
		return stats.IPs[i].Count > stats.IPs[j].Count
	})
	if len(stats.IPs) > limit {
		stats.IPs = stats.IPs[:limit]
	}
	
	stats.Ports, _ = dm.getTopPorts(limit)
	stats.Domains, _ = dm.getTopDomains(limit)
	
	return stats, nil
}


