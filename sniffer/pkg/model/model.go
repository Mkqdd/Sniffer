package model

import (
	"time"
)

// Packet represents a raw captured packet
// 原始数据包
type Packet struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp" ts_type:"string"`
	Length      int       `json:"length"`
	CaptureLen  int       `json:"capture_len"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`   // TCP, UDP, ICMP, etc.
	Data        []byte    `json:"-"`          // Raw packet data
	LayerInfo   string    `json:"layer_info"` // Layer summary
	
	// 进程关联信息 (100%准确方案)
	ProcessPID  int32  `json:"process_pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessExe  string `json:"process_exe,omitempty"`
}

// FiveTuple represents the 5-tuple for session identification
// 五元组
type FiveTuple struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// String returns a string representation of the 5-tuple
func (ft FiveTuple) String() string {
	return ft.SrcIP + ":" + ft.DstIP + ":" + ft.Protocol
}

// Session represents a parsed protocol session
// 会话（派生数据）
type Session struct {
	ID          int64      `json:"id"`
	Timestamp   time.Time  `json:"timestamp" ts_type:"string"`
	FiveTuple   FiveTuple  `json:"five_tuple"`
	Type        string     `json:"type"`         // DNS, HTTP, ICMP
	Domain      string     `json:"domain,omitempty"`       // For DNS/HTTP
	QueryType   string     `json:"query_type,omitempty"`   // For DNS
	ResponseIP  string     `json:"response_ip,omitempty"`  // For DNS
	Method      string     `json:"method,omitempty"`       // For HTTP
	Path        string     `json:"path,omitempty"`         // For HTTP
	StatusCode  int        `json:"status_code,omitempty"`  // For HTTP
	Host        string     `json:"host,omitempty"`         // For HTTP
	UserAgent   string     `json:"user_agent,omitempty"`   // For HTTP
	ContentType string     `json:"content_type,omitempty"` // For HTTP
	PostData    string     `json:"post_data,omitempty"`    // For HTTP POST
	ICMPType    uint8      `json:"icmp_type,omitempty"`    // For ICMP
	ICMPCode    uint8      `json:"icmp_code,omitempty"`    // For ICMP
	ICMPSeq     uint16     `json:"icmp_seq,omitempty"`     // For ICMP
	PayloadSize int        `json:"payload_size"`
	TTL         time.Time  `json:"ttl" ts_type:"string"`                    // Expiration time
	
	// 进程关联信息（从Packet继承）
	ProcessPID  int32  `json:"process_pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessExe  string `json:"process_exe,omitempty"`
}

// Metrics represents real-time capture metrics
// 实时指标
type Metrics struct {
	Timestamp       time.Time `json:"timestamp" ts_type:"string"`
	Interface       string    `json:"interface"`
	IsCapturing     bool      `json:"is_capturing"`
	IsPaused        bool      `json:"is_paused"`
	PacketsTotal    int64     `json:"packets_total"`
	PacketsDropped  int64     `json:"packets_dropped"`
	BytesTotal      int64     `json:"bytes_total"`
	PacketsPerSec   float64   `json:"packets_per_sec"`
	BytesPerSec     float64   `json:"bytes_per_sec"`
	RawCount        int       `json:"raw_count"`
	DNSCount        int       `json:"dns_count"`
	HTTPCount       int       `json:"http_count"`
	ICMPCount       int       `json:"icmp_count"`
}

// NetworkInterface represents a network interface
// 网络接口
type NetworkInterface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
	IsPhysical  bool     `json:"is_physical"`
	IsLoopback  bool     `json:"is_loopback"`
	IsUp        bool     `json:"is_up"`
}

// ExportRequest represents a PCAP export request
// 导出请求
type ExportRequest struct {
	StartTime int64  `json:"start_time"` // Unix timestamp
	EndTime   int64  `json:"end_time"`   // Unix timestamp
	Filter    string `json:"filter"`     // BPF filter
}

// TableType represents different data tables
// 表类型
type TableType string

const (
	TableRaw  TableType = "raw"
	TableDNS  TableType = "dns"
	TableHTTP TableType = "http"
	TableICMP TableType = "icmp"
)

// DashboardStats represents dashboard statistics
// 仪表盘统计数据
type DashboardStats struct {
	// 基础统计
	TotalPackets    int64   `json:"total_packets"`
	TotalBytes      int64   `json:"total_bytes"`
	AvgPacketSize   float64 `json:"avg_packet_size"`
	CaptureTime     int64   `json:"capture_time"` // 秒
	
	// 协议分布
	TCPCount        int64   `json:"tcp_count"`
	UDPCount        int64   `json:"udp_count"`
	ICMPCount       int64   `json:"icmp_count"`
	OtherCount      int64   `json:"other_count"`
	
	// 会话统计（与协议统计相同，前端期望这些字段名）
	DNSSessions     int64   `json:"dns_sessions"`
	HTTPSessions    int64   `json:"http_sessions"`
	ICMPSessions    int64   `json:"icmp_sessions"`
	SessionFlowsCount int64 `json:"session_flows_count"` // 会话流总数
	
	// Top 统计
	TopSrcIPs       []IPStat   `json:"top_src_ips"`
	TopDstIPs       []IPStat   `json:"top_dst_ips"`
	TopPorts        []PortStat `json:"top_ports"`
	TopDomains      []DomainStat `json:"top_domains"`
	
	// 流量趋势（最近60个数据点，每秒一个）
	TrafficTrend    []TrafficPoint `json:"traffic_trend"`
	
	// 存储信息
	StorageSize     int64   `json:"storage_size"`
	PcapFileCount   int     `json:"pcap_file_count"`
}

// IPStat IP统计
type IPStat struct {
	IP     string `json:"ip"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
}

// PortStat 端口统计
type PortStat struct {
	Port   uint16 `json:"port"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
}

// DomainStat 域名统计
type DomainStat struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// TrafficPoint 流量趋势点
type TrafficPoint struct {
	Timestamp int64   `json:"timestamp"` // Unix timestamp
	Packets   int64   `json:"packets"`
	Bytes     int64   `json:"bytes"`
	PPS       float64 `json:"pps"`
	BPS       float64 `json:"bps"`
}

// AlertRule 告警规则
type AlertRule struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	RuleType          string    `json:"rule_type"`          // dst_ip, dns, http, icmp, etc.
	Enabled           bool      `json:"enabled"`
	ConditionField    string    `json:"condition_field"`    // 条件字段
	ConditionOperator string    `json:"condition_operator"` // equals, contains, regex
	ConditionValue    string    `json:"condition_value"`    // 条件值
	AlertLevel        string    `json:"alert_level"`        // info, warning, error, critical
	Description       string    `json:"description"`
	CreatedAt         time.Time `json:"created_at" ts_type:"string"`
	UpdatedAt         time.Time `json:"updated_at" ts_type:"string"`
}

// AlertLog 告警记录
type AlertLog struct {
	ID              int64     `json:"id"`
	RuleID          int64     `json:"rule_id"`
	RuleName        string    `json:"rule_name"`
	RuleType        string    `json:"rule_type"`
	AlertLevel      string    `json:"alert_level"`
	TriggeredAt     time.Time `json:"triggered_at" ts_type:"string"`          // 首次触发时间
	LastTriggeredAt time.Time `json:"last_triggered_at" ts_type:"string"`     // 最后触发时间
	TriggerCount    int64     `json:"trigger_count"`         // 触发次数
	SrcIP           string    `json:"src_ip,omitempty"`
	DstIP           string    `json:"dst_ip,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	Domain          string    `json:"domain,omitempty"`
	URL             string    `json:"url,omitempty"`
	Details         string    `json:"details"`
	Acknowledged    bool      `json:"acknowledged"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty" ts_type:"string"`
	AcknowledgedBy  string    `json:"acknowledged_by,omitempty"`
}

// AlertRuleQuery 告警规则查询参数
type AlertRuleQuery struct {
	RuleType string `json:"rule_type,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// MaltrailEvent Maltrail 异常流量事件（由 sensor.py 通过 UDP 上报）
type MaltrailEvent struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp" ts_type:"string"`
	SensorName string    `json:"sensor_name"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    string    `json:"src_port"`
	DstIP      string    `json:"dst_ip"`
	DstPort    string    `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	TrailType  string    `json:"trail_type"`  // DNS, IP, URL, HTTP, UA, etc.
	Trail      string    `json:"trail"`       // 匹配到的 trail 内容
	Info       string    `json:"info"`        // 分类/描述
	Reference  string    `json:"reference"`  // 来源如 (heuristic), (static)
	CreatedAt  time.Time `json:"created_at" ts_type:"string"`
}

// MaltrailEventQuery 查询参数
type MaltrailEventQuery struct {
	Limit   int `json:"limit"`
	Offset  int `json:"offset"`
	SortBy  string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

// MaltrailEventList 分页结果
type MaltrailEventList struct {
	Data  []*MaltrailEvent `json:"data"`
	Total int64            `json:"total"`
}

// AlertLogQuery 告警记录查询参数
type AlertLogQuery struct {
	RuleID       *int64     `json:"rule_id,omitempty"`
	RuleType     string     `json:"rule_type,omitempty"`
	AlertLevel   string     `json:"alert_level,omitempty"`
	Acknowledged *bool      `json:"acknowledged,omitempty"`
	StartTime    *time.Time `json:"start_time,omitempty" ts_type:"string"`
	EndTime      *time.Time `json:"end_time,omitempty" ts_type:"string"`
	Limit        int        `json:"limit"`
	Offset       int        `json:"offset"`
	SortBy       string     `json:"sort_by"`
	SortOrder    string     `json:"sort_order"`
}
