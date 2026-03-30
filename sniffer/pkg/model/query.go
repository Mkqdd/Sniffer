package model

// QueryOptions 查询选项
type QueryOptions struct {
	Table      TableType `json:"table"`       // 表名
	Limit      int       `json:"limit"`       // 限制数量
	Offset     int       `json:"offset"`      // 偏移量
	SortBy     string    `json:"sort_by"`     // 排序字段
	SortOrder  string    `json:"sort_order"`  // 排序方向 (asc/desc)
	SearchText string    `json:"search_text"` // 搜索文本
	SearchType string    `json:"search_type"` // 搜索类型 (ip/port/domain/all)
}

// QueryResult 查询结果
type QueryResult struct {
	Total int          `json:"total"` // 总数
	Data  []*Session   `json:"data"`  // 数据
}

// SessionFlowQuery 会话流查询选项
type SessionFlowQuery struct {
	Limit     int    `json:"limit"`      // 限制数量
	Offset    int    `json:"offset"`     // 偏移量
	SortBy    string `json:"sort_by"`    // 排序字段
	SortOrder string `json:"sort_order"` // 排序方向
}

// SessionFlow 会话流统计
type SessionFlow struct {
	ID            int64     `json:"id"`
	SrcIP         string    `json:"src_ip"`
	DstIP         string    `json:"dst_ip"`
	SrcPort       uint16    `json:"src_port"`
	DstPort       uint16    `json:"dst_port"`
	Protocol      string    `json:"protocol"`
	PacketCount   int64     `json:"packet_count"`   // 包数量
	BytesCount    int64     `json:"bytes_count"`    // 字节数
	FirstSeen     string    `json:"first_seen"`     // 首次出现时间
	LastSeen      string    `json:"last_seen"`      // 最后出现时间
	Duration      float64   `json:"duration"`       // 持续时间（秒）
	SessionType   string    `json:"session_type"`   // 会话类型 (DNS/HTTP/ICMP/Other)
	
	// 进程关联信息
	ProcessPID    int32     `json:"process_pid,omitempty"`
	ProcessName   string    `json:"process_name,omitempty"`
	ProcessExe    string    `json:"process_exe,omitempty"`
}

// SessionFlowResult 会话流查询结果
type SessionFlowResult struct {
	Total int            `json:"total"` // 总数
	Data  []*SessionFlow `json:"data"`  // 数据
}


