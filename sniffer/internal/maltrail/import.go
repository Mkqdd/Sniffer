package maltrail

import (
	"bufio"
	"encoding/csv"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sniffer/pkg/model"
)

// MaltrailRuleNamePrefix 导入的 Maltrail 规则名称前缀，用于识别与批量删除
const MaltrailRuleNamePrefix = "Maltrail: "

var ipv4Regex = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

// TrailEntry 表示从 Maltrail 加载的一条 trail
type TrailEntry struct {
	Value  string // 域名、IP 或 URL
	Type   string // "domain", "ip", "url"
	Source string // 来源描述，如 static/malware/apt_glasses.txt
}

// Category names (as requested)
const (
	CategoryStaticMalware   = "trails.static.malware"
	CategoryStaticMalicious = "trails.static.malicious"
	CategoryStaticSuspicious = "trails.static.suspicious"
	CategoryCustom          = "trails.custom"
	CategoryFeed            = "trails.feed"
)

// LoadTrailsFromStaticDir 从 Maltrail 的 trails/static 目录加载所有 .txt（静态规则）
// baseDir 为 maltrail 根目录，如 /path/to/maltrail
func LoadTrailsFromStaticDir(baseDir string) ([]TrailEntry, error) {
	staticDir := filepath.Join(baseDir, "trails", "static")
	var entries []TrailEntry
	err := filepath.Walk(staticDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".txt") {
			return nil
		}
		rel, _ := filepath.Rel(staticDir, path)
		relUnix := filepath.ToSlash(rel)
		source := "static/" + relUnix
		fileEntries, err := loadTrailsFromFile(path, source)
		if err != nil {
			return nil
		}
		entries = append(entries, fileEntries...)
		return nil
	})
	return entries, err
}

// LoadTrailsFromCSV 从 Maltrail 的 trails.csv（编译后的动态规则）加载
// 每行格式: trail,info,reference
func LoadTrailsFromCSV(csvPath string) ([]TrailEntry, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var entries []TrailEntry
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		trail := strings.TrimSpace(row[0])
		if trail == "" || strings.HasPrefix(trail, "#") {
			continue
		}
		info := strings.TrimSpace(row[1])
		ref := strings.TrimSpace(row[2])
		t := classifyTrail(trail)
		entries = append(entries, TrailEntry{
			Value:  trail,
			Type:   t,
			Source: "csv:" + info + " " + ref,
		})
	}
	return entries, nil
}

func loadTrailsFromFile(path, source string) ([]TrailEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []TrailEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			line = line[strings.Index(line, "://")+3:]
		}
		line = strings.TrimRight(line, "/")
		t := classifyTrail(line)
		entries = append(entries, TrailEntry{Value: line, Type: t, Source: source})
	}
	return entries, scanner.Err()
}

func classifyTrail(value string) string {
	if ipv4Regex.MatchString(value) {
		return "ip"
	}
	if strings.Contains(value, "/") || strings.Contains(value, "://") {
		return "url"
	}
	return "domain"
}

// ConvertToAlertRules 将 TrailEntry 转为 Sniffer 告警规则
// namePrefix 用于标识来源，如 "Maltrail: "；导入前若 clearPrefix 非空则先删除该前缀的规则
func ConvertToAlertRules(entries []TrailEntry, namePrefix, alertLevel string) []*model.AlertRule {
	if alertLevel == "" {
		alertLevel = "warning"
	}
	if namePrefix == "" {
		namePrefix = MaltrailRuleNamePrefix
	}
	rules := make([]*model.AlertRule, 0, len(entries))
	seen := make(map[string]bool)
	for _, e := range entries {
		key := e.Type + ":" + e.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		rule := &model.AlertRule{
			Enabled:     true,
			AlertLevel:  alertLevel,
			Description: e.Source,
		}
		name := namePrefix + e.Value
		if len(name) > 120 {
			name = name[:117] + "..."
		}
		rule.Name = name
		switch e.Type {
		case "ip":
			rule.RuleType = "dst_ip"
			rule.ConditionField = "dst_ip"
			rule.ConditionOperator = "equals"
			rule.ConditionValue = e.Value
		case "url":
			rule.RuleType = "http"
			rule.ConditionField = "url"
			rule.ConditionOperator = "contains"
			rule.ConditionValue = e.Value
		default:
			rule.RuleType = "dns"
			rule.ConditionField = "domain"
			rule.ConditionOperator = "contains"
			rule.ConditionValue = e.Value
		}
		rules = append(rules, rule)
	}
	return rules
}

// HeuristicRuleNamePrefix 启发式规则名称前缀，用于识别与去重
const HeuristicRuleNamePrefix = "启发式: "

// GetDefaultHeuristicRules 返回 Sniffer 内置的启发式告警规则（类似 Maltrail sensor 启发式）
func GetDefaultHeuristicRules() []*model.AlertRule {
	return []*model.AlertRule{
		{
			Name:              "启发式: 长域名(可疑)",
			RuleType:          "dns",
			Enabled:           true,
			ConditionField:    "domain_length",
			ConditionOperator: "gt",
			ConditionValue:    "40",
			AlertLevel:        "info",
			Description:       "域名长度>40字符，常见于 DGA 或恶意子域",
		},
		{
			Name:              "启发式: User-Agent 含 sqlmap",
			RuleType:          "http",
			Enabled:           true,
			ConditionField:    "user_agent",
			ConditionOperator: "contains",
			ConditionValue:    "sqlmap",
			AlertLevel:        "critical",
			Description:       "SQL 注入扫描工具",
		},
		{
			Name:              "启发式: User-Agent 含 nikto",
			RuleType:          "http",
			Enabled:           true,
			ConditionField:    "user_agent",
			ConditionOperator: "contains",
			ConditionValue:    "nikto",
			AlertLevel:        "warning",
			Description:       "Web 扫描器",
		},
		{
			Name:              "启发式: User-Agent 含 nmap",
			RuleType:          "http",
			Enabled:           true,
			ConditionField:    "user_agent",
			ConditionOperator: "contains",
			ConditionValue:    "nmap",
			AlertLevel:        "warning",
			Description:       "端口/服务扫描",
		},
		{
			Name:              "启发式: 直接以 IP 访问 HTTP 且路径可疑",
			RuleType:          "http",
			Enabled:           true,
			ConditionField:    "url",
			ConditionOperator: "regex",
			ConditionValue:    `^\d+\.\d+\.\d+\.\d+.*/.*\.(exe|dll|scr|bat|ps1)$`,
			AlertLevel:        "warning",
			Description:       "疑似通过 IP 直连下载可执行文件",
		},
	}
}
