# FastMonitor - 网络流量监控与威胁检测工具

## 📖 项目简介

**FastMonitor** 是一款基于 **Wails 框架**开发开源的**跨平台网络流量监控与威胁检测工具**,集成了数据包分析、进程关联、会话流统计、威胁情报检测、地理位置可视化等功能于一体。
  
### 核心特性

- 🚀 **高性能抓包引擎**: 基于 gopacket/pcap 实现,支持数据包实时处理，并对五元组会话/DNS/ICMP/HTTP进行分类展示
- 🎯 **精准进程关联**: 自动将网络流量与进程绑定,支持主流操作系统
- 🛡️ **智能威胁检测**: 支持自定义病毒等威胁情报IOC规则,实时告警
- 📊 **实时仪表盘**: 大屏展示网络流量、协议分布、TOP排行
- 💾 **数据持久化**: SQLite存储 + PCAP文件归档,支持历史回溯
- 🎨 **现代化界面**: Vue 3 + Element Plus + 浅色/深色主题


<img width="1384" height="861" alt="image" src="https://github.com/user-attachments/assets/2d475dbe-60b7-4e3c-acec-b220b0e28691" />

-  **上图：系统网络会话监听，支持进程关联**
<img width="1384" height="861" alt="image" src="https://github.com/user-attachments/assets/e0e8fece-8818-40cf-9a73-c680d244fd3f" />

-  **上图：网络流量监控，数据外发及时发现**
  
<img width="1507" height="775" alt="截屏2025-10-08 14 10 46" src="https://github.com/user-attachments/assets/060488a4-f12a-4a78-933d-eafd9992ff5f" />

-  **上图：对当前计算机进行流量进程监听，支持监听系统进程、DNS请求、网络请求等，实现安全态势感知**

---

## 🎯 主要用途

| 应用场景 | 功能描述 |
|---------|---------|
| **网络监控** | 实时监控内网流量,发现异常外联和数据泄露 |
| **安全威胁分析** | 检测C2通信、钓鱼攻击、恶意软件行为 |
| **流量审计** | 记录所有网络活动,支持取证和合规审计 |
| **性能诊断** | 分析网络瓶颈、异常流量、协议分布 |
| **开发调试** | 抓包分析HTTP/DNS/ICMP等协议细节 |
| **安全研究** | 恶意样本行为分析、IOC提取 |

---

## 🚀 快速开始

### 构建运行

```bash
# 克隆仓库
git clone git@github.com:DeepShield-AI/sniffer.git
cd sniffer

# 一键部署 
./deploy_linux.sh

# 导入模型和测试数据
RF_app.pkl & lable.json => ./model/
test*.pcap => ./domain/test_pcaps/

# 启动系统
./start.sh

```
---

## 🏗️ 系统架构

```
┌────────────────────────────────────────────────────────┐
│                    PCAP File Input                     │
└────────────────────┬───────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│      Stage 1: DNS Information Extraction               │
│  ┌──────────────┐      ┌──────────────┐                │
│  │ DNS Packet   │      │ Flow Tuple   │                │
│  │ Parsing      │      │ Extraction   │                │
│  │ - Query      │      │ - IPv4       │                │
│  │   extraction │      │   handling   │                │
│  │ - Response   │      │ - TCP/UDP    │                │
│  │   parsing    │      │ - Flow       │                │
│  │ - A-record   │      │ merging      │                │
│  │   extraction │      │              │                │
│  └──────────────┘      └──────────────┘                │
└────────────────────┬───────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│      Stage 2: DNS-Flow Association & Domain Grouping   │
│  ┌───────────────┐     ┌──────────────┐                │
│  │ IP → Domain   │     │ Flow-Domain  │                │
│  │ Mapping       │     │ Association  │                │
│  │ - Reverse     │     │ - Domain     │                │
│  │   lookup      │     │   grouping   │                │
│  │ - Multi-domain│     │ - Flow merge │                │
│  │   support     │     │              │                │
│  └───────────────┘     └──────────────┘                │
└────────────────────┬───────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│      Stage 3: Aho-Corasick Automaton Matching          │
│  ┌──────────────┐      ┌──────────────┐                │
│  │ Build AC     │      │ Domain       │                │
│  │ Automaton    │      │ Matching     │                │
│  │ - Suffix Trie│      │ - Longest    │                │
│  │ - Failure    │      │   match      │                │
│  │   links      │      │ - Classify   │                │
│  │              │      │   output     │                │
│  └──────────────┘      └──────────────┘                │
└────────────────────┬───────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│      Stage 4: Output Organization & Classification     │
│  ┌──────────────┐      ┌──────────────┐                │
│  │ Classified   │      │ Unknown Flow │                │
│  │ Directories  │      │ Directory    │                │
│  │ - bytedance/ │      │ - unknown/   │                │
│  │ - mozilla/   │      │              │                │
│  └──────────────┘      └──────────────┘                │
└────────────────────────────────────────────────────────┘
```

---

## 📚 功能模块详解

### 1️⃣ 网卡选择 (Network Interface Selection)

#### 功能描述
- 自动检测系统所有可用网络接口(网卡)
- 支持物理网卡、虚拟网卡、回环接口、VPN隧道
- 实时显示网卡状态和流量统计

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **网卡列表** | 显示所有接口名称、IP地址、MAC地址、状态 |
| **网卡筛选** | 支持按接口类型(有线/无线/虚拟)筛选 |
| **实时状态** | 显示接口是否激活、当前流量速率 |
| **快速切换** | 一键切换抓包网卡,无需重启 |
| **权限检测** | 自动检测抓包权限,提示管理员权限 |

#### 技术实现
```go
// 网卡枚举 (internal/capture/capture.go)
func ListInterfaces() ([]*NetworkInterface, error) {
    devices, _ := pcap.FindAllDevs()
    for _, device := range devices {
        // 解析IP、MAC、MTU等信息
        // 检测网卡状态和类型
    }
}
```
---

### 2️⃣ 仪表盘 (Dashboard)

#### 功能描述
提供实时网络流量监控的大屏展示,包括统计图表、TOP排行、协议分布等可视化组件。

#### 核心功能
| 模块 | 说明 |
|-----|------|
| **实时流量曲线** | 显示上下行流量的时间趋势(bps/pps) |
| **协议分布饼图** | TCP/UDP/ICMP/DNS/HTTP等协议占比 |
| **TOP源地址** | 流量最大的前10个源IP |
| **TOP目标地址** | 流量最大的前10个目标IP |
| **TOP进程排行** | 网络活动最频繁的前10个进程 |
| **告警统计** | 实时显示Critical/Warning/Info告警数量 |

#### 可视化组件
```typescript
// 流量趋势图 (ECharts折线图)
{
  xAxis: { data: timestamps },     // 时间轴
  series: [
    { name: '上行流量', data: txBytes },
    { name: '下行流量', data: rxBytes }
  ]
}

// 协议分布图 (ECharts饼图)
{
  series: [{
    type: 'pie',
    data: [
      { name: 'TCP', value: 45.2 },
      { name: 'UDP', value: 30.1 },
      { name: 'ICMP', value: 5.3 }
    ]
  }]
}
```

#### 数据刷新
- **默认刷新间隔**: 2秒
- **数据窗口**: 最近60秒/5分钟/1小时可选
- **自适应性能**: 流量过大时自动降低刷新率

#### 大屏模式
- **触发方式**: 点击仪表盘右上角"全屏"按钮
- **布局风格**: 深色主题 + 赛博朋克风格边框
- **特殊效果**: 数字滚动动画、图表自适应缩放
- **退出方式**: 按ESC键或点击右上角退出按钮

---

### 3️⃣ 数据包 (Packet Capture)

#### 功能描述
实时捕获并解析网络数据包,支持多层协议分析和数据包过滤。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **实时抓包** | 每秒捕获数千个数据包并解码 |
| **多层解析** | 解析Ethernet → IP → TCP/UDP → HTTP/DNS |
| **字段提取** | 自动提取源/目标IP、端口、协议、载荷 |
| **BPF过滤器** | 支持Berkeley Packet Filter语法 |
| **数据包详情** | 显示原始十六进制和ASCII载荷 |
| **导出功能** | 导出为PCAP格式供Wireshark分析 |

#### 数据包字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `timestamp` | 捕获时间(纳秒精度) | 2025-10-08 14:32:15.123456 |
| `src_ip` | 源IP地址 | 192.168.1.100 |
| `dst_ip` | 目标IP地址 | 8.8.8.8 |
| `src_port` | 源端口 | 51234 |
| `dst_port` | 目标端口 | 443 |
| `protocol` | 传输层协议 | TCP / UDP / ICMP |
| `length` | 数据包长度(字节) | 1420 |
| `payload` | 应用层载荷(Base64编码) | SGVsbG8gV29ybGQ= |
| `process_name` | 关联进程名(如果成功映射) | chrome.exe |

#### BPF过滤器示例
```bash
# 只捕获HTTP流量
tcp port 80 or tcp port 8080

# 只捕获DNS查询
udp port 53

# 只捕获特定IP的流量
host 192.168.1.100

# 只捕获出站流量
src net 192.168.0.0/16

# 组合条件
tcp and dst port 443 and not host 127.0.0.1
```

#### 技术实现
```go
// 数据包捕获主循环 (internal/capture/capture.go)
func (c *Capture) Start() {
    handle, _ := pcap.OpenLive(c.device, snapLen, promiscuous, timeout)
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    for packet := range packetSource.Packets() {
        // 解析Ethernet层
        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        
        // 解析IP层
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        
        // 解析TCP/UDP层
        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        
        // 提取载荷
        payload := packet.ApplicationLayer().Payload()
        
        // 发送到处理管道
        c.packetChan <- parsedPacket
    }
}
```

---

### 4️⃣ DNS解析 (DNS Queries)

#### 功能描述
专门捕获并分析DNS查询和响应,检测恶意域名和DNS隧道。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **DNS记录解析** | 解析A/AAAA/CNAME/MX/TXT等记录类型 |
| **查询统计** | 统计最频繁查询的域名TOP10 |
| **响应时间** | 记录DNS服务器响应延迟 |
| **失败查询** | 记录NXDOMAIN和SERVFAIL响应 |
| **恶意域名检测** | 匹配威胁情报中的C2域名 |

#### DNS字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `query_name` | 查询域名 | www.example.com |
| `query_type` | 记录类型 | A / AAAA / CNAME |
| `response_code` | 响应码 | NOERROR / NXDOMAIN |
| `answers` | 解析结果(JSON数组) | ["93.184.216.34"] |
| `dns_server` | DNS服务器IP | 8.8.8.8 |
| `latency_ms` | 响应时间(毫秒) | 23 |

#### 威胁检测规则
```go
// DNS规则匹配 (内置银狐C2域名)
rule := &AlertRule{
    Name:              "银狐病毒 - C2域名检测",
    RuleType:          "dns",
    ConditionField:    "domain",
    ConditionOperator: "contains",
    ConditionValue:    "12-18.qq-weixin.org,8004.twilight.zip,addr.ktsr.cc",
    AlertLevel:        "critical",
}

// 匹配逻辑
func matchDNSRule(queryName string, rule *AlertRule) bool {
    domains := strings.Split(rule.ConditionValue, ",")
    for _, domain := range domains {
        if strings.Contains(queryName, domain) {
            return true  // 触发告警!
        }
    }
    return false
}
```

---

### 5️⃣ HTTP流量 (HTTP Requests)

#### 功能描述
捕获并分析HTTP/HTTPS流量,提取URL、User-Agent、状态码等关键信息。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **HTTP请求解析** | 提取Method/URL/Headers/Body |
| **HTTP响应解析** | 提取Status Code/Content-Type/Length |
| **HTTPS元数据** | 即使不解密也能提取SNI域名 |
| **恶意URL检测** | 匹配钓鱼URL和恶意下载链接 |
| **User-Agent分析** | 识别浏览器/爬虫/恶意软件UA |

#### HTTP字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `method` | HTTP方法 | GET / POST / PUT |
| `url` | 完整URL | https://example.com/api/data |
| `host` | 目标主机名 | example.com |
| `user_agent` | 客户端标识 | Mozilla/5.0 ... |
| `status_code` | 响应状态码 | 200 / 404 / 500 |
| `content_type` | 内容类型 | application/json |
| `content_length` | 响应大小(字节) | 4096 |

#### 威胁检测规则
```go
// HTTP规则 - 检测恶意PNG下载
rule := &AlertRule{
    Name:              "银狐病毒 - 恶意PNG下载检测",
    RuleType:          "http",
    ConditionField:    "url",
    ConditionOperator: "regex",
    ConditionValue:    "(?i)183\\.167\\.230\\.197:18743/(0CFA042F|5B16AF14|57BC9B7E|test)\\.Png",
    AlertLevel:        "critical",
}

// HTTP规则 - 检测钓鱼URL
rule := &AlertRule{
    Name:              "银狐病毒 - 钓鱼URL检测",
    RuleType:          "http",
    ConditionField:    "url",
    ConditionOperator: "contains",
    ConditionValue:    "cuomicufvhehy.cn",
    AlertLevel:        "critical",
}
```

#### HTTPS流量处理
⚠️ **注意**: FastMonitor **不解密HTTPS流量**(无中间人攻击),但仍可提取:
- **SNI(Server Name Indication)**: TLS握手时的明文域名
- **证书信息**: 服务器证书的颁发者和有效期
- **流量统计**: 上下行字节数和数据包数量

---

### 6️⃣ ICMP流量 (ICMP Packets)

#### 功能描述
捕获并分析ICMP数据包,包括ping请求、traceroute、网络不可达等消息。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **ICMP类型识别** | Echo Request/Reply、Destination Unreachable |
| **Ping统计** | 往返时延(RTT)、丢包率 |
| **网络诊断** | 识别路由问题、MTU问题 |
| **异常检测** | 检测ICMP Flood攻击、ICMP隧道 |

#### ICMP字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `type` | ICMP类型 | 8(Echo Request) / 0(Echo Reply) |
| `code` | ICMP代码 | 0(网络不可达) / 1(主机不可达) |
| `sequence` | 序列号 | 12345 |
| `identifier` | 标识符 | 54321 |
| `rtt_ms` | 往返时延(毫秒) | 15.2 |

#### 常见ICMP类型
| Type | Code | 说明 |
|------|------|------|
| 0 | 0 | Echo Reply (Ping响应) |
| 3 | 0-15 | Destination Unreachable (目标不可达) |
| 8 | 0 | Echo Request (Ping请求) |
| 11 | 0-1 | Time Exceeded (TTL超时,traceroute) |

---

### 7️⃣ 会话流统计 (Session Flow Statistics)

#### 功能描述
将零散的数据包聚合为会话流(Session),统计每个会话的流量、时延、数据包数等指标。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **五元组聚合** | 按(SrcIP, DstIP, SrcPort, DstPort, Protocol)聚合 |
| **双向流量统计** | 分别统计上下行字节数和数据包数 |
| **会话时长** | 记录会话开始时间和持续时长 |
| **地理位置** | 自动查询目标IP的国家/城市 |
| **进程绑定** | 自动关联发起该会话的进程 |
| **状态追踪** | 识别TCP连接状态(SYN/ACK/FIN/RST) |

#### 会话字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `session_key` | 会话唯一标识(哈希) | a3f8c2d1... |
| `src_ip` | 源IP | 192.168.1.100 |
| `dst_ip` | 目标IP | 93.184.216.34 |
| `src_port` | 源端口 | 51234 |
| `dst_port` | 目标端口 | 443 |
| `protocol` | 协议 | TCP |
| `tx_bytes` | 上行字节数 | 1024000 |
| `rx_bytes` | 下行字节数 | 5120000 |
| `tx_packets` | 上行数据包数 | 1500 |
| `rx_packets` | 下行数据包数 | 3800 |
| `start_time` | 会话开始时间 | 2025-10-08 14:32:15 |
| `duration_sec` | 会话持续时长(秒) | 125.3 |
| `dst_country` | 目标国家 | United States |
| `dst_city` | 目标城市 | Ashburn |
| `process_name` | 关联进程 | chrome.exe |

#### 会话聚合逻辑
```go
// 会话Key计算 (双向对称哈希)
func sessionKey(srcIP, dstIP string, srcPort, dstPort uint16, proto string) string {
    // 确保双向流量使用相同Key
    if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
        srcIP, dstIP = dstIP, srcIP
        srcPort, dstPort = dstPort, srcPort
    }
    return fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// 会话更新
func updateSession(packet *Packet) {
    key := sessionKey(packet.SrcIP, packet.DstIP, ...)
    session := sessions[key]
    
    // 更新统计
    if packet.SrcIP == session.SrcIP {
        session.TxBytes += packet.Length
        session.TxPackets++
    } else {
        session.RxBytes += packet.Length
        session.RxPackets++
    }
    
    session.LastSeen = time.Now()
}
```

---

###  设置 (Settings)

#### 功能描述
系统配置管理,包括抓包参数、告警规则、性能优化等设置。


#### 配置文件
```yaml
# config.yaml
capture:
  device: "eth0"                     # 抓包网卡
  bpf_filter: "tcp or udp"           # BPF过滤器
  promiscuous: true                  # 混杂模式
  snaplen: 65535                     # 捕获长度

storage:
  db_path: "./data/sniffer.db"       # SQLite数据库路径
  pcap_dir: "./data/pcap"            # PCAP保存目录
  pcap_rotation: "1h"                # PCAP轮转周期
  retention_days: 7                  # 数据保留天数

performance:
  ring_buffer_size: 10000            # 环形缓冲区大小
  batch_insert_size: 100             # 批量插入大小
  refresh_interval: 2000             # 前端刷新间隔(毫秒)

alert:
  enabled: true                      # 启用告警
  min_level: "warning"               # 最低告警级别
  notification: true                 # 桌面通知

geoip:
  db_path: "./data/GeoLite2-City.mmdb"  # GeoIP数据库路径
```

#### 高级设置
- **调试模式**: 启用详细日志输出
- **导出格式**: 选择JSON/CSV/PCAP导出格式
- **主题切换**: 深色/浅色主题切换
- **语言设置**: 中文/英文界面语言

---

## 🙏 致谢

- [Wails](https://wails.io/) - 跨平台桌面应用框架
- [gopacket](https://github.com/google/gopacket) - Go数据包处理库
- [ECharts](https://echarts.apache.org/) - 数据可视化图表库
- [Element Plus](https://element-plus.org/) - Vue 3 UI组件库
