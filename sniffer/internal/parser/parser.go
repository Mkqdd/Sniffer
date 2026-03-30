package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"sniffer/pkg/model"
)

var (
	ErrNotDNS   = errors.New("not a DNS packet")
	ErrNotHTTP  = errors.New("not an HTTP packet")
	ErrNotICMP  = errors.New("not an ICMP packet")
	ErrParseErr = errors.New("parse error")
)

// ParsePacket parses a raw packet and extracts basic information
func ParsePacket(data []byte, timestamp time.Time) (*model.Packet, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	pkt := &model.Packet{
		Timestamp:  timestamp,
		Length:     len(data),
		CaptureLen: len(data),
		Data:       data,
		LayerInfo:  "",
	}

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		pkt.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		pkt.Protocol = ip.NextHeader.String()
	}

	// Extract transport layer ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pkt.SrcPort = uint16(tcp.SrcPort)
		pkt.DstPort = uint16(tcp.DstPort)
		pkt.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.Protocol = "UDP"
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		pkt.Protocol = "ICMP"
	}

	// Build layer summary
	var layers []string
	for _, layer := range packet.Layers() {
		layers = append(layers, layer.LayerType().String())
	}
	pkt.LayerInfo = strings.Join(layers, " > ")

	return pkt, nil
}

// ParseDNS parses a DNS packet
func ParseDNS(pkt *model.Packet) (*model.Session, error) {
	// DNS typically uses UDP port 53
	if pkt.Protocol != "UDP" || (pkt.SrcPort != 53 && pkt.DstPort != 53) {
		return nil, ErrNotDNS
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)
	
	// Get UDP payload
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, ErrNotDNS
	}

	udp, _ := udpLayer.(*layers.UDP)
	payload := udp.Payload

	// Parse DNS
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseErr, err)
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: "UDP",
		},
		Type:        "DNS",
		PayloadSize: len(payload),
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour), // 7 days default
		
		// 继承进程信息
		ProcessPID:  pkt.ProcessPID,
		ProcessName: pkt.ProcessName,
		ProcessExe:  pkt.ProcessExe,
	}

	// Extract query information
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		session.Domain = strings.TrimSuffix(q.Name, ".")
		session.QueryType = dns.TypeToString[q.Qtype]
	}

	// Extract answer information (for responses)
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				session.ResponseIP = a.A.String()
				break
			} else if aaaa, ok := rr.(*dns.AAAA); ok {
				session.ResponseIP = aaaa.AAAA.String()
				break
			}
		}
	}

	return session, nil
}

// ParseHTTP parses an HTTP packet (HTTP/1.x only, not HTTPS)
func ParseHTTP(pkt *model.Packet) (*model.Session, error) {
	// HTTP typically uses TCP
	if pkt.Protocol != "TCP" {
		return nil, ErrNotHTTP
	}

	// Common HTTP ports
	isHTTPPort := pkt.SrcPort == 80 || pkt.DstPort == 80 ||
		pkt.SrcPort == 8080 || pkt.DstPort == 8080 ||
		pkt.SrcPort == 8000 || pkt.DstPort == 8000

	if !isHTTPPort {
		return nil, ErrNotHTTP
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)

	// Get TCP payload
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, ErrNotHTTP
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) == 0 {
		return nil, ErrNotHTTP
	}

	// Check if it looks like HTTP
	if !isHTTPData(payload) {
		return nil, ErrNotHTTP
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: "TCP",
		},
		Type:        "HTTP",
		PayloadSize: len(payload),
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour),
		
		// 继承进程信息
		ProcessPID:  pkt.ProcessPID,
		ProcessName: pkt.ProcessName,
		ProcessExe:  pkt.ProcessExe,
	}

	// Parse HTTP headers
	reader := bufio.NewReader(bytes.NewReader(payload))
	
	// Read first line
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return session, nil // Return partial session
	}

	firstLine = strings.TrimSpace(firstLine)
	parts := strings.Fields(firstLine)

	// Check if it's a request or response
	if len(parts) >= 3 {
		if strings.HasPrefix(parts[0], "HTTP/") {
			// Response
			var code int
			if _, err := fmt.Sscanf(parts[1], "%d", &code); err == nil {
				session.StatusCode = code
			}
		} else {
			// Request
			session.Method = parts[0]
			session.Path = parts[1]
		}
	}

	// Parse headers
	contentLength := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		
		if strings.HasPrefix(lineLower, "host:") {
			session.Host = strings.TrimSpace(line[5:])
		} else if strings.HasPrefix(lineLower, "user-agent:") {
			session.UserAgent = strings.TrimSpace(line[11:])
		} else if strings.HasPrefix(lineLower, "content-type:") {
			session.ContentType = strings.TrimSpace(line[13:])
		} else if strings.HasPrefix(lineLower, "content-length:") {
			fmt.Sscanf(line[15:], "%d", &contentLength)
		}
	}

	// 如果是 POST/PUT 请求，尝试读取请求体
	if (session.Method == "POST" || session.Method == "PUT") && contentLength > 0 {
		// 限制最大读取 10KB 避免内存问题
		maxRead := contentLength
		if maxRead > 10240 {
			maxRead = 10240
		}
		
		bodyBuf := make([]byte, maxRead)
		n, _ := reader.Read(bodyBuf)
		if n > 0 {
			bodyStr := string(bodyBuf[:n])
			contentTypeLower := strings.ToLower(session.ContentType)
			
			// 根据 Content-Type 判断
			isTextContent := strings.Contains(contentTypeLower, "text/") ||
				strings.Contains(contentTypeLower, "json") ||
				strings.Contains(contentTypeLower, "xml") ||
				strings.Contains(contentTypeLower, "urlencoded") ||
				strings.Contains(contentTypeLower, "form-data")
			
			// 如果是明确的文本类型或通过启发式判断为文本
			if isTextContent || isPrintableText(bodyStr) {
				// URL编码解码（application/x-www-form-urlencoded）
				if strings.Contains(contentTypeLower, "urlencoded") {
					decoded, err := decodeURLEncoded(bodyStr)
					if err == nil {
						session.PostData = decoded
					} else {
						session.PostData = bodyStr
					}
				} else if strings.Contains(contentTypeLower, "json") {
					// JSON格式化（简单处理）
					session.PostData = bodyStr
				} else {
					session.PostData = bodyStr
				}
			} else {
				session.PostData = fmt.Sprintf("[二进制数据, %d 字节]", contentLength)
			}
		}
	}

	return session, nil
}

// decodeURLEncoded 解码 URL 编码的表单数据
func decodeURLEncoded(s string) (string, error) {
	// 将 & 分隔的键值对格式化为易读格式
	pairs := strings.Split(s, "&")
	var result strings.Builder
	
	for i, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			// URL 解码
			key, err1 := decodeURIComponent(parts[0])
			value, err2 := decodeURIComponent(parts[1])
			
			if err1 == nil && err2 == nil {
				if i > 0 {
					result.WriteString("\n")
				}
				result.WriteString(fmt.Sprintf("%s: %s", key, value))
			} else {
				// 解码失败，保留原始
				if i > 0 {
					result.WriteString("\n")
				}
				result.WriteString(pair)
			}
		} else {
			if i > 0 {
				result.WriteString("\n")
			}
			result.WriteString(pair)
		}
	}
	
	return result.String(), nil
}

// decodeURIComponent 简单的URL解码（类似JavaScript的decodeURIComponent）
func decodeURIComponent(s string) (string, error) {
	// 替换 + 为空格
	s = strings.ReplaceAll(s, "+", " ")
	
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			// 十六进制解码
			hex := s[i+1 : i+3]
			var b byte
			_, err := fmt.Sscanf(hex, "%x", &b)
			if err == nil {
				result.WriteByte(b)
				i += 3
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	
	return result.String(), nil
}

// isPrintableText 检查字符串是否主要是可打印文本
func isPrintableText(s string) bool {
	if len(s) == 0 {
		return false
	}
	
	printable := 0
	total := 0
	for _, r := range s {
		total++
		// 允许更多字符：ASCII可见字符、空白字符、扩展ASCII、中文等
		if (r >= 32 && r <= 126) || r == '\n' || r == '\r' || r == '\t' || 
		   (r >= 128 && r < 256) || // 扩展ASCII
		   (r >= 0x4e00 && r <= 0x9fff) { // 中文
			printable++
		}
	}
	
	// 降低阈值到 70%，更容易识别为文本
	return total > 0 && float64(printable)/float64(total) > 0.7
}

// ParseICMP parses an ICMP packet
func ParseICMP(pkt *model.Packet) (*model.Session, error) {
	if pkt.Protocol != "ICMP" && pkt.Protocol != "ICMPv6" {
		return nil, ErrNotICMP
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)

	// Get ICMP layer
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		// Try ICMPv6
		icmpLayer = packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			return nil, ErrNotICMP
		}
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			Protocol: "ICMP",
		},
		Type:        "ICMP",
		PayloadSize: pkt.CaptureLen,
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour),
		
		// 继承进程信息
		ProcessPID:  pkt.ProcessPID,
		ProcessName: pkt.ProcessName,
		ProcessExe:  pkt.ProcessExe,
	}

	// Extract ICMP details
	if icmp4, ok := icmpLayer.(*layers.ICMPv4); ok {
		session.ICMPType = uint8(icmp4.TypeCode.Type())
		session.ICMPCode = uint8(icmp4.TypeCode.Code())
		session.ICMPSeq = icmp4.Seq
	} else if icmp6, ok := icmpLayer.(*layers.ICMPv6); ok {
		session.ICMPType = uint8(icmp6.TypeCode.Type())
		session.ICMPCode = uint8(icmp6.TypeCode.Code())
	}

	return session, nil
}

// isHTTPData checks if data looks like HTTP
func isHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for HTTP methods or response
	httpPrefixes := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
		[]byte("HTTP/1."),
	}

	for _, prefix := range httpPrefixes {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}

	return false
}

// GetFiveTuple extracts the 5-tuple from a packet
func GetFiveTuple(pkt *model.Packet) model.FiveTuple {
	return model.FiveTuple{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}
}

