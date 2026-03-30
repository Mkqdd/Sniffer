package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"

	"sniffer/internal/parser"
	"sniffer/internal/sslblacklist"
	"sniffer/internal/store"
	"sniffer/pkg/model"
)

// 这是给 replay 模式用的离线扫描器：
// 直接从 pcap 中重组 TCP/TLS，提取 JA3 / 证书 SHA1，命中 SSLBlackList 后写入指定 SQLite 数据库的 alert_logs。

type flowInfo struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

type tlsStream struct {
	netFlow  gopacket.Flow
	tcpFlow  gopacket.Flow
	flow     flowInfo
	buf      []byte
	hsBuf    []byte
	onResult func(flow flowInfo, res parser.TLSResult)
}

func (s *tlsStream) Reassembled(segs []tcpassembly.Reassembly) {
	for _, seg := range segs {
		if seg.Skip > 0 {
			s.buf = nil
			s.hsBuf = nil
			continue
		}
		if len(seg.Bytes) == 0 {
			continue
		}
		s.buf = append(s.buf, seg.Bytes...)

		for {
			records, consumed := parser.ParseTLSRecords(s.buf)
			if consumed == 0 {
				break
			}
			s.buf = s.buf[consumed:]
			for _, rec := range records {
				if rec.Type == 22 && len(rec.Body) > 0 { // Handshake
					s.hsBuf = append(s.hsBuf, rec.Body...)
				}
			}
			for {
				results, hsConsumed := parser.ParseTLSHandshakeMessagesFromBuffer(s.hsBuf)
				if hsConsumed == 0 {
					break
				}
				s.hsBuf = s.hsBuf[hsConsumed:]
				for _, res := range results {
					if s.onResult != nil {
						s.onResult(s.flow, res)
					}
				}
			}
		}
	}
}

func (s *tlsStream) ReassemblyComplete() {}

type tlsFactory struct {
	onResult func(flow flowInfo, res parser.TLSResult)
}

func (f *tlsFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	fi := flowInfo{
		srcIP:   netFlow.Src().String(),
		dstIP:   netFlow.Dst().String(),
		srcPort: endpointPort(tcpFlow.Src()),
		dstPort: endpointPort(tcpFlow.Dst()),
	}
	return &tlsStream{netFlow: netFlow, tcpFlow: tcpFlow, flow: fi, onResult: f.onResult}
}

func endpointPort(ep gopacket.Endpoint) uint16 {
	raw := ep.Raw()
	if len(raw) >= 2 {
		return uint16(raw[0])<<8 | uint16(raw[1])
	}
	var p uint16
	_, _ = fmt.Sscanf(ep.String(), "%d", &p)
	return p
}

func isTLSPort(p uint16) bool {
	return p == 443 || p == 8443 || p == 4433
}

func main() {
	var (
		pcapPath  = flag.String("pcap", "", "pcap file path")
		dbPath    = flag.String("db", "", "sqlite db path (domain/output/sniffer.db)")
		blDir     = flag.String("blacklist-dir", "SSLBlackList", "SSLBlackList directory (contains ja3_fingerprints.csv, sslblacklist.csv)")
		flushEvery = flag.Duration("flush-every", 5*time.Second, "tcpassembly flush interval")
	)
	flag.Parse()

	if *pcapPath == "" || *dbPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	bl := sslblacklist.NewBlacklist()
	if err := bl.LoadFromDir(*blDir); err != nil {
		log.Fatalf("load blacklist from %q: %v", *blDir, err)
	}

	st, err := store.NewSQLiteStore(*dbPath, 7)
	if err != nil {
		log.Fatalf("open db %q: %v", *dbPath, err)
	}
	defer st.Close()

	ruleID, err := st.EnsureSSLBlacklistRule()
	if err != nil {
		log.Fatalf("ensure ssl blacklist rule: %v", err)
	}

	f, err := os.Open(*pcapPath)
	if err != nil {
		log.Fatalf("open pcap %q: %v", *pcapPath, err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatalf("pcap reader: %v", err)
	}

	var firstLayer gopacket.LayerType
	switch r.LinkType() {
	case layers.LinkTypeEthernet:
		firstLayer = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		firstLayer = layers.LayerTypeLinuxSLL
	case layers.LinkTypeNull:
		firstLayer = layers.LayerTypeLoopback
	case layers.LinkTypeRaw:
		firstLayer = layers.LayerTypeIPv4
	default:
		firstLayer = layers.LayerTypeEthernet
	}

	onResult := func(flow flowInfo, res parser.TLSResult) {
		now := time.Now()
		if res.JA3MD5 != "" {
			if reason, ok := bl.LookupJA3(res.JA3MD5); ok {
				_ = st.CreateAlertLog(&model.AlertLog{
					RuleID:      ruleID,
					RuleName:    "SSL Blacklist (JA3)",
					RuleType:    "ssl_blacklist",
					AlertLevel:  "critical",
					TriggeredAt: now,
					SrcIP:       flow.srcIP,
					DstIP:       flow.dstIP,
					Protocol:    "TCP",
					Domain:      "ja3:" + res.JA3MD5,
					Details:     fmt.Sprintf("恶意 JA3 指纹: %s [%s]", res.JA3MD5, reason),
				})
			}
		}
		if res.CertSHA1 != "" {
			if reason, ok := bl.LookupCertSHA1(res.CertSHA1); ok {
				_ = st.CreateAlertLog(&model.AlertLog{
					RuleID:      ruleID,
					RuleName:    "SSL Blacklist (证书SHA1)",
					RuleType:    "ssl_blacklist",
					AlertLevel:  "critical",
					TriggeredAt: now,
					SrcIP:       flow.srcIP,
					DstIP:       flow.dstIP,
					Protocol:    "TCP",
					Domain:      "certsha1:" + res.CertSHA1,
					Details:     fmt.Sprintf("恶意证书 SHA1: %s [%s]", res.CertSHA1, reason),
				})
			}
		}
	}

	pool := tcpassembly.NewStreamPool(&tlsFactory{onResult: onResult})
	asm := tcpassembly.NewAssembler(pool)

	var (
		totalPackets int
		lastFlush    time.Time
	)

	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		totalPackets++
		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}

		pkt := gopacket.NewPacket(data, firstLayer, gopacket.NoCopy)
		net := pkt.NetworkLayer()
		tcpL := pkt.Layer(layers.LayerTypeTCP)
		if net == nil || tcpL == nil {
			continue
		}
		tcp, ok := tcpL.(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			continue
		}
		// 只处理常见 TLS 端口，减少开销
		if !isTLSPort(uint16(tcp.DstPort)) && !isTLSPort(uint16(tcp.SrcPort)) {
			continue
		}
		asm.AssembleWithTimestamp(net.NetworkFlow(), tcp, ts)
		if lastFlush.IsZero() {
			lastFlush = ts
		}
		if ts.Sub(lastFlush) >= *flushEvery {
			asm.FlushOlderThan(ts.Add(-60 * time.Second))
			lastFlush = ts
		}
	}

	asm.FlushAll()
	log.Printf("sslblacklist_scan completed: packets=%d db=%s pcap=%s", totalPackets, *dbPath, *pcapPath)
}

