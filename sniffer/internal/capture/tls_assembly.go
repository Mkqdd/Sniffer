package capture

import (
	"encoding/binary"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"sniffer/internal/parser"
)

const tlsStreamMaxBuf = 256 * 1024 // 单流最大缓冲 256KB，防止恶意连接占满内存

// TLSFlowInfo 用于从重组后的 TLS 流上报五元组信息
type TLSFlowInfo struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// OnTLSResult 从重组流中解析出 JA3/Cert SHA1 时的回调
type OnTLSResult func(flow TLSFlowInfo, res parser.TLSResult)

// tlsStream 实现 tcpassembly.Stream，缓冲并解析 TLS 记录
type tlsStream struct {
	flow     TLSFlowInfo
	onResult OnTLSResult
	buf      []byte
	hsBuf    []byte
	mu       sync.Mutex
}

func (s *tlsStream) Reassembled(segs []tcpassembly.Reassembly) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seg := range segs {
		if seg.Skip > 0 {
			// 丢包或乱序跳过，清空缓冲避免错位
			s.buf = nil
			s.hsBuf = nil
			continue
		}
		if len(seg.Bytes) == 0 {
			continue
		}
		s.buf = append(s.buf, seg.Bytes...)
		if len(s.buf) > tlsStreamMaxBuf {
			s.buf = s.buf[len(s.buf)-tlsStreamMaxBuf/2:]
		}

		// 先按 TLS record 切分，再把 Handshake record 的 body 拼进 hsBuf 解析握手消息
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

			// 解析尽可能多的 handshake messages（支持跨 record 分片）
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

			if len(s.hsBuf) > tlsStreamMaxBuf {
				s.hsBuf = s.hsBuf[len(s.hsBuf)-tlsStreamMaxBuf/2:]
			}
		}
	}
}

func (s *tlsStream) ReassemblyComplete() {
	s.mu.Lock()
	s.buf = nil
	s.hsBuf = nil
	s.mu.Unlock()
}

// tlsStreamFactory 为每个 TCP 流创建 tlsStream，并注入 flow 与 callback
type tlsStreamFactory struct {
	onResult OnTLSResult
}

func (f *tlsStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	flow := TLSFlowInfo{
		SrcIP:   netFlow.Src().String(),
		DstIP:   netFlow.Dst().String(),
		SrcPort: endpointPort(tcpFlow.Src()),
		DstPort: endpointPort(tcpFlow.Dst()),
	}
	return &tlsStream{flow: flow, onResult: f.onResult}
}

func endpointPort(ep gopacket.Endpoint) uint16 {
	raw := ep.Raw()
	if len(raw) >= 2 {
		return binary.BigEndian.Uint16(raw)
	}
	u, _ := strconv.ParseUint(ep.String(), 10, 16)
	return uint16(u)
}
