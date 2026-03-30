package parser

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ErrNotTLS = errors.New("not TLS")

// TLS 常量
const (
	tlsRecordHandshake  = 22
	handshakeClientHello = 1
	handshakeCertificate = 11
)

// TLSResult 从单个 TCP 载荷解析出的 TLS 检测结果（仅当完整记录在单包内时有效）
type TLSResult struct {
	JA3MD5   string // Client Hello 的 JA3 MD5（32 位十六进制小写），空表示非 Client Hello 或解析失败
	CertSHA1 string // 服务端证书 SHA1（40 位十六进制小写），空表示非 Certificate 或解析失败
}

// ParseTLSFromPacket 从已解析的 Packet 中尝试提取 TCP 载荷并解析 TLS，得到 JA3 或证书 SHA1
// 仅当目的端口为 443/8443/4433 等常见 TLS 端口且 TCP 载荷含完整 TLS 记录时有效
func ParseTLSFromPacket(data []byte) (TLSResult, error) {
	var out TLSResult
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return out, ErrNotTLS
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload
	if len(payload) < 5 {
		return out, ErrNotTLS
	}
	return parseTLSRecord(payload)
}

func parseTLSRecord(payload []byte) (TLSResult, error) {
	var out TLSResult
	if len(payload) < 5 {
		return out, nil
	}
	// TLS Record: Type(1) Version(2) Length(2)
	recType := payload[0]
	if recType != tlsRecordHandshake {
		return out, nil
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recLen {
		return out, nil // 不完整记录，忽略
	}
	body := payload[5 : 5+recLen]
	if len(body) < 4 {
		return out, nil
	}
	// Handshake: Type(1) Length(3)
	handshakeType := body[0]
	handshakeLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+handshakeLen {
		return out, nil
	}
	handshakeBody := body[4 : 4+handshakeLen]

	switch handshakeType {
	case handshakeClientHello:
		ja3, err := parseClientHelloJA3(handshakeBody)
		if err == nil && ja3 != "" {
			out.JA3MD5 = ja3
		}
	case handshakeCertificate:
		sha1Hex, err := parseCertificateSHA1(handshakeBody)
		if err == nil && sha1Hex != "" {
			out.CertSHA1 = sha1Hex
		}
	}
	return out, nil
}

// TLSRecord 表示从 TCP 字节流中切分出的单个 TLS record（已去掉 5 字节 record header）
type TLSRecord struct {
	Type byte
	Body []byte
}

// ParseTLSRecords 从缓冲区头部切分所有完整 TLS records（任意 Type），返回 records 与消费的字节数。
func ParseTLSRecords(buf []byte) (records []TLSRecord, consumed int) {
	for len(buf) >= 5 {
		recLen := int(binary.BigEndian.Uint16(buf[3:5]))
		need := 5 + recLen
		if recLen < 0 || need > len(buf) {
			break
		}
		recType := buf[0]
		body := buf[5:need]
		records = append(records, TLSRecord{Type: recType, Body: body})
		consumed += need
		buf = buf[need:]
	}
	return records, consumed
}

// ParseTLSHandshakeMessagesFromBuffer 从 Handshake 字节流（握手消息连续拼接，不含 TLS record header）
// 解析出所有完整 handshake message。支持同一个 TLS record 内多个 handshake，也支持 handshake 跨 record 分片。
func ParseTLSHandshakeMessagesFromBuffer(buf []byte) (results []TLSResult, consumed int) {
	for len(buf) >= 4 {
		handshakeType := buf[0]
		handshakeLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		need := 4 + handshakeLen
		if handshakeLen < 0 || need > len(buf) {
			break
		}
		body := buf[4:need]
		var out TLSResult
		switch handshakeType {
		case handshakeClientHello:
			if ja3, err := parseClientHelloJA3(body); err == nil && ja3 != "" {
				out.JA3MD5 = ja3
			}
		case handshakeCertificate:
			if sha1Hex, err := parseCertificateSHA1(body); err == nil && sha1Hex != "" {
				out.CertSHA1 = sha1Hex
			}
		}
		if out.JA3MD5 != "" || out.CertSHA1 != "" {
			results = append(results, out)
		}
		consumed += need
		buf = buf[need:]
	}
	return results, consumed
}

// ParseTLSRecordsFromBuffer 从缓冲区头部解析所有完整的 TLS 记录，用于 TCP 重组后的流。
// 返回解析出的 TLS 结果列表以及消费的字节数。非 Handshake 类型的记录会被跳过但计入 consumed。
func ParseTLSRecordsFromBuffer(buf []byte) (results []TLSResult, consumed int) {
	for len(buf) >= 5 {
		recLen := int(binary.BigEndian.Uint16(buf[3:5]))
		need := 5 + recLen
		if recLen < 0 || need > len(buf) {
			break
		}
		rec := buf[:need]
		res, _ := parseTLSRecord(rec)
		if res.JA3MD5 != "" || res.CertSHA1 != "" {
			results = append(results, res)
		}
		consumed += need
		buf = buf[need:]
	}
	return results, consumed
}

// parseClientHelloJA3 解析 Client Hello，生成 JA3 字符串并返回 MD5 的 32 位十六进制小写
func parseClientHelloJA3(body []byte) (string, error) {
	// ClientHello: Version(2) Random(32) SessionIDLen(1) SessionID(N) CipherSuitesLen(2) CipherSuites(N) CompressionLen(1) Compression(N) ExtensionsLen(2) Extensions(N)
	if len(body) < 2+32+1 {
		return "", fmt.Errorf("client hello too short")
	}
	version := binary.BigEndian.Uint16(body[0:2])
	pos := 2 + 32 // skip random
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return "", fmt.Errorf("client hello truncated")
	}
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(body) {
		return "", fmt.Errorf("client hello truncated")
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return "", fmt.Errorf("client hello truncated")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(body) {
		return "", fmt.Errorf("client hello truncated")
	}

	// JA3: SSLVersion, Ciphers, Extensions, EllipticCurves, EcPointFormats
	sslVer := strconv.Itoa(int(version))
	ciphers := extractCipherSuites(body[2+32+1+sidLen+2 : 2+32+1+sidLen+2+cipherLen])
	extList, curves, pointFmts := extractExtensions(body[pos:extEnd])
	ja3Str := strings.Join([]string{sslVer, ciphers, extList, curves, pointFmts}, ",")
	return md5Hex(ja3Str), nil
}

func extractCipherSuites(b []byte) string {
	var parts []string
	for i := 0; i+2 <= len(b); i += 2 {
		parts = append(parts, strconv.Itoa(int(binary.BigEndian.Uint16(b[i:i+2]))))
	}
	return strings.Join(parts, "-")
}

func extractExtensions(b []byte) (extList string, curves string, pointFmts string) {
	var extIDs []string
	for i := 0; i+4 <= len(b); {
		extID := binary.BigEndian.Uint16(b[i : i+2])
		extLen := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		extIDs = append(extIDs, strconv.Itoa(int(extID)))
		if i+4+extLen > len(b) {
			i += 4 + extLen
			continue
		}
		extData := b[i+4 : i+4+extLen]
		if extID == 0x000a && len(extData) >= 2 {
			groupLen := int(binary.BigEndian.Uint16(extData[0:2]))
			var grps []string
			for j := 2; j+2 <= 2+groupLen && j+2 <= len(extData); j += 2 {
				grps = append(grps, strconv.Itoa(int(binary.BigEndian.Uint16(extData[j:j+2]))))
			}
			curves = strings.Join(grps, "-")
		}
		if extID == 0x000b && len(extData) >= 1 {
			n := int(extData[0])
			var fmts []string
			for j := 1; j < 1+n && j < len(extData); j++ {
				fmts = append(fmts, strconv.Itoa(int(extData[j])))
			}
			pointFmts = strings.Join(fmts, "-")
		}
		i += 4 + extLen
	}
	extList = strings.Join(extIDs, "-")
	return extList, curves, pointFmts
}

func parseCertificateSHA1(body []byte) (string, error) {
	// TLS 1.2 Certificate:
	//   certificate_list_length(3)
	//   certificate_list:
	//     cert_length(3) + cert_der
	//
	// TLS 1.3 Certificate:
	//   certificate_request_context_length(1) + context
	//   certificate_list_length(3)
	//   certificate_list:
	//     cert_length(3) + cert_der + extensions_length(2) + extensions

	// Try TLS 1.2 first (most common in older pcaps)
	if sha1Hex, ok, err := parseCertificateSHA1TLS12(body); err == nil && ok {
		return sha1Hex, nil
	}
	// Fallback TLS 1.3 layout (still only works when handshake is in cleartext records)
	if sha1Hex, ok, err := parseCertificateSHA1TLS13(body); err == nil && ok {
		return sha1Hex, nil
	}
	return "", nil
}

func parseCertificateSHA1TLS12(body []byte) (sha1Hex string, ok bool, err error) {
	if len(body) < 3 {
		return "", false, fmt.Errorf("tls12 certificate message too short")
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if listLen < 3 || len(body) < 3+listLen {
		return "", false, fmt.Errorf("tls12 certificate list truncated")
	}
	rest := body[3 : 3+listLen]
	if len(rest) < 3 {
		return "", false, nil
	}
	firstCertLen := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
	if firstCertLen <= 0 || len(rest) < 3+firstCertLen {
		return "", false, nil
	}
	certDER := rest[3 : 3+firstCertLen]
	h := sha1.Sum(certDER)
	return hex.EncodeToString(h[:]), true, nil
}

func parseCertificateSHA1TLS13(body []byte) (sha1Hex string, ok bool, err error) {
	if len(body) < 1+3 {
		return "", false, fmt.Errorf("tls13 certificate message too short")
	}
	ctxLen := int(body[0])
	pos := 1 + ctxLen
	if pos+3 > len(body) {
		return "", false, fmt.Errorf("tls13 certificate context truncated")
	}
	listLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
	pos += 3
	if listLen < 3 || pos+listLen > len(body) {
		return "", false, fmt.Errorf("tls13 certificate list truncated")
	}
	rest := body[pos : pos+listLen]
	if len(rest) < 3 {
		return "", false, nil
	}
	firstCertLen := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
	i := 3
	if firstCertLen <= 0 || i+firstCertLen > len(rest) {
		return "", false, nil
	}
	certDER := rest[i : i+firstCertLen]
	i += firstCertLen
	// Skip extensions (2 bytes length + data)
	if i+2 > len(rest) {
		return "", false, nil
	}
	extLen := int(binary.BigEndian.Uint16(rest[i : i+2]))
	i += 2
	if i+extLen > len(rest) {
		return "", false, nil
	}
	h := sha1.Sum(certDER)
	return hex.EncodeToString(h[:]), true, nil
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
