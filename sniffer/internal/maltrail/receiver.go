package maltrail

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"sniffer/internal/config"
	"sniffer/internal/store"
	"sniffer/pkg/model"
)

// Receiver receives Maltrail sensor events via UDP and writes them to the store.
type Receiver struct {
	cfg   *config.Config
	store store.Store
}

// NewReceiver creates a Maltrail UDP receiver.
func NewReceiver(cfg *config.Config, st store.Store) *Receiver {
	return &Receiver{cfg: cfg, store: st}
}

// Run starts the UDP listener. It blocks until ctx is cancelled.
func (r *Receiver) Run(ctx context.Context) error {
	if !r.cfg.MaltrailEnabled || r.cfg.MaltrailUDPListen == "" {
		return nil
	}

	addr := r.cfg.MaltrailUDPListen
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("maltrail resolve udp %s: %w", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("maltrail listen udp %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("[maltrail] UDP receiver listening on %s", addr)

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("[maltrail] read error: %v", err)
				continue
			}
			if n == 0 {
				continue
			}
			r.handlePacket(buf[:n])
		}
	}
}

// handlePacket parses one UDP payload and writes to store.
// Maltrail sends: "<sec> <event_line>\n" where event_line is space-separated with optional quoted fields.
// event_line format: localtime sensor_name src_ip src_port dst_ip dst_port proto trail_type trail info reference
func (r *Receiver) handlePacket(data []byte) {
	line := bytes.TrimSpace(data)
	if len(line) == 0 {
		return
	}

	// First token: unix sec (optional; if not digit, whole line is event)
	firstSpace := bytes.IndexByte(line, ' ')
	if firstSpace <= 0 {
		log.Printf("[maltrail] skip: no space in payload (%d bytes)", len(line))
		return
	}
	secStr := string(line[:firstSpace])
	rest := bytes.TrimSpace(line[firstSpace:])
	if len(rest) == 0 {
		return
	}

	var sec int64
	if len(secStr) > 0 && secStr[0] >= '0' && secStr[0] <= '9' {
		var err error
		sec, err = strconv.ParseInt(secStr, 10, 64)
		if err != nil {
			log.Printf("[maltrail] skip: first word not unix sec %q", secStr)
			return
		}
	} else {
		// No leading sec (e.g. naive format): treat whole line as event, use current time
		sec = time.Now().Unix()
		rest = line
	}

	// Parse rest as maltrail event line: tokens with optional "..." quoting
	tokens := parseMaltrailLine(rest)
	// Expected: localtime, sensor_name, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference (11)
	// Minimum: localtime, sensor_name, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail (9)
	if len(tokens) < 9 {
		log.Printf("[maltrail] skip: got %d tokens (need >=9). raw rest: %q", len(tokens), truncate(rest, 200))
		return
	}

	ev := &model.MaltrailEvent{
		Timestamp:  time.Unix(sec, 0),
		SensorName: tokens[1],
		SrcIP:      tokens[2],
		SrcPort:    tokens[3],
		DstIP:      tokens[4],
		DstPort:    tokens[5],
		Protocol:   tokens[6],
		TrailType:  tokens[7],
		Trail:      tokens[8],
		Info:       "-",
		Reference:  "-",
	}
	if len(tokens) > 9 {
		ev.Info = tokens[9]
	}
	if len(tokens) > 10 {
		ev.Reference = tokens[10]
	}

	sqliteStore := r.store.GetDB()
	if sqliteStore == nil {
		return
	}
	if err := sqliteStore.WriteMaltrailEvent(ev); err != nil {
		log.Printf("[maltrail] write event: %v", err)
		return
	}
	log.Printf("[maltrail] event: %s %s -> %s trail=%s info=%s", ev.SrcIP, ev.DstIP, ev.Protocol, truncateStr(ev.Trail, 40), ev.Info)
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return append(append([]byte(nil), b[:max]...), '.', '.', '.')
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// parseMaltrailLine tokenizes a line with maltrail safe_value rules:
// space-separated, values containing space or " are quoted; "" inside quote is one ".
func parseMaltrailLine(b []byte) []string {
	var tokens []string
	p := bytes.TrimSpace(b)
	for len(p) > 0 {
		var token []byte
		if p[0] == '"' {
			// quoted: find closing " (skip "")
			end := -1
			for i := 1; i < len(p); i++ {
				if p[i] == '"' {
					if i+1 < len(p) && p[i+1] == '"' {
						i++
						continue
					}
					end = i
					break
				}
			}
			if end < 0 {
				token = p[1:]
				p = nil
			} else {
				raw := p[1:end]
				token = bytes.ReplaceAll(raw, []byte(`""`), []byte(`"`))
				p = bytes.TrimSpace(p[end+1:])
			}
		} else {
			i := bytes.IndexAny(p, " \t")
			if i < 0 {
				token = p
				p = nil
			} else {
				token = p[:i]
				p = bytes.TrimSpace(p[i:])
			}
		}
		if len(token) > 0 {
			tokens = append(tokens, string(token))
		}
	}
	return tokens
}
