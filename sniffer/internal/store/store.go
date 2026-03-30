package store

import (
	"io"
	"time"

	"sniffer/pkg/model"
)

// Store is the interface for packet and session storage
// 存储接口抽象
type Store interface {
	// WriteRaw writes a raw packet
	WriteRaw(pkt *model.Packet) error

	// WriteSession writes a parsed session (DNS/HTTP/ICMP)
	WriteSession(table model.TableType, session *model.Session) error

	// LoadSnapshot loads recent sessions from a table
	LoadSnapshot(table model.TableType, limit int) ([]*model.Session, error)

	// ExportPCAP exports packets in the time range to a PCAP file
	ExportPCAP(start, end time.Time, w io.Writer) error

	// Vacuum removes old data before the specified time
	Vacuum(before time.Time) error

	// Stats returns storage statistics
	Stats() (StoreStats, error)

	// ClearAll clears all stored data
	ClearAll() error

	// Close closes the store
	Close() error
	
	// GetDB returns the underlying SQLite store for direct access
	GetDB() *SQLiteStore
}

// StoreStats contains storage statistics
type StoreStats struct {
	RawCount      int64
	DNSCount      int64
	HTTPCount     int64
	ICMPCount     int64
	TotalSize     int64
	OldestPacket  time.Time
	NewestPacket  time.Time
	PcapFileCount int
}

