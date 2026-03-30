package store

import (
	"io"
	"time"

	"sniffer/internal/config"
	"sniffer/pkg/model"
)

// CompositeStore combines PCAP file storage and SQLite session storage
// 组合存储：PCAP文件 + SQLite数据库
type CompositeStore struct {
	pcapStore    *PcapFileStore
	sessionStore *SQLiteStore
}

// NewComposite creates a new composite store
func NewComposite(cfg *config.Config) (*CompositeStore, error) {
	// Create PCAP file store
	pcapStore, err := NewPcapFileStore(
		cfg.PcapDir,
		cfg.GetPcapSizeBytes(),
		cfg.PcapRotate,
		cfg.PcapCompress,
	)
	if err != nil {
		return nil, err
	}

	// Create SQLite session store
	sessionStore, err := NewSQLiteStore(cfg.DBPath, cfg.DBVacuumDay)
	if err != nil {
		pcapStore.Close()
		return nil, err
	}

	return &CompositeStore{
		pcapStore:    pcapStore,
		sessionStore: sessionStore,
	}, nil
}

// WriteRaw writes a raw packet to PCAP files
func (cs *CompositeStore) WriteRaw(pkt *model.Packet) error {
	return cs.pcapStore.WriteRaw(pkt)
}

// WriteSession writes a session to SQLite
func (cs *CompositeStore) WriteSession(table model.TableType, session *model.Session) error {
	return cs.sessionStore.WriteSession(table, session)
}

// LoadSnapshot loads sessions from SQLite
func (cs *CompositeStore) LoadSnapshot(table model.TableType, limit int) ([]*model.Session, error) {
	return cs.sessionStore.LoadSnapshot(table, limit)
}

// ExportPCAP exports packets from PCAP files
func (cs *CompositeStore) ExportPCAP(start, end time.Time, w io.Writer) error {
	return cs.pcapStore.ExportPCAP(start, end, w)
}

// Vacuum removes old data from both stores
func (cs *CompositeStore) Vacuum(before time.Time) error {
	// Vacuum PCAP files
	if err := cs.pcapStore.Vacuum(before); err != nil {
		return err
	}

	// Vacuum SQLite
	return cs.sessionStore.Vacuum(before)
}

// Stats returns combined statistics
func (cs *CompositeStore) Stats() (StoreStats, error) {
	pcapStats, err := cs.pcapStore.Stats()
	if err != nil {
		return StoreStats{}, err
	}

	sessionStats, err := cs.sessionStore.Stats()
	if err != nil {
		return StoreStats{}, err
	}

	// Combine stats
	stats := StoreStats{
		RawCount:      pcapStats.RawCount,
		DNSCount:      sessionStats.DNSCount,
		HTTPCount:     sessionStats.HTTPCount,
		ICMPCount:     sessionStats.ICMPCount,
		TotalSize:     pcapStats.TotalSize + sessionStats.TotalSize,
		PcapFileCount: pcapStats.PcapFileCount,
	}

	// Use earliest/latest times
	if pcapStats.OldestPacket.Before(sessionStats.OldestPacket) {
		stats.OldestPacket = pcapStats.OldestPacket
	} else {
		stats.OldestPacket = sessionStats.OldestPacket
	}

	if pcapStats.NewestPacket.After(sessionStats.NewestPacket) {
		stats.NewestPacket = pcapStats.NewestPacket
	} else {
		stats.NewestPacket = sessionStats.NewestPacket
	}

	return stats, nil
}

// ClearAll clears all data from both stores
func (cs *CompositeStore) ClearAll() error {
	// Clear PCAP files
	if err := cs.pcapStore.ClearAll(); err != nil {
		return err
	}

	// Clear SQLite database
	return cs.sessionStore.ClearAll()
}

// Close closes both stores
func (cs *CompositeStore) Close() error {
	err1 := cs.pcapStore.Close()
	err2 := cs.sessionStore.Close()

	if err1 != nil {
		return err1
	}
	return err2
}

// GetDB returns the underlying SQLite store
func (cs *CompositeStore) GetDB() *SQLiteStore {
	return cs.sessionStore
}

// ReplaceSessionStore replaces the current session store (for replay mode)
func (cs *CompositeStore) ReplaceSessionStore(newStore *SQLiteStore) {
	// Close the old session store
	if cs.sessionStore != nil {
		cs.sessionStore.Close()
	}
	// Replace with the new one
	cs.sessionStore = newStore
}

