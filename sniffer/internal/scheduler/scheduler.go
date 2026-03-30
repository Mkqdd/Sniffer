package scheduler

import (
	"context"
	"fmt"
	"time"

	"sniffer/internal/config"
	"sniffer/internal/store"
)

// Scheduler manages periodic maintenance tasks
// 调度器：定期清理和维护
type Scheduler struct {
	store store.Store
	cfg   *config.Config
}

// New creates a new Scheduler
func New(s store.Store, cfg *config.Config) *Scheduler {
	return &Scheduler{
		store: s,
		cfg:   cfg,
	}
}

// Run starts the scheduler (blocks until context is cancelled)
func (s *Scheduler) Run(ctx context.Context) error {
	interval := s.cfg.GetVacuumInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("Scheduler started: vacuum interval = %v, retention = %d days\n",
		interval, s.cfg.DBVacuumDay)

	// Run once immediately
	s.runMaintenance()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Scheduler stopped")
			return ctx.Err()

		case <-ticker.C:
			s.runMaintenance()
		}
	}
}

// runMaintenance runs all maintenance tasks
func (s *Scheduler) runMaintenance() {
	fmt.Printf("[%s] Running maintenance tasks...\n", time.Now().Format("2006-01-02 15:04:05"))

	// Calculate cutoff time
	cutoff := time.Now().AddDate(0, 0, -s.cfg.DBVacuumDay)

	// Run vacuum
	if err := s.store.Vacuum(cutoff); err != nil {
		fmt.Printf("Vacuum error: %v\n", err)
	}

	// Print statistics
	if stats, err := s.store.Stats(); err == nil {
		fmt.Printf("Storage stats: Raw=%d, DNS=%d, HTTP=%d, ICMP=%d, Size=%s, Files=%d\n",
			stats.RawCount,
			stats.DNSCount,
			stats.HTTPCount,
			stats.ICMPCount,
			formatBytes(stats.TotalSize),
			stats.PcapFileCount,
		)
	}
}

// formatBytes formats bytes as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

