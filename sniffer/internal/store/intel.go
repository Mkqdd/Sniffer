package store

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

type IntelCategory struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updated_at" ts_type:"string"`
}

type IntelItem struct {
	CategoryID int64
	ItemType   string // domain|ip|url
	Value      string
	Info       string
	Reference  string
	Source     string
}

type IntelHit struct {
	CategoryID int64
	Category   string
	ItemType   string
	Value      string
	Info       string
	Reference  string
	Source     string
}

// IntelCache keeps enabled intel in memory for fast matching.
type IntelCache struct {
	mu sync.RWMutex

	domains map[string]IntelHit // exact domain
	ips     map[string]IntelHit // exact ip
	urls    map[string]IntelHit // exact url

	// recent suppression to avoid spamming + heavy work
	recent map[string]time.Time
	ttl    time.Duration
}

func NewIntelCache() *IntelCache {
	return &IntelCache{
		domains: make(map[string]IntelHit),
		ips:     make(map[string]IntelHit),
		urls:    make(map[string]IntelHit),
		recent:  make(map[string]time.Time),
		ttl:     30 * time.Second,
	}
}

func (c *IntelCache) Replace(domains, ips, urls map[string]IntelHit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.domains = domains
	c.ips = ips
	c.urls = urls
	c.recent = make(map[string]time.Time)
}

func (c *IntelCache) ShouldSuppress(key string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.recent[key]; ok && now.Sub(t) < c.ttl {
		return true
	}
	c.recent[key] = now

	// light cleanup
	if len(c.recent) > 50000 {
		for k, v := range c.recent {
			if now.Sub(v) > c.ttl {
				delete(c.recent, k)
			}
		}
	}
	return false
}

func (c *IntelCache) Lookup(itemType, value string) (IntelHit, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch itemType {
	case "domain":
		h, ok := c.domains[value]
		return h, ok
	case "ip":
		h, ok := c.ips[value]
		return h, ok
	case "url":
		h, ok := c.urls[value]
		return h, ok
	default:
		return IntelHit{}, false
	}
}

// ClearAllIntel removes all intel categories and items.
func (s *SQLiteStore) ClearAllIntel() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM intel_items")
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM intel_categories")
	return err
}

// UpsertIntelCategory ensures a category exists and sets enabled/description.
func (s *SQLiteStore) UpsertIntelCategory(name string, enabled bool, description string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	en := 0
	if enabled {
		en = 1
	}
	_, _ = s.db.Exec(
		`INSERT INTO intel_categories(name, enabled, description, updated_at)
		 VALUES(?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, description=excluded.description, updated_at=CURRENT_TIMESTAMP`,
		name, en, description,
	)
	var id int64
	err := s.db.QueryRow("SELECT id FROM intel_categories WHERE name = ?", name).Scan(&id)
	return id, err
}

func (s *SQLiteStore) SetIntelCategoryEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec("UPDATE intel_categories SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE name=?", en, name)
	return err
}

func (s *SQLiteStore) ListIntelCategories() ([]*IntelCategory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, name, enabled, COALESCE(description,''), COALESCE(updated_at,'') FROM intel_categories ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*IntelCategory
	for rows.Next() {
		c := &IntelCategory{}
		var enabled int
		var updated string
		if err := rows.Scan(&c.ID, &c.Name, &enabled, &c.Description, &updated); err != nil {
			continue
		}
		c.Enabled = enabled == 1
		c.UpdatedAt = parseSQLiteTime(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceIntelItemsForCategory clears and bulk inserts items for given category.
func (s *SQLiteStore) ReplaceIntelItemsForCategory(categoryID int64, items []IntelItem) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM intel_items WHERE category_id = ?", categoryID)
	if err != nil {
		return 0, fmt.Errorf("clear intel items: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO intel_items(category_id, item_type, value, info, reference, source) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	inserted := 0
	for _, it := range items {
		v := strings.TrimSpace(it.Value)
		if v == "" {
			continue
		}
		_, err := stmt.Exec(categoryID, it.ItemType, v, it.Info, it.Reference, it.Source)
		if err == nil {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

// RefreshIntelCache loads enabled intel items into in-memory cache for fast matching.
func (s *SQLiteStore) RefreshIntelCache() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT c.id, c.name, i.item_type, i.value, COALESCE(i.info,''), COALESCE(i.reference,''), COALESCE(i.source,'')
		 FROM intel_items i
		 JOIN intel_categories c ON c.id = i.category_id
		 WHERE c.enabled=1`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	domains := make(map[string]IntelHit)
	ips := make(map[string]IntelHit)
	urls := make(map[string]IntelHit)

	for rows.Next() {
		var catID int64
		var catName, itemType, value, info, ref, src string
		if err := rows.Scan(&catID, &catName, &itemType, &value, &info, &ref, &src); err != nil {
			continue
		}
		h := IntelHit{
			CategoryID: catID,
			Category:   catName,
			ItemType:   itemType,
			Value:      value,
			Info:       info,
			Reference:  ref,
			Source:     src,
		}
		switch itemType {
		case "domain":
			domains[strings.ToLower(value)] = h
		case "ip":
			ips[value] = h
		case "url":
			urls[strings.ToLower(value)] = h
		}
	}
	if s.intelCache != nil {
		s.intelCache.Replace(domains, ips, urls)
	}
	return rows.Err()
}

// LookupIntelExact finds exact match in enabled categories. Returns info if found.
func (s *SQLiteStore) LookupIntelExact(itemType, value string) (*IntelItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	row := s.db.QueryRow(
		`SELECT i.category_id, i.item_type, i.value, COALESCE(i.info,''), COALESCE(i.reference,''), COALESCE(i.source,'')
		 FROM intel_items i
		 JOIN intel_categories c ON c.id = i.category_id
		 WHERE c.enabled=1 AND i.item_type=? AND i.value=?
		 LIMIT 1`,
		itemType, value,
	)
	var it IntelItem
	if err := row.Scan(&it.CategoryID, &it.ItemType, &it.Value, &it.Info, &it.Reference, &it.Source); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &it, nil
}

func (s *SQLiteStore) GetIntelCategoryNameByID(id int64) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var name string
	err := s.db.QueryRow("SELECT name FROM intel_categories WHERE id = ?", id).Scan(&name)
	return name, err
}

