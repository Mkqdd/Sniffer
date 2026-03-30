package maltrail

import (
	"path/filepath"
	"strings"

	"sniffer/internal/store"
)

// SyncOptions controls which sources to sync.
type SyncOptions struct {
	MaltrailRoot string
	TrailsCSV    string // optional
}

// SyncIntel loads Maltrail trails and stores them into intel categories/items (category-level toggles).
func SyncIntel(sqlite *store.SQLiteStore, opt SyncOptions) (map[string]int, error) {
	counts := map[string]int{}

	// Ensure categories exist (enabled by default)
	catIDs := map[string]int64{}
	for name, desc := range map[string]string{
		CategoryStaticMalware:    "Maltrail trails/static/malware (static)",
		CategoryStaticMalicious:  "Maltrail trails/static (malicious) (static)",
		CategoryStaticSuspicious: "Maltrail trails/static/suspicious (static)",
		CategoryCustom:           "Maltrail custom trails (csv reference contains custom)",
		CategoryFeed:             "Maltrail feed trails (csv reference contains feed)",
	} {
		id, err := sqlite.UpsertIntelCategory(name, true, desc)
		if err != nil {
			return nil, err
		}
		catIDs[name] = id
	}

	// Static: read and map into 3 buckets by path
	if opt.MaltrailRoot != "" {
		entries, err := LoadTrailsFromStaticDir(opt.MaltrailRoot)
		if err != nil {
			return nil, err
		}

		// Bucket items
		buckets := map[string][]store.IntelItem{
			CategoryStaticMalware:    {},
			CategoryStaticSuspicious: {},
			CategoryStaticMalicious:  {},
		}

		for _, e := range entries {
			cat := CategoryStaticMalicious
			// source like static/<subdir>/file.txt
			if strings.HasPrefix(e.Source, "static/malware/") {
				cat = CategoryStaticMalware
			} else if strings.HasPrefix(e.Source, "static/suspicious/") {
				cat = CategoryStaticSuspicious
			} else {
				// everything else under static/ treated as malicious as requested (includes mass_scanner*, etc.)
				cat = CategoryStaticMalicious
			}
			itemType := strings.ToLower(e.Type)
			buckets[cat] = append(buckets[cat], store.IntelItem{
				ItemType:  itemType,
				Value:     e.Value,
				Info:      "static",
				Reference: "(static)",
				Source:    e.Source,
			})
		}

		for cat, items := range buckets {
			n, err := sqlite.ReplaceIntelItemsForCategory(catIDs[cat], items)
			if err != nil {
				return nil, err
			}
			counts[cat] = n
		}
	}

	// CSV: split into custom vs feed vs (fallback to malicious)
	if opt.TrailsCSV != "" {
		entries, err := LoadTrailsFromCSV(opt.TrailsCSV)
		if err != nil {
			return nil, err
		}
		buckets := map[string][]store.IntelItem{
			CategoryCustom: {},
			CategoryFeed:   {},
		}
		for _, e := range entries {
			cat := CategoryFeed
			srcLower := strings.ToLower(e.Source)
			if strings.Contains(srcLower, "custom") {
				cat = CategoryCustom
			}
			buckets[cat] = append(buckets[cat], store.IntelItem{
				ItemType:  strings.ToLower(e.Type),
				Value:     e.Value,
				Info:      "",
				Reference: "",
				Source:    "csv:" + filepath.Base(opt.TrailsCSV) + " " + e.Source,
			})
		}
		for cat, items := range buckets {
			n, err := sqlite.ReplaceIntelItemsForCategory(catIDs[cat], items)
			if err != nil {
				return nil, err
			}
			counts[cat] = n
		}
	}

	return counts, nil
}

