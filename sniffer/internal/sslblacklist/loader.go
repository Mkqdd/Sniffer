package sslblacklist

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Blacklist 恶意 JA3（MD5）与证书 SHA1 黑名单
type Blacklist struct {
	mu       sync.RWMutex
	ja3MD5   map[string]string // ja3_md5 (32 hex lower) -> Listingreason
	certSHA1 map[string]string // sha1 (40 hex lower) -> Listingreason
}

// NewBlacklist 创建空黑名单
func NewBlacklist() *Blacklist {
	return &Blacklist{
		ja3MD5:   make(map[string]string),
		certSHA1: make(map[string]string),
	}
}

// LoadFromDir 从目录加载 ja3_fingerprints.csv 与 sslblacklist.csv
// dir 通常为 SSLBlackList 目录路径
func (b *Blacklist) LoadFromDir(dir string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	ja3Path := filepath.Join(dir, "ja3_fingerprints.csv")
	if err := b.loadJA3(ja3Path); err != nil {
		return fmt.Errorf("load ja3: %w", err)
	}

	sha1Path := filepath.Join(dir, "sslblacklist.csv")
	if err := b.loadSHA1(sha1Path); err != nil {
		return fmt.Errorf("load sslblacklist: %w", err)
	}

	return nil
}

func (b *Blacklist) loadJA3(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	// abuse.ch CSV 前面带大量 # 注释行，且字段数不固定；需允许可变字段数并跳过注释
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) < 4 {
			continue
		}
		ja3 := strings.TrimSpace(strings.ToLower(row[0]))
		if ja3 == "" || ja3 == "ja3_md5" {
			continue
		}
		reason := strings.TrimSpace(row[3])
		if reason != "" {
			b.ja3MD5[ja3] = reason
		}
	}
	return nil
}

func (b *Blacklist) loadSHA1(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	// 同样允许可变字段数并跳过 # 注释行
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) < 3 {
			continue
		}
		sha1 := strings.TrimSpace(strings.ToLower(row[1]))
		if sha1 == "" || sha1 == "sha1" {
			continue
		}
		reason := strings.TrimSpace(row[2])
		if reason != "" {
			b.certSHA1[sha1] = reason
		}
	}
	return nil
}

// LookupJA3 查询 JA3 MD5（32 位小写十六进制），命中返回 (原因, true)
func (b *Blacklist) LookupJA3(ja3MD5 string) (reason string, ok bool) {
	if len(ja3MD5) != 32 {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	reason, ok = b.ja3MD5[strings.ToLower(ja3MD5)]
	return reason, ok
}

// LookupCertSHA1 查询证书 SHA1（40 位小写十六进制），命中返回 (原因, true)
func (b *Blacklist) LookupCertSHA1(sha1Hex string) (reason string, ok bool) {
	if len(sha1Hex) != 40 {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	reason, ok = b.certSHA1[strings.ToLower(sha1Hex)]
	return reason, ok
}

// CountJA3 返回 JA3 黑名单条数
func (b *Blacklist) CountJA3() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.ja3MD5)
}

// CountCertSHA1 返回证书 SHA1 黑名单条数
func (b *Blacklist) CountCertSHA1() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.certSHA1)
}
