package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"sniffer/pkg/bytesize"
)

// Config represents the application configuration
// 应用配置
type Config struct {
	mu sync.RWMutex

	// Ring buffer limits
	RawMax  int `yaml:"raw_max" env:"SNIF_RAW_MAX"`
	DNSMax  int `yaml:"dns_max" env:"SNIF_DNS_MAX"`
	HTTPMax int `yaml:"http_max" env:"SNIF_HTTP_MAX"`
	ICMPMax int `yaml:"icmp_max" env:"SNIF_ICMP_MAX"`

	// PCAP rotation
	PcapRotate   int    `yaml:"pcap_rotate"`
	PcapSize     string `yaml:"pcap_size"`
	PcapCompress int    `yaml:"pcap_compress"`

	// Database maintenance
	DBVacuumDay      int    `yaml:"db_vacuum_day"`
	DBVacuumInterval string `yaml:"db_vacuum_interval"`

	// Storage paths
	DataDir string `yaml:"data_dir"`
	PcapDir string `yaml:"pcap_dir"`
	DBPath  string `yaml:"db_path"`

	// Capture settings
	SnapshotLen  int    `yaml:"snapshot_len"`
	Promiscuous  bool   `yaml:"promiscuous"`
	Timeout      string `yaml:"timeout"`
	BufferSize   string `yaml:"buffer_size"`

	// SSL 黑名单目录（含 ja3_fingerprints.csv、sslblacklist.csv），空则禁用
	SSLBlacklistDir string `yaml:"ssl_blacklist_dir"`

	// Maltrail integration
	MaltrailEnabled   bool   `yaml:"maltrail_enabled"`
	MaltrailUDPListen string `yaml:"maltrail_udp_listen"`

	// Parsed values
	pcapSizeBytes   bytesize.ByteSize
	bufferSizeBytes bytesize.ByteSize
	timeout         time.Duration
	vacuumInterval  time.Duration
}

// Limits represents the ring buffer limits
type Limits struct {
	RawMax  int `json:"raw_max"`
	DNSMax  int `json:"dns_max"`
	HTTPMax int `json:"http_max"`
	ICMPMax int `json:"icmp_max"`
}

// Default returns a config with default values
func Default() *Config {
	return &Config{
		RawMax:           20000,
		DNSMax:           5000,
		HTTPMax:          5000,
		ICMPMax:          5000,
		PcapRotate:       10,
		PcapSize:         "100MiB",
		PcapCompress:     3,
		DBVacuumDay:      7,
		DBVacuumInterval: "1h",
		DataDir:          "./data",
		PcapDir:          "./data/pcap",
		DBPath:           "./data/sniffer.db",
		SnapshotLen:      65535,
		Promiscuous:      true,
		Timeout:          "30ms",
		BufferSize:       "10MiB",
		MaltrailEnabled:  true,
		MaltrailUDPListen: "127.0.0.1:8337",
	}
}

// Load loads configuration from multiple sources in order:
// 1. Default values
// 2. YAML file(s)
// 3. Environment variables
// 4. CLI flags (if implemented)
func Load(paths ...string) (*Config, error) {
	cfg := Default()

	// Load from YAML files
	for _, path := range paths {
		if err := cfg.loadFromFile(path); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("load config from %s: %w", path, err)
			}
		}
	}

	// Load from environment variables
	cfg.loadFromEnv()

	// Parse and validate
	if err := cfg.parse(); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Create directories
	if err := cfg.ensureDirectories(); err != nil {
		return nil, fmt.Errorf("create directories: %w", err)
	}

	return cfg, nil
}

// loadFromFile loads configuration from a YAML file
func (c *Config) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, c)
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	if v := os.Getenv("SNIF_RAW_MAX"); v != "" {
		fmt.Sscanf(v, "%d", &c.RawMax)
	}
	if v := os.Getenv("SNIF_DNS_MAX"); v != "" {
		fmt.Sscanf(v, "%d", &c.DNSMax)
	}
	if v := os.Getenv("SNIF_HTTP_MAX"); v != "" {
		fmt.Sscanf(v, "%d", &c.HTTPMax)
	}
	if v := os.Getenv("SNIF_ICMP_MAX"); v != "" {
		fmt.Sscanf(v, "%d", &c.ICMPMax)
	}
	if v := os.Getenv("SNIF_DATA_DIR"); v != "" {
		c.DataDir = v
	}
}

// parse parses string values into typed fields
func (c *Config) parse() error {
	var err error

	// Parse byte sizes
	c.pcapSizeBytes, err = bytesize.Parse(c.PcapSize)
	if err != nil {
		return fmt.Errorf("parse pcap_size: %w", err)
	}

	c.bufferSizeBytes, err = bytesize.Parse(c.BufferSize)
	if err != nil {
		return fmt.Errorf("parse buffer_size: %w", err)
	}

	// Parse durations
	c.timeout, err = time.ParseDuration(c.Timeout)
	if err != nil {
		return fmt.Errorf("parse timeout: %w", err)
	}

	c.vacuumInterval, err = time.ParseDuration(c.DBVacuumInterval)
	if err != nil {
		return fmt.Errorf("parse db_vacuum_interval: %w", err)
	}

	// Validate ranges
	if c.PcapCompress < 0 || c.PcapCompress > 9 {
		return fmt.Errorf("pcap_compress must be 0-9, got %d", c.PcapCompress)
	}

	return nil
}

// ensureDirectories creates necessary directories
func (c *Config) ensureDirectories() error {
	dirs := []string{c.DataDir, c.PcapDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

// GetLimits returns the current ring buffer limits
func (c *Config) GetLimits() Limits {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Limits{
		RawMax:  c.RawMax,
		DNSMax:  c.DNSMax,
		HTTPMax: c.HTTPMax,
		ICMPMax: c.ICMPMax,
	}
}

// UpdateLimits updates the ring buffer limits atomically
func (c *Config) UpdateLimits(limits Limits) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RawMax = limits.RawMax
	c.DNSMax = limits.DNSMax
	c.HTTPMax = limits.HTTPMax
	c.ICMPMax = limits.ICMPMax
}

// GetPcapSizeBytes returns the parsed PCAP size in bytes
func (c *Config) GetPcapSizeBytes() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pcapSizeBytes.Bytes()
}

// GetBufferSizeBytes returns the parsed buffer size in bytes
func (c *Config) GetBufferSizeBytes() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bufferSizeBytes.Bytes()
}

// GetTimeout returns the parsed timeout duration
func (c *Config) GetTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// GetVacuumInterval returns the parsed vacuum interval
func (c *Config) GetVacuumInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.vacuumInterval
}

// Watch watches the config file for changes and calls onChange
// 监听配置文件变化并热重载
func (c *Config) Watch(ctx context.Context, configPath string, onChange func(*Config)) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastModTime time.Time
	if stat, err := os.Stat(configPath); err == nil {
		lastModTime = stat.ModTime()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			stat, err := os.Stat(configPath)
			if err != nil {
				continue
			}

			if stat.ModTime().After(lastModTime) {
				lastModTime = stat.ModTime()

				// Reload config
				newCfg, err := Load(configPath)
				if err != nil {
					fmt.Printf("Failed to reload config: %v\n", err)
					continue
				}

				// Copy new values to current config
				c.mu.Lock()
				*c = *newCfg
				c.mu.Unlock()

				// Notify
				if onChange != nil {
					onChange(c)
				}

				fmt.Println("Configuration reloaded successfully")
			}
		}
	}
}

// Save saves the current configuration to a file
func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

