package store

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"sniffer/pkg/model"
)

// PcapFileStore stores raw packets in rotating PCAP files
// PCAP文件存储（环形文件组）
type PcapFileStore struct {
	mu           sync.Mutex
	dir          string
	maxSize      int64
	rotateCount  int
	compressLvl  int
	currentFile  *pcapFile
	files        []*pcapFileInfo
	totalPackets int64
}

// pcapFile represents an active PCAP file being written
type pcapFile struct {
	path     string
	file     *os.File
	gzWriter *gzip.Writer
	writer   *pcapgo.Writer
	size     int64
	created  time.Time
}

// pcapFileInfo contains metadata about a PCAP file
type pcapFileInfo struct {
	Path    string
	Size    int64
	Created time.Time
	Count   int64
}

// NewPcapFileStore creates a new PCAP file store
func NewPcapFileStore(dir string, maxSize int64, rotateCount int, compressLvl int) (*PcapFileStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create pcap directory: %w", err)
	}

	store := &PcapFileStore{
		dir:         dir,
		maxSize:     maxSize,
		rotateCount: rotateCount,
		compressLvl: compressLvl,
		files:       make([]*pcapFileInfo, 0),
	}

	// Scan existing files
	if err := store.scanExistingFiles(); err != nil {
		return nil, err
	}

	// Open first file
	if err := store.rotate(); err != nil {
		return nil, err
	}

	return store, nil
}

// WriteRaw writes a raw packet to the current PCAP file
func (s *PcapFileStore) WriteRaw(pkt *model.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if rotation is needed
	if s.currentFile != nil && s.currentFile.size >= s.maxSize {
		if err := s.rotate(); err != nil {
			return fmt.Errorf("rotate pcap file: %w", err)
		}
	}

	// Write packet
	if s.currentFile == nil {
		if err := s.rotate(); err != nil {
			return fmt.Errorf("create pcap file: %w", err)
		}
	}

	// Create packet capture info
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: pkt.CaptureLen,
		Length:        pkt.Length,
	}

	// Write packet
	if err := s.currentFile.writer.WritePacket(ci, pkt.Data); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	// Update size
	packetSize := int64(ci.CaptureLength + 16) // 16 bytes for pcap packet header
	s.currentFile.size += packetSize
	s.totalPackets++

	return nil
}

// rotate closes the current file and opens a new one
func (s *PcapFileStore) rotate() error {
	// Close current file
	if s.currentFile != nil {
		if err := s.closeCurrentFile(); err != nil {
			return err
		}
	}

	// Generate new filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	ext := ".pcap"
	if s.compressLvl > 0 {
		ext = ".pcap.gz"
	}
	filename := fmt.Sprintf("capture_%s%s", timestamp, ext)
	path := filepath.Join(s.dir, filename)

	// Create file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file %s: %w", path, err)
	}

	// Create pcapFile struct
	pf := &pcapFile{
		path:    path,
		file:    file,
		created: time.Now(),
	}

	// Setup compression if needed
	var w io.Writer = file
	if s.compressLvl > 0 {
		gzWriter, err := gzip.NewWriterLevel(file, s.compressLvl)
		if err != nil {
			file.Close()
			return fmt.Errorf("create gzip writer: %w", err)
		}
		pf.gzWriter = gzWriter
		w = gzWriter
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(w)
	if err := pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		if pf.gzWriter != nil {
			pf.gzWriter.Close()
		}
		file.Close()
		return fmt.Errorf("write pcap header: %w", err)
	}

	pf.writer = pcapWriter
	s.currentFile = pf

	// Add to files list
	s.files = append(s.files, &pcapFileInfo{
		Path:    path,
		Created: pf.created,
	})

	// Cleanup old files if exceeding rotation count
	if len(s.files) > s.rotateCount {
		// Remove oldest files
		toRemove := len(s.files) - s.rotateCount
		for i := 0; i < toRemove; i++ {
			if err := os.Remove(s.files[i].Path); err != nil && !os.IsNotExist(err) {
				fmt.Printf("Warning: failed to remove old pcap file %s: %v\n", s.files[i].Path, err)
			}
		}
		s.files = s.files[toRemove:]
	}

	return nil
}

// closeCurrentFile closes the current PCAP file
func (s *PcapFileStore) closeCurrentFile() error {
	if s.currentFile == nil {
		return nil
	}

	var err error
	if s.currentFile.gzWriter != nil {
		err = s.currentFile.gzWriter.Close()
	}

	if err2 := s.currentFile.file.Close(); err == nil {
		err = err2
	}

	// Update file info
	stat, _ := os.Stat(s.currentFile.path)
	if stat != nil && len(s.files) > 0 {
		s.files[len(s.files)-1].Size = stat.Size()
	}

	s.currentFile = nil
	return err
}

// scanExistingFiles scans the directory for existing PCAP files
func (s *PcapFileStore) scanExistingFiles() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !s.isPcapFile(name) {
			continue
		}

		path := filepath.Join(s.dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		s.files = append(s.files, &pcapFileInfo{
			Path:    path,
			Size:    info.Size(),
			Created: info.ModTime(),
		})
	}

	// Sort by creation time
	sort.Slice(s.files, func(i, j int) bool {
		return s.files[i].Created.Before(s.files[j].Created)
	})

	return nil
}

// isPcapFile checks if a filename is a PCAP file
func (s *PcapFileStore) isPcapFile(name string) bool {
	return filepath.Ext(name) == ".pcap" ||
		(len(name) > 7 && name[len(name)-7:] == ".pcap.gz")
}

// ExportPCAP exports packets in the time range
func (s *PcapFileStore) ExportPCAP(start, end time.Time, w io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Flush current file
	if s.currentFile != nil && s.currentFile.gzWriter != nil {
		s.currentFile.gzWriter.Flush()
	}

	// Create PCAP writer for output
	pcapWriter := pcapgo.NewWriter(w)
	if err := pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	// Find relevant files
	for _, fileInfo := range s.files {
		// Simple time-based filtering (could be improved)
		if fileInfo.Created.After(end) {
			continue
		}

		// Read and filter packets from this file
		if err := s.exportFromFile(fileInfo.Path, start, end, pcapWriter); err != nil {
			return fmt.Errorf("export from %s: %w", fileInfo.Path, err)
		}
	}

	return nil
}

func isTruncatedEOF(err error) bool {
	if err == nil {
		return false
	}
	// gzip/pcap readers may surface truncation as io.ErrUnexpectedEOF or "unexpected EOF"
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(err.Error(), "unexpected EOF")
}

// exportFromFile exports packets from a single file
func (s *PcapFileStore) exportFromFile(path string, start, end time.Time, writer *pcapgo.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var r io.Reader = file
	if filepath.Ext(path) == ".gz" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("create gzip reader: %w", err)
		}
		defer gzReader.Close()
		r = gzReader
	}

	// Read packets
	pcapReader, err := pcapgo.NewReader(r)
	if err != nil {
		return fmt.Errorf("create pcap reader: %w", err)
	}

	for {
		data, ci, err := pcapReader.ReadPacketData()
		if err == io.EOF {
			break
		}
		// When the file is still being written/compressed, readers may hit truncation.
		// Treat it as EOF so export can still succeed for the available packets.
		if isTruncatedEOF(err) {
			break
		}
		if err != nil {
			return fmt.Errorf("read packet: %w", err)
		}

		// Filter by time
		if ci.Timestamp.Before(start) || ci.Timestamp.After(end) {
			continue
		}

		// Write packet
		if err := writer.WritePacket(ci, data); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
	}

	return nil
}

// Vacuum removes old PCAP files
func (s *PcapFileStore) Vacuum(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	newFiles := make([]*pcapFileInfo, 0, len(s.files))

	for _, fileInfo := range s.files {
		if fileInfo.Created.Before(before) {
			if err := os.Remove(fileInfo.Path); err != nil && !os.IsNotExist(err) {
				fmt.Printf("Warning: failed to remove old pcap file %s: %v\n", fileInfo.Path, err)
			} else {
				removed++
			}
		} else {
			newFiles = append(newFiles, fileInfo)
		}
	}

	s.files = newFiles
	fmt.Printf("Vacuum: removed %d old PCAP files\n", removed)

	return nil
}

// Stats returns storage statistics
func (s *PcapFileStore) Stats() (StoreStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var totalSize int64
	var oldest, newest time.Time

	for i, fileInfo := range s.files {
		totalSize += fileInfo.Size
		if i == 0 || fileInfo.Created.Before(oldest) {
			oldest = fileInfo.Created
		}
		if i == 0 || fileInfo.Created.After(newest) {
			newest = fileInfo.Created
		}
	}

	return StoreStats{
		RawCount:      s.totalPackets,
		TotalSize:     totalSize,
		OldestPacket:  oldest,
		NewestPacket:  newest,
		PcapFileCount: len(s.files),
	}, nil
}

// ClearAll clears all PCAP files
func (s *PcapFileStore) ClearAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close current file (ignore error if no file)
	_ = s.closeCurrentFile()

	// Delete all PCAP files in the directory
	patterns := []string{"*.pcap", "*.pcap.gz"}
	
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(s.dir, pattern))
		if err != nil {
			continue
		}
		for _, file := range matches {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				fmt.Printf("Warning: failed to remove %s: %v\n", file, err)
			}
		}
	}

	// Reset state
	s.files = nil
	s.currentFile = nil
	s.totalPackets = 0

	return nil
}

// Close closes the store
func (s *PcapFileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.closeCurrentFile()
}

