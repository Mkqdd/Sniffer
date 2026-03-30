package bytesize

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ByteSize represents a size in bytes
type ByteSize int64

const (
	B   ByteSize = 1
	KiB ByteSize = 1024
	MiB ByteSize = 1024 * KiB
	GiB ByteSize = 1024 * MiB
	TiB ByteSize = 1024 * GiB
)

var (
	unitMap = map[string]ByteSize{
		"b":   B,
		"B":   B,
		"k":   KiB,
		"K":   KiB,
		"kb":  KiB,
		"KB":  KiB,
		"kib": KiB,
		"KiB": KiB,
		"m":   MiB,
		"M":   MiB,
		"mb":  MiB,
		"MB":  MiB,
		"mib": MiB,
		"MiB": MiB,
		"g":   GiB,
		"G":   GiB,
		"gb":  GiB,
		"GB":  GiB,
		"gib": GiB,
		"GiB": GiB,
		"t":   TiB,
		"T":   TiB,
		"tb":  TiB,
		"TB":  TiB,
		"tib": TiB,
		"TiB": TiB,
	}

	sizeRegex = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([a-zA-Z]*)$`)
)

// Parse parses a human-readable byte size string
// Examples: "100MiB", "1.5GB", "1024", "5 GiB"
func Parse(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty string")
	}

	// Remove underscores for readability (e.g., "20_000")
	s = strings.ReplaceAll(s, "_", "")

	matches := sizeRegex.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	numStr := matches[1]
	unitStr := matches[2]

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", numStr)
	}

	if num < 0 {
		return 0, errors.New("size cannot be negative")
	}

	// Default to bytes if no unit specified
	unit := B
	if unitStr != "" {
		var ok bool
		unit, ok = unitMap[unitStr]
		if !ok {
			return 0, fmt.Errorf("unknown unit: %s", unitStr)
		}
	}

	return ByteSize(num * float64(unit)), nil
}

// String returns a human-readable representation
func (b ByteSize) String() string {
	if b < 0 {
		return fmt.Sprintf("-%s", (-b).String())
	}

	switch {
	case b >= TiB:
		return fmt.Sprintf("%.2f TiB", float64(b)/float64(TiB))
	case b >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(GiB))
	case b >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(MiB))
	case b >= KiB:
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(KiB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// Bytes returns the size in bytes as int64
func (b ByteSize) Bytes() int64 {
	return int64(b)
}

// MustParse parses a byte size string and panics on error
func MustParse(s string) ByteSize {
	size, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return size
}

