package config

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that accepts Go duration syntax plus a "d"
// (days) suffix in YAML, e.g. "300ms", "12h", "397d".
type Duration time.Duration

// ParseDuration parses "397d", "12h", "300ms" or a bare integer of seconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * 24 * float64(time.Hour)), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// String renders the duration, using days when it is a whole number of days.
func (d Duration) String() string {
	v := time.Duration(d)
	if v != 0 && v%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(v/(24*time.Hour)), 10) + "d"
	}
	return v.String()
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// ByteSize is a byte count that accepts "8MiB", "32MB", "512KiB", "1024" in YAML.
type ByteSize int64

var byteSizeRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([A-Za-z]*)$`)

var byteUnits = map[string]float64{
	"":    1,
	"b":   1,
	"k":   1 << 10,
	"kb":  1000,
	"kib": 1 << 10,
	"m":   1 << 20,
	"mb":  1000 * 1000,
	"mib": 1 << 20,
	"g":   1 << 30,
	"gb":  1000 * 1000 * 1000,
	"gib": 1 << 30,
}

// ParseByteSize parses a human-readable byte size.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	m := byteSizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid byte size %q", s)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q", s)
	}
	mult, ok := byteUnits[strings.ToLower(m[2])]
	if !ok {
		return 0, fmt.Errorf("invalid byte size unit %q", m[2])
	}
	v := n * mult
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("byte size %q too large", s)
	}
	return int64(v), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (b ByteSize) MarshalYAML() (any, error) { return b.String(), nil }

// String renders the size with a binary unit when it divides evenly.
func (b ByteSize) String() string {
	v := int64(b)
	switch {
	case v != 0 && v%(1<<30) == 0:
		return strconv.FormatInt(v>>30, 10) + "GiB"
	case v != 0 && v%(1<<20) == 0:
		return strconv.FormatInt(v>>20, 10) + "MiB"
	case v != 0 && v%(1<<10) == 0:
		return strconv.FormatInt(v>>10, 10) + "KiB"
	default:
		return strconv.FormatInt(v, 10)
	}
}

// Int64 returns the value as an int64.
func (b ByteSize) Int64() int64 { return int64(b) }
