// Package redismodel compares isolated Redis snapshots. It is a building block,
// not a Redis connection, migration workflow, or proof that writers are fenced.
package redismodel

import (
	"bytes"
	"context"
	"errors"
	"math"
	"regexp"
	"sort"
	"time"
)

var ErrComparison = errors.New("Redis model comparison failed")

// Metadata must be obtained from the selected Redis server, not caller guesses.
// RunID must change if the server restarts. Millis is the server's TIME in UTC.
// Complete means every field was positively inspected; an unavailable metadata
// check must return an error, not set Complete with zero-value assumptions.
type Metadata struct {
	Version, RunID                                   string
	Databases                                        int
	Complete                                         bool
	Cluster, HasModules, HasFunctions, HasOtherState bool
	Millis                                           int64
	ExpiredKeys, ExpiredFields, EvictedKeys          uint64
}

type Field struct {
	Name, Value []byte
	ExpiresAt   int64
}
type Member struct {
	Name  []byte
	Score float64
}

// ExpiresAt uses Redis absolute milliseconds, or -1 for no expiry. -2 (missing)
// and any other value are errors, not proof of equivalence.
type Value struct {
	Type      string
	ExpiresAt int64
	String    []byte
	List, Set [][]byte
	Hash      []Field
	SortedSet []Member
}

// Reader must use a binary-safe transport, enforce limits before allocating a
// reply, return all Redis metadata, and report errors for any unsupported data.
// Scan must use Redis SCAN on the selected database. Value must return the
// whole value, its PEXPIRETIME and, for hashes, every HPEXPIRETIME. KeyCount is
// DBSIZE. Implementations must not log raw keys or values. The caller must fence
// all writers independently for the entire comparison; this interface does not
// prove fencing or validate the input RDB's origin.
type Reader interface {
	Metadata(context.Context) (Metadata, error)
	KeyCount(context.Context, int) (uint64, error)
	Scan(context.Context, int, uint64, Limits) (uint64, [][]byte, error)
	Value(context.Context, int, []byte, Limits) (Value, error)
}

type Limits struct {
	MaxDatabases       int
	MaxKeys            uint64
	MaxPages           uint64
	MaxReplyBytes      uint64
	MaxTotalBytes      uint64
	MaxClockSkewMillis int64
	MaxDuration        time.Duration
}

type Result struct {
	Databases                     int
	Keys                          uint64
	StartedMillis, FinishedMillis int64
}

var supportedVersion = regexp.MustCompile(`^7\.4\.[0-9]+$`)

func validLimits(l Limits) bool {
	return l.MaxDatabases > 0 && l.MaxDatabases <= 256 && l.MaxKeys > 0 && l.MaxKeys <= 1000000 && l.MaxPages > 0 && l.MaxPages <= 1000000 && l.MaxReplyBytes > 0 && l.MaxTotalBytes > 0 && l.MaxReplyBytes <= l.MaxTotalBytes && l.MaxClockSkewMillis >= 0 && l.MaxClockSkewMillis <= 5000 && l.MaxDuration > 0
}
func validMeta(m Metadata, l Limits) bool {
	return m.Complete && supportedVersion.MatchString(m.Version) && m.RunID != "" && m.Databases > 0 && m.Databases <= l.MaxDatabases && !m.Cluster && !m.HasModules && !m.HasFunctions && !m.HasOtherState && m.Millis > 0 && m.Millis < 32503680000000 // before year 3000; keeps time arithmetic bounded
}
func difference(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}
func compatible(a, b Metadata, l Limits) bool {
	return validMeta(a, l) && validMeta(b, l) && a.Version == b.Version && a.Databases == b.Databases && difference(a.Millis, b.Millis) <= l.MaxClockSkewMillis
}
func checkedAdd(total *uint64, amount uint64, limit uint64) bool {
	if amount > limit || *total > limit-amount {
		return false
	}
	*total += amount
	return true
}
func addBytes(total *uint64, l Limits, data ...[]byte) bool {
	for _, b := range data {
		if !checkedAdd(total, uint64(len(b)), l.MaxTotalBytes) {
			return false
		}
	}
	return true
}
func deadline(v int64, earliest *int64) bool {
	if v == -1 {
		return true
	}
	if v <= 0 {
		return false
	}
	if *earliest == 0 || v < *earliest {
		*earliest = v
	}
	return true
}
func fail() error { return ErrComparison }

// Compare returns equivalence only for the state observed in the completed
// comparison window. Every observed expiry must remain in the future through
// its end plus the clock-skew allowance; crossings fail closed. Expirations already absent on both sides by
// the time observed are absent from the ending state, not proof of equality at
// an earlier snapshot time. Compare is read-only; fencing, trusted RDB identity,
// clock synchronization, and actual connectivity remain external obligations.
func Compare(ctx context.Context, a, b Reader, l Limits) (Result, error) {
	var result Result
	if a == nil || b == nil || !validLimits(l) {
		return result, fail()
	}
	ctx, cancel := context.WithTimeout(ctx, l.MaxDuration)
	defer cancel()
	start := time.Now()
	ma, err := a.Metadata(ctx)
	if err != nil {
		return result, fail()
	}
	mb, err := b.Metadata(ctx)
	if err != nil || !compatible(ma, mb, l) || ma.RunID == mb.RunID {
		return result, fail()
	}
	result.Databases = ma.Databases
	result.StartedMillis = max(ma.Millis, mb.Millis)
	var total, pages uint64
	var earliest int64
	for db := 0; db < ma.Databases; db++ {
		if ctx.Err() != nil {
			return Result{}, fail()
		}
		ka, err := scan(ctx, a, db, l, &pages, &total)
		if err != nil {
			return Result{}, fail()
		}
		kb, err := scan(ctx, b, db, l, &pages, &total)
		if err != nil || len(ka) != len(kb) {
			return Result{}, fail()
		}
		if uint64(len(ka)) > l.MaxKeys-result.Keys {
			return Result{}, fail()
		}
		result.Keys += uint64(len(ka))
		for k := range ka {
			if _, ok := kb[k]; !ok {
				return Result{}, fail()
			}
		}
		for k := range ka {
			if ctx.Err() != nil {
				return Result{}, fail()
			}
			x, err := a.Value(ctx, db, []byte(k), l)
			if err != nil {
				return Result{}, fail()
			}
			y, err := b.Value(ctx, db, []byte(k), l)
			if err != nil {
				return Result{}, fail()
			}
			if !equalValue(x, y, l, &total, &earliest) {
				return Result{}, fail()
			}
		}
		ca, err := a.KeyCount(ctx, db)
		if err != nil || ca != uint64(len(ka)) {
			return Result{}, fail()
		}
		cb, err := b.KeyCount(ctx, db)
		if err != nil || cb != uint64(len(kb)) {
			return Result{}, fail()
		}
	}
	ea, err := a.Metadata(ctx)
	if err != nil {
		return Result{}, fail()
	}
	eb, err := b.Metadata(ctx)
	if err != nil || !compatible(ea, eb, l) || ea.RunID != ma.RunID || eb.RunID != mb.RunID || ea.Version != ma.Version || eb.Version != mb.Version || ea.Databases != ma.Databases || eb.Databases != mb.Databases || ea.Millis < ma.Millis || eb.Millis < mb.Millis || ea.ExpiredKeys != ma.ExpiredKeys || eb.ExpiredKeys != mb.ExpiredKeys || ea.ExpiredFields != ma.ExpiredFields || eb.ExpiredFields != mb.ExpiredFields || ea.EvictedKeys != ma.EvictedKeys || eb.EvictedKeys != mb.EvictedKeys {
		return Result{}, fail()
	}
	elapsed := time.Since(start).Milliseconds()
	tolerance := l.MaxClockSkewMillis + 1000
	if difference(ea.Millis-ma.Millis, elapsed) > tolerance || difference(eb.Millis-mb.Millis, elapsed) > tolerance {
		return Result{}, fail()
	}
	result.FinishedMillis = max(ea.Millis, eb.Millis)
	if earliest > 0 && earliest <= result.FinishedMillis+l.MaxClockSkewMillis {
		return Result{}, fail()
	}
	if ctx.Err() != nil {
		return Result{}, fail()
	}
	return result, nil
}

func scan(ctx context.Context, r Reader, db int, l Limits, pages, total *uint64) (map[string]struct{}, error) {
	before, err := r.KeyCount(ctx, db)
	if err != nil || before > l.MaxKeys {
		return nil, fail()
	}
	keys := make(map[string]struct{})
	seen := map[uint64]bool{}
	cursor := uint64(0)
	for {
		if ctx.Err() != nil || !checkedAdd(pages, 1, l.MaxPages) || seen[cursor] {
			return nil, fail()
		}
		seen[cursor] = true
		next, batch, err := r.Scan(ctx, db, cursor, l)
		if err != nil || uint64(len(batch)) > l.MaxKeys {
			return nil, fail()
		}
		var reply uint64
		for _, k := range batch {
			if !checkedAdd(&reply, uint64(len(k)), l.MaxReplyBytes) || !addBytes(total, l, k) {
				return nil, fail()
			}
			keys[string(k)] = struct{}{}
			if uint64(len(keys)) > l.MaxKeys {
				return nil, fail()
			}
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	after, err := r.KeyCount(ctx, db)
	if err != nil || before != after || after != uint64(len(keys)) {
		return nil, fail()
	}
	return keys, nil
}

func equalValue(a, b Value, l Limits, total *uint64, earliest *int64) bool {
	if a.Type != b.Type || a.ExpiresAt != b.ExpiresAt || !deadline(a.ExpiresAt, earliest) || !deadline(b.ExpiresAt, earliest) {
		return false
	}
	switch a.Type {
	case "string":
		if len(a.List)+len(a.Set)+len(a.Hash)+len(a.SortedSet)+len(b.List)+len(b.Set)+len(b.Hash)+len(b.SortedSet) != 0 {
			return false
		}
		return bounded(l, total, a.String, b.String) && bytes.Equal(a.String, b.String)
	case "list":
		if len(a.List) == 0 || len(a.List) != len(b.List) || len(a.List) > int(l.MaxKeys) || !emptyOthers(a, "list") || !emptyOthers(b, "list") {
			return false
		}
		for i := range a.List {
			if !bounded(l, total, a.List[i], b.List[i]) || !bytes.Equal(a.List[i], b.List[i]) {
				return false
			}
		}
		return true
	case "set":
		if len(a.Set) == 0 || len(a.Set) != len(b.Set) || len(a.Set) > int(l.MaxKeys) || !emptyOthers(a, "set") || !emptyOthers(b, "set") {
			return false
		}
		x := append([][]byte(nil), a.Set...)
		y := append([][]byte(nil), b.Set...)
		sort.Slice(x, func(i, j int) bool { return bytes.Compare(x[i], x[j]) < 0 })
		sort.Slice(y, func(i, j int) bool { return bytes.Compare(y[i], y[j]) < 0 })
		for i := range x {
			if !bounded(l, total, x[i], y[i]) || !bytes.Equal(x[i], y[i]) || (i > 0 && (bytes.Equal(x[i], x[i-1]) || bytes.Equal(y[i], y[i-1]))) {
				return false
			}
		}
		return true
	case "hash":
		if len(a.Hash) == 0 || len(a.Hash) != len(b.Hash) || len(a.Hash) > int(l.MaxKeys) || !emptyOthers(a, "hash") || !emptyOthers(b, "hash") {
			return false
		}
		x := append([]Field(nil), a.Hash...)
		y := append([]Field(nil), b.Hash...)
		sort.Slice(x, func(i, j int) bool { return bytes.Compare(x[i].Name, x[j].Name) < 0 })
		sort.Slice(y, func(i, j int) bool { return bytes.Compare(y[i].Name, y[j].Name) < 0 })
		for i := range x {
			if !bounded(l, total, x[i].Name, x[i].Value, y[i].Name, y[i].Value) || !bytes.Equal(x[i].Name, y[i].Name) || !bytes.Equal(x[i].Value, y[i].Value) || x[i].ExpiresAt != y[i].ExpiresAt || !deadline(x[i].ExpiresAt, earliest) || !deadline(y[i].ExpiresAt, earliest) || (i > 0 && (bytes.Equal(x[i].Name, x[i-1].Name) || bytes.Equal(y[i].Name, y[i-1].Name))) {
				return false
			}
		}
		return true
	case "zset":
		if len(a.SortedSet) == 0 || len(a.SortedSet) != len(b.SortedSet) || len(a.SortedSet) > int(l.MaxKeys) || !emptyOthers(a, "zset") || !emptyOthers(b, "zset") {
			return false
		}
		x := append([]Member(nil), a.SortedSet...)
		y := append([]Member(nil), b.SortedSet...)
		sort.Slice(x, func(i, j int) bool { return bytes.Compare(x[i].Name, x[j].Name) < 0 })
		sort.Slice(y, func(i, j int) bool { return bytes.Compare(y[i].Name, y[j].Name) < 0 })
		for i := range x {
			if !bounded(l, total, x[i].Name, y[i].Name) || !bytes.Equal(x[i].Name, y[i].Name) || math.IsNaN(x[i].Score) || math.IsNaN(y[i].Score) || x[i].Score != y[i].Score || (i > 0 && (bytes.Equal(x[i].Name, x[i-1].Name) || bytes.Equal(y[i].Name, y[i-1].Name))) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
func emptyOthers(v Value, typ string) bool {
	return len(v.String) == 0 && (typ == "list" || len(v.List) == 0) && (typ == "set" || len(v.Set) == 0) && (typ == "hash" || len(v.Hash) == 0) && (typ == "zset" || len(v.SortedSet) == 0)
}
func bounded(l Limits, total *uint64, parts ...[]byte) bool {
	var size uint64
	for _, p := range parts {
		if !checkedAdd(&size, uint64(len(p)), l.MaxReplyBytes) {
			return false
		}
	}
	return checkedAdd(total, size, l.MaxTotalBytes)
}
