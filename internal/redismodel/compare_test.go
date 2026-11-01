package redismodel

import (
	"context"
	"errors"
	"math"
	"sort"
	"testing"
	"time"
)

type fakeReader struct {
	meta          Metadata
	db            []map[string]Value
	metadataCalls int
	restart       bool
	clockShift    int64
	finishAdvance int64
	duplicate     bool
	scanLoop      bool
	countShift    bool
	err           error
}

func (f *fakeReader) Metadata(ctx context.Context) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if f.err != nil {
		return Metadata{}, f.err
	}
	f.metadataCalls++
	m := f.meta
	m.Millis = time.Now().UnixMilli() + f.clockShift
	if f.metadataCalls > 1 {
		m.Millis += f.finishAdvance
	}
	if f.restart && f.metadataCalls > 1 {
		m.RunID += "-restarted"
	}
	return m, nil
}

func (f *fakeReader) KeyCount(ctx context.Context, db int) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n := uint64(len(f.db[db]))
	if f.countShift {
		n++
	}
	return n, nil
}

func (f *fakeReader) Scan(ctx context.Context, db int, cursor uint64, _ Limits) (uint64, [][]byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	keys := make([]string, 0, len(f.db[db]))
	for k := range f.db[db] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	batch := make([][]byte, len(keys))
	for i, k := range keys {
		batch[i] = []byte(k)
	}
	if f.scanLoop {
		return 5, batch, nil
	}
	if f.duplicate && cursor == 0 && len(batch) != 0 {
		return 1, batch, nil
	}
	if f.duplicate && cursor == 1 && len(batch) != 0 {
		return 0, batch[:1], nil
	}
	return 0, batch, nil
}

func (f *fakeReader) Value(ctx context.Context, db int, key []byte, _ Limits) (Value, error) {
	if err := ctx.Err(); err != nil {
		return Value{}, err
	}
	v, ok := f.db[db][string(key)]
	if !ok {
		return Value{}, errors.New("missing")
	}
	return v, nil
}

func fixture() (*fakeReader, *fakeReader, Limits) {
	until := time.Now().Add(time.Hour).UnixMilli()
	base := []map[string]Value{
		{"s\x00\n": {Type: "string", ExpiresAt: until, String: []byte{0, 255, '\n'}},
			"list": {Type: "list", ExpiresAt: -1, List: [][]byte{{0}, {255, 0}}},
			"set":  {Type: "set", ExpiresAt: -1, Set: [][]byte{{0}, {255}}},
			"hash": {Type: "hash", ExpiresAt: -1, Hash: []Field{{Name: []byte{0}, Value: []byte{255}, ExpiresAt: until}, {Name: []byte("z"), Value: []byte{0}, ExpiresAt: -1}}},
			"zset": {Type: "zset", ExpiresAt: -1, SortedSet: []Member{{Name: []byte{0}, Score: math.Inf(-1)}, {Name: []byte{255}, Score: 1.5}}}},
		{"other": {Type: "string", ExpiresAt: -1, String: []byte{0, 2}}},
	}
	clone := func() []map[string]Value {
		out := make([]map[string]Value, len(base))
		for i, db := range base {
			out[i] = make(map[string]Value)
			for k, v := range db {
				out[i][k] = v
			}
		}
		return out
	}
	a := &fakeReader{meta: Metadata{Version: "7.4.9", RunID: "a", Databases: 2, Complete: true}, db: clone(), duplicate: true}
	b := &fakeReader{meta: Metadata{Version: "7.4.9", RunID: "b", Databases: 2, Complete: true}, db: clone(), duplicate: true}
	return a, b, Limits{MaxDatabases: 16, MaxKeys: 100, MaxPages: 100, MaxReplyBytes: 1024, MaxTotalBytes: 10000, MaxClockSkewMillis: 100, MaxDuration: time.Second}
}

func TestCompareBinaryMultipleDatabasesAndDuplicateScans(t *testing.T) {
	a, b, lim := fixture()
	// Sets, hashes and sorted sets do not depend on enumeration order.
	v := b.db[0]["set"]
	v.Set = [][]byte{{255}, {0}}
	b.db[0]["set"] = v
	v = b.db[0]["hash"]
	v.Hash = []Field{v.Hash[1], v.Hash[0]}
	b.db[0]["hash"] = v
	v = b.db[0]["zset"]
	v.SortedSet = []Member{v.SortedSet[1], v.SortedSet[0]}
	b.db[0]["zset"] = v
	res, err := Compare(context.Background(), a, b, lim)
	if err != nil || res.Databases != 2 || res.Keys != 6 {
		t.Fatalf("result %+v, error %v", res, err)
	}
}

func TestCompareRejectsDifferencesAndUnsafeObservations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeReader, *fakeReader, *Limits)
	}{
		{"value", func(_, b *fakeReader, _ *Limits) {
			v := b.db[0]["s\x00\n"]
			v.String = []byte{0}
			b.db[0]["s\x00\n"] = v
		}},
		{"missing", func(_, b *fakeReader, _ *Limits) { delete(b.db[0], "set") }},
		{"extra", func(_, b *fakeReader, _ *Limits) { b.db[1]["extra"] = Value{Type: "string", ExpiresAt: -1} }},
		{"metadata incomplete", func(_, b *fakeReader, _ *Limits) { b.meta.Complete = false }},
		{"same server", func(a, b *fakeReader, _ *Limits) { b.meta.RunID = a.meta.RunID }},
		{"invalid patch version", func(a, b *fakeReader, _ *Limits) { a.meta.Version, b.meta.Version = "7.4.invalid", "7.4.invalid" }},
		{"key expiry", func(_, b *fakeReader, _ *Limits) { v := b.db[0]["s\x00\n"]; v.ExpiresAt++; b.db[0]["s\x00\n"] = v }},
		{"field expiry", func(_, b *fakeReader, _ *Limits) {
			v := b.db[0]["hash"]
			v.Hash = append([]Field(nil), v.Hash...)
			v.Hash[0].ExpiresAt++
			b.db[0]["hash"] = v
		}},
		{"missing field expiry", func(_, b *fakeReader, _ *Limits) {
			v := b.db[0]["hash"]
			v.Hash = append([]Field(nil), v.Hash...)
			v.Hash[0].ExpiresAt = -2
			b.db[0]["hash"] = v
		}},
		{"unsupported type", func(a, b *fakeReader, _ *Limits) {
			v := Value{Type: "stream", ExpiresAt: -1}
			a.db[0]["x"] = v
			b.db[0]["x"] = v
		}},
		{"type mismatch", func(_, b *fakeReader, _ *Limits) { v := b.db[0]["set"]; v.Type = "list"; b.db[0]["set"] = v }},
		{"nan score", func(a, b *fakeReader, _ *Limits) {
			v := Value{Type: "zset", ExpiresAt: -1, SortedSet: []Member{{Name: []byte("x"), Score: math.NaN()}}}
			a.db[0]["bad"] = v
			b.db[0]["bad"] = v
		}},
		{"modules", func(_, b *fakeReader, _ *Limits) { b.meta.HasModules = true }},
		{"functions", func(_, b *fakeReader, _ *Limits) { b.meta.HasFunctions = true }},
		{"other metadata", func(_, b *fakeReader, _ *Limits) { b.meta.HasOtherState = true }},
		{"cluster", func(_, b *fakeReader, _ *Limits) { b.meta.Cluster = true }},
		{"version", func(_, b *fakeReader, _ *Limits) { b.meta.Version = "7.2.0" }},
		{"database count", func(_, b *fakeReader, _ *Limits) { b.meta.Databases = 1 }},
		{"restart", func(_, b *fakeReader, _ *Limits) { b.restart = true }},
		{"clock skew", func(_, b *fakeReader, _ *Limits) { b.clockShift = 20000 }},
		{"scan loop", func(_, b *fakeReader, _ *Limits) { b.scanLoop = true }},
		{"count disagreement", func(_, b *fakeReader, _ *Limits) { b.countShift = true }},
		{"key limit", func(_, _ *fakeReader, l *Limits) { l.MaxKeys = 2 }},
		{"page limit", func(_, _ *fakeReader, l *Limits) { l.MaxPages = 1 }},
		{"reply byte limit", func(_, _ *fakeReader, l *Limits) { l.MaxReplyBytes = 1 }},
		{"total byte limit", func(_, _ *fakeReader, l *Limits) { l.MaxTotalBytes = 2; l.MaxReplyBytes = 1 }},
		{"reader failure", func(_, b *fakeReader, _ *Limits) { b.err = errors.New("details must not leak") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, b, l := fixture()
			tc.change(a, b, &l)
			if _, err := Compare(context.Background(), a, b, l); !errors.Is(err, ErrComparison) {
				t.Fatalf("got %v, want failed comparison", err)
			}
		})
	}
}

func TestCompareExpiryCrossingAndCancellation(t *testing.T) {
	a, b, l := fixture()
	for _, r := range []*fakeReader{a, b} {
		v := r.db[0]["s\x00\n"]
		v.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
		r.db[0]["s\x00\n"] = v
	}
	if _, err := Compare(context.Background(), a, b, l); !errors.Is(err, ErrComparison) {
		t.Fatalf("expired deadline accepted: %v", err)
	}
	// Deadline was in the future at start but crosses before the final server
	// TIME observation. The artificial advance remains within clock tolerance.
	a, b, l = fixture()
	deadline := time.Now().Add(100 * time.Millisecond).UnixMilli()
	for _, r := range []*fakeReader{a, b} {
		v := r.db[0]["s\x00\n"]
		v.ExpiresAt = deadline
		r.db[0]["s\x00\n"] = v
		r.finishAdvance = 200
	}
	if _, err := Compare(context.Background(), a, b, l); !errors.Is(err, ErrComparison) {
		t.Fatalf("deadline crossed during comparison accepted: %v", err)
	}
	a, b, l = fixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Compare(ctx, a, b, l); !errors.Is(err, ErrComparison) {
		t.Fatalf("cancelled comparison accepted: %v", err)
	}
}
