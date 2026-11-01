package redismodel

import (
	"bytes"
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// This is opt-in and is intended only for two disposable Redis 7.4 servers.
// It never writes data or creates a server. The separate disposable fixture
// populates purely synthetic values and removes its own Docker resources.
func TestRedisIntegrationFixture(t *testing.T) {
	left := os.Getenv("GUARDIAN_TEST_REDIS_A")
	right := os.Getenv("GUARDIAN_TEST_REDIS_B")
	mode := os.Getenv("GUARDIAN_TEST_REDIS_MODE")
	if left == "" && right == "" && mode == "" {
		t.Skip("disposable Redis fixture not configured")
	}
	if left == "" || right == "" || (mode != "equal" && mode != "mismatch" && mode != "field-expiry" && mode != "key-expiry" && mode != "unsupported" && mode != "list" && mode != "set" && mode != "hash" && mode != "zset") {
		t.Fatal("incomplete synthetic fixture configuration")
	}
	a, err := net.DialTimeout("tcp", left, 3*time.Second)
	if err != nil {
		t.Fatal("fixture connection A failed")
	}
	defer a.Close()
	b, err := net.DialTimeout("tcp", right, 3*time.Second)
	if err != nil {
		t.Fatal("fixture connection B failed")
	}
	defer b.Close()
	opts := RESPOptions{MaxReplyBytes: 1 << 20, MaxItems: 25000, CommandTimeout: 3 * time.Second, VerifiedNoAdditionalState: true}
	ra, err := NewRESPReader(a, opts)
	if err != nil {
		t.Fatal("fixture reader A failed")
	}
	rb, err := NewRESPReader(b, opts)
	if err != nil {
		t.Fatal("fixture reader B failed")
	}
	limits := Limits{MaxDatabases: 16, MaxKeys: 10000, MaxPages: 10000, MaxReplyBytes: 1 << 20, MaxTotalBytes: 8 << 20, MaxClockSkewMillis: 200, MaxDuration: 30 * time.Second}
	result, err := Compare(context.Background(), ra, rb, limits)
	if mode == "equal" {
		if err != nil || result.Databases != 16 || result.Keys != 6 {
			t.Fatalf("synthetic equality failed: databases=%d keys=%d error=%v", result.Databases, result.Keys, err)
		}
		deadline, parseErr := strconv.ParseInt(os.Getenv("GUARDIAN_TEST_REDIS_DEADLINE"), 10, 64)
		if parseErr != nil || deadline <= time.Now().UnixMilli() {
			t.Fatal("synthetic deadline is invalid")
		}
		key, keyErr := ra.Value(context.Background(), 0, []byte("k\x00\n"), limits)
		if keyErr != nil || key.ExpiresAt != deadline {
			t.Fatal("synthetic key expiry not preserved")
		}
		hash, hashErr := ra.Value(context.Background(), 0, []byte("hash"), limits)
		if hashErr != nil {
			t.Fatal("synthetic hash read failed")
		}
		found := false
		for _, field := range hash.Hash {
			if string(field.Name) == "expfield" && field.ExpiresAt == deadline {
				found = true
			}
		}
		if !found {
			t.Fatal("synthetic field expiry not preserved")
		}
		return
	}
	if err == nil {
		t.Fatalf("synthetic %s case was not rejected", mode)
	}
	if mode == "mismatch" {
		x, errA := ra.Value(context.Background(), 1, []byte("db1\x00"), limits)
		y, errB := rb.Value(context.Background(), 1, []byte("db1\x00"), limits)
		if errA != nil || errB != nil || string(x.String) != "v\xff" || string(y.String) != "different" {
			t.Fatal("fixture mismatch was not observed by the readers")
		}
	}
	if mode == "unsupported" {
		if _, streamErr := ra.Value(context.Background(), 0, []byte("stream"), limits); streamErr == nil {
			t.Fatal("reader accepted unsupported stream")
		}
	}
	if mode == "key-expiry" || mode == "field-expiry" {
		deadline, parseErr := strconv.ParseInt(os.Getenv("GUARDIAN_TEST_REDIS_DEADLINE"), 10, 64)
		if parseErr != nil {
			t.Fatal("synthetic deadline invalid")
		}
		key := []byte("k\x00\n")
		if mode == "field-expiry" {
			key = []byte("hash")
		}
		x, errA := ra.Value(context.Background(), 0, key, limits)
		y, errB := rb.Value(context.Background(), 0, key, limits)
		if errA != nil || errB != nil {
			t.Fatal("expiry fixture read failed")
		}
		if mode == "key-expiry" && (x.ExpiresAt != deadline || y.ExpiresAt != deadline+1000) {
			t.Fatal("key expiry mismatch not observed")
		}
		if mode == "field-expiry" {
			var ax, by int64
			for _, f := range x.Hash {
				if string(f.Name) == "expfield" {
					ax = f.ExpiresAt
				}
			}
			for _, f := range y.Hash {
				if string(f.Name) == "expfield" {
					by = f.ExpiresAt
				}
			}
			if ax != deadline || by != deadline+1000 {
				t.Fatal("field expiry mismatch not observed")
			}
		}
	}
	if mode == "list" || mode == "set" || mode == "hash" || mode == "zset" {
		x, errA := ra.Value(context.Background(), 0, []byte(mode), limits)
		y, errB := rb.Value(context.Background(), 0, []byte(mode), limits)
		if errA != nil || errB != nil {
			t.Fatal("synthetic value mutation not readable")
		}
		switch mode {
		case "list":
			if len(x.List) != 2 || len(y.List) != 3 || !bytes.Equal(y.List[0], []byte("extra")) {
				t.Fatal("list mutation missing")
			}
		case "set":
			if len(x.Set) != 2 || len(y.Set) != 3 {
				t.Fatal("set mutation missing")
			}
		case "hash":
			found := false
			for _, f := range y.Hash {
				if string(f.Name) == "plain" && string(f.Value) == "different" {
					found = true
				}
			}
			if !found {
				t.Fatal("hash mutation missing")
			}
		case "zset":
			found := false
			for _, m := range y.SortedSet {
				if bytes.Equal(m.Name, []byte{'m', 0}) && m.Score == 2.5 {
					found = true
				}
			}
			if !found {
				t.Fatal("sorted-set mutation missing")
			}
		}
	}
}
