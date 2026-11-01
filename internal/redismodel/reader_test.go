package redismodel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type respStep struct {
	args  [][]byte
	reply []byte
}

func arg(s ...string) [][]byte {
	out := make([][]byte, len(s))
	for i := range s {
		out[i] = []byte(s[i])
	}
	return out
}
func bulk(b []byte) []byte {
	return append(append([]byte(fmt.Sprintf("$%d\r\n", len(b))), b...), '\r', '\n')
}
func array(parts ...[]byte) []byte {
	out := []byte(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func requestReader(r *bufio.Reader) ([][]byte, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("bad request array")
	}
	n, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if err != nil || n < 1 || n > 10000 {
		return nil, errors.New("bad request count")
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		line, err = r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(line, "$") || !strings.HasSuffix(line, "\r\n") {
			return nil, errors.New("bad request bulk")
		}
		size, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
		if err != nil || size < 0 || size > 1<<20 {
			return nil, errors.New("bad request size")
		}
		value := make([]byte, size+2)
		if _, err = io.ReadFull(r, value); err != nil {
			return nil, err
		}
		if !bytes.Equal(value[size:], []byte("\r\n")) {
			return nil, errors.New("bad request suffix")
		}
		out = append(out, value[:size])
	}
	return out, nil
}
func equalArgs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
func testRESP(t *testing.T, steps []respStep) (*RESPReader, func()) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for _, s := range steps {
			got, err := requestReader(r)
			if err != nil {
				done <- err
				return
			}
			if !equalArgs(got, s.args) {
				done <- fmt.Errorf("unexpected command: %q", got)
				return
			}
			if _, err = server.Write(s.reply); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	rr, err := NewRESPReader(client, RESPOptions{MaxReplyBytes: 4096, MaxItems: 256, CommandTimeout: time.Second, VerifiedNoAdditionalState: true})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	finish := func() {
		client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("fake RESP server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("fake RESP server did not finish")
		}
	}
	return rr, finish
}
func respLimits() Limits {
	return Limits{MaxDatabases: 16, MaxKeys: 100, MaxPages: 100, MaxReplyBytes: 4096, MaxTotalBytes: 100000, MaxClockSkewMillis: 100, MaxDuration: time.Second}
}
func TestRESPReaderBinaryStringAndKey(t *testing.T) {
	key := []byte{'k', 0, '\n', 255}
	data := []byte{'v', 0, 255, '\r', '\n'}
	rr, finish := testRESP(t, []respStep{{arg("SELECT", "1"), []byte("+OK\r\n")}, {[][]byte{[]byte("TYPE"), key}, []byte("+string\r\n")}, {[][]byte{[]byte("PEXPIRETIME"), key}, []byte(":1900000000000\r\n")}, {[][]byte{[]byte("GET"), key}, bulk(data)}})
	defer finish()
	got, err := rr.Value(context.Background(), 1, key, respLimits())
	if err != nil || got.Type != "string" || got.ExpiresAt != 1900000000000 || !bytes.Equal(got.String, data) {
		t.Fatalf("unexpected value: type=%s expiry=%d equal=%v err=%v", got.Type, got.ExpiresAt, bytes.Equal(got.String, data), err)
	}
}
func TestRESPReaderHashFieldExpiriesAndBinary(t *testing.T) {
	key := []byte{'h', 0}
	f1 := []byte{'a', 0}
	f2 := []byte{'b', 255}
	v1 := []byte{0, 1}
	v2 := []byte{'\r', '\n'}
	rr, finish := testRESP(t, []respStep{{arg("SELECT", "0"), []byte("+OK\r\n")}, {[][]byte{[]byte("TYPE"), key}, []byte("+hash\r\n")}, {[][]byte{[]byte("PEXPIRETIME"), key}, []byte(":-1\r\n")}, {[][]byte{[]byte("HGETALL"), key}, array(bulk(f1), bulk(v1), bulk(f2), bulk(v2))}, {[][]byte{[]byte("HPEXPIRETIME"), key, []byte("FIELDS"), []byte("2"), f1, f2}, array([]byte(":1900000000001\r\n"), []byte(":-1\r\n"))}})
	defer finish()
	got, err := rr.Value(context.Background(), 0, key, respLimits())
	if err != nil || got.Type != "hash" || got.ExpiresAt != -1 || len(got.Hash) != 2 {
		t.Fatalf("unexpected hash result, err=%v", err)
	}
	if !bytes.Equal(got.Hash[0].Name, f1) || !bytes.Equal(got.Hash[0].Value, v1) || got.Hash[0].ExpiresAt != 1900000000001 || !bytes.Equal(got.Hash[1].Name, f2) || !bytes.Equal(got.Hash[1].Value, v2) || got.Hash[1].ExpiresAt != -1 {
		t.Fatal("hash field or expiry mismatch")
	}
}
func TestRESPReaderScanPreservesBinary(t *testing.T) {
	key := []byte{'s', 0, 255, '\n'}
	rr, finish := testRESP(t, []respStep{{arg("SELECT", "2"), []byte("+OK\r\n")}, {arg("SCAN", "0", "COUNT", "512"), array(bulk([]byte("7")), array(bulk(key), bulk([]byte("z"))))}})
	defer finish()
	next, keys, err := rr.Scan(context.Background(), 2, 0, respLimits())
	if err != nil || next != 7 || len(keys) != 2 || !bytes.Equal(keys[0], key) {
		t.Fatalf("scan next=%d count=%d err=%v", next, len(keys), err)
	}
}
func TestRESPReaderRejectsUnsafeResponses(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{"bulk too large", []byte("$999999999999999999999\r\n")},
		{"bulk just over bound", []byte("$4097\r\n")},
		{"array too large", []byte("*999999999999999999999\r\n")},
		{"array just over item bound", []byte("*257\r\n")},
		{"negative array", []byte("*-1\r\n")},
		{"null", []byte("$-1\r\n")},
		{"wrong reply type", bulk([]byte("0"))},
		{"negative db size", []byte(":-1\r\n")},
		{"error", []byte("-ERR synthetic\r\n")},
		{"bad integer", []byte(":x\r\n")},
		{"unknown prefix", []byte("?x\r\n")},
		{"truncated bulk", []byte("$3\r\nx")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, finish := testRESP(t, []respStep{{arg("SELECT", "0"), []byte("+OK\r\n")}, {arg("DBSIZE"), tc.response}})
			defer finish()
			if _, err := rr.KeyCount(context.Background(), 0); err == nil {
				t.Fatal("unsafe reply accepted")
			}
		})
	}
}
func TestRESPReaderRejectsMissingFieldAndUnsupportedType(t *testing.T) {
	t.Run("unsupported stream", func(t *testing.T) {
		rr, finish := testRESP(t, []respStep{{arg("SELECT", "0"), []byte("+OK\r\n")}, {arg("TYPE", "key"), []byte("+stream\r\n")}})
		defer finish()
		if _, err := rr.Value(context.Background(), 0, []byte("key"), respLimits()); err == nil {
			t.Fatal("stream accepted")
		}
	})
	t.Run("field disappeared", func(t *testing.T) {
		rr, finish := testRESP(t, []respStep{{arg("SELECT", "0"), []byte("+OK\r\n")}, {arg("TYPE", "key"), []byte("+hash\r\n")}, {arg("PEXPIRETIME", "key"), []byte(":-1\r\n")}, {arg("HGETALL", "key"), array(bulk([]byte("f")), bulk([]byte("v")))}, {arg("HPEXPIRETIME", "key", "FIELDS", "1", "f"), array([]byte(":-2\r\n"))}})
		defer finish()
		if _, err := rr.Value(context.Background(), 0, []byte("key"), respLimits()); err == nil {
			t.Fatal("missing field accepted")
		}
	})
}
func TestRESPReaderHonorsCancellationDuringRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	gotReq := make(chan struct{})
	go func() { r := bufio.NewReader(server); _, _ = requestReader(r); close(gotReq) }()
	rr, err := NewRESPReader(client, RESPOptions{MaxReplyBytes: 4096, MaxItems: 128, CommandTimeout: time.Second, VerifiedNoAdditionalState: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := rr.KeyCount(ctx, 0); done <- err }()
	<-gotReq
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled operation accepted")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled read did not unblock")
	}
}

func metadataSteps() []respStep {
	return []respStep{
		{arg("INFO", "SERVER"), bulk([]byte("# Server\r\nredis_version:7.4.9\r\nredis_mode:standalone\r\nrun_id:synthetic-a\r\n"))},
		{arg("INFO", "CLUSTER"), bulk([]byte("# Cluster\r\ncluster_enabled:0\r\n"))},
		{arg("INFO", "REPLICATION"), bulk([]byte("role:master\r\n"))},
		{arg("INFO", "PERSISTENCE"), bulk([]byte("loading:0\r\n"))},
		{arg("INFO", "STATS"), bulk([]byte("expired_keys:0\r\nexpired_subkeys:0\r\nevicted_keys:0\r\n"))},
		{arg("CONFIG", "GET", "databases"), array(bulk([]byte("databases")), bulk([]byte("16")))},
		{arg("CONFIG", "GET", "maxmemory-policy"), array(bulk([]byte("maxmemory-policy")), bulk([]byte("noeviction")))},
		{arg("MODULE", "LIST"), array()},
		{arg("FUNCTION", "LIST"), array()},
		{arg("TIME"), array(bulk([]byte("1900000000")), bulk([]byte("123456")))},
	}
}
func TestRESPReaderMetadataChecksAllRequiredSettings(t *testing.T) {
	rr, finish := testRESP(t, metadataSteps())
	defer finish()
	m, err := rr.Metadata(context.Background())
	if err != nil || !m.Complete || m.Version != "7.4.9" || m.RunID != "synthetic-a" || m.Databases != 16 || m.Millis != 1900000000123 || m.HasModules || m.HasFunctions || m.Cluster {
		t.Fatalf("unexpected metadata: %+v error=%v", m, err)
	}
}

func TestRESPReaderMetadataWithoutAttestationIsIncomplete(t *testing.T) {
	rr, finish := testRESP(t, metadataSteps())
	defer finish()
	rr.opts.VerifiedNoAdditionalState = false
	m, err := rr.Metadata(context.Background())
	if err != nil || m.Complete || validMeta(m, respLimits()) {
		t.Fatalf("missing attestation must fail comparison validation: complete=%t error=%v", m.Complete, err)
	}
}
func TestRESPReaderMetadataFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		index int
		reply []byte
	}{
		{"clustered", 1, bulk([]byte("cluster_enabled:1\r\n"))},
		{"replica", 2, bulk([]byte("role:slave\r\n"))},
		{"loading", 3, bulk([]byte("loading:1\r\n"))},
		{"missing expiry counter", 4, bulk([]byte("expired_keys:0\r\nevicted_keys:0\r\n"))},
		{"bad database count", 5, array(bulk([]byte("databases")), bulk([]byte("0")))},
		{"eviction policy", 6, array(bulk([]byte("maxmemory-policy")), bulk([]byte("allkeys-lru")))},
		{"modules", 7, array(array(bulk([]byte("name")), bulk([]byte("synthetic-module"))))},
		{"functions", 8, array(array(bulk([]byte("name")), bulk([]byte("synthetic-function"))))},
		{"malformed time", 9, array(bulk([]byte("1900000000")), bulk([]byte("1000000")))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			steps := metadataSteps()[:tc.index+1]
			steps[tc.index].reply = tc.reply
			rr, finish := testRESP(t, steps)
			defer finish()
			if m, err := rr.Metadata(context.Background()); err == nil || m.Complete {
				t.Fatalf("unsafe metadata accepted: %+v %v", m, err)
			}
		})
	}
}
