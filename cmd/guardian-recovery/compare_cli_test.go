package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This exercises the actual command's configured reader and comparison limits
// through TCP/RESP, rather than checking each component with unrelated options.
func TestCompareRedisCommandComparesActualProtocolValues(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(strconv.FormatBool(same), func(t *testing.T) {
			a := comparisonEndpoint(t, "first", []byte("binary\x00\xff"))
			value := []byte("binary\x00\xff")
			if !same {
				value = []byte("different")
			}
			b := comparisonEndpoint(t, "second", value)
			var out bytes.Buffer
			err := run(context.Background(), []string{"compare-redis", "--a", a, "--b", b, "--verified-no-additional-state"}, &out)
			if !same {
				if err == nil || out.Len() != 0 {
					t.Fatal("different protocol values accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Equivalent bool `json:"equivalent"`
				Databases  int  `json:"databases"`
				Keys       int  `json:"keys"`
			}
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !result.Equivalent || result.Databases != 1 || result.Keys != 1 {
				t.Fatalf("unexpected comparison result: %+v", result)
			}
		})
	}
}

func comparisonEndpoint(t *testing.T, runID string, value []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)
		bulk := func(s []byte) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }
		for {
			command, err := comparisonRequest(reader)
			if err != nil {
				return
			}
			response := ""
			switch command[0] {
			case "INFO":
				fields := map[string]string{
					"SERVER":      "redis_version:7.4.9\r\nrun_id:" + runID + "\r\nredis_mode:standalone\r\n",
					"CLUSTER":     "cluster_enabled:0\r\n",
					"REPLICATION": "role:master\r\n",
					"PERSISTENCE": "loading:0\r\n",
					"STATS":       "expired_keys:0\r\nexpired_subkeys:0\r\nevicted_keys:0\r\n",
				}
				response = bulk([]byte(fields[command[1]]))
			case "CONFIG":
				v := "noeviction"
				if command[2] == "databases" {
					v = "1"
				}
				response = "*2\r\n" + bulk([]byte(command[2])) + bulk([]byte(v))
			case "MODULE", "FUNCTION":
				response = "*0\r\n"
			case "TIME":
				now := time.Now()
				response = "*2\r\n" + bulk([]byte(strconv.FormatInt(now.Unix(), 10))) + bulk([]byte(strconv.Itoa(now.Nanosecond()/1000)))
			case "SELECT":
				response = "+OK\r\n"
			case "DBSIZE":
				response = ":1\r\n"
			case "SCAN":
				response = "*2\r\n" + bulk([]byte("0")) + "*1\r\n" + bulk([]byte("fixture-key"))
			case "TYPE":
				response = "+string\r\n"
			case "PEXPIRETIME":
				response = ":-1\r\n"
			case "GET":
				response = bulk(value)
			default:
				response = "-ERR unsupported\r\n"
			}
			if _, err := io.WriteString(conn, response); err != nil {
				return
			}
		}
	}()
	return listener.Addr().String()
}

func comparisonRequest(r *bufio.Reader) ([]string, error) {
	header, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(header, "*") {
		return nil, fmt.Errorf("invalid command")
	}
	n, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil || n < 1 || n > 16 {
		return nil, fmt.Errorf("invalid command count")
	}
	parts := make([]string, n)
	for i := range parts {
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "$") {
			return nil, fmt.Errorf("invalid command element")
		}
		size, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil || size < 0 || size > 4096 {
			return nil, fmt.Errorf("invalid command bytes")
		}
		data := make([]byte, size+2)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		if string(data[size:]) != "\r\n" {
			return nil, fmt.Errorf("invalid command terminator")
		}
		parts[i] = string(data[:size])
	}
	return parts, nil
}
