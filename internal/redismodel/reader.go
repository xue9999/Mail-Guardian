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
	"sync"
	"time"
)

// RESPOptions bound individual commands/replies, including RESP framing and
// nested array elements. MaxItems also bounds the separate in-memory array
// representation; its allocation can exceed the RESP byte limit. Callers must
// independently fence all writers and use private endpoints for both servers.
type RESPOptions struct {
	MaxReplyBytes  uint64
	MaxItems       uint64
	CommandTimeout time.Duration
	// The adapter cannot inspect every kind of auxiliary RDB state. This must
	// be established independently for the exact isolated snapshots. A false
	// value leaves metadata incomplete and comparisons fail closed.
	VerifiedNoAdditionalState bool
}

// RESPReader implements Reader over an already-open connection. It does not
// dial or authenticate, expose a general command interface, or establish that a
// server is isolated. All commands are read-only. A failed command closes the
// connection so a partial RESP reply can never poison a later request.
type RESPReader struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	opts   RESPOptions
	failed bool
	limit  *Limits // protected by mu; scoped to a scan/value operation
}

func NewRESPReader(conn net.Conn, opts RESPOptions) (*RESPReader, error) {
	if conn == nil || opts.MaxReplyBytes < 128 || opts.MaxReplyBytes > 64<<20 || opts.MaxItems < 2 || opts.MaxItems > 100000 || opts.CommandTimeout <= 0 || opts.CommandTimeout > time.Minute {
		return nil, ErrComparison
	}
	return &RESPReader{conn: conn, reader: bufio.NewReaderSize(conn, 4096), opts: opts}, nil
}

type resp struct {
	kind    byte
	bulk    []byte
	integer int64
	array   []resp
}
type parseBudget struct {
	bytes, items, allocated uint64
	options                 RESPOptions
}

func (b *parseBudget) take(n uint64) error {
	if n > b.options.MaxReplyBytes || b.bytes > b.options.MaxReplyBytes-n {
		return ErrComparison
	}
	b.bytes += n
	return nil
}
func (b *parseBudget) node() error {
	if b.items >= b.options.MaxItems {
		return ErrComparison
	}
	b.items++
	return nil
}
func line(r *bufio.Reader, b *parseBudget) ([]byte, error) {
	// Protocol numeric/header lines are capped independently of server output.
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(frag) > 128-len(out) {
			return nil, ErrComparison
		}
		if e := b.take(uint64(len(frag))); e != nil {
			return nil, e
		}
		out = append(out, frag...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, ErrComparison
		}
	}
	if len(out) < 2 || out[len(out)-2] != '\r' {
		return nil, ErrComparison
	}
	return out[:len(out)-2], nil
}
func decimal(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 20 || b[0] == '+' {
		return 0, ErrComparison
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return 0, ErrComparison
	}
	return n, nil
}
func parse(r *bufio.Reader, b *parseBudget, depth int) (resp, error) {
	if depth > 3 || b.node() != nil {
		return resp{}, ErrComparison
	}
	k, err := r.ReadByte()
	if err != nil || b.take(1) != nil {
		return resp{}, ErrComparison
	}
	switch k {
	case '+', ':', '-':
		v, err := line(r, b)
		if err != nil || k == '-' {
			return resp{}, ErrComparison
		}
		if k == ':' {
			n, err := decimal(v)
			if err != nil {
				return resp{}, ErrComparison
			}
			return resp{kind: k, integer: n}, nil
		}
		return resp{kind: k, bulk: append([]byte(nil), v...)}, nil
	case '$':
		v, err := line(r, b)
		if err != nil {
			return resp{}, ErrComparison
		}
		n, err := decimal(v)
		if err != nil || n < 0 || uint64(n) > b.options.MaxReplyBytes || uint64(n)+2 > b.options.MaxReplyBytes-b.bytes {
			return resp{}, ErrComparison
		}
		data := make([]byte, int(n)+2)
		if _, err := io.ReadFull(r, data); err != nil || b.take(uint64(len(data))) != nil || data[len(data)-2] != '\r' || data[len(data)-1] != '\n' {
			return resp{}, ErrComparison
		}
		return resp{kind: k, bulk: data[:len(data)-2]}, nil
	case '*':
		v, err := line(r, b)
		if err != nil {
			return resp{}, ErrComparison
		}
		n, err := decimal(v)
		if err != nil || n < 0 || uint64(n) > b.options.MaxItems-b.items || uint64(n) > b.options.MaxItems-b.allocated || uint64(n) > (b.options.MaxReplyBytes-b.bytes)/3 {
			return resp{}, ErrComparison
		}
		b.allocated += uint64(n)
		vals := make([]resp, int(n))
		for i := range vals {
			vals[i], err = parse(r, b, depth+1)
			if err != nil {
				return resp{}, ErrComparison
			}
		}
		return resp{kind: k, array: vals}, nil
	default:
		return resp{}, ErrComparison
	}
}

func (r *RESPReader) exchange(ctx context.Context, args ...[]byte) (resp, error) {
	options := r.opts
	if r.limit != nil {
		options.MaxReplyBytes = min(options.MaxReplyBytes, r.limit.MaxReplyBytes)
		options.MaxItems = min(options.MaxItems, 2*r.limit.MaxKeys+8)
	}
	if r.failed || ctx.Err() != nil || len(args) == 0 || uint64(len(args)) > options.MaxItems {
		return resp{}, ErrComparison
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "*%d\r\n", len(args))
	for _, a := range args {
		if uint64(len(a)) > options.MaxReplyBytes || uint64(req.Len())+uint64(len(a))+32 > options.MaxReplyBytes {
			return resp{}, ErrComparison
		}
		fmt.Fprintf(&req, "$%d\r\n", len(a))
		req.Write(a)
		req.WriteString("\r\n")
	}
	deadline := time.Now().Add(r.opts.CommandTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := r.conn.SetDeadline(deadline); err != nil {
		r.failed = true
		r.conn.Close()
		return resp{}, ErrComparison
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = r.conn.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		_ = r.conn.SetDeadline(time.Time{})
	}()
	if _, err := io.Copy(r.conn, &req); err != nil {
		r.failed = true
		r.conn.Close()
		return resp{}, ErrComparison
	}
	v, err := parse(r.reader, &parseBudget{options: options}, 0)
	if err != nil || ctx.Err() != nil {
		r.failed = true
		r.conn.Close()
		return resp{}, ErrComparison
	}
	return v, nil
}
func args(s ...string) [][]byte {
	out := make([][]byte, len(s))
	for i := range s {
		out[i] = []byte(s[i])
	}
	return out
}
func (r *RESPReader) selectDB(ctx context.Context, db int) error {
	if db < 0 || db > 255 {
		return ErrComparison
	}
	v, e := r.exchange(ctx, args("SELECT", strconv.Itoa(db))...)
	if e != nil || v.kind != '+' || string(v.bulk) != "OK" {
		return ErrComparison
	}
	return nil
}
func textReply(v resp) ([]byte, bool) { return v.bulk, v.kind == '$' || v.kind == '+' }
func parseInfo(v resp) (map[string]string, error) {
	if v.kind != '$' {
		return nil, ErrComparison
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(v.bulk), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, val, ok := strings.Cut(line, ":")
		if !ok || k == "" {
			return nil, ErrComparison
		}
		if _, exists := result[k]; exists {
			return nil, ErrComparison
		}
		result[k] = val
	}
	return result, nil
}
func configValue(v resp, key string) (string, error) {
	if v.kind != '*' || len(v.array) != 2 {
		return "", ErrComparison
	}
	a, ok := textReply(v.array[0])
	if !ok || string(a) != key {
		return "", ErrComparison
	}
	b, ok := textReply(v.array[1])
	if !ok {
		return "", ErrComparison
	}
	return string(b), nil
}
func (r *RESPReader) Metadata(ctx context.Context) (Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var m Metadata
	v, e := r.exchange(ctx, args("INFO", "SERVER")...)
	if e != nil {
		return m, ErrComparison
	}
	info, e := parseInfo(v)
	if e != nil {
		return m, ErrComparison
	}
	m.Version, m.RunID = info["redis_version"], info["run_id"]
	if info["redis_mode"] != "standalone" || m.Version == "" || m.RunID == "" {
		return Metadata{}, ErrComparison
	}
	v, e = r.exchange(ctx, args("INFO", "CLUSTER")...)
	if e != nil {
		return Metadata{}, ErrComparison
	}
	info, e = parseInfo(v)
	if e != nil || info["cluster_enabled"] != "0" {
		return Metadata{}, ErrComparison
	}
	for _, required := range []struct{ section, key, value string }{
		{"REPLICATION", "role", "master"},
		{"PERSISTENCE", "loading", "0"},
	} {
		v, e = r.exchange(ctx, args("INFO", required.section)...)
		if e != nil {
			return Metadata{}, ErrComparison
		}
		info, e = parseInfo(v)
		if e != nil || info[required.key] != required.value {
			return Metadata{}, ErrComparison
		}
	}
	v, e = r.exchange(ctx, args("INFO", "STATS")...)
	if e != nil {
		return Metadata{}, ErrComparison
	}
	info, e = parseInfo(v)
	if e != nil {
		return Metadata{}, ErrComparison
	}
	for _, item := range []struct {
		key    string
		target *uint64
	}{
		{"expired_keys", &m.ExpiredKeys}, {"expired_subkeys", &m.ExpiredFields}, {"evicted_keys", &m.EvictedKeys},
	} {
		value, ok := info[item.key]
		if !ok || value == "" {
			return Metadata{}, ErrComparison
		}
		*item.target, e = strconv.ParseUint(value, 10, 64)
		if e != nil {
			return Metadata{}, ErrComparison
		}
	}
	v, e = r.exchange(ctx, args("CONFIG", "GET", "databases")...)
	if e != nil {
		return Metadata{}, ErrComparison
	}
	dbs, e := configValue(v, "databases")
	if e != nil {
		return Metadata{}, ErrComparison
	}
	n, e := strconv.Atoi(dbs)
	if e != nil || n < 1 || n > 256 {
		return Metadata{}, ErrComparison
	}
	m.Databases = n
	v, e = r.exchange(ctx, args("CONFIG", "GET", "maxmemory-policy")...)
	if e != nil {
		return Metadata{}, ErrComparison
	}
	policy, e := configValue(v, "maxmemory-policy")
	if e != nil || policy != "noeviction" {
		return Metadata{}, ErrComparison
	}
	for _, cmd := range [][][]byte{args("MODULE", "LIST"), args("FUNCTION", "LIST")} {
		v, e = r.exchange(ctx, cmd...)
		if e != nil || v.kind != '*' || len(v.array) != 0 {
			return Metadata{}, ErrComparison
		}
	}
	v, e = r.exchange(ctx, args("TIME")...)
	if e != nil || v.kind != '*' || len(v.array) != 2 {
		return Metadata{}, ErrComparison
	}
	sec, ok := textReply(v.array[0])
	if !ok {
		return Metadata{}, ErrComparison
	}
	micros, ok := textReply(v.array[1])
	if !ok {
		return Metadata{}, ErrComparison
	}
	s, e := decimal(sec)
	if e != nil || s <= 0 || s >= 32503680000 {
		return Metadata{}, ErrComparison
	}
	us, e := decimal(micros)
	if e != nil || us < 0 || us >= 1000000 {
		return Metadata{}, ErrComparison
	}
	m.Millis = s*1000 + us/1000
	m.Complete = r.opts.VerifiedNoAdditionalState
	return m, nil
}
func (r *RESPReader) KeyCount(ctx context.Context, db int) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.selectDB(ctx, db); err != nil {
		return 0, ErrComparison
	}
	v, e := r.exchange(ctx, args("DBSIZE")...)
	if e != nil || v.kind != ':' || v.integer < 0 {
		return 0, ErrComparison
	}
	return uint64(v.integer), nil
}
func compatibleOptions(opts RESPOptions, l Limits) bool {
	return validLimits(l) && l.MaxReplyBytes <= opts.MaxReplyBytes && 2*l.MaxKeys+8 <= opts.MaxItems
}
func (r *RESPReader) Scan(ctx context.Context, db int, cursor uint64, l Limits) (uint64, [][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !compatibleOptions(r.opts, l) || r.selectDB(ctx, db) != nil {
		return 0, nil, ErrComparison
	}
	r.limit = &l
	defer func() { r.limit = nil }()
	v, e := r.exchange(ctx, args("SCAN", strconv.FormatUint(cursor, 10), "COUNT", "512")...)
	if e != nil || v.kind != '*' || len(v.array) != 2 || v.array[1].kind != '*' || uint64(len(v.array[1].array)) > l.MaxKeys {
		return 0, nil, ErrComparison
	}
	raw, ok := textReply(v.array[0])
	if !ok {
		return 0, nil, ErrComparison
	}
	next, e := strconv.ParseUint(string(raw), 10, 64)
	if e != nil {
		return 0, nil, ErrComparison
	}
	keys := make([][]byte, 0, len(v.array[1].array))
	var total uint64
	for _, item := range v.array[1].array {
		if item.kind != '$' || !checkedAdd(&total, uint64(len(item.bulk)), l.MaxReplyBytes) {
			return 0, nil, ErrComparison
		}
		keys = append(keys, item.bulk)
	}
	return next, keys, nil
}
func (r *RESPReader) Value(ctx context.Context, db int, key []byte, l Limits) (Value, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var value Value
	if !compatibleOptions(r.opts, l) || uint64(len(key)) > l.MaxReplyBytes || r.selectDB(ctx, db) != nil {
		return value, ErrComparison
	}
	r.limit = &l
	defer func() { r.limit = nil }()
	v, e := r.exchange(ctx, []byte("TYPE"), key)
	if e != nil || v.kind != '+' {
		return value, ErrComparison
	}
	value.Type = string(v.bulk)
	if value.Type != "string" && value.Type != "list" && value.Type != "set" && value.Type != "hash" && value.Type != "zset" {
		return Value{}, ErrComparison
	}
	v, e = r.exchange(ctx, []byte("PEXPIRETIME"), key)
	if e != nil || v.kind != ':' || (v.integer != -1 && v.integer <= 0) {
		return Value{}, ErrComparison
	}
	value.ExpiresAt = v.integer
	var command [][]byte
	switch value.Type {
	case "string":
		command = [][]byte{[]byte("GET"), key}
	case "list":
		command = [][]byte{[]byte("LRANGE"), key, []byte("0"), []byte("-1")}
	case "set":
		command = [][]byte{[]byte("SMEMBERS"), key}
	case "hash":
		command = [][]byte{[]byte("HGETALL"), key}
	case "zset":
		command = [][]byte{[]byte("ZRANGE"), key, []byte("0"), []byte("-1"), []byte("WITHSCORES")}
	}
	v, e = r.exchange(ctx, command...)
	if e != nil {
		return Value{}, ErrComparison
	}
	if value.Type == "string" {
		if v.kind != '$' || uint64(len(v.bulk)) > l.MaxReplyBytes {
			return Value{}, ErrComparison
		}
		value.String = v.bulk
		return value, nil
	}
	if v.kind != '*' || len(v.array) == 0 || uint64(len(v.array)) > 2*l.MaxKeys {
		return Value{}, ErrComparison
	}
	var size uint64
	for _, part := range v.array {
		if part.kind != '$' || !checkedAdd(&size, uint64(len(part.bulk)), l.MaxReplyBytes) {
			return Value{}, ErrComparison
		}
	}
	switch value.Type {
	case "list", "set":
		if uint64(len(v.array)) > l.MaxKeys {
			return Value{}, ErrComparison
		}
		items := make([][]byte, len(v.array))
		for i, p := range v.array {
			items[i] = p.bulk
		}
		if value.Type == "list" {
			value.List = items
		} else {
			value.Set = items
		}
	case "zset":
		if len(v.array)%2 != 0 || uint64(len(v.array)/2) > l.MaxKeys {
			return Value{}, ErrComparison
		}
		for i := 0; i < len(v.array); i += 2 {
			score, err := strconv.ParseFloat(string(v.array[i+1].bulk), 64)
			if err != nil {
				return Value{}, ErrComparison
			}
			value.SortedSet = append(value.SortedSet, Member{Name: v.array[i].bulk, Score: score})
		}
	case "hash":
		if len(v.array)%2 != 0 || uint64(len(v.array)/2) > l.MaxKeys {
			return Value{}, ErrComparison
		}
		fields := [][]byte{[]byte("HPEXPIRETIME"), key, []byte("FIELDS"), []byte(strconv.Itoa(len(v.array) / 2))}
		for i := 0; i < len(v.array); i += 2 {
			fields = append(fields, v.array[i].bulk)
			value.Hash = append(value.Hash, Field{Name: v.array[i].bulk, Value: v.array[i+1].bulk})
		}
		expiries, err := r.exchange(ctx, fields...)
		if err != nil || expiries.kind != '*' || len(expiries.array) != len(value.Hash) {
			return Value{}, ErrComparison
		}
		for i, expiry := range expiries.array {
			if expiry.kind != ':' || (expiry.integer != -1 && expiry.integer <= 0) {
				return Value{}, ErrComparison
			}
			value.Hash[i].ExpiresAt = expiry.integer
		}
	}
	return value, nil
}
