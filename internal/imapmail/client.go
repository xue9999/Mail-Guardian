package imapmail

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type Client struct {
	client         *imapclient.Client
	account        string
	selected       string
	uidValidity    uint32
	uidNext        uint32
	done           chan struct{}
	closeOnce      sync.Once
	logoutOnce     sync.Once
	ctx            context.Context
	cancel         context.CancelCauseFunc
	commandTimeout time.Duration
}

// Match go-imap's existing maximum for reading/writing a message literal.
// Each command gets its own budget; a healthy session has no total age limit.
const defaultCommandTimeout = 5 * time.Minute

type Mailbox struct {
	Name       string
	Delimiter  rune
	Attributes []string
	IsJunk     bool
}

type Capabilities struct {
	Move      bool
	UIDPlus   bool
	IMAP4rev2 bool
	Names     []string
}

type Message struct {
	Folder       string
	UIDValidity  uint32
	UID          uint32
	Size         int64
	MessageID    string
	InternalDate time.Time
	Flags        []string
	Raw          []byte
}

type MoveResult struct {
	UIDValidity uint32
	UID         uint32
}

var (
	ErrAuthentication     = errors.New("serwer odrzucił dane logowania IMAP")
	ErrUIDValidityChanged = errors.New("UIDVALIDITY folderu zmieniło się; operacja według UID została zablokowana")
)

// Authentication keeps the login mechanism explicit as providers add token
// adapters. Unsupported methods must never fall back to a password LOGIN.
type Authentication struct {
	Method, Username, Secret string
}

func DialAuthenticated(ctx context.Context, host string, port int, auth Authentication) (*Client, error) {
	if auth.Method != "password" && auth.Method != "" {
		return nil, errors.New("nieobsługiwana metoda uwierzytelniania IMAP; logowanie zablokowane")
	}
	return Dial(ctx, host, port, auth.Username, auth.Secret)
}

func Dial(ctx context.Context, host string, port int, account, password string) (*Client, error) {
	return dialWithTLSConfig(ctx, host, port, account, password, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
}

func dialWithTLSConfig(ctx context.Context, host string, port int, account, password string, tlsConfig *tls.Config) (*Client, error) {
	if host == "" || port < 1 || account == "" || password == "" {
		return nil, errors.New("niepełne dane połączenia IMAP")
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tlsConfig = tlsConfig.Clone()
	if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"imap"}
	}
	dialer := &tls.Dialer{Config: tlsConfig, NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}}
	conn, err := dialWithDNSRetry(ctx, func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", address)
	}, []time.Duration{2 * time.Second, 4 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("połączenie TLS z %s: %w", address, err)
	}
	c := imapclient.New(conn, &imapclient.Options{TLSConfig: tlsConfig})
	out := newClient(ctx, c, account)
	// LOGIN must not race the server's initial greeting. imapclient.New only
	// creates the reader goroutine; it does not wait until the server is ready.
	if err := out.command("greeting", c.WaitGreeting); err != nil {
		out.abort()
		return nil, fmt.Errorf("powitanie serwera IMAP: %w", err)
	}
	caps, err := command(out, "CAPABILITY", func() (imap.CapSet, error) { return c.Caps(), nil })
	if err != nil || caps == nil {
		out.abort()
		if err != nil {
			return nil, fmt.Errorf("możliwości serwera IMAP: %w", err)
		}
		return nil, errors.New("serwer IMAP nie potwierdził możliwości przed logowaniem")
	}
	if err := out.command("LOGIN", func() error { return c.Login(account, password).Wait() }); err != nil {
		_ = out.Close()
		return nil, loginError(err)
	}
	return out, nil
}

// Retry only name-resolution failures while establishing the initial TLS
// connection. No IMAP greeting, login, command, or mailbox mutation has taken
// place here. Other connection/TLS failures are returned without retrying.
// A bounded retry also handles a transient "no such host" immediately after
// a sleeping host wakes, without treating that error as proof of its cause.
func dialWithDNSRetry(ctx context.Context, dial func(context.Context) (net.Conn, error), delays []time.Duration) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		conn, err := dial(ctx)
		if err == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		var dnsErr *net.DNSError
		if attempt >= len(delays) || !errors.As(err, &dnsErr) || !(dnsErr.IsNotFound || dnsErr.IsTemporary || dnsErr.IsTimeout) {
			return nil, err
		}
		timer := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func newClient(ctx context.Context, c *imapclient.Client, account string) *Client {
	lifetime, cancel := context.WithCancelCause(ctx)
	out := &Client{client: c, account: account, done: make(chan struct{}), ctx: lifetime, cancel: cancel, commandTimeout: defaultCommandTimeout}
	go func() {
		select {
		case <-out.ctx.Done():
			out.abort()
		case <-out.done:
		}
	}()
	return out
}

func loginError(err error) error {
	var response *imap.Error
	if errors.As(err, &response) && response.Type == imap.StatusResponseTypeNo &&
		(response.Code == "" || response.Code == "AUTHENTICATIONFAILED" || response.Code == "AUTHORIZATIONFAILED") {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}
	// A reset, timeout or server outage is not evidence of a wrong password.
	return fmt.Errorf("nie udało się zakończyć logowania IMAP: %w", err)
}

func (c *Client) Close() error {
	var err error
	c.logoutOnce.Do(func() {
		if c.ctx.Err() == nil {
			err = c.command("LOGOUT", func() error { return c.client.Logout().Wait() })
		}
		c.abort()
	})
	return err
}

func (c *Client) abort() {
	c.cancel(context.Canceled)
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.client.Close()
	})
}

// Context is cancelled when the caller stops the session or a command loses
// its connection/deadline. The engine uses it to stop before the next message.
func (c *Client) Context() context.Context { return c.ctx }

func (c *Client) command(name string, operation func() error) error {
	_, err := command(c, name, func() (struct{}, error) { return struct{}{}, operation() })
	return err
}

// Start the watchdog before constructing the command, because construction can
// itself block while writing. Closing go-imap unblocks Wait/Collect/Write.
func command[T any](c *Client, name string, operation func() (T, error)) (T, error) {
	var zero T
	if err := context.Cause(c.ctx); err != nil {
		return zero, err
	}
	timeout := c.commandTimeout
	if name == "LOGOUT" && timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		defer close(expired)
		c.cancel(fmt.Errorf("komenda IMAP %s przekroczyła limit %s: %w", name, timeout, context.DeadlineExceeded))
		c.abort()
	})
	result, err := operation()
	if !timer.Stop() {
		<-expired
	}
	if cause := context.Cause(c.ctx); cause != nil {
		return zero, cause
	}
	var response *imap.Error
	recoverable := errors.As(err, &response) && (response.Type == imap.StatusResponseTypeNo || response.Type == imap.StatusResponseTypeBad)
	if err != nil && !recoverable {
		// Tagged NO/BAD responses affect one command. A transport/protocol error
		// means the session cannot safely process the rest of the mailbox.
		c.cancel(err)
		c.abort()
	}
	return result, err
}

func (c *Client) Capabilities() Capabilities {
	caps, _ := command(c, "CAPABILITY", func() (imap.CapSet, error) { return c.client.Caps(), nil })
	var names []string
	for capName := range caps {
		names = append(names, string(capName))
	}
	slices.Sort(names)
	return Capabilities{
		Move:      caps.Has(imap.CapMove),
		UIDPlus:   caps.Has(imap.CapUIDPlus),
		IMAP4rev2: caps.Has(imap.CapIMAP4rev2),
		Names:     names,
	}
}

func (c *Client) SafeMoveSupported() bool {
	return safeMoveSupported(c.Capabilities())
}

func safeMoveSupported(caps Capabilities) bool {
	// Fail closed: UIDPLUS alone would make go-imap emulate MOVE with COPY,
	// STORE \Deleted and UID EXPUNGE. Guardian permits moves only when the
	// server advertises native MOVE (directly or as part of IMAP4rev2).
	return caps.Move || caps.IMAP4rev2
}

func (c *Client) SafeDeleteSupported() bool {
	return c.Capabilities().UIDPlus
}

func (c *Client) ListMailboxes() ([]Mailbox, error) {
	data, err := command(c, "LIST", func() ([]*imap.ListData, error) { return c.client.List("", "*", nil).Collect() })
	if err != nil {
		return nil, fmt.Errorf("lista folderów IMAP: %w", err)
	}
	out := make([]Mailbox, 0, len(data))
	for _, item := range data {
		m := Mailbox{Name: item.Mailbox, Delimiter: item.Delim}
		for _, attr := range item.Attrs {
			m.Attributes = append(m.Attributes, string(attr))
			if attr == imap.MailboxAttrJunk {
				m.IsJunk = true
			}
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b Mailbox) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

func DetectSpamFolder(mailboxes []Mailbox) string {
	for _, box := range mailboxes {
		if box.IsJunk {
			return box.Name
		}
	}
	candidates := []string{"spam", "junk", "niechciane", "wiadomości-śmieci", "wiadomosci-smieci"}
	for _, wanted := range candidates {
		for _, box := range mailboxes {
			name := strings.ToLower(strings.TrimSpace(box.Name))
			if name == wanted || strings.HasSuffix(name, "/"+wanted) || strings.HasSuffix(name, "."+wanted) {
				return box.Name
			}
		}
	}
	return ""
}

func (c *Client) EnsureMailboxes(names ...string) error {
	existing, err := c.ListMailboxes()
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(existing))
	folded := make(map[string]string, len(existing))
	for _, box := range existing {
		seen[box.Name] = true
		folded[strings.ToLower(box.Name)] = box.Name
	}
	for _, name := range names {
		if seen[name] {
			continue
		}
		if conflict, ok := folded[strings.ToLower(name)]; ok {
			return fmt.Errorf(
				"folder %q różni się od wymaganej nazwy %q tylko wielkością liter; zmień jego nazwę przed uruchomieniem Guardiana",
				conflict,
				name,
			)
		}
		if err := c.command("CREATE", func() error { return c.client.Create(name, nil).Wait() }); err != nil {
			return fmt.Errorf("tworzenie folderu %q: %w", name, err)
		}
		seen[name] = true
		folded[strings.ToLower(name)] = name
	}
	return nil
}

func (c *Client) SearchSince(folder string, since time.Time, limit int) ([]uint32, uint32, error) {
	uidValidity, err := c.selectFolderFresh(folder, true)
	if err != nil {
		return nil, 0, err
	}
	criteria := &imap.SearchCriteria{}
	if !since.IsZero() {
		criteria.Since = since
	}
	data, err := command(c, "UID SEARCH", func() (*imap.SearchData, error) { return c.client.UIDSearch(criteria, nil).Wait() })
	if err != nil {
		return nil, 0, fmt.Errorf("wyszukiwanie w folderze %q: %w", folder, err)
	}
	uids := data.AllUIDs()
	out := make([]uint32, len(uids))
	for i, uid := range uids {
		out[i] = uint32(uid)
	}
	slices.Sort(out)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, uidValidity, nil
}

// SearchExactSize narrows an investigation to messages of one RFC822 size.
// The caller must still verify the complete message before identifying it.
func (c *Client) SearchExactSize(folder string, size int64) ([]uint32, uint32, error) {
	if size < 1 {
		return nil, 0, errors.New("rozmiar wiadomości musi być dodatni")
	}
	uidValidity, err := c.selectFolderFresh(folder, true)
	if err != nil {
		return nil, 0, err
	}
	data, err := command(c, "UID SEARCH", func() (*imap.SearchData, error) {
		return c.client.UIDSearch(&imap.SearchCriteria{Larger: size - 1, Smaller: size + 1}, nil).Wait()
	})
	if err != nil {
		return nil, 0, fmt.Errorf("wyszukiwanie rozmiaru w folderze %q: %w", folder, err)
	}
	uids := data.AllUIDs()
	out := make([]uint32, len(uids))
	for i, uid := range uids {
		out[i] = uint32(uid)
	}
	slices.Sort(out)
	return out, uidValidity, nil
}

// SearchUIDPage searches a bounded numeric UID range strictly above afterUID.
// The server therefore never needs to return an unbounded folder-wide result.
func (c *Client) SearchUIDPage(folder string, afterUID uint32, limit int) ([]uint32, uint32, bool, error) {
	if limit < 1 || limit > 1000 {
		return nil, 0, false, errors.New("rozmiar strony UID musi mieścić się między 1 a 1000")
	}
	uidValidity, err := c.selectFolder(folder, true)
	if err != nil {
		return nil, 0, false, err
	}
	start := afterUID + 1
	if start == 0 || c.uidNext == 0 {
		return nil, uidValidity, true, nil
	}
	lastUID := c.uidNext - 1
	if start > lastUID {
		return nil, uidValidity, true, nil
	}
	end := start + uint32(limit) - 1
	if end < start || end > lastUID {
		end = lastUID
	}
	uidSet := imap.UIDSet{}
	uidSet.AddRange(imap.UID(start), imap.UID(end))
	data, err := command(c, "UID SEARCH", func() (*imap.SearchData, error) {
		return c.client.UIDSearch(&imap.SearchCriteria{UID: []imap.UIDSet{uidSet}}, nil).Wait()
	})
	if err != nil {
		return nil, 0, false, fmt.Errorf("stronicowane wyszukiwanie w folderze %q: %w", folder, err)
	}
	uids := data.AllUIDs()
	out := make([]uint32, len(uids))
	for i, uid := range uids {
		out[i] = uint32(uid)
	}
	slices.Sort(out)
	complete := end >= lastUID
	return out, uidValidity, complete, nil
}

func (c *Client) Fetch(folder string, uid uint32, withRaw bool) (Message, error) {
	uidValidity, err := c.selectFolder(folder, true)
	if err != nil {
		return Message{}, err
	}
	options := &imap.FetchOptions{
		UID: true, Envelope: true, Flags: true, InternalDate: true, RFC822Size: true,
	}
	if withRaw {
		options.BodySection = []*imap.FetchItemBodySection{{Peek: true}}
	}
	items, err := command(c, "UID FETCH", func() ([]*imapclient.FetchMessageBuffer, error) {
		return c.client.Fetch(imap.UIDSetNum(imap.UID(uid)), options).Collect()
	})
	if err != nil {
		return Message{}, fmt.Errorf("pobieranie UID %d z %q: %w", uid, folder, err)
	}
	if len(items) != 1 {
		return Message{}, fmt.Errorf("wiadomość UID %d zniknęła z folderu %q", uid, folder)
	}
	item := items[0]
	msg := Message{
		Folder: folder, UIDValidity: uidValidity, UID: uint32(item.UID),
		Size: item.RFC822Size, InternalDate: item.InternalDate,
	}
	if item.Envelope != nil {
		msg.MessageID = item.Envelope.MessageID
	}
	for _, flag := range item.Flags {
		msg.Flags = append(msg.Flags, string(flag))
	}
	if withRaw {
		if len(item.BodySection) != 1 {
			return Message{}, fmt.Errorf("serwer nie zwrócił pełnej treści UID %d", uid)
		}
		msg.Raw = item.BodySection[0].Bytes
	}
	return msg, nil
}

// ProbeFetch reports only whether individual read-only FETCH items succeed.
// It is intended for diagnosing server-side failures without exposing mail.
func (c *Client) ProbeFetch(folder string, uid uint32) (map[string]string, error) {
	if _, err := c.selectFolderFresh(folder, true); err != nil {
		return nil, err
	}
	checks := []struct {
		name    string
		options *imap.FetchOptions
	}{
		{"uid", &imap.FetchOptions{UID: true}},
		{"size", &imap.FetchOptions{RFC822Size: true}},
		{"envelope", &imap.FetchOptions{Envelope: true}},
		{"flags", &imap.FetchOptions{Flags: true}},
		{"internal_date", &imap.FetchOptions{InternalDate: true}},
		{"body", &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Peek: true}}}},
	}
	result := map[string]string{}
	for _, check := range checks {
		items, err := command(c, "UID FETCH", func() ([]*imapclient.FetchMessageBuffer, error) {
			return c.client.Fetch(imap.UIDSetNum(imap.UID(uid)), check.options).Collect()
		})
		if err != nil {
			result[check.name] = err.Error()
			if cause := context.Cause(c.ctx); cause != nil {
				return result, cause
			}
		} else if len(items) != 1 {
			result[check.name] = "missing"
		} else {
			result[check.name] = "ok"
		}
	}
	return result, nil
}

func (c *Client) Move(folder string, expectedUIDValidity, uid uint32, destination string, markUnread bool) (MoveResult, error) {
	return c.move(folder, expectedUIDValidity, uid, destination, markUnread, "")
}

// MoveWithRaw confirms a MOVE without COPYUID by finding the exact message
// among UIDs newly assigned in the destination. An ambiguous match stays
// unresolved for the engine's durable reconciliation path.
func (c *Client) MoveWithRaw(folder string, expectedUIDValidity, uid uint32, destination string, markUnread bool, rawSHA256 string) (MoveResult, error) {
	return c.move(folder, expectedUIDValidity, uid, destination, markUnread, rawSHA256)
}

func (c *Client) move(folder string, expectedUIDValidity, uid uint32, destination string, markUnread bool, rawSHA256 string) (MoveResult, error) {
	if !c.SafeMoveSupported() {
		return MoveResult{}, errors.New("serwer nie obsługuje natywnego IMAP MOVE; przenoszenie zablokowane")
	}
	var destinationValidity, destinationNext uint32
	if rawSHA256 != "" {
		var err error
		destinationValidity, err = c.selectFolderFresh(destination, true)
		if err != nil {
			return MoveResult{}, err
		}
		destinationNext = c.uidNext
		if destinationNext == 0 {
			return MoveResult{}, errors.New("serwer nie podał UIDNEXT folderu docelowego; przenoszenie zablokowane")
		}
	}
	uidValidity, err := c.selectFolder(folder, false)
	if err != nil {
		return MoveResult{}, err
	}
	if err := requireUIDValidity(folder, expectedUIDValidity, uidValidity); err != nil {
		return MoveResult{}, err
	}
	data, err := command(c, "UID MOVE", func() (*imapclient.MoveData, error) {
		return c.client.Move(imap.UIDSetNum(imap.UID(uid)), destination).Wait()
	})
	if err != nil {
		return MoveResult{}, fmt.Errorf("przenoszenie UID %d z %q do %q: %w", uid, folder, destination, err)
	}
	result := MoveResult{UIDValidity: data.UIDValidity}
	if uids, ok := data.DestUIDs.(imap.UIDSet); ok {
		nums, complete := uids.Nums()
		if complete && len(nums) == 1 {
			result.UID = uint32(nums[0])
		}
	}
	if (result.UID == 0 || result.UIDValidity == 0) && rawSHA256 != "" {
		if resolved, ok := c.resolveMovedUID(destination, destinationValidity, destinationNext, rawSHA256); ok {
			result = resolved
		}
	}
	if markUnread && result.UID > 0 {
		if err := c.MarkUnread(destination, result.UIDValidity, result.UID); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (c *Client) resolveMovedUID(destination string, oldValidity, oldNext uint32, rawSHA256 string) (MoveResult, bool) {
	// Some providers acknowledge MOVE before their destination view catches
	// up. Retry confirmation reads only; repeating MOVE could duplicate mail.
	for attempt, delay := range []time.Duration{0, 250 * time.Millisecond, 750 * time.Millisecond} {
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				return MoveResult{}, false
			case <-timer.C:
			}
		}
		result, retry := c.resolveMovedUIDOnce(destination, oldValidity, oldNext, rawSHA256)
		if result.UID != 0 {
			return result, true
		}
		if !retry {
			break
		}
	}
	return MoveResult{}, false
}

// retry is true only for a complete, unambiguous read with no match yet.
// Errors, changed UIDVALIDITY and multiple matches require durable recovery.
func (c *Client) resolveMovedUIDOnce(destination string, oldValidity, oldNext uint32, rawSHA256 string) (result MoveResult, retry bool) {
	newValidity, err := c.selectFolderFresh(destination, true)
	if err != nil || oldNext == 0 || newValidity == 0 || newValidity != oldValidity || c.uidNext < oldNext {
		return MoveResult{}, false
	}
	if c.uidNext-oldNext > 1000 {
		return MoveResult{}, false
	}
	uids, _, complete, err := c.SearchUIDPage(destination, oldNext-1, 1000)
	if err != nil || !complete {
		return MoveResult{}, false
	}
	var matchedUID uint32
	for _, candidateUID := range uids {
		// Confirmation needs exact bytes, not an ENVELOPE parsed by the
		// provider. An unrelated malformed envelope must not break a move.
		items, err := command(c, "UID FETCH", func() ([]*imapclient.FetchMessageBuffer, error) {
			return c.client.Fetch(imap.UIDSetNum(imap.UID(candidateUID)), &imap.FetchOptions{
				UID: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}},
			}).Collect()
		})
		if err != nil || len(items) != 1 || uint32(items[0].UID) != candidateUID || len(items[0].BodySection) != 1 {
			return MoveResult{}, false
		}
		sum := sha256.Sum256(items[0].BodySection[0].Bytes)
		if hex.EncodeToString(sum[:]) == rawSHA256 {
			if matchedUID != 0 {
				return MoveResult{}, false
			}
			matchedUID = candidateUID
		}
	}
	if matchedUID == 0 {
		return MoveResult{}, true
	}
	return MoveResult{UIDValidity: newValidity, UID: matchedUID}, false
}

func (c *Client) MarkUnread(folder string, expectedUIDValidity, uid uint32) error {
	uidValidity, err := c.selectFolder(folder, false)
	if err != nil {
		return err
	}
	if err := requireUIDValidity(folder, expectedUIDValidity, uidValidity); err != nil {
		return err
	}
	if err := c.command("UID STORE", func() error {
		return c.client.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{
			Op: imap.StoreFlagsDel, Silent: true, Flags: []imap.Flag{imap.FlagSeen},
		}, nil).Close()
	}); err != nil {
		return fmt.Errorf("oznaczanie odzyskanej wiadomości jako nieprzeczytanej: %w", err)
	}
	return nil
}

func (c *Client) AppendUnread(folder string, raw []byte, internalDate time.Time) (MoveResult, error) {
	if len(raw) == 0 {
		return MoveResult{}, errors.New("nie można przywrócić pustej wiadomości")
	}
	if internalDate.IsZero() {
		internalDate = time.Now()
	}
	data, err := command(c, "APPEND", func() (*imap.AppendData, error) {
		cmd := c.client.Append(folder, int64(len(raw)), &imap.AppendOptions{Time: internalDate})
		if _, err := cmd.Write(raw); err != nil {
			return nil, err
		}
		if err := cmd.Close(); err != nil {
			return nil, err
		}
		return cmd.Wait()
	})
	if err != nil {
		return MoveResult{}, fmt.Errorf("przywracanie wiadomości do %q: %w", folder, err)
	}
	return MoveResult{UIDValidity: data.UIDValidity, UID: uint32(data.UID)}, nil
}

func (c *Client) DeleteUID(folder string, expectedUIDValidity, uid uint32) error {
	if !c.SafeDeleteSupported() {
		return errors.New("serwer nie obsługuje UIDPLUS; trwałe kasowanie zablokowane")
	}
	uidValidity, err := c.selectFolder(folder, false)
	if err != nil {
		return err
	}
	if err := requireUIDValidity(folder, expectedUIDValidity, uidValidity); err != nil {
		return err
	}
	if err := c.command("UID STORE", func() error {
		return c.client.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
		}, nil).Close()
	}); err != nil {
		return err
	}
	// STORE and UID EXPUNGE are separate UID mutations. Re-select and compare
	// the generation again immediately before the irreversible second command;
	// the mailbox may have been rebuilt while the STORE response was in flight.
	uidValidity, err = c.selectFolderFresh(folder, false)
	if err != nil {
		return err
	}
	if err := requireUIDValidity(folder, expectedUIDValidity, uidValidity); err != nil {
		return err
	}
	if err := c.command("UID EXPUNGE", func() error { return c.client.UIDExpunge(imap.UIDSetNum(imap.UID(uid))).Close() }); err != nil {
		rollbackErr := c.command("UID STORE rollback", func() error {
			return c.client.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{
				Op: imap.StoreFlagsDel, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
			}, nil).Close()
		})
		if rollbackErr != nil {
			return fmt.Errorf(
				"UID EXPUNGE %d w %q nie zostało jednoznacznie potwierdzone (%v), a cofnięcie flagi \\\\Deleted także się nie udało: %w",
				uid, folder, err, rollbackErr,
			)
		}
		return fmt.Errorf(
			"UID EXPUNGE %d w %q nie powiodło się; flaga \\\\Deleted została cofnięta: %w",
			uid, folder, err,
		)
	}
	return nil
}

func requireUIDValidity(folder string, expected, actual uint32) error {
	if expected == 0 || actual == 0 || expected != actual {
		return fmt.Errorf("%w: folder %q, oczekiwano %d, serwer zgłosił %d", ErrUIDValidityChanged, folder, expected, actual)
	}
	return nil
}

func (c *Client) selectFolder(folder string, readOnly bool) (uint32, error) {
	if c.selected == folder && c.uidValidity != 0 {
		// A read-write selection also satisfies a read-only request.
		if readOnly {
			return c.uidValidity, nil
		}
		// Select again because we do not track whether the existing selection is read-only.
	}
	return c.selectFolderFresh(folder, readOnly)
}

func (c *Client) selectFolderFresh(folder string, readOnly bool) (uint32, error) {
	data, err := command(c, "SELECT", func() (*imap.SelectData, error) {
		return c.client.Select(folder, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	})
	if err != nil {
		return 0, fmt.Errorf("otwieranie folderu %q: %w", folder, err)
	}
	c.selected = folder
	c.uidValidity = data.UIDValidity
	c.uidNext = uint32(data.UIDNext)
	return data.UIDValidity, nil
}
