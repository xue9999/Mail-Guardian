package imapmail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func commandFixture(t *testing.T, ctx context.Context, timeout time.Duration, respond func(net.Conn, string, string)) *Client {
	t.Helper()
	conn, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		fmt.Fprint(server, "* PREAUTH [CAPABILITY IMAP4rev1] fixture ready\r\n")
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return
			}
			respond(server, fields[0], fields[1])
		}
	}()
	client := newClient(ctx, imapclient.New(conn, nil), "fixture")
	client.commandTimeout = timeout
	t.Cleanup(func() {
		client.abort()
		server.Close()
		<-done
	})
	if err := client.command("greeting", client.client.WaitGreeting); err != nil {
		t.Fatal(err)
	}
	return client
}

func fixtureListReply(conn net.Conn, tag, name string) {
	if name == "LOGOUT" {
		fmt.Fprintf(conn, "* BYE done\r\n%s OK done\r\n", tag)
		return
	}
	fmt.Fprintf(conn, "* LIST () \"/\" \"INBOX\"\r\n%s OK listed\r\n", tag)
}

func TestHealthyCommandsCanOutliveIndividualCommandBudget(t *testing.T) {
	const budget = 200 * time.Millisecond
	client := commandFixture(t, context.Background(), budget, func(conn net.Conn, tag, name string) {
		if name == "LIST" {
			time.Sleep(55 * time.Millisecond)
		}
		fixtureListReply(conn, tag, name)
	})
	started := time.Now()
	for i := 0; i < 5; i++ {
		boxes, err := client.ListMailboxes()
		if err != nil || len(boxes) != 1 || boxes[0].Name != "INBOX" {
			t.Fatalf("healthy command %d failed: %+v %v", i, boxes, err)
		}
	}
	if time.Since(started) <= budget || client.Context().Err() != nil {
		t.Fatal("healthy session was limited by its total age")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStalledCommandCancelsSessionAndDoesNotSendNextCommand(t *testing.T) {
	var requests atomic.Int32
	client := commandFixture(t, context.Background(), 50*time.Millisecond, func(net.Conn, string, string) { requests.Add(1) })
	_, err := client.ListMailboxes()
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(context.Cause(client.Context()), context.DeadlineExceeded) {
		t.Fatalf("stalled command did not preserve its timeout cause: %v / %v", err, context.Cause(client.Context()))
	}
	_, nextErr := client.ListMailboxes()
	if !errors.Is(nextErr, context.DeadlineExceeded) || requests.Load() != 1 {
		t.Fatalf("cancelled session sent another command: requests=%d err=%v", requests.Load(), nextErr)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestParentCancellationUnblocksActiveCommand(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	started := make(chan struct{})
	client := commandFixture(t, ctx, time.Second, func(net.Conn, string, string) { close(started) })
	result := make(chan error, 1)
	go func() { _, err := client.ListMailboxes(); result <- err }()
	<-started
	cause := errors.New("fixture interrupted")
	cancel(cause)
	select {
	case err := <-result:
		if !errors.Is(err, cause) || !errors.Is(context.Cause(client.Context()), cause) {
			t.Fatalf("parent cancellation cause lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not interrupt the active command")
	}
}

func TestTaggedCommandFailureKeepsSessionUsable(t *testing.T) {
	var requests atomic.Int32
	client := commandFixture(t, context.Background(), time.Second, func(conn net.Conn, tag, name string) {
		if name == "LIST" && requests.Add(1) == 1 {
			fmt.Fprintf(conn, "%s NO temporary command failure\r\n", tag)
			return
		}
		fixtureListReply(conn, tag, name)
	})
	if _, err := client.ListMailboxes(); err == nil || client.Context().Err() != nil {
		t.Fatalf("a tagged NO incorrectly cancelled the session: %v", err)
	}
	if _, err := client.ListMailboxes(); err != nil {
		t.Fatalf("session did not recover after a tagged NO: %v", err)
	}
}

func TestLogoutTimeoutDoesNotDeadlockClose(t *testing.T) {
	client := commandFixture(t, context.Background(), 50*time.Millisecond, func(net.Conn, string, string) {})
	result := make(chan error, 1)
	go func() { result <- client.Close() }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("logout timeout cause lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed-out LOGOUT deadlocked with transport close")
	}
}

func TestByeClosesSessionBeforeNextCommand(t *testing.T) {
	var requests atomic.Int32
	client := commandFixture(t, context.Background(), time.Second, func(conn net.Conn, tag, name string) {
		requests.Add(1)
		fmt.Fprint(conn, "* BYE server shutting down\r\n")
		conn.Close()
	})
	if _, err := client.ListMailboxes(); err == nil || context.Cause(client.Context()) == nil {
		t.Fatalf("server BYE did not cancel the session: %v", err)
	}
	if _, err := client.ListMailboxes(); err == nil || requests.Load() != 1 {
		t.Fatalf("a command was sent after BYE: requests=%d err=%v", requests.Load(), err)
	}
}

func TestOnlyNoAndBadStatusErrorsAreRecoverable(t *testing.T) {
	for _, status := range []imap.StatusResponseType{imap.StatusResponseTypeNo, imap.StatusResponseTypeBad, imap.StatusResponseTypeBye, imap.StatusResponseTypePreAuth} {
		t.Run(string(status), func(t *testing.T) {
			var requests atomic.Int32
			client := commandFixture(t, context.Background(), time.Second, func(conn net.Conn, tag, name string) {
				requests.Add(1)
				fixtureListReply(conn, tag, name)
			})
			statusErr := &imap.Error{Type: status, Text: "fixture status"}
			if err := client.command("fixture status", func() error { return statusErr }); !errors.Is(err, statusErr) {
				t.Fatalf("status error lost: %v", err)
			}
			recoverable := status == imap.StatusResponseTypeNo || status == imap.StatusResponseTypeBad
			if (client.Context().Err() == nil) != recoverable {
				t.Fatalf("wrong recovery policy for %s: %v", status, context.Cause(client.Context()))
			}
			_, err := client.ListMailboxes()
			if recoverable {
				if err != nil || requests.Load() != 1 {
					t.Fatalf("recoverable error disabled the session: %v", err)
				}
			} else if !errors.Is(err, statusErr) || requests.Load() != 0 {
				t.Fatalf("session-ending status allowed another command: requests=%d err=%v", requests.Load(), err)
			}
		})
	}
}
