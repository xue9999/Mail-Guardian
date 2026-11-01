package imapmail

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoginWaitsForServerGreeting(t *testing.T) {
	serverTLS, roots := testTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			result <- err
			return
		}
		conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		b := make([]byte, 1)
		n, err := conn.Read(b)
		var networkError net.Error
		if n != 0 || err == nil || !errors.As(err, &networkError) || !networkError.Timeout() {
			result <- fmt.Errorf("client sent bytes before the greeting")
			return
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(conn, "* OK [CAPABILITY IMAP4rev1] greeting ready\r\n")
		reader := bufio.NewReader(conn)
		loggedIn := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				result <- err
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				result <- fmt.Errorf("invalid command")
				return
			}
			switch fields[1] {
			case "CAPABILITY":
				fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1\r\n%s OK capabilities\r\n", fields[0])
			case "LOGIN":
				loggedIn = true
				fmt.Fprintf(conn, "%s OK [CAPABILITY IMAP4rev1] authenticated\r\n", fields[0])
			case "LOGOUT":
				if !loggedIn {
					result <- fmt.Errorf("missing LOGIN")
					return
				}
				fmt.Fprintf(conn, "* BYE\r\n%s OK done\r\n", fields[0])
				result <- nil
				return
			default:
				result <- fmt.Errorf("unexpected command")
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscan(portText, &port)
	client, err := dialWithTLSConfig(ctx, host, port, "fixture", "fixture-password", &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
