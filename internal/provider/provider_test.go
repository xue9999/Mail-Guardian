package provider

import "testing"

func TestProfilesRequireExplicitSecureConnectionAndKnownAuthentication(t *testing.T) {
	c, err := Resolve("", "", 0, "", "me@o2.pl", "")
	if err != nil || c.Host != "poczta.o2.pl" || c.Port != 993 || c.Username != "me@o2.pl" || c.AuthMethod != Password {
		t.Fatalf("legacy defaults: %+v %v", c, err)
	}
	for _, host := range []string{"imap.example.org", "127.0.0.1", "::1"} {
		if _, err := Resolve("custom", host, 993, "login", "me@example.org", Password); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"", "https://imap.example.org", "imap.example.org:993", " user@example.org", "imap.example.org\n"} {
		if _, err := Resolve("custom", host, 993, "login", "me@example.org", Password); err == nil {
			t.Fatalf("bad endpoint %q accepted", host)
		}
	}
	if _, err := Resolve("o2", "imap.example.org", 993, "me", "me@example.org", Password); err == nil {
		t.Fatal("o2 profile accepted foreign endpoint")
	}
	if _, err := Resolve("gmail", "imap.gmail.com", 993, "me", "me@example.org", Password); err == nil {
		t.Fatal("unqualified profile accepted")
	}
}
