package platform

import "testing"

func TestLinuxPathsIsolateInstancesAndRejectTraversal(t *testing.T) {
	a, err := LinuxPaths("pilot-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LinuxPaths("pilot-b")
	if err != nil {
		t.Fatal(err)
	}
	if a.Config != "/etc/mail-guardian/pilot-a/config.toml" || a.Data != "/var/lib/mail-guardian/pilot-a" || a.Database == b.Database || a.Compose == b.Compose {
		t.Fatalf("paths: %+v %+v", a, b)
	}
	for _, name := range []string{"", "..", "../pilot", "/etc", "a/b", "-option", "a\n"} {
		if _, err := LinuxPaths(name); err == nil {
			t.Fatalf("unsafe instance %q accepted", name)
		}
	}
}
