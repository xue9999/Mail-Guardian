package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/o2-mail-guardian/guardian/internal/apperror"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/service"
)

func TestServerConfigIsExplicitPrivateAndNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pilot.toml")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	a := &application{out: &output, errOut: &output, configPath: path}
	writeFixture := func(output string, data []byte) error {
		return createPrivateInitialConfig(filepath.Dir(path), output, data, uint32(os.Geteuid()))
	}
	args := []string{"init-config", "--instance", "pilot", "--email", "fixture@o2.pl", "--server-spam", "Spam", "--output", path}
	if err := a.serverCommandWithConfigWriter(args, writeFixture); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLinuxConfig(cfg, "pilot"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatal("configuration is not private")
	}
	original, _ := os.ReadFile(path)
	if err := a.serverCommandWithConfigWriter(args, writeFixture); err == nil {
		t.Fatal("existing configuration was overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("existing configuration changed")
	}
	if err := a.serverCommand([]string{"validate-config", "--instance", "pilot"}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*config.Config){
		func(c *config.Config) { c.Runtime.DataDir += "/../other" },
		func(c *config.Config) { c.Runtime.Database = "/tmp/guardian.db" },
		func(c *config.Config) { c.Runtime.ComposeFile = "/tmp/compose.yaml" },
		func(c *config.Config) { c.Runtime.ArchiveDir = "/tmp/archive" },
		func(c *config.Config) { c.Safety.Mode = "invalid" },
		func(c *config.Config) { c.Safety.PurgeEnabled = true },
	} {
		bad := cfg
		change(&bad)
		if err := validateLinuxConfig(bad, "pilot"); err == nil {
			t.Fatal("unsafe Linux configuration accepted")
		}
	}
	for _, slug := range []string{"", "../pilot", "-pilot", "pilot;id", strings.Repeat("a", 65)} {
		if err := validateLinuxConfig(cfg, slug); err == nil {
			t.Fatal("invalid instance accepted")
		}
	}
}

func TestServerConfigurationRejectsMissingFolderWithoutCreatingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	var output bytes.Buffer
	a := &application{out: &output, errOut: &output}
	if err := a.serverCommand([]string{"init-config", "--instance", "pilot", "--email", "fixture@o2.pl", "--output", path}); err == nil {
		t.Fatal("unconfirmed server spam folder accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid setup created output")
	}
}

func TestServerActiveConfigurationIsExplicitAndPurgeRemainsDisabled(t *testing.T) {
	for _, mode := range []string{"protect", "active", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.toml")
			var output bytes.Buffer
			a := &application{out: &output, errOut: &output, configPath: path}
			writer := func(output string, data []byte) error {
				return createPrivateInitialConfig(dir, output, data, uint32(os.Geteuid()))
			}
			err := a.serverCommandWithConfigWriter([]string{"init-config", "--instance", "pilot", "--email", "fixture@o2.pl", "--server-spam", "Spam", "--mode", mode, "--output", path}, writer)
			if mode == "invalid" {
				if err == nil {
					t.Fatal("invalid mode accepted")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("invalid mode created output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil || cfg.Safety.Mode != mode || cfg.Safety.PurgeEnabled {
				t.Fatalf("policy changed or permanent deletion enabled: %+v %v", cfg.Safety, err)
			}
			cfg.Safety.PurgeEnabled = true
			if err := validateLinuxConfig(cfg, "pilot"); err == nil {
				t.Fatal("permanent deletion accepted")
			}
		})
	}
}

func TestLinuxEntryPointsDoNotFallbackToMacRuntime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command dispatch")
	}
	var output bytes.Buffer
	a := &application{out: &output, errOut: &output, configPath: filepath.Join(t.TempDir(), "missing.toml")}
	if err := a.execute(nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Linux pilot") || strings.Contains(output.String(), "otwiera proste menu") {
		t.Fatal("no-argument Linux invocation entered or advertised the Mac menu")
	}
	for _, args := range [][]string{{"run"}, {"stack", "up"}, {"stack", "down"}, {"service-run"}, {"status"}, {"doctor"}, {"archive", "list"}} {
		output.Reset()
		if err := a.execute(args); err == nil {
			t.Fatalf("missing Linux config accepted for %v", args)
		}
		if output.Len() != 0 {
			t.Fatalf("%v began work before configuration validation: %s", args, output.String())
		}
	}
	for _, args := range [][]string{{"menu"}, {"repair"}, {"setup"}, {"api", "status"}, {"mode", "active"}, {"purge"}} {
		if err := a.execute(args); err == nil {
			t.Fatalf("unsupported Linux entry point accepted: %v", args)
		}
	}
}

func TestLinuxServiceAndStackCheckInstanceLockBeforeMaintenance(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux locking boundary")
	}
	data := t.TempDir()
	cfg, err := config.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Account.Username = "fixture@o2.pl", "fixture@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = data
	cfg.Runtime.Database = filepath.Join(data, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(data, "archive")
	cfg.Runtime.LogFile = filepath.Join(data, "guardian.log")
	configPath := filepath.Join(data, "config.toml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireRunLock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	var output bytes.Buffer
	a := &application{configPath: configPath, out: &output, errOut: &output}
	for _, call := range []struct {
		name string
		run  func() error
	}{
		{"service-run", a.linuxServiceRun},
		{"stack up", func() error { return a.stackCommand([]string{"up"}) }},
		{"stack down", func() error { return a.stackCommand([]string{"down"}) }},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.run()
			if err == nil || apperror.From(err).Code != apperror.Busy {
				t.Fatalf("expected lock rejection before helper dispatch, got %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("operation emitted output before lock rejection: %s", output.String())
			}
			for _, name := range []string{service.HeartbeatFileName, "guardian.db", "guardian.log"} {
				if _, err := os.Stat(filepath.Join(data, name)); !os.IsNotExist(err) {
					t.Fatalf("%s changed before acquiring the instance lock", name)
				}
			}
		})
	}
}
