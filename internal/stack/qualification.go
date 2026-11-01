package stack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type QualificationSandbox struct {
	ScanURL, LearnURL, Password, Root string
	names                             []string
	label                             string
}

// NewQualificationSandbox starts a fresh disposable model. It has no access
// to the production Redis volume, credentials or plaintext message files.
func (m Manager) NewQualificationSandbox(ctx context.Context, dataDir string) (s *QualificationSandbox, retErr error) {
	if runtime.GOOS == "linux" {
		return nil, errors.New("kwalifikacja na Linux wymaga odrębnego środowiska administratora; worker nie ma dostępu do Dockera")
	}
	if err := m.CheckStorage(); err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	label := hex.EncodeToString(random[:])
	prefix := "guardian-qualification-" + label[:12]
	root, err := os.MkdirTemp(dataDir, "qualification-sandbox-")
	if err != nil {
		return nil, err
	}
	s = &QualificationSandbox{Root: root, label: label}
	defer func(owned *QualificationSandbox) {
		if retErr != nil {
			owned.Close()
		}
	}(s)
	local := filepath.Join(root, "local.d")
	if err := os.Mkdir(local, 0o700); err != nil {
		return nil, err
	}
	for _, name := range []string{"fuzzy_check.conf", "logging.inc", "neural.conf", "options.inc", "url_redirector.conf"} {
		content, err := os.ReadFile(filepath.Join(filepath.Dir(m.ComposeFile), "rspamd", "local.d", name))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(local, name), content, 0o644); err != nil {
			return nil, err
		}
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	s.Password = hex.EncodeToString(secret[:])
	redisName, rspamdName := prefix+"-redis", prefix+"-rspamd"
	files := map[string]string{
		"classifier-bayes.conf": "backend = \"redis\";\nnew_schema = true;\nmin_learns = 100;\nautolearn = false;\nexpire = 8640000;\n",
		"redis.conf":            fmt.Sprintf("servers = %q;\ntimeout = 2s;\n", redisName+":6379"),
		"worker-controller.inc": fmt.Sprintf("password = %q;\nenable_password = %q;\n", s.Password, s.Password),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(local, name), []byte(body), 0o644); err != nil {
			return nil, err
		}
	}
	run := func(args ...string) error {
		out, err := stackCommand(ctx, commandPath("docker"), append([]string{"--context", "colima"}, args...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nie udało się uruchomić odrębnego modelu: %w (%s)", err, safeOutput(out))
		}
		return nil
	}
	s.names = append(s.names, redisName)
	if err := run("run", "-d", "--name", redisName, "--label", "guardian.qualification="+label, "--network", "o2-mail-guardian", "--read-only", "--cap-drop", "ALL", "--user", "redis", "--memory", "256m", "--pids-limit", "96", "redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99", "redis-server", "--save", "", "--appendonly", "no"); err != nil {
		return nil, err
	}
	args := []string{"run", "-d", "--name", rspamdName, "--label", "guardian.qualification=" + label, "--network", "o2-mail-guardian", "--read-only", "--cap-drop", "ALL", "--memory", "1g", "--cpus", "2", "--pids-limit", "256", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--tmpfs", "/run:rw,noexec,nosuid,size=16m", "--tmpfs", "/var/lib/rspamd:rw,size=128m,mode=777", "-e", "RSPAMD_LOCAL_ADDR=*", "-e", "RSPAMD_LOG_TYPE=console", "-p", "127.0.0.1::11333", "-p", "127.0.0.1::11334"}
	entries, err := os.ReadDir(local)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		args = append(args, "-v", filepath.Join(local, entry.Name())+":/etc/rspamd/local.d/"+entry.Name()+":ro")
	}
	args = append(args, "rspamd/rspamd:4.1.2@sha256:15dfe447f8913516c4ff24933a0727aff53d88bf38ef1937fb74f5152568f496")
	s.names = append(s.names, rspamdName)
	if err := run(args...); err != nil {
		return nil, err
	}
	endpoint := func(port string) (string, error) {
		out, err := stackCommand(ctx, commandPath("docker"), "--context", "colima", "port", rspamdName, port+"/tcp").Output()
		if err != nil {
			return "", err
		}
		address := strings.TrimSpace(string(out))
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return "", errors.New("silnik testowy nie jest ograniczony do localhost")
		}
		return "http://" + address, nil
	}
	s.ScanURL, err = endpoint("11333")
	if err != nil {
		return nil, err
	}
	s.ScanURL += "/checkv2"
	s.LearnURL, err = endpoint("11334")
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *QualificationSandbox) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := len(s.names) - 1; i >= 0; i-- {
		name := s.names[i]
		out, err := stackCommand(ctx, commandPath("docker"), "--context", "colima", "inspect", "--format", `{{index .Config.Labels "guardian.qualification"}}`, name).Output()
		if err == nil && strings.TrimSpace(string(out)) == s.label {
			_ = stackCommand(ctx, commandPath("docker"), "--context", "colima", "rm", "-f", name).Run()
		}
	}
	if strings.HasPrefix(filepath.Base(s.Root), "qualification-sandbox-") {
		_ = os.RemoveAll(s.Root)
	}
	s.Password = ""
}
