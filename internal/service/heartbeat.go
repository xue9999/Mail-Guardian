package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const HeartbeatFileName = "service-health.json"

type Heartbeat struct {
	Protocol    int        `json:"protocol"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	Stage       string     `json:"stage"`
	ErrorCode   string     `json:"error_code,omitempty"`
	Version     string     `json:"version,omitempty"`
}

func ReadHeartbeat(dataDir string) (Heartbeat, error) {
	path := filepath.Join(dataDir, HeartbeatFileName)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Heartbeat{Protocol: 1}, nil
	}
	if err != nil {
		return Heartbeat{}, err
	}
	if len(body) > 32<<10 {
		return Heartbeat{}, errors.New("heartbeat file too large")
	}
	var heartbeat Heartbeat
	if err := json.Unmarshal(body, &heartbeat); err != nil {
		return Heartbeat{}, err
	}
	if heartbeat.Protocol != 1 {
		return Heartbeat{}, errors.New("unsupported heartbeat version")
	}
	return heartbeat, nil
}

func WriteHeartbeat(dataDir string, heartbeat Heartbeat) error {
	heartbeat.Protocol = 1
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dataDir, HeartbeatFileName), append(body, '\n'), 0o600)
}
