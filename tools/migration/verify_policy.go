// Offline operator check: use a disposable private database copy, never live state.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/engine"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

func main() {
	configuration := flag.String("config", "", "private source or mapped configuration")
	database := flag.String("disposable-database", "", "explicit disposable offline database copy")
	flag.Parse()
	if *configuration == "" || *database == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "explicit config and disposable database are required")
		os.Exit(1)
	}
	cfg, err := config.Load(*configuration)
	if err == nil && cfg.Safety.PurgeEnabled {
		err = fmt.Errorf("permanent deletion must remain disabled")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "offline policy configuration rejected")
		os.Exit(1)
	}
	db, err := store.Open(*database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "offline policy database unavailable")
		os.Exit(1)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = db.RequireConfiguration(ctx, cfg); err == nil {
		e := engine.Engine{Config: cfg, Store: db, Now: time.Now}
		err = e.ValidateActivePolicy(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "existing active policy did not pass the current engine gate:", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"existing_active_policy_qualified": true, "purge_enabled": false,
		"mailbox_access": false, "credentials_accessed": false,
	})
}
