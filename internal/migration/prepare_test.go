package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

func preparationProgress(t *testing.T, path string, id int) {
	t.Helper()
	readinessExec(t, path, "INSERT INTO reconciliations(message_id,source_cursor,source_complete,destination_cursor,updated_at) VALUES(?,17,1,23,'2026-10-30T19:00:00Z')", id)
}

// Inject a deterministic external filesystem change only after the helper has
// created its output. This exercises drift/path replacement without relying on
// scheduler timing or exposing production fault-injection callbacks.
type preparationFilesystemChange struct {
	context.Context
	output string
	change func() error
	fired  atomic.Bool
	result chan error
}

func (c *preparationFilesystemChange) Err() error {
	if _, err := os.Lstat(c.output); err == nil && c.fired.CompareAndSwap(false, true) {
		c.result <- c.change()
	}
	return c.Context.Err()
}

func TestPrepareSnapshotDetectsSourceDriftAfterMaterializationStarts(t *testing.T) {
	source, cfg := readinessFixture(t)
	preparationProgress(t, source, 2)
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(filepath.Dir(source), "prepared.db")
	ctx := &preparationFilesystemChange{
		Context: context.Background(), output: output, result: make(chan error, 1),
		change: func() error {
			f, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			_, err = f.Write([]byte{0})
			return errors.Join(err, f.Close())
		},
	}
	if _, err := PrepareSnapshot(ctx, source, output, cfg, readinessTestLimits()); err == nil {
		t.Fatal("accepted a source changed after its inspected byte image")
	}
	if !ctx.fired.Load() {
		t.Fatal("source drift fixture was not exercised")
	}
	if err := <-ctx.result; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("source drift left a new output: %v", err)
	}
	got, err := os.ReadFile(source)
	if err != nil || !reflect.DeepEqual(got, append(original, 0)) {
		t.Fatal("preparation changed source beyond the explicit fixture mutation")
	}
}

func TestPrepareSnapshotDoesNotFollowOrDeleteAReplacedOutput(t *testing.T) {
	source, cfg := readinessFixture(t)
	preparationProgress(t, source, 2)
	original := readinessFileHash(t, source)
	output := filepath.Join(filepath.Dir(source), "prepared.db")
	displaced := filepath.Join(filepath.Dir(source), "displaced-own-output.db")
	ctx := &preparationFilesystemChange{
		Context: context.Background(), output: output, result: make(chan error, 1),
		change: func() error {
			if err := os.Rename(output, displaced); err != nil {
				return err
			}
			return os.Symlink(source, output)
		},
	}
	if _, err := PrepareSnapshot(ctx, source, output, cfg, readinessTestLimits()); err == nil {
		t.Fatal("accepted a replaced output namespace")
	}
	if !ctx.fired.Load() {
		t.Fatal("output substitution fixture was not exercised")
	}
	if err := <-ctx.result; err != nil {
		t.Fatal(err)
	}
	if readinessFileHash(t, source) != original {
		t.Fatal("normalization followed the replacement to the original source")
	}
	if target, err := os.Readlink(output); err != nil || target != source {
		t.Fatal("guarded cleanup removed or replaced the unrelated new symlink")
	}
}

// preparationLogicalRows reads fixture databases only. Production preparation
// must never open the original source with a mutable SQLite connection.
func preparationLogicalRows(t *testing.T, path string) map[string]string {
	t.Helper()
	uri, err := sqliteURI(path, "ro")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result := map[string]string{}
	for _, table := range []string{"messages", "events", "runs", "settings"} {
		order := "id"
		if table == "settings" {
			order = "key"
		}
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY " + order)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var values [][]any
		for rows.Next() {
			value := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range value {
				pointers[i] = &value[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			values = append(values, value)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(struct {
			Columns []string
			Rows    [][]any
		}{columns, values})
		if err != nil {
			t.Fatal(err)
		}
		result[table] = string(data)
	}
	return result
}

func preparationDirectoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

func preparationAssertNoSidecars(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("unexpected sidecar %q: %v", suffix, err)
		}
	}
}

func TestPrepareSnapshotRemovesOnlySupersededProgressFromPrivateClone(t *testing.T) {
	source, cfg := readinessFixture(t)
	preparationProgress(t, source, 2) // fixture row 2 is exactly superseded
	readinessExec(t, source, "INSERT INTO events(message_id,at,action,detail) VALUES(2,'2026-10-30T19:00:00Z','fixture-history','preserve event')")
	before := readinessFileHash(t, source)
	logical := preparationLogicalRows(t, source)
	if _, err := InspectSnapshot(context.Background(), source, cfg, readinessTestLimits()); err == nil {
		t.Fatal("source with residual progress was accepted as already prepared")
	}
	destination := filepath.Join(filepath.Dir(source), "prepared.db")
	prepared, err := PrepareSnapshot(context.Background(), source, destination, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.SourceSHA256 != before || prepared.PreparedSHA256 != readinessFileHash(t, destination) || prepared.RemovedSupersededProgress != 1 {
		t.Fatalf("preparation receipt differs: %+v", prepared)
	}
	if before == prepared.PreparedSHA256 {
		t.Fatal("deleting residual progress did not change prepared bytes")
	}
	if readinessFileHash(t, source) != before {
		t.Fatal("preparation changed original source")
	}
	if _, err := InspectSnapshot(context.Background(), destination, cfg, readinessTestLimits()); err != nil {
		t.Fatalf("prepared output is not strictly ready: %v", err)
	}
	if got := preparationLogicalRows(t, destination); !reflect.DeepEqual(got, logical) {
		t.Fatal("preparation changed messages, events, runs or settings")
	}
	if _, err := InspectSnapshot(context.Background(), source, cfg, readinessTestLimits()); err == nil {
		t.Fatal("preparation silently normalized the original source")
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("prepared output permissions/type: %v %v", info, err)
	}
	preparationAssertNoSidecars(t, source)
	preparationAssertNoSidecars(t, destination)
}

func TestPrepareSnapshotClonesAlreadyReadySourceWithoutInventingChanges(t *testing.T) {
	source, cfg := readinessFixture(t)
	before, logical := readinessFileHash(t, source), preparationLogicalRows(t, source)
	destination := filepath.Join(filepath.Dir(source), "prepared.db")
	prepared, err := PrepareSnapshot(context.Background(), source, destination, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.SourceSHA256 != before || prepared.PreparedSHA256 != readinessFileHash(t, destination) || prepared.RemovedSupersededProgress != 0 {
		t.Fatalf("unexpected already-ready receipt: %+v", prepared)
	}
	if _, err := InspectSnapshot(context.Background(), destination, cfg, readinessTestLimits()); err != nil {
		t.Fatal(err)
	}
	if readinessFileHash(t, source) != before || !reflect.DeepEqual(preparationLogicalRows(t, destination), logical) {
		t.Fatal("already-ready clone lost source or logical history")
	}
	preparationAssertNoSidecars(t, source)
	preparationAssertNoSidecars(t, destination)
}

func TestPrepareSnapshotRejectsNonSupersededOrUnresolvedProgress(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string){
		"kept-message-progress":    func(t *testing.T, path string) { preparationProgress(t, path, 1) },
		"missing-message-progress": func(t *testing.T, path string) { preparationProgress(t, path, 999) },
		"mixed-progress": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			preparationProgress(t, path, 1)
		},
		"foreign-account": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			readinessExec(t, path, "UPDATE messages SET account='foreign@example.invalid' WHERE id=2")
		},
		"pending-move": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			readinessExec(t, path, "UPDATE messages SET status='pending_move' WHERE id=2")
		},
		"pending-learn": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			readinessExec(t, path, "UPDATE messages SET status='pending_learn' WHERE id=1")
		},
		"checkpoint-required": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			readinessExec(t, path, "INSERT INTO settings(key,value) VALUES('model_checkpoint_required','1')")
		},
		"unknown-schema": func(t *testing.T, path string) {
			preparationProgress(t, path, 2)
			readinessExec(t, path, "CREATE TABLE future_state(payload TEXT)")
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, cfg := readinessFixture(t)
			mutate(t, source)
			before := readinessFileHash(t, source)
			dir := filepath.Dir(source)
			names := preparationDirectoryNames(t, dir)
			destination := filepath.Join(dir, "prepared.db")
			if _, err := PrepareSnapshot(context.Background(), source, destination, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("normalized unsafe state %s", name)
			}
			if readinessFileHash(t, source) != before {
				t.Fatal("failed preparation changed source")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("failed preparation left output: %v", err)
			}
			if after := preparationDirectoryNames(t, dir); !reflect.DeepEqual(after, names) {
				t.Fatalf("failed preparation leaked or removed files: before=%v after=%v", names, after)
			}
		})
	}
}

func TestPrepareSnapshotPreservesCollisionsAndRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"existing-output", "same-path", "source-symlink", "destination-symlink", "parent-symlink", "public-parent", "preexisting-sidecar"} {
		t.Run(kind, func(t *testing.T) {
			source, cfg := readinessFixture(t)
			preparationProgress(t, source, 2)
			original := source
			dir := filepath.Dir(source)
			destination := filepath.Join(dir, "prepared.db")
			var preserved string
			switch kind {
			case "existing-output":
				preserved = destination
				if err := os.WriteFile(destination, []byte("original destination"), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-path":
				destination = source
			case "source-symlink":
				source = filepath.Join(dir, "source-link.db")
				if err := os.Symlink(original, source); err != nil {
					t.Fatal(err)
				}
			case "destination-symlink":
				preserved = filepath.Join(dir, "untouched-target")
				if err := os.WriteFile(preserved, []byte("original destination"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(preserved, destination); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				real := filepath.Join(dir, "real-parent")
				if err := os.Mkdir(real, 0700); err != nil {
					t.Fatal(err)
				}
				linked := filepath.Join(dir, "linked-parent")
				if err := os.Symlink(real, linked); err != nil {
					t.Fatal(err)
				}
				destination = filepath.Join(linked, "prepared.db")
			case "public-parent":
				public := filepath.Join(dir, "public-parent")
				if err := os.Mkdir(public, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(public, 0755); err != nil {
					t.Fatal(err)
				}
				destination = filepath.Join(public, "prepared.db")
			case "preexisting-sidecar":
				preserved = destination + "-journal"
				if err := os.WriteFile(preserved, []byte("original destination"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readinessFileHash(t, original)
			if _, err := PrepareSnapshot(context.Background(), source, destination, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted unsafe path %s", kind)
			}
			if readinessFileHash(t, original) != before {
				t.Fatal("path rejection changed or removed source")
			}
			if preserved != "" {
				data, err := os.ReadFile(preserved)
				if err != nil || string(data) != "original destination" {
					t.Fatal("path rejection changed or removed existing destination data")
				}
			}
			if kind != "existing-output" && kind != "same-path" && kind != "destination-symlink" {
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatalf("unsafe preparation left a new output: %v", err)
				}
			}
		})
	}
}

func TestPrepareSnapshotRejectsCancellationMissingInputAndResourceBounds(t *testing.T) {
	for _, kind := range []string{"cancelled", "missing-source", "empty-source", "empty-destination", "database-bound", "row-bound"} {
		t.Run(kind, func(t *testing.T) {
			source, cfg := readinessFixture(t)
			preparationProgress(t, source, 2)
			original, before := source, readinessFileHash(t, source)
			dir := filepath.Dir(source)
			destination := filepath.Join(dir, "prepared.db")
			limits := readinessTestLimits()
			ctx := context.Background()
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-source":
				source = filepath.Join(dir, "absent.db")
			case "empty-source":
				source = ""
			case "empty-destination":
				destination = ""
			case "database-bound":
				limits.MaxDatabaseBytes = 512
			case "row-bound":
				limits.MaxRows = 1
			}
			names := preparationDirectoryNames(t, dir)
			_, err := PrepareSnapshot(ctx, source, destination, cfg, limits)
			if err == nil {
				t.Fatalf("accepted invalid preparation %s", kind)
			}
			if kind == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation not preserved: %v", err)
			}
			if readinessFileHash(t, original) != before {
				t.Fatal("invalid preparation changed source")
			}
			if after := preparationDirectoryNames(t, dir); !reflect.DeepEqual(after, names) {
				t.Fatalf("invalid preparation changed directory: before=%v after=%v", names, after)
			}
		})
	}
}
