package runbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateBundleWritesContractFilesAndDirs(t *testing.T) {
	base := t.TempDir()
	createdAt := time.Date(2026, 5, 16, 12, 30, 0, 0, time.UTC)

	b, err := Create(base, Spec{
		ID:        "run-123",
		CreatedAt: createdAt,
		Repo:      "/repo",
		Agent:     "codex",
		Task:      "fix tests",
		Backend:   "local-quarantine",
		Command:   []string{"go", "test", "./..."},
	}, []byte("version: 1\n"))
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	if b.Path != filepath.Join(base, "run-123") {
		t.Fatalf("bundle path = %q", b.Path)
	}

	for _, rel := range []string{
		"capsule.json",
		"policy.yaml",
		"commands.jsonl",
		"policy_decisions.jsonl",
		"network.jsonl",
		"process_tree.jsonl",
		"secrets.jsonl",
		"stdout.log",
		"stderr.log",
		"filesystem_diff.patch",
		"exit.json",
		"attestation.intoto.json",
		"replay.sh",
		"artifacts",
		"workspace",
	} {
		if _, err := os.Stat(filepath.Join(b.Path, rel)); err != nil {
			t.Fatalf("%s was not created: %v", rel, err)
		}
	}

	var spec Spec
	data, err := os.ReadFile(filepath.Join(b.Path, "capsule.json"))
	if err != nil {
		t.Fatalf("read capsule.json: %v", err)
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("decode capsule.json: %v", err)
	}
	if spec.ID != "run-123" || spec.Agent != "codex" || spec.Task != "fix tests" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
}

func TestAppendJSONLAndRewriteJSON(t *testing.T) {
	b, err := Create(t.TempDir(), Spec{ID: "run-123", CreatedAt: time.Now()}, []byte("version: 1\n"))
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	if err := b.AppendJSONL("commands.jsonl", map[string]string{"command": "go test ./..."}); err != nil {
		t.Fatalf("append jsonl: %v", err)
	}
	if err := b.WriteJSON("exit.json", map[string]int{"code": 0}); err != nil {
		t.Fatalf("write json: %v", err)
	}

	lines, err := os.ReadFile(filepath.Join(b.Path, "commands.jsonl"))
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if got := strings.TrimSpace(string(lines)); !strings.Contains(got, `"command":"go test ./..."`) {
		t.Fatalf("jsonl = %q", got)
	}

	data, err := os.ReadFile(filepath.Join(b.Path, "exit.json"))
	if err != nil {
		t.Fatalf("read exit: %v", err)
	}
	if !strings.Contains(string(data), `"code": 0`) {
		t.Fatalf("exit json = %s", data)
	}
}
