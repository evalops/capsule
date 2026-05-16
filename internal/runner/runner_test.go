package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeRunnerPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	data := []byte(`
version: 1
capsule:
  max_runtime_seconds: 30
network:
  default: deny
  allow:
    - github.com
secrets:
  default: deny
  grants:
    - name: github_token
      capability: create_pr
      delivery: brokered_env
      max_ttl_seconds: 60
commands:
  deny:
    - "sudo *"
  require_approval:
    - "git push *"
evidence:
  record_commands: true
  record_network: true
  record_file_diff: true
  record_process_tree: true
  require_attestation: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "hello.txt"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "ignored"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestRunQuarantinesRepoWritesAndCapturesDiff(t *testing.T) {
	repo := writeRepo(t)
	emit := filepath.Join(t.TempDir(), "latest")

	result, err := Run(context.Background(), Options{
		Repo:       repo,
		PolicyPath: writeRunnerPolicy(t),
		Emit:       emit,
		Agent:      "shell",
		Task:       "change hello",
		Command:    []string{"sh", "-c", "echo after > hello.txt"},
		Now:        func() time.Time { return time.Date(2026, 5, 16, 1, 2, 3, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}

	hostData, err := os.ReadFile(filepath.Join(repo, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hostData) != "before\n" {
		t.Fatalf("host repo was mutated: %q", hostData)
	}

	diff, err := os.ReadFile(filepath.Join(emit, "filesystem_diff.patch"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diff), "-before") || !strings.Contains(string(diff), "+after") {
		t.Fatalf("diff did not capture change:\n%s", diff)
	}
	if _, err := os.Stat(filepath.Join(emit, "workspace", ".git", "ignored")); !os.IsNotExist(err) {
		t.Fatalf("source .git directory should not be copied into workspace")
	}
}

func TestRunCapturesNewFilesInDiff(t *testing.T) {
	repo := writeRepo(t)
	emit := filepath.Join(t.TempDir(), "new-file")

	result, err := Run(context.Background(), Options{
		Repo:       repo,
		PolicyPath: writeRunnerPolicy(t),
		Emit:       emit,
		Command:    []string{"sh", "-c", "printf 'new file\n' > created.txt"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}

	diff, err := os.ReadFile(filepath.Join(emit, "filesystem_diff.patch"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diff), "diff --git a/created.txt b/created.txt") || !strings.Contains(string(diff), "+new file") {
		t.Fatalf("new file was not captured in diff:\n%s", diff)
	}
}

func TestRunBlocksDeniedCommandBeforeExecution(t *testing.T) {
	repo := writeRepo(t)
	emit := filepath.Join(t.TempDir(), "blocked")

	result, err := Run(context.Background(), Options{
		Repo:       repo,
		PolicyPath: writeRunnerPolicy(t),
		Emit:       emit,
		Command:    []string{"sudo", "sh", "-c", "echo after > hello.txt"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ExitCode != 126 {
		t.Fatalf("exit code = %d, want denied code 126", result.ExitCode)
	}

	diff, err := os.ReadFile(filepath.Join(emit, "filesystem_diff.patch"))
	if err != nil {
		t.Fatal(err)
	}
	if string(diff) != "" {
		t.Fatalf("blocked command should not produce diff, got:\n%s", diff)
	}

	decisions, err := os.ReadFile(filepath.Join(emit, "policy_decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decisions), `"action":"deny"`) {
		t.Fatalf("policy decision did not record deny:\n%s", decisions)
	}
}

func TestRunBlocksDeniedNetworkDestinationBeforeExecution(t *testing.T) {
	repo := writeRepo(t)
	emit := filepath.Join(t.TempDir(), "network-blocked")

	result, err := Run(context.Background(), Options{
		Repo:       repo,
		PolicyPath: writeRunnerPolicy(t),
		Emit:       emit,
		Command:    []string{"curl", "https://example.com/install.sh"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ExitCode != 97 {
		t.Fatalf("exit code = %d, want network denied code 97", result.ExitCode)
	}

	events, err := os.ReadFile(filepath.Join(emit, "network.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(events), `"host":"example.com"`) || !strings.Contains(string(events), `"action":"deny"`) {
		t.Fatalf("network event did not record deny:\n%s", events)
	}

	commands, err := os.ReadFile(filepath.Join(emit, "commands.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), `"action":"executed"`) {
		t.Fatalf("denied network command should not execute:\n%s", commands)
	}
}
