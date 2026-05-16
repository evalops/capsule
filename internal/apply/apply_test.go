package apply

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evalops/capsule/internal/runner"
)

func makeGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "hello.txt"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"git", "init", "-b", "main"},
		{"git", "add", "-A"},
		{"git", "-c", "user.name=Capsule Test", "-c", "user.email=capsule@example.com", "commit", "-m", "initial"},
	} {
		cmd := exec.Command(command[0], command[1:]...)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(command, " "), err, output)
		}
	}
	return repo
}

func makePolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
capsule:
  max_runtime_seconds: 30
network:
  default: deny
secrets:
  default: deny
commands:
  deny: []
  require_approval: []
evidence:
  record_commands: true
  record_file_diff: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyRequiresCleanWorktreeAndTestsPassed(t *testing.T) {
	repo := makeGitRepo(t)
	runDir := filepath.Join(t.TempDir(), "run")
	result, err := runner.Run(context.Background(), runner.Options{
		Repo:       repo,
		PolicyPath: makePolicy(t),
		Emit:       runDir,
		Command:    []string{"sh", "-c", "echo after > hello.txt"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("run exit = %d", result.ExitCode)
	}

	applied, err := Apply(context.Background(), Options{
		RunDir:       runDir,
		Repo:         repo,
		Requirements: []Requirement{RequireCleanWorktree, RequireTestsPassed, RequireNoSecretDiff},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied.Applied {
		t.Fatalf("expected patch to be applied")
	}
	data, err := os.ReadFile(filepath.Join(repo, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "after\n" {
		t.Fatalf("repo data = %q, want after", data)
	}
}

func TestApplyRejectsDirtyWorktree(t *testing.T) {
	repo := makeGitRepo(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if _, err := runner.Run(context.Background(), runner.Options{
		Repo:       repo,
		PolicyPath: makePolicy(t),
		Emit:       runDir,
		Command:    []string{"sh", "-c", "echo after > hello.txt"},
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Apply(context.Background(), Options{
		RunDir:       runDir,
		Repo:         repo,
		Requirements: []Requirement{RequireCleanWorktree},
	})
	if err == nil || !strings.Contains(err.Error(), "worktree is not clean") {
		t.Fatalf("expected clean worktree error, got %v", err)
	}
}

func TestApplyRejectsSecretLookingDiff(t *testing.T) {
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, "filesystem_diff.patch"), []byte("+token = \"ghp_1234567890abcdefghijklmnopqrstuv\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "exit.json"), []byte(`{"code":0}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Apply(context.Background(), Options{
		RunDir:       runDir,
		Repo:         t.TempDir(),
		Requirements: []Requirement{RequireNoSecretDiff},
	})
	if err == nil || !strings.Contains(err.Error(), "secret-like material") {
		t.Fatalf("expected secret diff error, got %v", err)
	}
}
