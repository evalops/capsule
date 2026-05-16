package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteVersionAndInit(t *testing.T) {
	var out bytes.Buffer
	if code := Execute([]string{"--version"}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.Contains(out.String(), "capsule") {
		t.Fatalf("version output = %q", out.String())
	}

	policyPath := filepath.Join(t.TempDir(), "coding-agent.yaml")
	out.Reset()
	if code := Execute([]string{"init", "--policy", policyPath}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("init exit = %d", code)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !strings.Contains(string(data), "version: 1") || !strings.Contains(string(data), "github_token") {
		t.Fatalf("policy did not look like default policy:\n%s", data)
	}
}

func TestExecuteRunInspectDiffAndApply(t *testing.T) {
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

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if code := Execute([]string{"init", "--policy", policyPath}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("init exit = %d", code)
	}

	runDir := filepath.Join(t.TempDir(), "latest")
	var out bytes.Buffer
	errOut := &bytes.Buffer{}
	code := Execute([]string{
		"run",
		"--repo", repo,
		"--policy", policyPath,
		"--emit", runDir,
		"--agent", "shell",
		"--task", "change hello",
		"--", "sh", "-c", "echo after > hello.txt",
	}, &out, errOut)
	if code != 0 {
		t.Fatalf("run exit = %d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "bundle:") {
		t.Fatalf("run output = %q", out.String())
	}

	out.Reset()
	if code := Execute([]string{"inspect", runDir}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("inspect exit = %d", code)
	}
	if !strings.Contains(out.String(), "changed files: 1") {
		t.Fatalf("inspect output = %q", out.String())
	}

	out.Reset()
	if code := Execute([]string{"diff", runDir}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("diff exit = %d", code)
	}
	if !strings.Contains(out.String(), "+after") {
		t.Fatalf("diff output = %q", out.String())
	}

	out.Reset()
	if code := Execute([]string{"eval", runDir, "--suite", "coding-agent-safety"}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("eval exit = %d", code)
	}
	if !strings.Contains(out.String(), "passed: true") {
		t.Fatalf("eval output = %q", out.String())
	}

	out.Reset()
	if code := Execute([]string{"apply", runDir, "--repo", repo, "--require", "clean-worktree", "--require", "tests-passed", "--require", "no-secret-diff"}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("apply exit = %d", code)
	}
	data, err := os.ReadFile(filepath.Join(repo, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "after\n" {
		t.Fatalf("repo file = %q", data)
	}
}
