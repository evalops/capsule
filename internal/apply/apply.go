package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Requirement string

const (
	RequireCleanWorktree Requirement = "clean-worktree"
	RequireTestsPassed   Requirement = "tests-passed"
	RequireNoSecretDiff  Requirement = "no-secret-diff"
)

type Options struct {
	RunDir       string
	Repo         string
	Requirements []Requirement
	DryRun       bool
}

type Result struct {
	Applied      bool          `json:"applied"`
	DryRun       bool          `json:"dry_run"`
	Requirements []Requirement `json:"requirements"`
}

func Apply(ctx context.Context, opts Options) (*Result, error) {
	if opts.RunDir == "" {
		return nil, fmt.Errorf("run directory is required")
	}
	if opts.Repo == "" {
		opts.Repo = "."
	}
	repo, err := filepath.Abs(opts.Repo)
	if err != nil {
		return nil, err
	}

	patch, err := os.ReadFile(filepath.Join(opts.RunDir, "filesystem_diff.patch"))
	if err != nil {
		return nil, err
	}
	for _, requirement := range opts.Requirements {
		if err := checkRequirement(ctx, requirement, opts.RunDir, repo, patch); err != nil {
			return nil, err
		}
	}
	if len(strings.TrimSpace(string(patch))) == 0 {
		return &Result{Applied: false, DryRun: opts.DryRun, Requirements: opts.Requirements}, nil
	}
	if err := gitApply(ctx, repo, patch, true); err != nil {
		return nil, err
	}
	if opts.DryRun {
		return &Result{Applied: false, DryRun: true, Requirements: opts.Requirements}, nil
	}
	if err := gitApply(ctx, repo, patch, false); err != nil {
		return nil, err
	}
	return &Result{Applied: true, DryRun: false, Requirements: opts.Requirements}, nil
}

func checkRequirement(ctx context.Context, requirement Requirement, runDir, repo string, patch []byte) error {
	switch requirement {
	case RequireCleanWorktree:
		output, err := gitOutput(ctx, repo, "status", "--porcelain")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(output)) != "" {
			return fmt.Errorf("worktree is not clean")
		}
	case RequireTestsPassed:
		exit, err := readExit(runDir)
		if err != nil {
			return err
		}
		if exit.Code != 0 {
			return fmt.Errorf("run did not pass: exit code %d", exit.Code)
		}
	case RequireNoSecretDiff:
		if secretPattern().Match(patch) {
			return fmt.Errorf("diff contains secret-like material")
		}
	default:
		return fmt.Errorf("unknown requirement %q", requirement)
	}
	return nil
}

type exitFile struct {
	Code int `json:"code"`
}

func readExit(runDir string) (exitFile, error) {
	var exit exitFile
	data, err := os.ReadFile(filepath.Join(runDir, "exit.json"))
	if err != nil {
		return exit, err
	}
	if err := json.Unmarshal(data, &exit); err != nil {
		return exit, err
	}
	return exit, nil
}

func gitApply(ctx context.Context, repo string, patch []byte, check bool) error {
	args := []string{"apply"}
	if check {
		args = append(args, "--check")
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(string(patch))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return nil
}

func gitOutput(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return output, nil
}

func secretPattern() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(ghp_[a-z0-9_]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|xox[baprs]-[a-z0-9-]{20,})`)
}
