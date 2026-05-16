package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/evalops/capsule/internal/policy"
	"github.com/evalops/capsule/internal/runbundle"
)

const (
	deniedExitCode   = 126
	approvalExitCode = 125
	commandErrorCode = 127
)

type Options struct {
	Repo           string
	PolicyPath     string
	Emit           string
	Agent          string
	Task           string
	Command        []string
	AllowNet       []string
	SecretRequests []SecretRequest
	Now            func() time.Time
}

type SecretRequest struct {
	Name       string
	Capability string
}

type Result struct {
	BundlePath   string
	ExitCode     int
	Status       string
	Blocked      bool
	DiffPath     string
	ChangedFiles []string
}

type policyRecord struct {
	Time    time.Time     `json:"time"`
	Kind    string        `json:"kind"`
	Subject string        `json:"subject"`
	Action  policy.Action `json:"action"`
	Rule    string        `json:"rule,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

type commandRecord struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Command    []string  `json:"command"`
	Action     string    `json:"action"`
	ExitCode   int       `json:"exit_code"`
}

func Run(ctx context.Context, opts Options) (*Result, error) {
	now := opts.now()
	if opts.Agent == "" {
		opts.Agent = "shell"
	}
	if opts.Repo == "" {
		opts.Repo = "."
	}
	if len(opts.Command) == 0 {
		return nil, errors.New("command is required")
	}

	repo, err := filepath.Abs(opts.Repo)
	if err != nil {
		return nil, err
	}
	policyPath, err := filepath.Abs(opts.PolicyPath)
	if err != nil {
		return nil, err
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	p.Network.Allow = append(p.Network.Allow, opts.AllowNet...)

	bundleBase, specID := bundleLocation(opts.Emit, now)
	b, err := runbundle.Create(bundleBase, runbundle.Spec{
		ID:         specID,
		CreatedAt:  now,
		Repo:       repo,
		Agent:      opts.Agent,
		Task:       opts.Task,
		Backend:    "local-quarantine",
		PolicyPath: policyPath,
		Command:    opts.Command,
		AllowNet:   opts.AllowNet,
		Secrets:    secretLabels(opts.SecretRequests),
	}, policyBytes)
	if err != nil {
		return nil, err
	}

	if err := copyTree(repo, b.Spec.Workspace); err != nil {
		return nil, err
	}
	if err := initWorkspaceBaseline(ctx, b.Spec.Workspace); err != nil {
		return nil, err
	}

	timeout := runtimeLimit(p)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := snapshotProcesses(b, "before", now); err != nil {
		return nil, err
	}

	commandString := strings.Join(opts.Command, " ")
	commandDecision := p.DecideCommand(commandString)
	if err := b.AppendJSONL("policy_decisions.jsonl", policyRecord{
		Time:    now,
		Kind:    "command",
		Subject: commandString,
		Action:  commandDecision.Action,
		Rule:    commandDecision.Rule,
		Reason:  commandDecision.Reason,
	}); err != nil {
		return nil, err
	}

	if commandDecision.Action == policy.ActionDeny || commandDecision.Action == policy.ActionApprovalRequired {
		code := deniedExitCode
		status := "blocked"
		if commandDecision.Action == policy.ActionApprovalRequired {
			code = approvalExitCode
			status = "approval_required"
		}
		result := &Result{BundlePath: b.Path, ExitCode: code, Status: status, Blocked: true, DiffPath: filepath.Join(b.Path, "filesystem_diff.patch")}
		if err := finalizeRun(ctx, b, result, nil, now, now); err != nil {
			return nil, err
		}
		return result, nil
	}

	env := os.Environ()
	env, err = brokerSecrets(b, p, opts.SecretRequests, env, now)
	if err != nil {
		return nil, err
	}

	startedAt := opts.now()
	stdout, stderr, exitCode := executeCommand(runCtx, b.Spec.Workspace, opts.Command, env)
	finishedAt := opts.now()

	if err := b.WriteBytes("stdout.log", stdout); err != nil {
		return nil, err
	}
	if err := b.WriteBytes("stderr.log", stderr); err != nil {
		return nil, err
	}
	if err := b.AppendJSONL("commands.jsonl", commandRecord{
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Command:    opts.Command,
		Action:     "executed",
		ExitCode:   exitCode,
	}); err != nil {
		return nil, err
	}
	if err := snapshotProcesses(b, "after", finishedAt); err != nil {
		return nil, err
	}

	result := &Result{BundlePath: b.Path, ExitCode: exitCode, Status: "completed", DiffPath: filepath.Join(b.Path, "filesystem_diff.patch")}
	if err := finalizeRun(ctx, b, result, stdout, startedAt, finishedAt); err != nil {
		return nil, err
	}
	return result, nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func bundleLocation(emit string, now time.Time) (string, string) {
	if emit == "" {
		return "runs", runbundle.NewID(now)
	}
	clean := filepath.Clean(emit)
	return filepath.Dir(clean), filepath.Base(clean)
}

func runtimeLimit(p *policy.Policy) time.Duration {
	if p.Capsule.MaxRuntimeSeconds > 0 {
		return time.Duration(p.Capsule.MaxRuntimeSeconds) * time.Second
	}
	return 30 * time.Minute
}

func executeCommand(ctx context.Context, dir string, command []string, env []string) ([]byte, []byte, int) {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Env = env

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.Bytes(), stderr.Bytes(), exitErr.ExitCode()
		}
		_, _ = stderr.WriteString(err.Error())
		return stdout.Bytes(), stderr.Bytes(), commandErrorCode
	}
	return stdout.Bytes(), stderr.Bytes(), 0
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if shouldSkip(rel, entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeType != 0 {
			return nil
		}
		return copyFile(path, target, info.Mode())
	})
}

func shouldSkip(rel string, entry fs.DirEntry) bool {
	base := filepath.Base(rel)
	if base == ".git" || base == ".capsule" || base == "runs" {
		return true
	}
	return entry.Type()&os.ModeSymlink != 0
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func initWorkspaceBaseline(ctx context.Context, workspace string) error {
	commands := [][]string{
		{"git", "init", "-b", "main"},
		{"git", "add", "-A"},
		{"git", "-c", "user.name=Capsule", "-c", "user.email=capsule@evalops.dev", "commit", "--allow-empty", "-m", "capsule baseline"},
	}
	for _, command := range commands {
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		cmd.Dir = workspace
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w\n%s", strings.Join(command, " "), err, output)
		}
	}
	return nil
}

func finalizeRun(ctx context.Context, b *runbundle.Bundle, result *Result, stdout []byte, startedAt, finishedAt time.Time) error {
	diff, err := gitOutput(ctx, b.Spec.Workspace, "diff", "--binary", "HEAD", "--", ".")
	if err != nil {
		return err
	}
	if err := b.WriteBytes("filesystem_diff.patch", diff); err != nil {
		return err
	}

	status, err := gitOutput(ctx, b.Spec.Workspace, "status", "--porcelain")
	if err != nil {
		return err
	}
	result.ChangedFiles = changedFiles(status)

	exit := map[string]any{
		"code":          result.ExitCode,
		"status":        result.Status,
		"blocked":       result.Blocked,
		"started_at":    startedAt,
		"finished_at":   finishedAt,
		"changed_files": result.ChangedFiles,
	}
	if err := b.WriteJSON("exit.json", exit); err != nil {
		return err
	}
	if err := writeAttestation(b, diff, stdout, exit); err != nil {
		return err
	}
	return writeReplay(b)
}

func gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, exitErr.Stderr)
		}
		return nil, err
	}
	return output, nil
}

func changedFiles(status []byte) []string {
	var changed []string
	for _, line := range strings.Split(strings.TrimSpace(string(status)), "\n") {
		if line == "" {
			continue
		}
		if len(line) > 3 {
			changed = append(changed, strings.TrimSpace(line[3:]))
		}
	}
	return changed
}

func writeAttestation(b *runbundle.Bundle, diff, stdout []byte, exit any) error {
	policyBytes, err := b.ReadBytes("policy.yaml")
	if err != nil {
		return err
	}
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://evalops.dev/capsule/run/v1",
		"subject": []map[string]any{
			{"name": "filesystem_diff.patch", "digest": map[string]string{"sha256": digest(diff)}},
			{"name": "policy.yaml", "digest": map[string]string{"sha256": digest(policyBytes)}},
			{"name": "stdout.log", "digest": map[string]string{"sha256": digest(stdout)}},
		},
		"predicate": map[string]any{
			"spec": b.Spec,
			"exit": exit,
		},
	}
	return b.WriteJSON("attestation.intoto.json", statement)
}

func writeReplay(b *runbundle.Bundle) error {
	args := append([]string{
		"capsule", "run",
		"--repo", b.Spec.Repo,
		"--policy", b.Spec.PolicyPath,
		"--agent", b.Spec.Agent,
		"--task", b.Spec.Task,
	}, "--")
	args = append(args, b.Spec.Command...)

	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	script := "#!/usr/bin/env bash\nset -euo pipefail\n" + strings.Join(quoted, " ") + "\n"
	if err := b.WriteBytes("replay.sh", []byte(script)); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(b.Path, "replay.sh"), 0o755)
}

func snapshotProcesses(b *runbundle.Bundle, stage string, at time.Time) error {
	args := []string{"-axo", "pid,ppid,stat,command"}
	if runtime.GOOS == "windows" {
		return nil
	}
	output, err := exec.Command("ps", args...).Output()
	if err != nil {
		return b.AppendJSONL("process_tree.jsonl", map[string]any{"time": at, "stage": stage, "error": err.Error()})
	}
	return b.AppendJSONL("process_tree.jsonl", map[string]any{"time": at, "stage": stage, "snapshot": string(output)})
}

func brokerSecrets(b *runbundle.Bundle, p *policy.Policy, requests []SecretRequest, env []string, at time.Time) ([]string, error) {
	for _, request := range requests {
		decision := p.DecideSecret(request.Name, request.Capability)
		if err := b.AppendJSONL("policy_decisions.jsonl", policyRecord{
			Time:    at,
			Kind:    "secret",
			Subject: request.Name + ":" + request.Capability,
			Action:  decision.Action,
			Rule:    decision.Rule,
			Reason:  decision.Reason,
		}); err != nil {
			return nil, err
		}
		record := map[string]any{"time": at, "name": request.Name, "capability": request.Capability, "action": decision.Action}
		if decision.Action != policy.ActionAllow {
			if err := b.AppendJSONL("secrets.jsonl", record); err != nil {
				return nil, err
			}
			continue
		}
		source := "CAPSULE_SECRET_" + strings.ToUpper(strings.ReplaceAll(request.Name, "-", "_"))
		value := os.Getenv(source)
		record["delivered"] = value != ""
		record["delivery"] = "brokered_env"
		if value != "" {
			env = append(env, strings.ToUpper(request.Name)+"="+value)
		}
		if err := b.AppendJSONL("secrets.jsonl", record); err != nil {
			return nil, err
		}
	}
	return env, nil
}

func secretLabels(requests []SecretRequest) []string {
	labels := make([]string, 0, len(requests))
	for _, request := range requests {
		labels = append(labels, request.Name+":"+request.Capability)
	}
	return labels
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '/' || r == '.' || r == ':' || r == '=' || r == ',' || r == '+' || r == '@' || r == '%' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
