package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	applycmd "github.com/evalops/capsule/internal/apply"
	"github.com/evalops/capsule/internal/evalcheck"
	"github.com/evalops/capsule/internal/runner"
)

const Version = "0.1.0"

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintf(stdout, "capsule %s\n", Version)
		return 0
	}

	var err error
	var code int
	switch args[0] {
	case "init":
		err = initCommand(args[1:], stdout)
	case "run":
		code, err = runCommand(args[1:], stdout)
	case "inspect":
		err = inspectCommand(args[1:], stdout)
	case "diff":
		err = diffCommand(args[1:], stdout)
	case "apply":
		err = applyCommand(args[1:], stdout)
	case "eval":
		code, err = evalCommand(args[1:], stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}

	if err != nil {
		fmt.Fprintln(stderr, err)
		if code != 0 {
			return code
		}
		return 1
	}
	return code
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: capsule <init|run|inspect|diff|apply|eval|version> [options]")
}

func initCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "policies/coding-agent.yaml", "policy file to write")
	force := fs.Bool("force", false, "overwrite an existing policy")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*policyPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", *policyPath)
	}
	if err := os.MkdirAll(filepath.Dir(*policyPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*policyPath, []byte(defaultPolicy), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", *policyPath)
	return nil
}

func runCommand(args []string, stdout io.Writer) (int, error) {
	flagArgs, command := splitCommand(args)
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	repo := fs.String("repo", ".", "repo to copy into the capsule workspace")
	policyPath := fs.String("policy", "policies/coding-agent.yaml", "policy file")
	emit := fs.String("emit", "", "run bundle directory")
	agent := fs.String("agent", "shell", "agent identity")
	task := fs.String("task", "", "task intent")
	var allowNet repeatValue
	var secrets repeatValue
	fs.Var(&allowNet, "allow-net", "network host to allow; repeatable or comma-separated")
	fs.Var(&secrets, "secret", "secret grant as name:capability; repeatable")

	if err := fs.Parse(flagArgs); err != nil {
		return 2, err
	}
	if len(command) == 0 {
		return 2, fmt.Errorf("run command is required after --")
	}

	secretRequests, err := parseSecrets(secrets.values())
	if err != nil {
		return 2, err
	}
	result, err := runner.Run(context.Background(), runner.Options{
		Repo:           *repo,
		PolicyPath:     *policyPath,
		Emit:           *emit,
		Agent:          *agent,
		Task:           *task,
		Command:        command,
		AllowNet:       allowNet.values(),
		SecretRequests: secretRequests,
	})
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(stdout, "bundle: %s\n", result.BundlePath)
	fmt.Fprintf(stdout, "status: %s\n", result.Status)
	fmt.Fprintf(stdout, "exit: %d\n", result.ExitCode)
	fmt.Fprintf(stdout, "changed files: %d\n", len(result.ChangedFiles))
	return result.ExitCode, nil
}

func inspectCommand(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("inspect requires a run directory")
	}
	runDir := args[0]
	var spec struct {
		ID      string   `json:"id"`
		Agent   string   `json:"agent"`
		Task    string   `json:"task"`
		Backend string   `json:"backend"`
		Command []string `json:"command"`
	}
	if err := readJSON(filepath.Join(runDir, "capsule.json"), &spec); err != nil {
		return err
	}
	var exit struct {
		Code         int      `json:"code"`
		Status       string   `json:"status"`
		Blocked      bool     `json:"blocked"`
		ChangedFiles []string `json:"changed_files"`
	}
	if err := readJSON(filepath.Join(runDir, "exit.json"), &exit); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "capsule: %s\n", spec.ID)
	fmt.Fprintf(stdout, "agent: %s\n", spec.Agent)
	fmt.Fprintf(stdout, "backend: %s\n", spec.Backend)
	fmt.Fprintf(stdout, "task: %s\n", spec.Task)
	fmt.Fprintf(stdout, "command: %s\n", strings.Join(spec.Command, " "))
	fmt.Fprintf(stdout, "status: %s\n", exit.Status)
	fmt.Fprintf(stdout, "exit: %d\n", exit.Code)
	fmt.Fprintf(stdout, "blocked: %t\n", exit.Blocked)
	fmt.Fprintf(stdout, "changed files: %d\n", len(exit.ChangedFiles))
	fmt.Fprintf(stdout, "policy decisions: %d\n", countLines(filepath.Join(runDir, "policy_decisions.jsonl")))
	fmt.Fprintf(stdout, "commands: %d\n", countLines(filepath.Join(runDir, "commands.jsonl")))
	fmt.Fprintf(stdout, "network events: %d\n", countLines(filepath.Join(runDir, "network.jsonl")))
	return nil
}

func diffCommand(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("diff requires a run directory")
	}
	data, err := os.ReadFile(filepath.Join(args[0], "filesystem_diff.patch"))
	if err != nil {
		return err
	}
	_, err = stdout.Write(data)
	return err
}

func applyCommand(args []string, stdout io.Writer) error {
	parsed, err := parseApplyArgs(args)
	if err != nil {
		return err
	}
	result, err := applycmd.Apply(context.Background(), applycmd.Options{
		RunDir:       parsed.runDir,
		Repo:         parsed.repo,
		Requirements: parsed.requirements,
		DryRun:       parsed.dryRun,
	})
	if err != nil {
		return err
	}
	switch {
	case result.Applied:
		fmt.Fprintln(stdout, "applied: true")
	case result.DryRun:
		fmt.Fprintln(stdout, "applied: false (dry run)")
	default:
		fmt.Fprintln(stdout, "applied: false (no changes)")
	}
	return nil
}

func evalCommand(args []string, stdout io.Writer) (int, error) {
	runDir, suite, err := parseEvalArgs(args)
	if err != nil {
		return 2, err
	}
	report, err := evalcheck.Run(runDir, suite)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(stdout, "suite: %s\n", report.Suite)
	fmt.Fprintf(stdout, "passed: %t\n", report.Passed)
	for _, finding := range report.Findings {
		fmt.Fprintf(stdout, "- %s: %s (%s)\n", finding.ID, finding.Status, finding.Message)
	}
	if !report.Passed {
		return 1, nil
	}
	return 0, nil
}

func splitCommand(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

type repeatValue []string

func (v *repeatValue) String() string {
	return strings.Join(*v, ",")
}

func (v *repeatValue) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*v = append(*v, part)
		}
	}
	return nil
}

func (v repeatValue) values() []string {
	out := make([]string, len(v))
	copy(out, v)
	return out
}

func parseSecrets(values []string) ([]runner.SecretRequest, error) {
	requests := make([]runner.SecretRequest, 0, len(values))
	for _, value := range values {
		name, capability, ok := strings.Cut(value, ":")
		if !ok || name == "" || capability == "" {
			return nil, fmt.Errorf("secret must be name:capability, got %q", value)
		}
		requests = append(requests, runner.SecretRequest{Name: name, Capability: capability})
	}
	return requests, nil
}

type applyArgs struct {
	runDir       string
	repo         string
	requirements []applycmd.Requirement
	dryRun       bool
}

func parseApplyArgs(args []string) (applyArgs, error) {
	parsed := applyArgs{repo: "."}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			parsed.dryRun = true
		case arg == "--repo" || arg == "--require":
			if i+1 >= len(args) {
				return parsed, fmt.Errorf("%s requires a value", arg)
			}
			i++
			if arg == "--repo" {
				parsed.repo = args[i]
			} else {
				parsed.requirements = append(parsed.requirements, applycmd.Requirement(args[i]))
			}
		case strings.HasPrefix(arg, "--repo="):
			parsed.repo = strings.TrimPrefix(arg, "--repo=")
		case strings.HasPrefix(arg, "--require="):
			parsed.requirements = append(parsed.requirements, applycmd.Requirement(strings.TrimPrefix(arg, "--require=")))
		case strings.HasPrefix(arg, "--"):
			return parsed, fmt.Errorf("unknown apply flag %s", arg)
		default:
			if parsed.runDir != "" {
				return parsed, fmt.Errorf("apply accepts one run directory")
			}
			parsed.runDir = arg
		}
	}
	if parsed.runDir == "" {
		return parsed, fmt.Errorf("apply requires a run directory")
	}
	return parsed, nil
}

func parseEvalArgs(args []string) (string, string, error) {
	var runDir string
	suite := "coding-agent-safety"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--suite":
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("--suite requires a value")
			}
			i++
			suite = args[i]
		case strings.HasPrefix(arg, "--suite="):
			suite = strings.TrimPrefix(arg, "--suite=")
		case strings.HasPrefix(arg, "--"):
			return "", "", fmt.Errorf("unknown eval flag %s", arg)
		default:
			if runDir != "" {
				return "", "", fmt.Errorf("eval accepts one run directory")
			}
			runDir = arg
		}
	}
	if runDir == "" {
		return "", "", fmt.Errorf("eval requires a run directory")
	}
	return runDir, suite, nil
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			count++
		}
	}
	return count
}

const defaultPolicy = `version: 1
capsule:
  default_user: agent
  max_runtime_seconds: 1800
  cpus: 4
  memory_mb: 4096

filesystem:
  mounts:
    - name: repo
      host_path: .
      mode: overlay-rw
      diff_required: true
    - name: home
      host_path: /tmp/capsule-home
      mode: rw
    - name: ssh
      host_path: ~/.ssh
      mode: none

network:
  default: deny
  allow:
    - github.com
    - api.github.com
    - registry.npmjs.org
    - crates.io
    - static.crates.io
    - proxy.golang.org
    - sum.golang.org

secrets:
  default: deny
  grants:
    - name: github_token
      capability: create_pr
      delivery: brokered_env
      max_ttl_seconds: 600

commands:
  deny:
    - "sudo *"
    - "curl * | sh"
    - "rm -rf /"
  require_approval:
    - "git push *"
    - "gh pr merge *"
    - "terraform apply *"

evidence:
  record_commands: true
  record_network: true
  record_file_diff: true
  record_process_tree: true
  require_attestation: true
`
