package runbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Spec struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	Repo        string    `json:"repo,omitempty"`
	Agent       string    `json:"agent,omitempty"`
	Task        string    `json:"task,omitempty"`
	Backend     string    `json:"backend,omitempty"`
	PolicyPath  string    `json:"policy_path,omitempty"`
	Command     []string  `json:"command,omitempty"`
	AllowNet    []string  `json:"allow_net,omitempty"`
	Secrets     []string  `json:"secrets,omitempty"`
	Workspace   string    `json:"workspace,omitempty"`
	Artifacts   string    `json:"artifacts,omitempty"`
	GeneratedBy string    `json:"generated_by,omitempty"`
}

type Bundle struct {
	Path string
	Spec Spec
}

func Create(base string, spec Spec, policyBytes []byte) (*Bundle, error) {
	if spec.ID == "" {
		spec.ID = NewID(spec.CreatedAt)
	}
	if spec.CreatedAt.IsZero() {
		spec.CreatedAt = time.Now().UTC()
	}
	if spec.Backend == "" {
		spec.Backend = "local-quarantine"
	}
	if spec.GeneratedBy == "" {
		spec.GeneratedBy = "capsule"
	}

	path := filepath.Join(base, spec.ID)
	spec.Workspace = filepath.Join(path, "workspace")
	spec.Artifacts = filepath.Join(path, "artifacts")

	for _, dir := range []string{path, spec.Workspace, spec.Artifacts} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	b := &Bundle{Path: path, Spec: spec}
	if err := b.WriteJSON("capsule.json", spec); err != nil {
		return nil, err
	}
	if err := b.WriteBytes("policy.yaml", policyBytes); err != nil {
		return nil, err
	}

	for _, name := range []string{
		"commands.jsonl",
		"policy_decisions.jsonl",
		"network.jsonl",
		"process_tree.jsonl",
		"secrets.jsonl",
		"stdout.log",
		"stderr.log",
		"filesystem_diff.patch",
	} {
		if err := b.WriteBytes(name, nil); err != nil {
			return nil, err
		}
	}
	if err := b.WriteJSON("exit.json", map[string]any{"code": nil, "status": "not_started"}); err != nil {
		return nil, err
	}
	if err := b.WriteJSON("attestation.intoto.json", map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://evalops.dev/capsule/run/v1"}); err != nil {
		return nil, err
	}
	if err := b.WriteBytes("replay.sh", []byte("#!/usr/bin/env bash\nset -euo pipefail\n# replay command is written after capsule run finalizes\n")); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Join(b.Path, "replay.sh"), 0o755); err != nil {
		return nil, err
	}

	return b, nil
}

func NewID(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return strings.ReplaceAll(t.UTC().Format("2006-01-02T15-04-05.000000000Z"), ".", "-")
}

func (b *Bundle) AppendJSONL(name string, value any) error {
	path, err := b.safePath(name)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	_, err = file.Write([]byte("\n"))
	return err
}

func (b *Bundle) WriteJSON(name string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return b.WriteBytes(name, append(encoded, '\n'))
}

func (b *Bundle) WriteBytes(name string, data []byte) error {
	path, err := b.safePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (b *Bundle) ReadBytes(name string) ([]byte, error) {
	path, err := b.safePath(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func (b *Bundle) safePath(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("unsafe bundle path %q", name)
	}
	return filepath.Join(b.Path, name), nil
}
