package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Action string

const (
	ActionAllow            Action = "allow"
	ActionDeny             Action = "deny"
	ActionApprovalRequired Action = "approval_required"
)

type Decision struct {
	Action Action `json:"action"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Policy struct {
	Version    int              `yaml:"version" json:"version"`
	Capsule    CapsulePolicy    `yaml:"capsule" json:"capsule"`
	Filesystem FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
	Network    NetworkPolicy    `yaml:"network" json:"network"`
	Secrets    SecretPolicy     `yaml:"secrets" json:"secrets"`
	Commands   CommandPolicy    `yaml:"commands" json:"commands"`
	Evidence   EvidencePolicy   `yaml:"evidence" json:"evidence"`
}

type CapsulePolicy struct {
	DefaultUser       string `yaml:"default_user" json:"default_user,omitempty"`
	MaxRuntimeSeconds int    `yaml:"max_runtime_seconds" json:"max_runtime_seconds,omitempty"`
	CPUs              int    `yaml:"cpus" json:"cpus,omitempty"`
	MemoryMB          int    `yaml:"memory_mb" json:"memory_mb,omitempty"`
}

type FilesystemPolicy struct {
	Mounts []MountPolicy `yaml:"mounts" json:"mounts,omitempty"`
}

type MountPolicy struct {
	Name         string `yaml:"name" json:"name"`
	HostPath     string `yaml:"host_path" json:"host_path"`
	Mode         string `yaml:"mode" json:"mode"`
	DiffRequired bool   `yaml:"diff_required" json:"diff_required,omitempty"`
}

type NetworkPolicy struct {
	Default string   `yaml:"default" json:"default,omitempty"`
	Allow   []string `yaml:"allow" json:"allow,omitempty"`
}

type SecretPolicy struct {
	Default string        `yaml:"default" json:"default,omitempty"`
	Grants  []SecretGrant `yaml:"grants" json:"grants,omitempty"`
}

type SecretGrant struct {
	Name          string `yaml:"name" json:"name"`
	Capability    string `yaml:"capability" json:"capability"`
	Delivery      string `yaml:"delivery" json:"delivery"`
	MaxTTLSeconds int    `yaml:"max_ttl_seconds" json:"max_ttl_seconds,omitempty"`
}

type CommandPolicy struct {
	Deny            []string `yaml:"deny" json:"deny,omitempty"`
	RequireApproval []string `yaml:"require_approval" json:"require_approval,omitempty"`
}

type EvidencePolicy struct {
	RecordCommands     bool `yaml:"record_commands" json:"record_commands"`
	RecordNetwork      bool `yaml:"record_network" json:"record_network"`
	RecordFileDiff     bool `yaml:"record_file_diff" json:"record_file_diff"`
	RecordProcessTree  bool `yaml:"record_process_tree" json:"record_process_tree"`
	RequireAttestation bool `yaml:"require_attestation" json:"require_attestation"`
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Version == 0 {
		return nil, fmt.Errorf("policy version is required")
	}
	return &p, nil
}

func (p *Policy) DecideCommand(command string) Decision {
	for _, rule := range p.Commands.Deny {
		if matchPattern(rule, command) {
			return Decision{Action: ActionDeny, Rule: rule, Reason: "command matches deny rule"}
		}
	}
	for _, rule := range p.Commands.RequireApproval {
		if matchPattern(rule, command) {
			return Decision{Action: ActionApprovalRequired, Rule: rule, Reason: "command requires approval"}
		}
	}
	return Decision{Action: ActionAllow}
}

func (p *Policy) DecideNetwork(host string) Decision {
	host = normalizeHost(host)
	for _, allowed := range p.Network.Allow {
		allowed = normalizeHost(allowed)
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return Decision{Action: ActionAllow, Rule: allowed}
		}
	}
	if strings.EqualFold(p.Network.Default, "allow") {
		return Decision{Action: ActionAllow, Rule: "network.default"}
	}
	return Decision{Action: ActionDeny, Reason: "host is not in network allowlist"}
}

func (p *Policy) DecideSecret(name, capability string) Decision {
	for _, grant := range p.Secrets.Grants {
		if grant.Name == name && grant.Capability == capability {
			return Decision{Action: ActionAllow, Rule: name + ":" + capability}
		}
	}
	if strings.EqualFold(p.Secrets.Default, "allow") {
		return Decision{Action: ActionAllow, Rule: "secrets.default"}
	}
	return Decision{Action: ActionDeny, Reason: "secret capability is not granted"}
}

func matchPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == value {
		return true
	}

	quoted := regexp.QuoteMeta(pattern)
	expr := "^" + strings.ReplaceAll(quoted, `\*`, ".*") + "$"
	matched, err := regexp.MatchString(expr, value)
	return err == nil && matched
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return strings.TrimSuffix(host, ".")
}
