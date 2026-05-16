# Capsule

Capsule is a local agent execution runner for policy-bound, diff-quarantined, replayable coding and ops work.

The product contract is simple:

```text
agent intent -> policy -> isolated workcell -> brokered filesystem/network/secrets -> trace + diff + attestation -> approval or apply
```

The first implementation is intentionally dogfood-shaped. It prioritizes the proof bundle over a generic sandbox API:

- the agent works in a copied/quarantined workspace, not directly in the host checkout
- policy decisions are written as JSONL evidence
- top-level commands, stdout/stderr, process snapshots, network broker events, secret grants, file diffs, artifacts, and attestations are captured into a run bundle
- applying a result is a separate command with checks such as clean worktree, successful run, and no obvious secret material in the patch
- the local backend is explicit about its limits; hardened VM isolation belongs behind the same capsule spec as a later `podman/crun/krun` backend

## MVP CLI

```bash
capsule init

capsule run \
  --repo ~/src/evalops/platform \
  --agent codex \
  --policy ./policies/coding-agent.yaml \
  --task "fix failing tests in internal/console" \
  --allow-net github.com,api.github.com,registry.npmjs.org \
  --secret github_token:create_pr \
  --emit ./runs/latest \
  -- bash -lc 'go test ./internal/console/...'

capsule inspect ./runs/latest
capsule diff ./runs/latest
capsule apply ./runs/latest --repo ~/src/evalops/platform --require clean-worktree --require tests-passed --require no-secret-diff
```

## Run Bundle

Each run emits a directory like:

```text
runs/2026-05-16T...
  capsule.json
  policy.yaml
  policy_decisions.jsonl
  commands.jsonl
  network.jsonl
  process_tree.jsonl
  secrets.jsonl
  stdout.log
  stderr.log
  filesystem_diff.patch
  exit.json
  attestation.intoto.json
  replay.sh
  workspace/
  artifacts/
```

The boring-looking output is the product. A capsule run should be reviewable without trusting the agent that produced it.

## Security Posture

Capsule does not claim that the local quarantine backend is a complete untrusted-code boundary. It is a governance and evidence layer with filesystem quarantine and command/network/secret brokers for practical dogfooding.

The intended hardened architecture is layered:

```text
host
  -> unprivileged container / namespace / cgroup / seccomp / LSM boundary
    -> libkrun-backed VMM process through an OCI runtime
      -> guest microVM
        -> non-root agent process
```

The unit of trust is the capsule spec, policy, brokered access, and emitted evidence, not the VM alone.

