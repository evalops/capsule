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
capsule eval ./runs/latest --suite coding-agent-safety
capsule apply ./runs/latest --repo ~/src/evalops/platform --require clean-worktree --require tests-passed --require no-secret-diff
```

Build locally:

```bash
go build -o bin/capsule ./cmd/capsule
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

## What Works Today

- `capsule init` writes a default coding-agent policy.
- `capsule run` copies a repo into a run-local workspace, excludes `.git`, creates a private baseline commit, executes a command, and emits a patch.
- Top-level denied commands are blocked before execution.
- Top-level network commands such as `curl`, `wget`, `git`, `gh`, `npm`, `pnpm`, `yarn`, `go`, and `cargo` are checked for URL-style destinations before execution.
- Explicit secret requests are checked against policy and delivered only from `CAPSULE_SECRET_<NAME>` into brokered env vars.
- `capsule inspect`, `capsule diff`, `capsule eval`, and `capsule apply` operate on the run bundle.
- `capsule apply` can require a clean worktree, successful run, and no obvious secret-looking material in the patch.

## What Is Deliberately Not Claimed Yet

- The `local-quarantine` backend is not a hardened untrusted-code boundary.
- It does not force all possible network egress through an OS-level firewall.
- It does not intercept every nested command an arbitrary shell or agent process may execute.
- It does not yet run a libkrun-backed microVM. That backend should preserve the same policy and evidence contract rather than changing the product surface.

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

## Roadmap

1. Add a `podman` backend that preserves the same run-bundle contract.
2. Add `podman --runtime=krun` support for libkrun-backed OCI workcells.
3. Move network enforcement from top-level broker checks to backend-level egress policy.
4. Sign attestations and ingest run bundles into an EvalOps/Cerebro graph.
5. Add PR attachment helpers for proof bundles and approval-paused sessions.
