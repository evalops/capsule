# Architecture

Capsule is an agent action control layer, not a generic sandbox service.

## Core Objects

- `CapsuleSpec`: task intent, agent identity, repo mount, backend, command, and requested capabilities.
- `Policy`: filesystem, network, secret, command, runtime, and evidence rules.
- `RunBundle`: immutable evidence directory produced by one execution.
- `Broker`: the host-side control point for filesystem writes, network-aware tool shims, and secret delivery.
- `Attestation`: a signed-or-signable statement over policy, command, diff, and exit metadata.

## Backends

The first backend is `local-quarantine`:

- copies the repo into a run-local workspace
- initializes a private git baseline in that workspace
- executes the requested command there
- captures the patch as the only host-applicable mutation

Future hardened backends should preserve the same run bundle contract while swapping the execution cell:

- `podman`
- `podman --runtime=krun`
- direct libkrun wrapper only after the host-side isolation and broker threat model is explicit

## Evidence Graph Shape

The bundle is designed to map cleanly into EvalOps/Cerebro-style graph records:

- `agent_run`
- `tool_call`
- `command_execution`
- `filesystem_mutation`
- `network_access`
- `secret_grant`
- `policy_decision`
- `approval_request`
- `artifact`
- `outcome`

That lets downstream systems ask policy and provenance questions without scraping logs.

