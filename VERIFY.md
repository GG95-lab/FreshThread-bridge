# Verify the FreshThread bridge

This source project builds only the public bridge. The desktop engine, scoring,
checkpoint persistence, handoff implementation and app updater are private.
This verification concerns the bridge's Codex connection, not the private app.

## Data passed to the private app

| Input from Codex | Passed through the bridge |
| --- | --- |
| Prompt submission | Event and session ID. Prompt and other fields are discarded. |
| Session start | Event, session ID and start source. |
| Compaction and stop | Event and session/turn IDs; stop also carries a loop flag. |
| Shell command completion | Session/turn/tool IDs, working directory, installation-keyed command hash, build/test classification and exit outcome. Raw command and output are discarded. |
| MCP checkpoint | Declared task summary fields and root task/turn identity. This summary can contain user-authored content. |

The bridge reads the existing DPAPI-protected installation key at
`%LOCALAPPDATA%/com.freshthread.desktop/installation.key` for command identity.
It does not create or replace the key. It also hashes the colocated private
engine binary before starting it. It does not read Codex rollout files or
contain a network client. The private app still reads local Codex session data
and has its own update and optional bug-report network paths. The local pipe
between bridge and engine is not an operating-system sandbox.

## Data returned to Codex

The bridge can return this exact, fixed reminder when requested by the engine:

> FreshThread session-integrity checkpointing is active for this task. Before every final user-facing response, including brief acknowledgements and turns without tool work, use the FreshThread record-session-integrity skill exactly as instructed. Record the current task state in this turn; do not invent work or start a separate model turn. Do not mention this internal measurement unless the user asks.

The engine cannot substitute arbitrary text for this reminder. Successful MCP
results contain only `checkpoint_recorded`, `replayed`, `probe_status`,
`retention_basis_points` and `recommendation_authority` (false). Errors use
fixed status codes rather than raw engine exceptions.

## Check an installed bridge after publication

1. Read `%LOCALAPPDATA%\com.freshthread.desktop\integration\freshthread-integration.cmd`
   without running it. Confirm it starts `bin\freshthread-integration-bridge-<hash>.exe`
   and names the private backend plus its SHA256.
2. Hash that exact bridge file with `Get-FileHash -Algorithm SHA256`. Compare
   it with the reviewed public GitHub Release asset.
3. Replace the placeholders below with values from that public release and
   verify the installed file against its build attestation:

```powershell
gh attestation verify '<installed-bridge-path>' --repo '<owner/repository>' --signer-workflow '<owner/repository>/.github/workflows/release.yml' --source-digest '<full-commit>' --source-ref 'refs/tags/<tag>' --deny-self-hosted-runners
```

This checks the file at inspection time. It does not establish the behavior of
the private app, future replacements or every possible Codex configuration.
Use the source commit and tag of the release actually installed on your machine.

## Before publication

The project has a pinned toolchain and lockfile and no private source
dependencies. After build authorization, its native checks are `cargo test
--locked` and `cargo build --release --locked --target x86_64-pc-windows-msvc`.
The tagged public GitHub workflow must test, build and attest the exact file.
The private installer must include that file unchanged. The private release
policy requires an immutable public release asset, its pinned SHA256 and a
successful verification of repository, source commit, tag and workflow.
Reproducible Windows builds have not been demonstrated.
