# FreshThread — Open-source Codex connection & network viewer

Two open-source Windows components of FreshThread live here:

- **Codex connection** — the bridge between Codex and the FreshThread app.
- **Network activity viewer** — shows the connections Windows reports for
  FreshThread and related programs. Open it from **Network activity…** in the tray.

Both have independently verifiable GitHub builds, so you can check your
installed files against their public release builds.

**[Download FreshThread](https://github.com/GG95-lab/FreshThread-app/releases)** ·
**[Browse the source](https://github.com/GG95-lab/FreshThread-bridge/tree/main)** ·
**[Verify your installation](VERIFY.md)**

## What the bridge passes on

- **Activity events:** the bridge removes prompts, raw shell commands and
  command output from Codex hook messages before forwarding a small status update.
- **Task summaries:** the bridge passes summaries saved by Codex. These can
  include text you wrote and are stored locally by FreshThread. Context you
  approve for a handoff is passed to the new Codex task.
- **Local session data:** the main app also reads Codex session files on your PC
  for measurements and handoff context.
- **Network access:** the bridge has no internet connection. The main app only
  goes online for updates and their signed minimum-version policy, and for a
  bug report you choose to send.
- **Codex reminders:** FreshThread may send a fixed reminder to save the task
  state and ask Codex not to mention that bookkeeping unless you ask. The exact
  text is in [VERIFY.md](VERIFY.md).

## Network activity viewer

Shows addresses and connection states for FreshThread, WebView2, Codex and
related programs. No admin rights needed. It does not read message contents,
save traffic logs or upload anything. Watching stops when you close the window.
Very short connections can be missed. [What it can see](NETWORK.md).

## License

[MPL-2.0](LICENSE). The main FreshThread app is separate and private.
