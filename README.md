# FreshThread — Open-source Codex connection & network viewer

This repository contains two open-source Windows components of FreshThread:

- **Codex connection:** the bridge that connects the FreshThread app to Codex.
- **Network activity viewer:** a separate tool that shows connections reported
  by Windows. Open it from FreshThread's **Network activity…** tray option.

Both components have independently verifiable GitHub builds. You can review
their source code and verify the exact files included in your installation.

**[Download FreshThread for Windows](https://github.com/GG95-lab/FreshThread-app/releases)** ·
**[Browse the source](https://github.com/GG95-lab/FreshThread-bridge/tree/main)** ·
**[Verify your installed components](VERIFY.md)**

The FreshThread desktop app currently has no Windows publisher signature.
Public source code and GitHub build attestations provide additional transparency;
they do not replace Windows publisher signing. The main FreshThread app remains
private.

## Codex connection

An older installer may still use the previous connection until it receives an
app update that includes this bridge.

Once this bridge is loaded, compatible FreshThread updates can reconnect in the
background without closing Codex. A call already in progress finishes first.
The bridge checks the new app file before switching and keeps the same Codex
connection open. Moving from an older bridge, or changing the plugin's tools or
permissions, can still require a Codex restart.

The bridge receives messages from Codex. It removes your prompt, shell command
and command output before passing a small status update to the FreshThread app.
For a handoff, it also passes the task summary you ask Codex to save. That
summary can contain information you wrote, so it is stored locally by the app.

The bridge itself has no internet connection. The main app reads your Codex
session files on your computer to show the measurements, and it only goes online
to check for updates and their signed minimum-version policy, and to send a bug
report if you choose to submit one. This
source code shows exactly what Codex's hooks and the FreshThread tool pass to the app.

FreshThread may send Codex a fixed reminder to save the current task state. The
reminder also asks Codex not to mention that bookkeeping unless you ask. The
exact text and steps to check the installed bridge are in [Verification](VERIFY.md).

This bridge is licensed under [MPL-2.0](LICENSE). People may use and change it;
if they distribute changed bridge files, they must make those files' source
available. This license does not apply to the separate private FreshThread app.

## Network activity viewer

FreshThread's **Network activity…** tray option opens a separate, public
`freshthread-inspect.exe`. Its blue terminal-style window shows connections
reported by Windows, with labels for FreshThread, WebView2, Codex and related
programs. Connections are grouped by program; select a row and press Enter to
inspect its connections. Full executable paths are omitted to protect usernames.

No administrator permission is needed. Very short connections can be missed.
The window shows addresses and connection states, not encrypted message contents
or the reason for a request. Nothing is uploaded or saved as a traffic log.

Close the window to stop watching. The inspector has its own GitHub build
verification, alongside the bridge. See [verification steps](VERIFY.md) and
[what the viewer can see](NETWORK.md).
