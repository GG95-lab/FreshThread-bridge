# FreshThread bridge

This is the small, open-source part of FreshThread that connects to Codex on
Windows. The main FreshThread app remains private. [Get the app here](https://github.com/GG95-lab/FreshThread-BETA-version/releases).
An older installer may still use the previous connection until it receives an
app update that includes this bridge.

The bridge receives messages from Codex. It removes your prompt, shell command
and command output before passing a small status update to the FreshThread app.
For a handoff, it also passes the task summary you ask Codex to save. That
summary can contain information you wrote, so it is stored locally by the app.

The bridge itself has no internet connection. The main app reads your Codex
session files on your computer to show the measurements, and it only goes online
to check for updates and to send a bug report if you choose to submit one. This
source code shows exactly what Codex's hooks and the FreshThread tool pass to the app.

FreshThread may send Codex a fixed reminder to save the current task state. The
reminder also asks Codex not to mention that bookkeeping unless you ask. The
exact text and steps to check the installed bridge are in [Verification](VERIFY.md).

This bridge is licensed under [MPL-2.0](LICENSE). People may use and change it;
if they distribute changed bridge files, they must make those files' source
available. This license does not apply to the separate private FreshThread app.
