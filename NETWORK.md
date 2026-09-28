# Network activity

FreshThread's tray menu opens a separate **freshthread-inspect.exe** window.
It uses blue terminal-style text, with no visible scrollbars. Select a row
with the mouse or arrow keys; Enter opens its details. Wheel and Page Up/Down
navigate longer lists. P pauses sampling, ? opens help, and Q closes the window.

## What it shows

The viewer asks Windows for the current TCP connections and local UDP endpoints
once per second. It groups FreshThread's own programs before related programs,
including WebView2 and Codex. Times are local. Long addresses are shortened in
the list and shown in full in the selectable, wrapping details area.

Short connections between samples can be missed. Windows' UDP table shows
local endpoints, not remote destinations. A blank list does not mean that a
program never connected. The viewer does not read encrypted message contents
or guess a request's purpose from an IP address.

WebView2 is Microsoft's display runtime; it can also carry an app's requests.
A Codex connection does not prove that FreshThread caused it.

## Observation boundary

Only an open, unpaused viewer samples. Closing the window stops it. There is
no admin mode, ETW session, service, DNS lookup, upload or saved traffic history.
The executable does not read Codex conversations, FreshThread's database or its
installation key, and it does not launch the private FreshThread engine.
The bridge's hook/MCP path does not load or call the inspector.

Process matching uses executable location, PID, creation time, Windows session
and ancestry. It excludes unrelated WebView2 processes and other Windows sessions.
Unknown installation paths, inaccessible processes and exited parents can limit
the view. Labels do not authenticate executable publishers.
The UI is limited to 2048 endpoints and says when rows have been omitted.

## Independent verification

Both executables are built from this public repository. Each has its own SHA256
and is a subject of the GitHub build attestation. Verifying the bridge alone
does not verify the inspector. See [Verification](VERIFY.md).

## Development validation

Run `cargo test --workspace --locked` and `cargo fmt --all -- --check`.
Tests exercise real local TCP/UDP sockets, process identity rejection, bounded
display columns and native window/control bounds without scrollbars. Release
acceptance additionally needs the actual tray launch, close/reopen, pause/resume,
DPI/resize, updater cleanup, packaged digests and both GitHub attestations.
These source tests do not establish end-to-end packaged acceptance.

## Windows references

- [TCP tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [UDP endpoint tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [Wrapping native edit controls](https://learn.microsoft.com/en-us/windows/win32/controls/edit-control-styles)

