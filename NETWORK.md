# Network activity

FreshThread's tray menu opens a separate **freshthread-inspect.exe** window.
It uses blue terminal-style text, with no visible scrollbars. Select a row
with the mouse or arrow keys; Enter opens its details, then cycles through the
connections in that program group. Wheel and Page Up/Down
navigate longer lists. P pauses sampling, ? opens help, and Q closes the window.

## What it shows

The viewer asks Windows for the current TCP connections and local UDP endpoints
once per second. It groups FreshThread's own programs before related programs,
including WebView2 and Codex. One list row summarizes each program group; times
are local. The prominent first line describes FreshThread's observed external
TCP connections, excluding listeners and loopback. It does not infer which side
initiated a connection, measure bytes sent, or prove an absence of traffic.
Related programs appear in a muted "Not FreshThread" group. WebView2 can carry
application requests; the label identifies the process, not the request's author.

Connection states, protocols, process IDs and full addresses appear in the
selectable, wrapping details area. Executable names replace full paths to avoid
revealing a Windows username or workspace. "Only this PC can connect" applies
only to loopback endpoints. Wildcard listeners may be reachable from other
devices, depending on firewall settings. UDP destinations remain unknown.

When available, names come from Windows' local DNS cache through the documented
MSFT_DNSClientCache provider. This never performs a network DNS lookup. Cache
reads run away from the UI, at most once per 15 seconds while unpaused. Only
names matching visible remote addresses are retained in memory. A cached name
is a hint: shared IPs can have several names, and a cache entry does not prove
which hostname a program used. Missing, partial or inaccessible cache data falls
back to the IP address. Pausing cancels further cache work; closing the viewer
ends its process and worker even if a Windows provider stalls.

Short connections between samples can be missed. Windows' UDP table shows
local endpoints, not remote destinations. A blank list does not mean that a
program never connected. The viewer does not read encrypted message contents
or guess a request's purpose from an IP address.

WebView2 is Microsoft's display runtime; it can also carry an app's requests.
A Codex connection does not prove that FreshThread caused it.

## Observation boundary

Only an open, unpaused viewer samples. Closing the window stops it. There is
no admin mode, ETW session, service, network DNS lookup, upload or saved traffic history.
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
display columns, grouped selection across state changes, loopback versus wildcard
listeners, path redaction and native window/control bounds without scrollbars. Release
acceptance additionally needs the actual tray launch, close/reopen, pause/resume,
DPI/resize, updater cleanup, packaged digests and both GitHub attestations.
These source tests do not establish end-to-end packaged acceptance.

## Windows references

- [TCP tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [UDP endpoint tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [Wrapping native edit controls](https://learn.microsoft.com/en-us/windows/win32/controls/edit-control-styles)
- [Local DNS cache records](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/dnsclientcimprov/msft-dnsclientcache)

