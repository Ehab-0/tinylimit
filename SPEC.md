# TinyLimit: build specification

This file is the complete specification for TinyLimit. It is written for a coding agent that will implement the whole project in one pass. Where this file and any other note disagree, this file wins.

Status of the facts below:

- **Verified** means checked against the WinDivert source and documentation (repository `basil00/WinDivert`, `include/windivert.h`, `doc/windivert.html`, `sys/windivert.c`).
- **Unverified** means written from memory. Check it against Microsoft's documentation before relying on it.
- Nothing in this design has been run on a real machine yet.

---

## 1. What TinyLimit is

A Windows tool that caps download and upload speed per app. The user picks an app, types two numbers, and presses Apply.

The reason the project exists is trust: the whole program is one Rust source file with no third-party packages, small enough to audit in under an hour. Every design choice below favours fewer lines and fewer moving parts over features or peak performance.

## 2. Hard constraints

These are not negotiable. If one cannot be met, stop and report instead of working around it.

| # | Constraint |
| --- | --- |
| C1 | All program code lives in `src/main.rs`. No other `.rs` files, no `build.rs`. |
| C2 | Zero third-party crates. `[dependencies]` is empty; `Cargo.lock` contains exactly one package. Rust standard library only. |
| C3 | `src/main.rs` is at most 900 lines, counted from the top of the file down to the line `#[cfg(test)]`. Target is about 740. Do not golf: no multi-statement lines, no removed comments to hit the number. |
| C4 | Every `unsafe` block has a one-line comment saying why it is sound. Keep `unsafe` blocks as small as possible. |
| C5 | The program opens no sockets and makes no network requests. |
| C6 | The program writes exactly one file: `limits.txt` beside the .exe (plus its temporary `limits.txt.tmp`). No registry access, no service, no other files. |
| C7 | Target is `x86_64-pc-windows-msvc`, Windows 10 22H2 and Windows 11. No other platforms. |
| C8 | The only non-system component is WinDivert 2.2.2 (`WinDivert.dll` and `WinDivert64.sys`), shipped unmodified. |
| C9 | A crash, panic or kill of the program must leave the network working. Release builds use `panic = "abort"`. |

## 3. Non-goals

Do not build any of these: background service, start with Windows, tray icon, traffic history, charts, quotas, schedules, alerts, blocking rules, per-domain or per-port rules, app groups, remote control, REST API, command-line options, plugins, update checks, live speed display, translations, installer.

## 4. Deliverables

| File | Content |
| --- | --- |
| `src/main.rs` | The whole program and its unit tests |
| `Cargo.toml` | Section 13 |
| `Cargo.lock` | Generated; one package only |
| `rust-toolchain.toml` | Pins one exact stable Rust version (the current stable at implementation time) and the target |
| `.cargo/config.toml` | Linker flags for the administrator prompt (section 13) |
| `.github/workflows/build.yml` | Section 14 |
| `README.md` | Section 16 |
| `LICENSE` | MIT |
| `docs/index.html` | The project web page (section 17) |
| `docs/.nojekyll` | Empty file, so GitHub Pages serves the page as-is |
| `SPEC.md` | This file, unchanged |

## 5. User-visible behaviour

| ID | Requirement |
| --- | --- |
| F1 | A limit belongs to an app, identified by its .exe file name, compared case-insensitively (stored lowercase). Example: `chrome.exe`. |
| F2 | Download and upload limits are separate. Either may be empty, meaning unlimited. At least one must be set. |
| F3 | Limits are whole numbers in KB/s. 1 KB = 1,024 bytes. Minimum 1, maximum 4,000,000. |
| F4 | All processes with the same .exe name share one download budget and one upload budget. |
| F5 | A process started after the limit was applied is limited from its first connection. |
| F6 | Connections that were already open when a limit is applied are limited too. |
| F7 | Limits cover TCP and UDP over IPv4 and IPv6. Loopback traffic is never touched. |
| F8 | Applying, changing or removing a limit takes effect within 1 second. |
| F9 | Apps without a limit keep working normally while other apps are limited. |
| F10 | Closing the window stops all limiting and closes the driver handles. The WinDivert driver itself stays loaded until reboot (section 11). |
| F11 | The tool refuses to limit protected names: `system`, `[system process]`, `svchost.exe`, `lsass.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `smss.exe`, and its own .exe name. |
| F12 | If the driver cannot be opened, the tool shows one message box with the Windows error code and a plain cause, then exits. Causes: error 5 = not administrator; error 2 = `WinDivert.dll` or `WinDivert64.sys` missing beside the .exe; error 577 = driver signature blocked; anything else = "blocked by antivirus or Windows Memory Integrity". |
| F13 | When "Remember limits" is ticked (the default), limits are saved to `limits.txt` each time one is applied or removed. |
| F14 | At start-up, saved limits are loaded and enforced at once with no clicks. |
| F15 | Unticking "Remember limits" rewrites the file at once so it holds only the switch setting. Limits already active stay active until the window closes. Ticking it again saves the current limits. |
| F16 | The tool has to be started by hand. It never starts with Windows. |
| F17 | Up to 255 limits. Apply is refused with a status message beyond that. |
| F18 | Bytes are counted as whole IP packet length (headers included), so the cap matches what a speed test shows. |

## 6. User interface

One fixed-size window (not resizable, no maximise), about 440 by 560 pixels, built only from standard Win32 controls. No custom drawing. Window title: `TinyLimit - limits apply only while this window is open`.

Controls, top to bottom:

| Control | Win32 class | Behaviour |
| --- | --- | --- |
| Label "Find app" + search box | `STATIC`, `EDIT` | On every change, re-filter the app list (substring match, case-insensitive). |
| App list | `LISTBOX` | Unique .exe names of running processes, lowercase, sorted A to Z. Refreshed every 2 seconds by a timer and on every search change. Keep the selected name selected across refreshes. |
| "Download KB/s" field | `EDIT` with `ES_NUMBER` | Empty means unlimited. |
| "Upload KB/s" field | `EDIT` with `ES_NUMBER` | Empty means unlimited. |
| Apply button | `BUTTON` | Sets or replaces the limit for the selected app. Disabled unless an app is selected and the fields pass F2 and F3. |
| Label "Active limits" + list | `STATIC`, `LISTBOX` | One row per limit: `chrome.exe   down 500   up 200` (show `-` for unlimited). Selecting a row selects that app for editing and loads its numbers into the two fields. |
| Remove button | `BUTTON` | Removes the limit selected in the active list. Disabled when nothing is selected there. |
| "Remember limits" checkbox | `BUTTON` with `BS_AUTOCHECKBOX` | F13 to F15. |
| Status line | `STATIC` | `Running. N limits active.` or a one-line problem report. |

Rules:

- The "selected app" is whichever of the two lists was clicked last.
- A limit stays in the active list when its app is not running.
- All user-facing strings are `const`s in one block at the top of the file. English only.
- Send `WM_SETFONT` with `GetStockObject(DEFAULT_GUI_FONT)` to every control.
- Use `IsDialogMessageW` in the message loop so Tab moves between controls.
- No message boxes except for F12.

## 7. Architecture

One process, five threads, three pieces of shared state.

Shared state (all `static`):

| Name | Type | Meaning |
| --- | --- | --- |
| `PORTS` | `[AtomicU8; 262144]` | For each (IP version, protocol, local port): the limit slot that owns it, or 0. Index = `(is_ipv6 << 17) | (is_udp << 16) | local_port`. |
| `LIMITS` | `Mutex<Limits>` | Slots 1 to 255, each `Option<Limit>`. A `Limit` holds the app name, the two rates and the two budgets. |
| `QUEUE` | `Mutex<Queue>` | Delayed packets in a `BTreeMap<(release_ns, sequence), (Vec<u8>, Address)>`, plus the current network handle (0 when closed). |
| `ACTIVE` | `AtomicUsize` | Number of limits. The packet thread diverts traffic only while this is above 0. |
| `BUSY_SINCE` | `AtomicU64` | Millisecond timestamp set while the packet thread is processing a packet, 0 while it waits for one. |

Lock rules: never hold `LIMITS` and `QUEUE` at the same time. Never call a blocking Windows function while holding either, except `WinDivertSend` under `QUEUE`.

Threads:

| Thread | Job |
| --- | --- |
| UI (main) | Window and message loop. On Apply or Remove: update `LIMITS`, update `ACTIVE`, run the port scan (7.2), save `limits.txt`. |
| Flow listener | Blocks on the WinDivert flow handle. For each new connection, records which limit slot owns its local port (7.1). |
| Packet loop | While `ACTIVE > 0`: holds the WinDivert network handle, receives every non-loopback TCP and UDP packet, and passes, delays or drops it (7.3). |
| Release | Every 1 ms, sends the delayed packets that are due (7.4). |
| Watchdog | Every 500 ms, exits the process if the packet loop has been stuck on one packet for over 2 seconds (7.5). |

All time values used by the budgets and the queue are `u64` nanoseconds since program start (from one `Instant` taken in `main`). This keeps the budget logic pure and testable.

### 7.1 Flow listener

Opened once at start-up and kept for the life of the process. Opening it is also the F12 check.

```
handle = WinDivertOpen("true", LAYER_FLOW, 0, FLAG_SNIFF | FLAG_RECV_ONLY)
loop:
    WinDivertRecv(handle, null, 0, null, &addr)        // flow events carry no packet data
    if addr.event != EVENT_FLOW_ESTABLISHED: continue
    if addr.flow.protocol is not 6 (TCP) or 17 (UDP): continue
    name = exe_name(addr.flow.process_id)              // lowercase file name, or None
    slot = LIMITS.lock().slot_of(name), or 0
    PORTS[index(addr.ipv6, protocol, addr.flow.local_port)].store(slot)
```

- Always store, including 0. This is what clears a port when a different, unlimited app reuses it.
- `FLOW_DELETED` events are ignored.
- `addr.flow.local_port` is in host byte order (verified).
- The flags must be exactly `SNIFF | RECV_ONLY`. Any other combination makes `WinDivertOpen` fail with error 87 at this layer (verified in the documentation).

### 7.2 Port scan

Run by the UI thread after every Apply and once at start-up after loading saved limits. It makes F6 work.

```
for each of: TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6 owner tables:
    for each row (local_port, pid):
        name = exe_name(pid), cached per pid for this scan
        slot = slot_of(name)
        if slot != 0: PORTS[index(...)].store(slot)
```

On Remove, walk all of `PORTS` and reset every entry equal to the removed slot to 0, before the slot is reused.

### 7.3 Packet loop

```
loop forever:
    sleep 100 ms until ACTIVE > 0
    h = WinDivertOpen("!loopback and (tcp or udp)", LAYER_NETWORK, 0, 0)
    if it fails: set status text, sleep 1 s, continue
    QUEUE.lock().handle = h
    loop:
        BUSY_SINCE.store(0)
        ok = WinDivertRecv(h, buf, 65535, &len, &addr)
        BUSY_SINCE.store(now_ms)
        if !ok and GetLastError() == 232 (ERROR_NO_DATA): break     // handle was shut down
        if !ok: after 10 failures in a row break; else continue
        slot = slot_for_packet(buf, len, addr)                      // 0 if unparsable or unknown
        if slot == 0: send(h, buf, len, addr); continue
        verdict = LIMITS.lock(): if slot is occupied, charge its download or upload budget; else PassNow
        PassNow   -> send(h, buf, len, addr)
        DelayTo(t)-> QUEUE.lock().insert((t, next_sequence), (copy of packet, addr))
        Drop      -> nothing
    // teardown
    q = QUEUE.lock(); send every queued packet now; q.handle = 0; unlock
    WinDivertClose(h)
```

- `slot_for_packet`: call `WinDivertHelperParsePacket` to get the TCP or UDP header pointer. Source port is bytes 0..2 and destination port is bytes 2..4 of that header, both big-endian. Local port = source port when `addr.outbound` is 1, else destination port. IP version comes from `addr.ipv6`.
- Direction: `addr.outbound == 1` charges the upload budget, otherwise the download budget.
- Reinjection uses the address struct exactly as received.
- The UI thread stops this loop by taking `QUEUE`, reading the handle, and calling `WinDivertShutdown(h, SHUTDOWN_RECV)` when `ACTIVE` reaches 0.
- No file access, no process lookups and no allocation in this loop except the copy of a delayed packet.

### 7.4 Budgets

Pure functions, no Windows types, fully unit-tested.

```
BURST_NS     = 50 ms
MAX_DELAY_NS = 1 s

struct Budget { rate: u64 /* bytes per second, 0 = unlimited */, next_ns: u64 }

charge(budget, packet_len, now_ns) -> PassNow | DelayTo(t) | Drop:
    if rate == 0: return PassNow
    t = max(next_ns, now_ns saturating_sub BURST_NS)
    if t > now_ns + MAX_DELAY_NS: return Drop          // budget untouched
    next_ns = t + packet_len * 1_000_000_000 / rate
    return PassNow if t <= now_ns else DelayTo(t)
```

Properties the tests must prove: every non-dropped packet is charged; packets of one budget are released in arrival order; an idle budget allows at most 50 ms of traffic through at once; queued bytes per budget never exceed about 1 second of traffic.

Changing a limit's rate resets that budget's `next_ns` to now.

Release thread: every 1 ms, take `QUEUE`; if the handle is not 0, pop and send every entry whose release time has passed; release the lock.

### 7.5 Watchdog and exit

- Watchdog: `if BUSY_SINCE != 0 and now_ms - BUSY_SINCE > 2000 { std::process::exit(2) }`. Exiting makes Windows close the handles, which restores normal traffic.
- Normal exit (window closed): take `QUEUE`, send everything queued, shut down the network handle, then `std::process::exit(0)`. Do not try to join threads.

## 8. WinDivert interface (verified)

Load `WinDivert.dll` at start-up with `LoadLibraryW` using the **absolute path** of the directory containing the .exe, then `GetProcAddress` for each function. Do not rely on the DLL search order: this process runs as administrator.

```c
HANDLE WinDivertOpen(const char *filter, int layer, INT16 priority, UINT64 flags);   // INVALID_HANDLE_VALUE on failure
BOOL   WinDivertRecv(HANDLE h, void *packet, UINT packetLen, UINT *recvLen, WINDIVERT_ADDRESS *addr);
BOOL   WinDivertSend(HANDLE h, const void *packet, UINT packetLen, UINT *sendLen, const WINDIVERT_ADDRESS *addr);
BOOL   WinDivertShutdown(HANDLE h, int how);
BOOL   WinDivertClose(HANDLE h);
BOOL   WinDivertHelperParsePacket(const void *packet, UINT packetLen,
           void **ipHdr, void **ipv6Hdr, UINT8 *protocol, void **icmpHdr, void **icmpv6Hdr,
           void **tcpHdr, void **udpHdr, void **data, UINT *dataLen, void **next, UINT *nextLen);
           // every out-pointer may be NULL
```

Constants:

| Name | Value |
| --- | --- |
| `LAYER_NETWORK` | 0 |
| `LAYER_FLOW` | 2 |
| `FLAG_SNIFF` | 0x0001 |
| `FLAG_RECV_ONLY` | 0x0004 |
| `EVENT_FLOW_ESTABLISHED` | 1 |
| `EVENT_FLOW_DELETED` | 2 |
| `SHUTDOWN_RECV` | 1 |
| `ERROR_NO_DATA` | 232 |

`WINDIVERT_ADDRESS` is 80 bytes, `#[repr(C)]`:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | `timestamp: i64` |
| 8 | 4 | `bits: u32`: layer = bits 0-7, event = bits 8-15, sniffed = bit 16, outbound = bit 17, loopback = bit 18, impostor = bit 19, ipv6 = bit 20, checksum flags = bits 21-23 |
| 12 | 4 | `reserved: u32` |
| 16 | 64 | union; treat as `[u8; 64]` |

Flow data inside the union (only valid on the flow handle):

| Union offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | `endpoint_id: u64` |
| 8 | 8 | `parent_endpoint_id: u64` |
| 16 | 4 | `process_id: u32` |
| 20 | 16 | `local_addr: [u32; 4]` (not used by TinyLimit) |
| 36 | 16 | `remote_addr: [u32; 4]` (not used) |
| 52 | 2 | `local_port: u16`, host byte order |
| 54 | 2 | `remote_port: u16`, host byte order |
| 56 | 1 | `protocol: u8` (6 = TCP, 17 = UDP) |

Add a compile-time assertion that the Rust struct is 80 bytes.

Other verified facts:

- The ipv6 bit is set correctly on flow events as well as packets.
- Packets injected with `WinDivertSend` are not captured again by the same handle.
- Several threads may use one handle at the same time.
- After `WinDivertShutdown(h, SHUTDOWN_RECV)`, `WinDivertRecv` keeps returning queued packets and then fails with error 232.
- The driver's own queue holds packets for at most 2 seconds by default, then drops them. This is why the packet loop must never stall.
- The driver stays loaded after the last handle closes, until reboot or `sc stop WinDivert`.

## 9. Windows interface (unverified: check each against Microsoft's documentation)

Declare each function by hand with `#[link(name = "...", kind = "raw-dylib")] extern "system"`. Expected list; the final list goes in the README:

| DLL | Functions | Used for |
| --- | --- | --- |
| kernel32 | `LoadLibraryW`, `GetProcAddress`, `GetLastError`, `OpenProcess`, `QueryFullProcessImageNameW`, `CloseHandle`, `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `GetModuleHandleW` | Loading WinDivert, process names, app list |
| iphlpapi | `GetExtendedTcpTable`, `GetExtendedUdpTable` | Port scan (7.2) |
| user32 | `RegisterClassW`, `CreateWindowExW`, `DefWindowProcW`, `GetMessageW`, `IsDialogMessageW`, `TranslateMessage`, `DispatchMessageW`, `SendMessageW`, `SetWindowTextW`, `GetWindowTextW`, `EnableWindow`, `SetTimer`, `PostQuitMessage`, `MessageBoxW`, `LoadCursorW` | Window |
| gdi32 | `GetStockObject` | Default font |

Notes:

- `exe_name(pid)`: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, 0, pid)`, then `QueryFullProcessImageNameW`, take the text after the last `\`, lowercase it. Any failure returns `None` (slot 0).
- Owner tables: call with `TableClass` 5 (`TCP_TABLE_OWNER_PID_ALL`) for TCP and 1 (`UDP_TABLE_OWNER_PID`) for UDP, address family 2 (IPv4) and 23 (IPv6). Call once to get the size (error 122), then again with a buffer. Each table is a `u32` row count followed by rows.
- Row sizes and fields: TCP/IPv4 24 bytes (`state, local_addr, local_port, remote_addr, remote_port, pid`, all `u32`); TCP/IPv6 56 bytes (`local_addr[16], local_scope, local_port, remote_addr[16], remote_scope, remote_port, state, pid`); UDP/IPv4 12 bytes (`local_addr, local_port, pid`); UDP/IPv6 28 bytes (`local_addr[16], local_scope, local_port, pid`).
- In these tables the port is in network byte order in the low 16 bits of its `u32`: `u16::from_be(value as u16)`.
- `thread::sleep(1 ms)` may sleep up to about 15 ms on some systems. If manual test A1 shows jumpy speeds, add `timeBeginPeriod(1)` from `winmm` and list it in the README.

## 10. Saved limits file

Path: `limits.txt` in the directory of the running .exe (`std::env::current_exe()`).

```
remember on
500 200 chrome.exe
0 100 some app.exe
```

- Line 1 is `remember on` or `remember off`.
- Each later line is `<download KB/s> <upload KB/s> <exe name>`. 0 means unlimited. The name is the rest of the line, so it may contain spaces.
- With `remember off` the file holds only line 1.
- Writing: write `limits.txt.tmp`, then rename over `limits.txt`. A failed write shows a status message and is otherwise ignored.
- Reading, at start-up only: a missing file means remember on, no limits. Read at most 64 KB. Skip any line that is malformed, breaks F3, names a protected app (F11), duplicates an earlier name, or comes after the 255th limit. Report `N saved lines skipped` in the status line. Never refuse to start because of this file.
- Parsing and formatting are pure functions with unit tests.

## 11. Safety requirements

| ID | Situation | Required result |
| --- | --- | --- |
| S1 | No limits are set | The network handle is closed; no packets are diverted. Only the sniff-only flow handle is open. |
| S2 | Crash, panic or kill | Windows closes the handles; traffic flows normally at once. Nothing needs cleanup. |
| S3 | Packet loop stuck on one packet for over 2 seconds | The watchdog exits the process (7.5). |
| S4 | Sender far above the limit | Packets that would wait over 1 second are dropped; memory stays bounded. |
| S5 | Packet cannot be parsed or has no known owner | Passed through unchanged, immediately. |
| S6 | Protected app chosen or loaded from file | Refused (F11) or skipped (section 10). |
| S7 | Driver cannot be opened | F12. |
| S8 | Window closed | Queued packets are sent, handles are shut down, process exits. |
| S9 | `limits.txt` damaged | Section 10; start-up continues. |

## 12. Source layout

`src/main.rs` in this order, each section under a banner comment, so an auditor can read top to bottom:

1. Header comment: what the program does, the thread list, the list of outside functions.
2. `#![windows_subsystem = "windows"]`, constants, user-facing strings.
3. Pure logic: budgets, port index, name rules, limits table, limits file parse and format.
4. `#[cfg(windows)]` foreign declarations: WinDivert, then Windows.
5. `#[cfg(windows)]` engine: shared state, flow listener, port scan, packet loop, release, watchdog.
6. `#[cfg(windows)]` window: creation, message handler, list refresh, Apply and Remove.
7. `main` (Windows), and a `#[cfg(not(windows))]` `main` that prints "Windows only".
8. `#[cfg(test)]` unit tests for section 3.

The pure logic must compile and its tests must pass on any operating system.

## 13. Build configuration

`Cargo.toml`:

```toml
[package]
name = "tinylimit"
version = "1.0.0"
edition = "2021"
license = "MIT"

[dependencies]

[profile.release]
panic = "abort"
lto = true
codegen-units = 1
strip = true
```

`.cargo/config.toml` (unverified; confirm the flags are accepted by the MSVC linker in CI):

```toml
[target.x86_64-pc-windows-msvc]
rustflags = [
  "-C", "link-arg=/MANIFEST:EMBED",
  "-C", "link-arg=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'",
]
```

This makes Windows show the administrator prompt at launch. The F12 check for error 5 stays in the code regardless.

The build must finish with zero compiler warnings.

## 14. GitHub Actions workflow

One workflow, `build.yml`, on push, pull request and tags matching `v*`. Runner: `windows-2022`. Permissions: `contents: write`, `id-token: write`, `attestations: write`.

Steps, in order:

1. Check out the code.
2. Fail if `Cargo.lock` has more than one `[[package]]` entry.
3. Fail if `src/main.rs` has more than 900 lines before the `#[cfg(test)]` line.
4. `cargo test --locked`.
5. `cargo build --release --locked`.
6. Download `https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip` and fail unless its SHA-256 equals a value written in the workflow.
7. Assemble `TinyLimit-<version>-x64.zip`: `tinylimit.exe`, `x64/WinDivert.dll`, `x64/WinDivert64.sys`, `LICENSE`, WinDivert's `LICENSE` as `WinDivert-LICENSE.txt`, `README.md`.
8. Write `SHA256SUMS.txt` for the ZIP.
9. On tags only: create a build attestation for the ZIP with `actions/attest-build-provenance`, then publish the ZIP and checksums with `gh release create`.

Rules:

- Pin every Action to a full commit hash, with the version in a comment. Look the hashes up; do not invent them.
- The WinDivert ZIP hash must be computed from the real download, never guessed. Record in the README the hashes of the two extracted files. For reference, OpenNetLimit's documentation publishes these for WinDivert 2.2.2 from the NuGet package: `WinDivert.dll` `C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2`, `WinDivert64.sys` `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2`. If the official ZIP's files differ, say so in the README; do not fail the build.
- No other third-party Actions.

## 15. Tests

Unit tests (in `main.rs`, run on any OS):

- A stream at twice the limit is released at the limit within 2% over 10 simulated seconds.
- Released packets of one budget keep arrival order.
- A packet that would wait over 1 second is dropped and the budget is unchanged.
- After a long idle period, at most 50 ms worth of bytes pass with no delay.
- Rate 0 always passes.
- Port index is unique for all combinations of IP version, protocol and port, and stays below 262,144.
- Name rules: lowercase, exact match on file name, protected names refused.
- Limits file: format then parse returns the same limits; each kind of bad line in section 10 is skipped and counted; `remember off` loads no limits.
- Limits table: add, replace, remove, slot reuse, refusal at 255.

Manual tests (need a real Windows machine, administrator, driver loaded). The agent must not claim these pass unless it actually ran them:

| # | Check | Pass when |
| --- | --- | --- |
| A1 | Download cap 500 KB/s on a large download | 30-second average is 450 to 550 KB/s |
| A2 | Upload cap 200 KB/s on a large upload | 30-second average is 180 to 220 KB/s |
| A3 | Multi-process browser capped at 1,000 KB/s | Total stays under 1,100 KB/s |
| A4 | App started after Apply | Limited from its first connection |
| A5 | Download already running, then Apply | Limited within 1 second |
| A6 | Unlimited second app during A1 | Its speed drops by less than 5% |
| A7 | QUIC site or video call in a limited browser | Capped, stays connected |
| A8 | IPv6 download | Capped like IPv4 |
| A9 | Kill the tool during A1 | Full speed returns, no network loss |
| A10 | Close the window during A1 | Same as A9 |
| A11 | Start without administrator rights | Administrator prompt; if declined or absent, the F12 message |
| A12 | Speed test, tool open, no limits | Within 2% of the tool-closed result |
| A13 | Apply, close, start again | Limit listed and enforced with no clicks |
| A14 | Untick Remember, close, start again | No limits, box unticked, file holds one line |

## 16. README content

Short and plain. Required sections:

1. What it does, in three sentences, with one screenshot placeholder.
2. Download and run: unzip, run as administrator, keep the three files together.
3. Verify the download: `SHA256SUMS.txt`, and `gh attestation verify <zip> --repo <owner>/<repo>`.
4. Audit guide: the section map from section 12, the final list of every outside function called, the number of `unsafe` blocks, and how to confirm zero dependencies.
5. About the driver: WinDivert is third-party kernel code; its file hashes; antivirus may flag it; it stays loaded until reboot and can be stopped with `sc stop WinDivert`.
6. The unsigned .exe and the SmartScreen warning.
7. `limits.txt` format and the Remember switch.
8. Known limitations (below).
9. Manual test checklist from section 15 with a tested or untested mark on each line.

Known limitations to state:

- While any limit is active, all TCP and UDP packets pass through the tool; unlimited apps' packets are passed straight on.
- Connections are matched to apps by local port, protocol and IP version. Two apps using the same port number on different local addresses can be confused.
- The first few packets of a brand-new connection may pass before its owner is known.
- Download limiting is indirect: packets are delayed after they reach the PC, and the sender then slows down. Speed settles within a few seconds.
- Not tested with VPN software.
- 64-bit Windows only.

## 17. Project web page

A one-page site served by GitHub Pages at `https://<owner>.github.io/<repo>/`. It follows the same trust rules as the program.

Rules:

- One file, `docs/index.html`, with all CSS inline in a `<style>` block. At most 300 lines.
- No JavaScript at all.
- No requests to any other host: no CDN, web fonts, analytics, badges, embedded videos or remote images. Use system fonts. Any diagram is inline SVG.
- Served straight from the `docs/` folder of the `main` branch. No build step, no site generator, no extra workflow.
- Works on a phone (single column under 600 px wide) and follows the visitor's light or dark setting with `prefers-color-scheme`.
- Valid HTML5 with a `<title>`, a meta description, `lang="en"`, and readable contrast in both themes.
- Take `<owner>/<repo>` from the Git remote. If there is none, use the placeholder `OWNER/REPO` and list every place it appears in the final report.

Content, in this order:

1. Name and one-line pitch: "Cap any Windows app's download and upload speed. One source file you can read in an hour."
2. Download button linking to `https://github.com/<owner>/<repo>/releases/latest`, with "Windows 10 and 11, 64-bit" beside it.
3. How to use it, in three steps: unzip, run as administrator, pick an app and press Apply. A placeholder box where a screenshot will go (no image file yet).
4. Why you can trust it: one source file, zero third-party packages, makes no network connections, writes one text file, built in public by GitHub Actions. Each claim links to where it can be checked (`src/main.rs`, `Cargo.lock`, the workflow file).
5. Verify your download: the two commands from README section 3.
6. How it works: a short paragraph and a small inline SVG of the five parts from section 7 (window, flow listener, packet loop, release queue, WinDivert driver).
7. What to know first: the driver is third-party kernel code and may be flagged by antivirus; the SmartScreen warning; the known limitations from section 16.
8. Footer: links to the source, the README, this specification and the licence.

The page must not state anything the README does not, and must not claim that any manual test passed unless the README marks it as tested.

Enabling the site is a one-time manual step for the repository owner (Settings, Pages, "Deploy from a branch", `main`, `/docs`). Put that step in the README and in the final report.

## 18. Definition of done

- All files in section 4 exist and constraints C1 to C9 hold.
- `docs/index.html` meets every rule in section 17 and contains no `<script>` tag and no `http` reference to a host other than `github.com` links.
- `cargo test` passes; the release build for `x86_64-pc-windows-msvc` succeeds with zero warnings.
- The workflow file is complete, with real pinned hashes or a clearly marked list of the ones that could not be looked up.
- The final report states: the line count of `main.rs`, the number of `unsafe` blocks, the final outside-function list, which unverified items in sections 9 and 13 were confirmed and how, and which manual tests were and were not run.
- Anything in this specification that turned out to be wrong is reported, with what was done instead.
