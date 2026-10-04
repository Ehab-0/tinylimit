// ============================================================================
// TinyLimit: caps download and upload speed per Windows app.
//
// The user picks an app by its .exe name and types two numbers (KB/s). While
// the window is open, every TCP and UDP packet of that app is paced to the
// limit using the WinDivert driver. Closing the window ends all limiting.
//
// Threads:
//   1. UI (main)     window and message loop; Apply, Remove, port scan, saving
//   2. Flow listener learns which limit owns each new connection's local port
//   3. Packet loop   receives every non-loopback TCP/UDP packet and passes,
//                    delays or drops it (only while at least one limit exists)
//   4. Release       every 1 ms sends the delayed packets that are due
//   5. Watchdog      exits the process if the packet loop is stuck
//
// Outside functions called (the complete list, all declared in section 4):
//   WinDivert.dll (loaded by absolute path): WinDivertOpen, WinDivertRecv,
//     WinDivertSend, WinDivertShutdown, WinDivertClose,
//     WinDivertHelperParsePacket
//   kernel32: LoadLibraryW, GetProcAddress, GetLastError, OpenProcess,
//     QueryFullProcessImageNameW, CloseHandle, CreateToolhelp32Snapshot,
//     Process32FirstW, Process32NextW, GetModuleHandleW
//   iphlpapi: GetExtendedTcpTable, GetExtendedUdpTable
//   user32: RegisterClassW, CreateWindowExW, DefWindowProcW, GetMessageW,
//     IsDialogMessageW, TranslateMessage, DispatchMessageW, SendMessageW,
//     SetWindowTextW, GetWindowTextW, EnableWindow, SetTimer, PostQuitMessage,
//     MessageBoxW, LoadCursorW, AdjustWindowRect
//   gdi32: GetStockObject
// ============================================================================

// ============================================================================
// 2. Constants and user-facing strings
// ============================================================================
#![windows_subsystem = "windows"]
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashSet;

const BURST_NS: u64 = 50_000_000;
const MAX_DELAY_NS: u64 = 1_000_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;
const MAX_LIMITS: usize = 255;
const PORT_TABLE_SIZE: usize = 1 << 18;
const MIN_KBPS: u64 = 1;
const MAX_KBPS: u64 = 4_000_000;
const BYTES_PER_KB: u64 = 1024;
const MAX_FILE_BYTES: usize = 64 * 1024;
const LIMITS_FILE: &str = "limits.txt";
const LIMITS_TEMP_FILE: &str = "limits.txt.tmp";

// Names that may never be limited (F11). The tool's own name is added at run time.
const PROTECTED_NAMES: [&str; 9] = [
    "system",
    "[system process]",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
];

const TEXT_TITLE: &str = "TinyLimit - limits apply only while this window is open";
const TEXT_FIND_APP: &str = "Find app";
const TEXT_DOWNLOAD: &str = "Download KB/s";
const TEXT_UPLOAD: &str = "Upload KB/s";
const TEXT_APPLY: &str = "Apply";
const TEXT_ACTIVE_LIMITS: &str = "Active limits";
const TEXT_REMOVE: &str = "Remove";
const TEXT_REMEMBER: &str = "Remember limits";
const TEXT_HIDE_PROTECTED: &str = "Hide protected apps";
const TEXT_STATUS_RUNNING: &str = "Running.";
const TEXT_PROTECTED: &str = "That app is protected and cannot be limited.";
const TEXT_TOO_MANY: &str = "Limit refused: 255 limits are already active.";
const TEXT_SAVE_FAILED: &str = "Could not save limits.txt.";
const TEXT_NET_HANDLE_FAILED: &str = "Could not open the packet handle; retrying.";
const TEXT_ERROR_TITLE: &str = "TinyLimit cannot start";
const TEXT_CAUSE_ADMIN: &str = "Not running as administrator.";
const TEXT_CAUSE_MISSING: &str = "WinDivert.dll or WinDivert64.sys is missing beside the .exe.";
const TEXT_CAUSE_SIGNATURE: &str = "Windows blocked the driver signature.";
const TEXT_CAUSE_OTHER: &str = "Blocked by antivirus or Windows Memory Integrity.";

// ============================================================================
// 3. Pure logic: budgets, port index, name rules, limits table, limits file
// ============================================================================

// What to do with one packet, decided by `charge`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    PassNow,
    DelayTo(u64),
    Drop,
}

// One pacing budget: `next_ns` is the earliest time the next packet may leave.
#[derive(Debug, Clone, Copy)]
struct Budget {
    rate: u64, // bytes per second, 0 = unlimited
    next_ns: u64,
}

impl Budget {
    fn new(rate: u64, now_ns: u64) -> Budget {
        Budget { rate, next_ns: now_ns }
    }

    // Charges one packet of `packet_len` bytes and says when it may leave.
    fn charge(&mut self, packet_len: u64, now_ns: u64) -> Verdict {
        if self.rate == 0 {
            return Verdict::PassNow;
        }
        let earliest = now_ns.saturating_sub(BURST_NS);
        let start = self.next_ns.max(earliest);
        if start > now_ns + MAX_DELAY_NS {
            return Verdict::Drop;
        }
        self.next_ns = start + packet_len * NS_PER_SECOND / self.rate;
        if start <= now_ns {
            Verdict::PassNow
        } else {
            Verdict::DelayTo(start)
        }
    }
}

// Index into PORTS: (is_ipv6 << 17) | (is_udp << 16) | local_port.
fn port_index(is_ipv6: bool, is_udp: bool, local_port: u16) -> usize {
    ((is_ipv6 as usize) << 17) | ((is_udp as usize) << 16) | local_port as usize
}

// Lowercases an app name; names are always stored and compared this way (F1).
fn normalize_name(name: &str) -> String {
    name.to_lowercase()
}

fn is_protected(name: &str, own_exe_name: &str) -> bool {
    let lower = normalize_name(name);
    lower == normalize_name(own_exe_name) || PROTECTED_NAMES.contains(&lower.as_str())
}

// A saved or typed limit, in KB/s. 0 means unlimited.
#[derive(Debug, PartialEq, Eq, Clone)]
struct LimitSetting {
    name: String,
    down_kbps: u64,
    up_kbps: u64,
}

// F2 and F3: each side is 0 (unlimited) or 1..=4,000,000, and not both 0.
fn rates_are_valid(down_kbps: u64, up_kbps: u64) -> bool {
    let side_ok = |kbps: u64| kbps == 0 || (MIN_KBPS..=MAX_KBPS).contains(&kbps);
    side_ok(down_kbps) && side_ok(up_kbps) && (down_kbps != 0 || up_kbps != 0)
}

// One live limit: the app name and its two budgets.
struct Limit {
    name: String,
    down_kbps: u64,
    up_kbps: u64,
    down: Budget,
    up: Budget,
}

#[derive(Debug, PartialEq, Eq)]
enum SetError {
    Full,
}

// Slots 1 to 255; slot 0 means "no limit" everywhere else.
struct Limits {
    slots: Vec<Option<Limit>>,
}

impl Limits {
    fn new() -> Limits {
        let mut slots = Vec::new();
        slots.resize_with(MAX_LIMITS + 1, || None);
        Limits { slots }
    }

    fn count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    // Slot (1..=255) owned by `name`, or 0.
    fn slot_of(&self, name: &str) -> u8 {
        let wanted = normalize_name(name);
        for (index, slot) in self.slots.iter().enumerate().skip(1) {
            if let Some(limit) = slot {
                if limit.name == wanted {
                    return index as u8;
                }
            }
        }
        0
    }

    // Adds or replaces a limit and returns its slot. A changed rate resets that budget.
    fn set(&mut self, setting: &LimitSetting, now_ns: u64) -> Result<u8, SetError> {
        let name = normalize_name(&setting.name);
        let existing = self.slot_of(&name);
        let slot = if existing != 0 { existing } else { self.free_slot().ok_or(SetError::Full)? };
        let old = self.slots[slot as usize].take();
        // An unchanged rate keeps its budget; a new or changed rate starts a fresh one.
        let down = match &old {
            Some(limit) if limit.down_kbps == setting.down_kbps => limit.down,
            _ => Budget::new(setting.down_kbps * BYTES_PER_KB, now_ns),
        };
        let up = match &old {
            Some(limit) if limit.up_kbps == setting.up_kbps => limit.up,
            _ => Budget::new(setting.up_kbps * BYTES_PER_KB, now_ns),
        };
        self.slots[slot as usize] = Some(Limit { name, down_kbps: setting.down_kbps, up_kbps: setting.up_kbps, down, up });
        Ok(slot)
    }

    fn free_slot(&self) -> Option<u8> {
        (1..=MAX_LIMITS).find(|&index| self.slots[index].is_none()).map(|index| index as u8)
    }

    // Removes the limit in `slot`; the slot can then be reused.
    fn remove(&mut self, slot: u8) {
        self.slots[slot as usize] = None;
    }

    // All limits, sorted by name, for the "Active limits" list and the file.
    fn settings(&self) -> Vec<LimitSetting> {
        let mut all: Vec<LimitSetting> = self
            .slots
            .iter()
            .flatten()
            .map(|l| LimitSetting { name: l.name.clone(), down_kbps: l.down_kbps, up_kbps: l.up_kbps })
            .collect();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        all
    }

    // Charges a packet to the slot's download or upload budget (7.3).
    fn charge(&mut self, slot: u8, is_upload: bool, packet_len: u64, now_ns: u64) -> Verdict {
        match self.slots[slot as usize].as_mut() {
            Some(limit) if is_upload => limit.up.charge(packet_len, now_ns),
            Some(limit) => limit.down.charge(packet_len, now_ns),
            None => Verdict::PassNow,
        }
    }
}

// Formats the limits file (section 10): switch line, then one line per limit.
fn format_limits_file(remember: bool, settings: &[LimitSetting]) -> String {
    let mut text = String::from(if remember { "remember on\n" } else { "remember off\n" });
    if remember {
        for setting in settings {
            text.push_str(&format!("{} {} {}\n", setting.down_kbps, setting.up_kbps, setting.name));
        }
    }
    text
}

struct ParsedFile {
    remember: bool,
    settings: Vec<LimitSetting>,
    skipped: usize,
}

// Parses one limit line: `<down> <up> <name>`; None if malformed or rule-breaking.
fn parse_limit_line(line: &str, own_exe_name: &str) -> Option<LimitSetting> {
    let mut parts = line.splitn(3, ' ');
    let down_kbps: u64 = parts.next()?.parse().ok()?;
    let up_kbps: u64 = parts.next()?.parse().ok()?;
    let name = normalize_name(parts.next()?.trim());
    if name.is_empty() || !rates_are_valid(down_kbps, up_kbps) || is_protected(&name, own_exe_name) {
        return None;
    }
    Some(LimitSetting { name, down_kbps, up_kbps })
}

// Parses the limits file text (section 10). Bad lines are skipped and counted.
fn parse_limits_file(text: &str, own_exe_name: &str) -> ParsedFile {
    let mut lines = text.lines();
    let remember = lines.next().map(|first| first.trim() != "remember off").unwrap_or(true);
    let mut parsed = ParsedFile { remember, settings: Vec::new(), skipped: 0 };
    if !remember {
        return parsed;
    }
    let mut seen: HashSet<String> = HashSet::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        match parse_limit_line(line.trim_end(), own_exe_name) {
            Some(setting) if parsed.settings.len() < MAX_LIMITS && !seen.contains(&setting.name) => {
                seen.insert(setting.name.clone());
                parsed.settings.push(setting);
            }
            _ => parsed.skipped += 1,
        }
    }
    parsed
}

// Plain-language cause for a failed driver start-up (F12). Error 126 is what
// LoadLibraryW reports for a missing WinDivert.dll; 2 is a missing .sys file.
fn cause_text(error_code: u32) -> &'static str {
    match error_code {
        5 => TEXT_CAUSE_ADMIN,
        2 | 126 => TEXT_CAUSE_MISSING,
        577 => TEXT_CAUSE_SIGNATURE,
        _ => TEXT_CAUSE_OTHER,
    }
}

// ============================================================================
// 4. Foreign declarations (Windows only): WinDivert, then Windows
// ============================================================================
#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;
    use std::mem::size_of;

    // Every HANDLE is a pointer-sized integer here; 0 is NULL, -1 is INVALID_HANDLE_VALUE.
    pub type Handle = isize;
    pub const INVALID_HANDLE: Handle = -1;

    // --- WinDivert 2.2.2 (windivert.h, tag v2.2.2) ---
    pub const LAYER_NETWORK: i32 = 0;
    pub const LAYER_FLOW: i32 = 2;
    pub const FLAG_SNIFF: u64 = 0x0001;
    pub const FLAG_RECV_ONLY: u64 = 0x0004;
    pub const EVENT_FLOW_ESTABLISHED: u32 = 1;
    pub const SHUTDOWN_RECV: i32 = 1;
    pub const ERROR_NO_DATA: u32 = 232;
    pub const PACKET_BUFFER_BYTES: usize = 40 + 0xFFFF; // WINDIVERT_MTU_MAX

    // WINDIVERT_ADDRESS: 80 bytes. `bits` holds layer, event, sniffed, outbound, loopback, impostor, ipv6.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Address {
        _timestamp: i64,
        bits: u32,
        _reserved: u32,
        union_bytes: [u8; 64],
    }
    const _: () = assert!(size_of::<Address>() == 80);

    impl Address {
        pub fn zeroed() -> Address {
            Address { _timestamp: 0, bits: 0, _reserved: 0, union_bytes: [0; 64] }
        }
        pub fn event(&self) -> u32 {
            (self.bits >> 8) & 0xFF
        }
        pub fn outbound(&self) -> bool {
            self.bits & (1 << 17) != 0
        }
        pub fn ipv6(&self) -> bool {
            self.bits & (1 << 20) != 0
        }
        // Flow data lives in the union: process_id at 16, local_port (host order) at 52, protocol at 56.
        pub fn flow_process_id(&self) -> u32 {
            u32::from_ne_bytes([self.union_bytes[16], self.union_bytes[17], self.union_bytes[18], self.union_bytes[19]])
        }
        pub fn flow_local_port(&self) -> u16 {
            u16::from_ne_bytes([self.union_bytes[52], self.union_bytes[53]])
        }
        pub fn flow_protocol(&self) -> u8 {
            self.union_bytes[56]
        }
    }

    type Pointer = *mut c_void;
    type OpenFn = unsafe extern "system" fn(*const u8, i32, i16, u64) -> Handle;
    type RecvFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut Address) -> i32;
    type SendFn = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const Address) -> i32;
    type ShutdownFn = unsafe extern "system" fn(Handle, i32) -> i32;
    type CloseFn = unsafe extern "system" fn(Handle) -> i32;
    type ParseFn = unsafe extern "system" fn(
        *const u8, u32, // packet, length
        *mut Pointer, *mut Pointer, *mut u8, // ipHdr, ipv6Hdr, protocol
        *mut Pointer, *mut Pointer, // icmpHdr, icmpv6Hdr
        *mut Pointer, *mut Pointer, // tcpHdr, udpHdr
        *mut Pointer, *mut u32, // data, dataLen
        *mut Pointer, *mut u32, // next, nextLen
    ) -> i32;

    // The WinDivert.dll entry points, looked up once at start-up.
    #[derive(Clone, Copy)]
    pub struct Divert {
        pub open: OpenFn,
        pub recv: RecvFn,
        pub send: SendFn,
        pub shutdown: ShutdownFn,
        pub close: CloseFn,
        pub parse: ParseFn,
    }

    // Loads WinDivert.dll from an absolute path; Err holds the Windows error code.
    pub fn load_divert(dll_path: &str) -> Result<Divert, u32> {
        let wide_path = wide(dll_path);
        // SAFETY: wide_path is NUL-terminated and outlives the call.
        let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
        if module == 0 {
            return Err(last_error());
        }
        Ok(Divert {
            open: lookup(module, b"WinDivertOpen\0")?,
            recv: lookup(module, b"WinDivertRecv\0")?,
            send: lookup(module, b"WinDivertSend\0")?,
            shutdown: lookup(module, b"WinDivertShutdown\0")?,
            close: lookup(module, b"WinDivertClose\0")?,
            parse: lookup(module, b"WinDivertHelperParsePacket\0")?,
        })
    }

    // Looks up one exported function; T must be the matching `extern "system" fn` pointer type.
    fn lookup<T: Copy>(module: Handle, name: &[u8]) -> Result<T, u32> {
        // SAFETY: name is NUL-terminated and module is a handle returned by LoadLibraryW.
        let address = unsafe { GetProcAddress(module, name.as_ptr()) };
        if address.is_null() {
            return Err(last_error());
        }
        assert!(size_of::<T>() == size_of::<*const c_void>());
        // SAFETY: T is a function pointer type (same size as address) written to match the WinDivert prototype.
        Ok(unsafe { std::mem::transmute_copy::<*const c_void, T>(&address) })
    }

    // --- Windows (values checked against the Windows SDK 10.0.19041 headers) ---
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const TH32CS_SNAPPROCESS: u32 = 2;
    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 23;
    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    pub const UDP_TABLE_OWNER_PID: u32 = 1;
    pub const WS_OVERLAPPED: u32 = 0;
    pub const WS_CHILD: u32 = 0x4000_0000;
    pub const WS_VISIBLE: u32 = 0x1000_0000;
    pub const WS_CAPTION: u32 = 0x00C0_0000;
    pub const WS_VSCROLL: u32 = 0x0020_0000;
    pub const WS_SYSMENU: u32 = 0x0008_0000;
    pub const WS_TABSTOP: u32 = 0x0001_0000;
    pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
    pub const WS_EX_CLIENTEDGE: u32 = 0x200;
    pub const ES_AUTOHSCROLL: u32 = 0x80;
    pub const ES_NUMBER: u32 = 0x2000;
    pub const BS_PUSHBUTTON: u32 = 0;
    pub const BS_AUTOCHECKBOX: u32 = 3;
    pub const LBS_NOTIFY: u32 = 1;
    pub const LBS_NOINTEGRALHEIGHT: u32 = 0x100;
    pub const LBS_USETABSTOPS: u32 = 0x80;
    pub const MB_OK: u32 = 0;
    pub const MB_ICONERROR: u32 = 0x10;
    pub const COLOR_BTNFACE: isize = 15;
    pub const DEFAULT_GUI_FONT: i32 = 17;
    pub const IDC_ARROW: usize = 32512;
    pub const WM_DESTROY: u32 = 0x0002;
    pub const WM_SETFONT: u32 = 0x0030;
    pub const WM_COMMAND: u32 = 0x0111;
    pub const WM_TIMER: u32 = 0x0113;
    pub const EN_CHANGE: usize = 0x0300;
    pub const BN_CLICKED: usize = 0;
    pub const LBN_SELCHANGE: usize = 1;
    pub const BM_GETCHECK: u32 = 0x00F0;
    pub const BM_SETCHECK: u32 = 0x00F1;
    pub const BST_CHECKED: isize = 1;
    pub const LB_ERR: isize = -1;
    pub const LB_ADDSTRING: u32 = 0x0180;
    pub const LB_RESETCONTENT: u32 = 0x0184;
    pub const LB_SETCURSEL: u32 = 0x0186;
    pub const LB_GETCURSEL: u32 = 0x0188;
    pub const LB_GETTOPINDEX: u32 = 0x018E;
    pub const LB_SETTABSTOPS: u32 = 0x0192;
    pub const LB_SETTOPINDEX: u32 = 0x0197;

    // PROCESSENTRY32W (tlhelp32.h): 568 bytes on x64.
    #[repr(C)]
    pub struct ProcessEntry {
        pub size: u32,
        _usage: u32,
        _process_id: u32,
        _heap_id: usize,
        _module_id: u32,
        _threads: u32,
        _parent_id: u32,
        _priority: i32,
        _flags: u32,
        pub exe_file: [u16; 260],
    }
    const _: () = assert!(size_of::<ProcessEntry>() == 568);

    impl ProcessEntry {
        pub fn new() -> ProcessEntry {
            ProcessEntry {
                size: size_of::<ProcessEntry>() as u32,
                _usage: 0,
                _process_id: 0,
                _heap_id: 0,
                _module_id: 0,
                _threads: 0,
                _parent_id: 0,
                _priority: 0,
                _flags: 0,
                exe_file: [0; 260],
            }
        }
    }

    // WNDCLASSW (winuser.h): 72 bytes on x64.
    #[repr(C)]
    pub struct WindowClass {
        pub style: u32,
        pub window_proc: unsafe extern "system" fn(Handle, u32, usize, isize) -> isize,
        pub class_extra: i32,
        pub window_extra: i32,
        pub instance: Handle,
        pub icon: Handle,
        pub cursor: Handle,
        pub background: isize,
        pub menu_name: *const u16,
        pub class_name: *const u16,
    }
    const _: () = assert!(size_of::<WindowClass>() == 72);

    // MSG (winuser.h): 48 bytes on x64; `pt` is two i32.
    #[repr(C)]
    #[derive(Default)]
    pub struct Message {
        pub hwnd: Handle,
        pub message: u32,
        pub wparam: usize,
        pub lparam: isize,
        pub time: u32,
        pub point_x: i32,
        pub point_y: i32,
    }
    const _: () = assert!(size_of::<Message>() == 48);

    #[link(name = "kernel32", kind = "raw-dylib")]
    extern "system" {
        pub fn LoadLibraryW(file_name: *const u16) -> Handle;
        pub fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;
        pub fn GetLastError() -> u32;
        pub fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        pub fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
        pub fn CloseHandle(handle: Handle) -> i32;
        pub fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        pub fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        pub fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        pub fn GetModuleHandleW(module_name: *const u16) -> Handle;
    }

    #[link(name = "iphlpapi", kind = "raw-dylib")]
    extern "system" {
        pub fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, order: i32, family: u32, class: u32, reserved: u32) -> u32;
        pub fn GetExtendedUdpTable(table: *mut c_void, size: *mut u32, order: i32, family: u32, class: u32, reserved: u32) -> u32;
    }

    #[link(name = "user32", kind = "raw-dylib")]
    extern "system" {
        pub fn RegisterClassW(class: *const WindowClass) -> u16;
        pub fn CreateWindowExW(
            ex_style: u32, class_name: *const u16, title: *const u16, style: u32,
            x: i32, y: i32, width: i32, height: i32,
            parent: Handle, menu: Handle, instance: Handle, param: *mut c_void,
        ) -> Handle;
        pub fn DefWindowProcW(hwnd: Handle, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn GetMessageW(message: *mut Message, hwnd: Handle, filter_min: u32, filter_max: u32) -> i32;
        pub fn IsDialogMessageW(dialog: Handle, message: *mut Message) -> i32;
        pub fn TranslateMessage(message: *const Message) -> i32;
        pub fn DispatchMessageW(message: *const Message) -> isize;
        pub fn SendMessageW(hwnd: Handle, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn SetWindowTextW(hwnd: Handle, text: *const u16) -> i32;
        pub fn GetWindowTextW(hwnd: Handle, text: *mut u16, max_count: i32) -> i32;
        pub fn EnableWindow(hwnd: Handle, enable: i32) -> i32;
        pub fn SetTimer(hwnd: Handle, timer_id: usize, milliseconds: u32, callback: *const c_void) -> usize;
        pub fn PostQuitMessage(exit_code: i32);
        pub fn MessageBoxW(hwnd: Handle, text: *const u16, caption: *const u16, kind: u32) -> i32;
        pub fn LoadCursorW(instance: Handle, cursor_name: *const u16) -> Handle;
        pub fn AdjustWindowRect(rect: *mut i32, style: u32, has_menu: i32) -> i32; // rect: left, top, right, bottom
    }

    #[link(name = "gdi32", kind = "raw-dylib")]
    extern "system" {
        pub fn GetStockObject(object: i32) -> Handle;
    }

    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn last_error() -> u32 {
        // SAFETY: GetLastError takes no arguments and has no preconditions.
        unsafe { GetLastError() }
    }
}

// ============================================================================
// 5. Engine (Windows only): shared state, flow listener, port scan, packet loop,
//    release thread, watchdog, saved limits
// ============================================================================
#[cfg(windows)]
mod engine {
    use super::ffi::*;
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::io::Read;
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize};
    use std::sync::{LazyLock, Mutex, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    // Delayed packets, ordered by (release time, arrival sequence), and the open network handle (0 = closed).
    pub struct Queue {
        handle: Handle,
        sequence: u64,
        packets: BTreeMap<(u64, u64), (Vec<u8>, Address)>,
    }

    // Owning limit slot per (IP version, protocol, local port); 0 = no limit.
    static PORTS: [AtomicU8; PORT_TABLE_SIZE] = [const { AtomicU8::new(0) }; PORT_TABLE_SIZE];
    pub static LIMITS: LazyLock<Mutex<Limits>> = LazyLock::new(|| Mutex::new(Limits::new()));
    static QUEUE: Mutex<Queue> = Mutex::new(Queue { handle: 0, sequence: 0, packets: BTreeMap::new() });
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static BUSY_SINCE: AtomicU64 = AtomicU64::new(0);
    pub static NET_PROBLEM: AtomicBool = AtomicBool::new(false);
    static START: OnceLock<Instant> = OnceLock::new();
    static DIVERT: OnceLock<Divert> = OnceLock::new();
    static OWN_NAME: OnceLock<String> = OnceLock::new();

    // Called once from main before any thread starts.
    pub fn init(divert: Divert, own_exe_name: String) {
        let _ = START.set(Instant::now());
        let _ = DIVERT.set(divert);
        let _ = OWN_NAME.set(own_exe_name);
    }

    pub fn own_exe_name() -> &'static str {
        OWN_NAME.get().map(String::as_str).unwrap_or("")
    }

    fn divert() -> &'static Divert {
        DIVERT.get().expect("init runs before any thread")
    }

    pub fn now_ns() -> u64 {
        START.get().expect("init runs before any thread").elapsed().as_nanos() as u64
    }

    // Never 0, because BUSY_SINCE uses 0 for "waiting".
    fn now_ms() -> u64 {
        now_ns() / 1_000_000 + 1
    }

    fn send_packet(handle: Handle, packet: &[u8], addr: &Address) {
        // SAFETY: packet and addr are valid for the call; a failed send is harmless and ignored.
        unsafe { (divert().send)(handle, packet.as_ptr(), packet.len() as u32, null_mut(), addr) };
    }

    fn shutdown_receive(handle: Handle) {
        // SAFETY: handle came from WinDivertOpen and is only closed by the packet thread after this.
        unsafe { (divert().shutdown)(handle, SHUTDOWN_RECV) };
    }

    // Sends every queued packet now, due or not.
    fn flush_queue(queue: &mut Queue, handle: Handle) {
        while let Some((_, (packet, addr))) = queue.packets.pop_first() {
            send_packet(handle, &packet, &addr);
        }
    }

    // Lowercase .exe file name of a process, or None when it cannot be queried.
    pub fn exe_name(process_id: u32) -> Option<String> {
        // SAFETY: plain query call; a NULL result is handled below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process == 0 {
            return None;
        }
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        // SAFETY: buffer holds `length` UTF-16 units and process is an open handle.
        let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
        // SAFETY: process is an open handle that is not used again.
        unsafe { CloseHandle(process) };
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        path.rsplit('\\').next().map(normalize_name)
    }

    // Unique lowercase .exe names of running processes, sorted A to Z.
    pub fn running_app_names() -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        // SAFETY: plain snapshot call; INVALID_HANDLE is handled below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE {
            return names;
        }
        let mut entry = ProcessEntry::new();
        let mut found = next_process(snapshot, &mut entry, true);
        while found {
            let length = entry.exe_file.iter().position(|&unit| unit == 0).unwrap_or(entry.exe_file.len());
            names.insert(normalize_name(&String::from_utf16_lossy(&entry.exe_file[..length])));
            found = next_process(snapshot, &mut entry, false);
        }
        // SAFETY: snapshot is an open handle that is not used again.
        unsafe { CloseHandle(snapshot) };
        names
    }

    fn next_process(snapshot: Handle, entry: &mut ProcessEntry, first: bool) -> bool {
        // SAFETY: snapshot is open and entry.size was set by ProcessEntry::new.
        let result = unsafe { if first { Process32FirstW(snapshot, entry) } else { Process32NextW(snapshot, entry) } };
        result != 0
    }

    // --- Flow listener (7.1) ---

    // Opens the flow handle. It is also the F12 check; Err holds the Windows error code.
    pub fn open_flow_handle() -> Result<Handle, u32> {
        // SAFETY: the filter is NUL-terminated; the flags are exactly SNIFF | RECV_ONLY as WinDivert requires.
        let handle = unsafe { (divert().open)(b"true\0".as_ptr(), LAYER_FLOW, 0, FLAG_SNIFF | FLAG_RECV_ONLY) };
        if handle == INVALID_HANDLE {
            return Err(last_error());
        }
        Ok(handle)
    }

    fn flow_listener(handle: Handle) {
        loop {
            let mut addr = Address::zeroed();
            // SAFETY: flow events carry no packet data, so a NULL buffer is allowed; addr is a valid out-pointer.
            let ok = unsafe { (divert().recv)(handle, null_mut(), 0, null_mut(), &mut addr) };
            if ok == 0 {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            let protocol = addr.flow_protocol();
            if addr.event() != EVENT_FLOW_ESTABLISHED || (protocol != 6 && protocol != 17) {
                continue;
            }
            let name = exe_name(addr.flow_process_id());
            let index = port_index(addr.ipv6(), protocol == 17, addr.flow_local_port());
            let limits = LIMITS.lock().unwrap();
            let slot = name.map_or(0, |name| limits.slot_of(&name));
            PORTS[index].store(slot, SeqCst);
        }
    }

    // --- Port scan (7.2) ---

    // One owner table: row layout from Microsoft's MIB_*ROW_OWNER_PID structures.
    struct OwnerTable {
        family: u32,
        class: u32,
        row_size: usize,
        port_offset: usize,
        pid_offset: usize,
        is_udp: bool,
    }

    const OWNER_TABLES: [OwnerTable; 4] = [
        OwnerTable { family: AF_INET, class: TCP_TABLE_OWNER_PID_ALL, row_size: 24, port_offset: 8, pid_offset: 20, is_udp: false },
        OwnerTable { family: AF_INET6, class: TCP_TABLE_OWNER_PID_ALL, row_size: 56, port_offset: 20, pid_offset: 52, is_udp: false },
        OwnerTable { family: AF_INET, class: UDP_TABLE_OWNER_PID, row_size: 12, port_offset: 4, pid_offset: 8, is_udp: true },
        OwnerTable { family: AF_INET6, class: UDP_TABLE_OWNER_PID, row_size: 28, port_offset: 20, pid_offset: 24, is_udp: true },
    ];

    fn fetch_owner_table(table: &OwnerTable, buffer: *mut std::ffi::c_void, size: &mut u32) -> u32 {
        let family = table.family;
        // SAFETY: buffer is NULL (size query) or points to *size writable bytes.
        unsafe {
            if table.is_udp {
                GetExtendedUdpTable(buffer, size, 0, family, table.class, 0)
            } else {
                GetExtendedTcpTable(buffer, size, 0, family, table.class, 0)
            }
        }
    }

    // (PORTS index, process id) for every row of one owner table.
    fn owner_rows(table: &OwnerTable) -> Vec<(usize, u32)> {
        let mut size = 0u32;
        fetch_owner_table(table, null_mut(), &mut size);
        let mut buffer = vec![0u8; size as usize + 4096];
        size = buffer.len() as u32;
        if fetch_owner_table(table, buffer.as_mut_ptr().cast(), &mut size) != 0 {
            return Vec::new();
        }
        let read = |offset: usize| u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]]);
        let mut rows = Vec::new();
        for row in 0..read(0) as usize {
            let start = 4 + row * table.row_size;
            if start + table.row_size > buffer.len() {
                break;
            }
            let port = u16::from_be(read(start + table.port_offset) as u16);
            rows.push((port_index(table.family == AF_INET6, table.is_udp, port), read(start + table.pid_offset)));
        }
        rows
    }

    // Marks the ports of connections that already exist (F6).
    pub fn port_scan() {
        if ACTIVE.load(SeqCst) == 0 {
            return;
        }
        let mut names: HashMap<u32, Option<String>> = HashMap::new();
        let mut owners: Vec<(usize, String)> = Vec::new();
        for table in &OWNER_TABLES {
            for (index, process_id) in owner_rows(table) {
                if let Some(name) = names.entry(process_id).or_insert_with(|| exe_name(process_id)) {
                    owners.push((index, name.clone()));
                }
            }
        }
        let limits = LIMITS.lock().unwrap();
        for (index, name) in owners {
            let slot = limits.slot_of(&name);
            if slot != 0 {
                PORTS[index].store(slot, SeqCst);
            }
        }
    }

    // --- Apply and remove (called by the UI thread) ---

    pub fn apply_limit(setting: &LimitSetting) -> Result<(), SetError> {
        let count = {
            let mut limits = LIMITS.lock().unwrap();
            limits.set(setting, now_ns())?;
            limits.count()
        };
        ACTIVE.store(count, SeqCst);
        port_scan();
        Ok(())
    }

    // Start-up: enforce the saved limits at once (F14).
    pub fn restore_limits(settings: &[LimitSetting]) {
        let mut limits = LIMITS.lock().unwrap();
        for setting in settings {
            let _ = limits.set(setting, now_ns());
        }
        ACTIVE.store(limits.count(), SeqCst);
        drop(limits);
        port_scan();
    }

    pub fn remove_limit(name: &str) {
        let count = {
            let mut limits = LIMITS.lock().unwrap();
            let slot = limits.slot_of(name);
            if slot != 0 {
                limits.remove(slot);
                for port in PORTS.iter().filter(|port| port.load(SeqCst) == slot) {
                    port.store(0, SeqCst);
                }
            }
            limits.count()
        };
        ACTIVE.store(count, SeqCst);
        if count == 0 {
            let queue = QUEUE.lock().unwrap();
            if queue.handle != 0 {
                shutdown_receive(queue.handle);
            }
        }
    }

    // --- Packet loop (7.3) ---

    // Local port is the source port of an outbound packet, else the destination port.
    fn slot_for_packet(packet: &[u8], addr: &Address) -> u8 {
        let mut tcp_header: *mut std::ffi::c_void = null_mut();
        let mut udp_header: *mut std::ffi::c_void = null_mut();
        // SAFETY: packet is valid for its length; unused out-pointers are NULL, which the helper allows.
        let parsed = unsafe {
            (divert().parse)(
                packet.as_ptr(), packet.len() as u32, null_mut(), null_mut(), null_mut(), null_mut(),
                null_mut(), &mut tcp_header, &mut udp_header, null_mut(), null_mut(), null_mut(), null_mut(),
            )
        };
        let is_udp = !udp_header.is_null();
        let header = if is_udp { udp_header } else { tcp_header };
        if parsed == 0 || header.is_null() {
            return 0;
        }
        let offset = (header as usize).wrapping_sub(packet.as_ptr() as usize);
        if offset.saturating_add(4) > packet.len() {
            return 0;
        }
        let source = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let destination = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let local_port = if addr.outbound() { source } else { destination };
        PORTS[port_index(addr.ipv6(), is_udp, local_port)].load(SeqCst)
    }

    fn process_packet(handle: Handle, packet: &[u8], addr: &Address) {
        let slot = slot_for_packet(packet, addr);
        if slot == 0 {
            send_packet(handle, packet, addr);
            return;
        }
        let verdict = LIMITS.lock().unwrap().charge(slot, addr.outbound(), packet.len() as u64, now_ns());
        match verdict {
            Verdict::PassNow => send_packet(handle, packet, addr),
            Verdict::DelayTo(release_ns) => {
                let mut queue = QUEUE.lock().unwrap();
                queue.sequence += 1;
                let key = (release_ns, queue.sequence);
                queue.packets.insert(key, (packet.to_vec(), *addr));
            }
            Verdict::Drop => {}
        }
    }

    // Receives and handles packets until the handle is shut down or fails 10 times in a row.
    fn receive_until_shutdown(handle: Handle, buffer: &mut [u8]) {
        let mut failures = 0;
        loop {
            BUSY_SINCE.store(0, SeqCst);
            let mut length = 0u32;
            let mut addr = Address::zeroed();
            // SAFETY: buffer is as long as the size passed; length and addr are valid out-pointers.
            let ok = unsafe { (divert().recv)(handle, buffer.as_mut_ptr(), buffer.len() as u32, &mut length, &mut addr) };
            BUSY_SINCE.store(now_ms(), SeqCst);
            if ok == 0 {
                failures += 1;
                if last_error() == ERROR_NO_DATA || failures >= 10 {
                    return;
                }
                continue;
            }
            failures = 0;
            process_packet(handle, &buffer[..length as usize], &addr);
        }
    }

    fn packet_loop() {
        let mut buffer = vec![0u8; PACKET_BUFFER_BYTES];
        loop {
            BUSY_SINCE.store(0, SeqCst);
            if ACTIVE.load(SeqCst) == 0 {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            // SAFETY: the filter is NUL-terminated; flags 0 means a normal (diverting) handle.
            let handle = unsafe { (divert().open)(b"!loopback and (tcp or udp)\0".as_ptr(), LAYER_NETWORK, 0, 0) };
            NET_PROBLEM.store(handle == INVALID_HANDLE, SeqCst);
            if handle == INVALID_HANDLE {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            QUEUE.lock().unwrap().handle = handle;
            if ACTIVE.load(SeqCst) == 0 {
                shutdown_receive(handle); // the last limit was removed before the handle was published
            }
            receive_until_shutdown(handle, &mut buffer);
            BUSY_SINCE.store(0, SeqCst); // teardown is not "stuck on a packet"
            {
                let mut queue = QUEUE.lock().unwrap();
                flush_queue(&mut queue, handle);
                queue.handle = 0;
            }
            // SAFETY: handle is open and no other thread uses it any more (QUEUE.handle is 0).
            unsafe { (divert().close)(handle) };
        }
    }

    // --- Release thread (7.4) and watchdog (7.5) ---

    fn release_loop() {
        loop {
            thread::sleep(Duration::from_millis(1));
            let now = now_ns();
            let mut queue = QUEUE.lock().unwrap();
            let handle = queue.handle;
            while handle != 0 {
                let Some(entry) = queue.packets.first_entry() else { break };
                if entry.key().0 > now {
                    break;
                }
                let (packet, addr) = entry.remove();
                send_packet(handle, &packet, &addr);
            }
        }
    }

    // Exiting makes Windows close the handles, which restores normal traffic.
    fn watchdog() {
        loop {
            thread::sleep(Duration::from_millis(500));
            let since = BUSY_SINCE.load(SeqCst);
            if since != 0 && now_ms().saturating_sub(since) > 2000 {
                std::process::exit(2);
            }
        }
    }

    pub fn start_threads(flow_handle: Handle) {
        thread::spawn(move || flow_listener(flow_handle));
        thread::spawn(packet_loop);
        thread::spawn(release_loop);
        thread::spawn(watchdog);
    }

    // Normal exit (S8): send what is queued, shut the network handle down, leave.
    pub fn exit_cleanly() -> ! {
        {
            let mut queue = QUEUE.lock().unwrap();
            let handle = queue.handle;
            if handle != 0 {
                flush_queue(&mut queue, handle);
                shutdown_receive(handle);
            }
        }
        std::process::exit(0)
    }

    // --- Saved limits (section 10) ---

    fn limits_dir() -> PathBuf {
        std::env::current_exe().ok().and_then(|path| path.parent().map(PathBuf::from)).unwrap_or_default()
    }

    pub fn divert_dll_path() -> PathBuf {
        limits_dir().join("WinDivert.dll")
    }

    // Reads limits.txt (at most 64 KB). A missing or unreadable file means defaults.
    pub fn load_saved_limits() -> ParsedFile {
        let mut bytes = Vec::new();
        if let Ok(file) = std::fs::File::open(limits_dir().join(LIMITS_FILE)) {
            let _ = file.take(MAX_FILE_BYTES as u64).read_to_end(&mut bytes);
        }
        parse_limits_file(&String::from_utf8_lossy(&bytes), own_exe_name())
    }

    // Writes limits.txt.tmp, then renames it over limits.txt. Returns false on failure.
    pub fn save_limits(remember: bool) -> bool {
        let settings = LIMITS.lock().unwrap().settings();
        let text = format_limits_file(remember, &settings);
        let temp_path = limits_dir().join(LIMITS_TEMP_FILE);
        std::fs::write(&temp_path, text).is_ok() && std::fs::rename(&temp_path, limits_dir().join(LIMITS_FILE)).is_ok()
    }
}

// ============================================================================
// 6. Window (Windows only): creation, message handler, list refresh, Apply, Remove
// ============================================================================
#[cfg(windows)]
mod window {
    use super::engine::*;
    use super::ffi::*;
    use super::*;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::atomic::AtomicIsize;
    use std::sync::Mutex;

    const ID_NONE: usize = 0;
    const ID_SEARCH: usize = 101;
    const ID_APP_LIST: usize = 102;
    const ID_DOWN: usize = 103;
    const ID_UP: usize = 104;
    const ID_APPLY: usize = 105;
    const ID_ACTIVE_LIST: usize = 106;
    const ID_REMOVE: usize = 107;
    const ID_REMEMBER: usize = 108;
    const ID_STATUS: usize = 109;
    const ID_HIDE_PROTECTED: usize = 110;
    const TIMER_REFRESH: usize = 1;
    const CLIENT_SIZE: (i32, i32) = (576, 500); // inner window size; the frame is added in run()

    struct Control {
        id: usize,
        class: &'static str,
        text: &'static str,
        style: u32,
        ex_style: u32,
        rect: (i32, i32, i32, i32), // x, y, width, height
    }

    const CHILD: u32 = WS_CHILD | WS_VISIBLE;
    const FIELD: u32 = CHILD | WS_TABSTOP;
    const LIST: u32 = FIELD | LBS_NOTIFY | WS_VSCROLL | LBS_NOINTEGRALHEIGHT;

    // Top to bottom, as in section 6. Labels have no id.
    // Grid: 12 px margin on every side; both lists are 552 x 140; both checkboxes end at the right margin.
    const CONTROLS: [Control; 14] = [
        Control { id: ID_NONE, class: "STATIC", text: TEXT_FIND_APP, style: CHILD, ex_style: 0, rect: (12, 15, 60, 18) },
        Control { id: ID_SEARCH, class: "EDIT", text: "", style: FIELD | ES_AUTOHSCROLL, ex_style: WS_EX_CLIENTEDGE, rect: (76, 12, 488, 22) },
        Control { id: ID_APP_LIST, class: "LISTBOX", text: "", style: LIST, ex_style: WS_EX_CLIENTEDGE, rect: (12, 40, 552, 140) },
        Control { id: ID_HIDE_PROTECTED, class: "BUTTON", text: TEXT_HIDE_PROTECTED, style: FIELD | BS_AUTOCHECKBOX, ex_style: 0, rect: (404, 184, 160, 20) },
        Control { id: ID_NONE, class: "STATIC", text: TEXT_DOWNLOAD, style: CHILD, ex_style: 0, rect: (12, 217, 95, 18) },
        Control { id: ID_DOWN, class: "EDIT", text: "", style: FIELD | ES_NUMBER, ex_style: WS_EX_CLIENTEDGE, rect: (110, 214, 80, 22) },
        Control { id: ID_NONE, class: "STATIC", text: TEXT_UPLOAD, style: CHILD, ex_style: 0, rect: (248, 217, 95, 18) },
        Control { id: ID_UP, class: "EDIT", text: "", style: FIELD | ES_NUMBER, ex_style: WS_EX_CLIENTEDGE, rect: (346, 214, 80, 22) },
        Control { id: ID_APPLY, class: "BUTTON", text: TEXT_APPLY, style: FIELD | BS_PUSHBUTTON, ex_style: 0, rect: (484, 213, 80, 24) },
        Control { id: ID_NONE, class: "STATIC", text: TEXT_ACTIVE_LIMITS, style: CHILD, ex_style: 0, rect: (12, 250, 200, 18) },
        Control { id: ID_ACTIVE_LIST, class: "LISTBOX", text: "", style: LIST | LBS_USETABSTOPS, ex_style: WS_EX_CLIENTEDGE, rect: (12, 270, 552, 140) },
        Control { id: ID_REMOVE, class: "BUTTON", text: TEXT_REMOVE, style: FIELD | BS_PUSHBUTTON, ex_style: 0, rect: (12, 422, 90, 26) },
        Control { id: ID_REMEMBER, class: "BUTTON", text: TEXT_REMEMBER, style: FIELD | BS_AUTOCHECKBOX, ex_style: 0, rect: (404, 423, 160, 24) },
        Control { id: ID_STATUS, class: "STATIC", text: "", style: CHILD, ex_style: 0, rect: (12, 458, 552, 30) },
    ];

    // What the UI thread remembers between messages. Never held while calling Windows.
    struct Ui {
        apps: Vec<String>,         // names shown in the app list
        active_names: Vec<String>, // names shown in the active-limits list
        selected_app: String,      // last clicked app, empty if none
        problem: String,           // one-line problem report, empty if none
        skipped: usize,            // saved lines skipped at start-up
        remember: bool,
    }

    static UI: Mutex<Ui> = Mutex::new(Ui {
        apps: Vec::new(),
        active_names: Vec::new(),
        selected_app: String::new(),
        problem: String::new(),
        skipped: 0,
        remember: true,
    });
    static HANDLES: [AtomicIsize; 10] = [const { AtomicIsize::new(0) }; 10];

    fn control(id: usize) -> Handle {
        HANDLES[id - ID_SEARCH].load(SeqCst)
    }

    fn send(hwnd: Handle, message: u32, wparam: usize, lparam: isize) -> isize {
        // SAFETY: hwnd is a window of this thread; callers pass pointers in lparam only to data that outlives the call.
        unsafe { SendMessageW(hwnd, message, wparam, lparam) }
    }

    fn set_text(hwnd: Handle, text: &str) {
        let text = wide(text);
        // SAFETY: text is NUL-terminated and outlives the call.
        unsafe { SetWindowTextW(hwnd, text.as_ptr()) };
    }

    fn get_text(hwnd: Handle) -> String {
        let mut buffer = [0u16; 64];
        // SAFETY: buffer holds the 64 units passed as the maximum.
        let length = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), 64) };
        String::from_utf16_lossy(&buffer[..length.max(0) as usize])
    }

    fn set_enabled(hwnd: Handle, enabled: bool) {
        // SAFETY: plain call on a window handle.
        unsafe { EnableWindow(hwnd, enabled as i32) };
    }

    fn list_add(list: Handle, text: &str) {
        let text = wide(text);
        send(list, LB_ADDSTRING, 0, text.as_ptr() as isize);
    }

    fn rate_text(kbps: u64) -> String {
        if kbps == 0 { "-".to_string() } else { kbps.to_string() }
    }

    // Empty field = unlimited (0); None if a field is not a number.
    fn read_rates() -> Option<(u64, u64)> {
        let parse = |text: String| if text.is_empty() { Some(0) } else { text.parse::<u64>().ok() };
        Some((parse(get_text(control(ID_DOWN)))?, parse(get_text(control(ID_UP)))?))
    }

    fn set_problem(text: &str) {
        UI.lock().unwrap().problem = text.to_string();
    }

    // --- List refresh ---

    fn refresh_apps() {
        let filter = get_text(control(ID_SEARCH)).to_lowercase();
        let hide_protected = send(control(ID_HIDE_PROTECTED), BM_GETCHECK, 0, 0) == BST_CHECKED;
        let shown = |name: &String| name.contains(&filter) && !(hide_protected && is_protected(name, own_exe_name()));
        let names: Vec<String> = running_app_names().into_iter().filter(shown).collect();
        let selected = {
            let mut ui = UI.lock().unwrap();
            if ui.apps == names {
                return;
            }
            ui.apps = names.clone();
            ui.selected_app.clone()
        };
        let list = control(ID_APP_LIST);
        let top = send(list, LB_GETTOPINDEX, 0, 0);
        send(list, LB_RESETCONTENT, 0, 0);
        for (index, name) in names.iter().enumerate() {
            list_add(list, name);
            if *name == selected {
                send(list, LB_SETCURSEL, index, 0);
            }
        }
        send(list, LB_SETTOPINDEX, top as usize, 0);
    }

    fn refresh_active() {
        let settings = LIMITS.lock().unwrap().settings();
        let selected = UI.lock().unwrap().selected_app.clone();
        let list = control(ID_ACTIVE_LIST);
        send(list, LB_RESETCONTENT, 0, 0);
        for (index, setting) in settings.iter().enumerate() {
            list_add(list, &format!("{}\tdown {}\tup {}", setting.name, rate_text(setting.down_kbps), rate_text(setting.up_kbps)));
            if setting.name == selected {
                send(list, LB_SETCURSEL, index, 0);
            }
        }
        UI.lock().unwrap().active_names = settings.into_iter().map(|setting| setting.name).collect();
    }

    fn refresh_buttons() {
        let has_app = !UI.lock().unwrap().selected_app.is_empty();
        let rates_ok = read_rates().is_some_and(|(down, up)| rates_are_valid(down, up));
        set_enabled(control(ID_APPLY), has_app && rates_ok);
        set_enabled(control(ID_REMOVE), send(control(ID_ACTIVE_LIST), LB_GETCURSEL, 0, 0) != LB_ERR);
    }

    fn refresh_status() {
        let count = LIMITS.lock().unwrap().count();
        let (problem, skipped) = {
            let ui = UI.lock().unwrap();
            (ui.problem.clone(), ui.skipped)
        };
        let noun = if count == 1 { "limit" } else { "limits" };
        let text = if !problem.is_empty() {
            problem
        } else if NET_PROBLEM.load(SeqCst) {
            TEXT_NET_HANDLE_FAILED.to_string()
        } else if skipped > 0 {
            format!("{TEXT_STATUS_RUNNING} {count} {noun} active. {skipped} saved lines skipped.")
        } else {
            format!("{TEXT_STATUS_RUNNING} {count} {noun} active.")
        };
        set_text(control(ID_STATUS), &text);
    }

    // After every Apply, Remove or switch change: save if asked to, then redraw.
    fn finish_change() {
        let remember = UI.lock().unwrap().remember;
        let saved = !remember || save_limits(true);
        set_problem(if saved { "" } else { TEXT_SAVE_FAILED });
        refresh_active();
        refresh_buttons();
        refresh_status();
    }

    // --- Actions ---

    fn on_apply() {
        let name = UI.lock().unwrap().selected_app.clone();
        let Some((down_kbps, up_kbps)) = read_rates() else { return };
        if name.is_empty() || !rates_are_valid(down_kbps, up_kbps) {
            return;
        }
        if is_protected(&name, own_exe_name()) {
            set_problem(TEXT_PROTECTED);
            return refresh_status();
        }
        match apply_limit(&LimitSetting { name, down_kbps, up_kbps }) {
            Ok(()) => finish_change(),
            Err(SetError::Full) => {
                set_problem(TEXT_TOO_MANY);
                refresh_status();
            }
        }
    }

    fn on_remove() {
        let row = send(control(ID_ACTIVE_LIST), LB_GETCURSEL, 0, 0);
        let name = UI.lock().unwrap().active_names.get(row as usize).cloned();
        if let Some(name) = name {
            remove_limit(&name);
            finish_change();
        }
    }

    fn on_app_clicked() {
        let row = send(control(ID_APP_LIST), LB_GETCURSEL, 0, 0);
        let mut ui = UI.lock().unwrap();
        if let Some(name) = ui.apps.get(row as usize).cloned() {
            ui.selected_app = name;
        }
        drop(ui);
        send(control(ID_ACTIVE_LIST), LB_SETCURSEL, usize::MAX, 0);
        refresh_buttons();
    }

    fn on_active_clicked() {
        let row = send(control(ID_ACTIVE_LIST), LB_GETCURSEL, 0, 0);
        let Some(name) = UI.lock().unwrap().active_names.get(row as usize).cloned() else { return };
        UI.lock().unwrap().selected_app = name.clone();
        send(control(ID_APP_LIST), LB_SETCURSEL, usize::MAX, 0);
        let settings = LIMITS.lock().unwrap().settings(); // lock released before any window call
        if let Some(setting) = settings.into_iter().find(|setting| setting.name == name) {
            set_text(control(ID_DOWN), &if setting.down_kbps == 0 { String::new() } else { setting.down_kbps.to_string() });
            set_text(control(ID_UP), &if setting.up_kbps == 0 { String::new() } else { setting.up_kbps.to_string() });
        }
        refresh_buttons();
    }

    // F13 to F15: ticking saves the current limits, unticking leaves only the switch line.
    fn on_remember() {
        let remember = send(control(ID_REMEMBER), BM_GETCHECK, 0, 0) == BST_CHECKED;
        UI.lock().unwrap().remember = remember;
        let saved = save_limits(remember);
        set_problem(if saved { "" } else { TEXT_SAVE_FAILED });
        refresh_status();
    }

    fn on_command(id: usize, code: usize) {
        match (id, code) {
            (ID_SEARCH, EN_CHANGE) | (ID_HIDE_PROTECTED, BN_CLICKED) => refresh_apps(),
            (ID_DOWN | ID_UP, EN_CHANGE) => refresh_buttons(),
            (ID_APP_LIST, LBN_SELCHANGE) => on_app_clicked(),
            (ID_ACTIVE_LIST, LBN_SELCHANGE) => on_active_clicked(),
            (ID_APPLY, BN_CLICKED) => on_apply(),
            (ID_REMOVE, BN_CLICKED) => on_remove(),
            (ID_REMEMBER, BN_CLICKED) => on_remember(),
            _ => {}
        }
    }

    extern "system" fn window_proc(hwnd: Handle, message: u32, wparam: usize, lparam: isize) -> isize {
        match message {
            WM_COMMAND => {
                on_command(wparam & 0xFFFF, (wparam >> 16) & 0xFFFF);
                0
            }
            WM_TIMER => {
                refresh_apps();
                refresh_status();
                0
            }
            WM_DESTROY => {
                // SAFETY: plain call; ends the message loop in run().
                unsafe { PostQuitMessage(0) };
                0
            }
            // SAFETY: forwards the message unchanged to the default handler.
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    // --- Creation and message loop ---

    fn create(class: &str, text: &str, style: u32, ex_style: u32, rect: (i32, i32, i32, i32), parent: Handle, menu: Handle, instance: Handle) -> Handle {
        let (class, text) = (wide(class), wide(text));
        // SAFETY: class and text are NUL-terminated and outlive the call; no creation parameter is passed.
        unsafe { CreateWindowExW(ex_style, class.as_ptr(), text.as_ptr(), style, rect.0, rect.1, rect.2, rect.3, parent, menu, instance, null_mut()) }
    }

    fn build_controls(parent: Handle, instance: Handle) {
        // SAFETY: GetStockObject has no preconditions.
        let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
        for item in &CONTROLS {
            let handle = create(item.class, item.text, item.style, item.ex_style, item.rect, parent, item.id as Handle, instance);
            send(handle, WM_SETFONT, font as usize, 1);
            if item.id != ID_NONE {
                HANDLES[item.id - ID_SEARCH].store(handle, SeqCst);
            }
        }
    }

    fn pump_message(window: Handle, message: &mut Message) {
        // SAFETY: message was filled in by GetMessageW.
        let handled = unsafe { IsDialogMessageW(window, message) } != 0;
        if !handled {
            // SAFETY: message was filled in by GetMessageW.
            unsafe { TranslateMessage(message) };
            // SAFETY: as above.
            unsafe { DispatchMessageW(message) };
        }
    }

    // Shows the window and runs the message loop until the window is closed.
    pub fn run(remember: bool, skipped: usize) {
        {
            let mut ui = UI.lock().unwrap();
            ui.remember = remember;
            ui.skipped = skipped;
        }
        // SAFETY: NULL asks for the handle of this .exe.
        let instance = unsafe { GetModuleHandleW(null()) };
        let class_name = wide("TinyLimitWindow");
        // SAFETY: IDC_ARROW is a predefined cursor id passed as a pseudo-pointer, as Windows documents.
        let cursor = unsafe { LoadCursorW(0, IDC_ARROW as *const u16) };
        let class = WindowClass {
            style: 0,
            window_proc,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: 0,
            cursor,
            background: COLOR_BTNFACE + 1,
            menu_name: null(),
            class_name: class_name.as_ptr(),
        };
        // SAFETY: class and class_name are valid for the call.
        unsafe { RegisterClassW(&class) };
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
        let mut frame = [0, 0, CLIENT_SIZE.0, CLIENT_SIZE.1];
        // SAFETY: frame is four i32 (a RECT) and style has no menu, so Windows only widens the rectangle by the frame.
        unsafe { AdjustWindowRect(frame.as_mut_ptr(), style, 0) };
        let rect = (i32::MIN, i32::MIN, frame[2] - frame[0], frame[3] - frame[1]); // i32::MIN is CW_USEDEFAULT
        let hwnd = create("TinyLimitWindow", TEXT_TITLE, style, 0, rect, 0, 0, instance);
        build_controls(hwnd, instance);
        send(control(ID_REMEMBER), BM_SETCHECK, remember as usize, 0);
        send(control(ID_HIDE_PROTECTED), BM_SETCHECK, 1, 0);
        send(control(ID_ACTIVE_LIST), LB_SETTABSTOPS, 2, [150, 230].as_ptr() as isize); // columns, in dialog units
        // SAFETY: a NULL callback delivers WM_TIMER to window_proc.
        unsafe { SetTimer(hwnd, TIMER_REFRESH, 2000, null()) };
        refresh_apps();
        refresh_active();
        refresh_buttons();
        refresh_status();
        let mut message = Message::default();
        // SAFETY: message is a valid, writable MSG.
        while unsafe { GetMessageW(&mut message, 0, 0, 0) } > 0 {
            pump_message(hwnd, &mut message);
        }
    }
}

// ============================================================================
// 7. main
// ============================================================================
// Shows the one F12 message box and exits.
#[cfg(windows)]
fn fail_to_start(error_code: u32) -> ! {
    let text = ffi::wide(&format!("Windows error {error_code}: {}", cause_text(error_code)));
    let title = ffi::wide(TEXT_ERROR_TITLE);
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe { ffi::MessageBoxW(0, text.as_ptr(), title.as_ptr(), ffi::MB_OK | ffi::MB_ICONERROR) };
    std::process::exit(1)
}

#[cfg(windows)]
fn main() {
    let own_exe_name = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| normalize_name(&name.to_string_lossy())))
        .unwrap_or_default();
    let divert = match ffi::load_divert(&engine::divert_dll_path().to_string_lossy()) {
        Ok(divert) => divert,
        Err(error_code) => fail_to_start(error_code),
    };
    engine::init(divert, own_exe_name);
    let flow_handle = match engine::open_flow_handle() {
        Ok(handle) => handle,
        Err(error_code) => fail_to_start(error_code),
    };
    let saved = engine::load_saved_limits();
    engine::restore_limits(&saved.settings);
    engine::start_threads(flow_handle);
    window::run(saved.remember, saved.skipped);
    engine::exit_cleanly();
}

#[cfg(not(windows))]
fn main() {
    println!("Windows only");
}

// ============================================================================
// 8. Unit tests for section 3
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "tinylimit.exe";

    fn setting(name: &str, down_kbps: u64, up_kbps: u64) -> LimitSetting {
        LimitSetting { name: name.to_string(), down_kbps, up_kbps }
    }

    #[test]
    fn stream_at_twice_the_limit_is_released_at_the_limit() {
        let rate = 1_000_000u64;
        let mut budget = Budget::new(rate, 0);
        let packet_len = 1500u64;
        let gap_ns = packet_len * NS_PER_SECOND / (2 * rate);
        let mut released_bytes = 0u64;
        let mut now = 0u64;
        while now < 10 * NS_PER_SECOND {
            match budget.charge(packet_len, now) {
                Verdict::PassNow => released_bytes += packet_len,
                Verdict::DelayTo(release_at) if release_at < 10 * NS_PER_SECOND => released_bytes += packet_len,
                _ => {}
            }
            now += gap_ns;
        }
        let expected = rate * 10;
        let error = released_bytes.abs_diff(expected) as f64 / expected as f64;
        assert!(error < 0.02, "released {released_bytes}, expected about {expected}");
    }

    #[test]
    fn delayed_packets_keep_arrival_order() {
        let mut budget = Budget::new(100_000, 0);
        let mut last_release = 0u64;
        for arrival in 0..50u64 {
            let now = arrival * 1_000_000;
            let release = match budget.charge(1000, now) {
                Verdict::PassNow => now,
                Verdict::DelayTo(t) => t,
                Verdict::Drop => continue,
            };
            assert!(release >= last_release);
            last_release = release;
        }
    }

    #[test]
    fn packet_over_one_second_late_is_dropped_and_budget_unchanged() {
        let mut budget = Budget::new(1000, 0);
        budget.next_ns = 5 * NS_PER_SECOND;
        let before = budget.next_ns;
        assert_eq!(budget.charge(1500, 0), Verdict::Drop);
        assert_eq!(budget.next_ns, before);
    }

    #[test]
    fn idle_budget_lets_at_most_fifty_milliseconds_through_at_once() {
        let rate = 1_000_000u64;
        let mut budget = Budget::new(rate, 0);
        let now = 100 * NS_PER_SECOND;
        let mut immediate_bytes = 0u64;
        for _ in 0..1000 {
            if budget.charge(1000, now) == Verdict::PassNow {
                immediate_bytes += 1000;
            }
        }
        let burst_limit = rate * BURST_NS / NS_PER_SECOND;
        assert!(immediate_bytes <= burst_limit + 1000, "{immediate_bytes} bytes passed at once");
        assert!(immediate_bytes >= burst_limit / 2);
    }

    #[test]
    fn queued_bytes_stay_near_one_second_of_traffic() {
        let rate = 100_000u64;
        let mut budget = Budget::new(rate, 0);
        let mut accepted_bytes = 0u64;
        for _ in 0..10_000 {
            if budget.charge(1500, 0) != Verdict::Drop {
                accepted_bytes += 1500;
            }
        }
        assert!(accepted_bytes <= rate * (MAX_DELAY_NS + BURST_NS) / NS_PER_SECOND + 1500);
    }

    #[test]
    fn rate_zero_always_passes() {
        let mut budget = Budget::new(0, 0);
        for step in 0..100u64 {
            assert_eq!(budget.charge(65_535, step), Verdict::PassNow);
        }
    }

    #[test]
    fn port_index_is_unique_and_in_range() {
        let mut seen = vec![false; PORT_TABLE_SIZE];
        for is_ipv6 in [false, true] {
            for is_udp in [false, true] {
                for port in 0..=u16::MAX {
                    let index = port_index(is_ipv6, is_udp, port);
                    assert!(index < PORT_TABLE_SIZE);
                    assert!(!seen[index]);
                    seen[index] = true;
                }
            }
        }
    }

    #[test]
    fn name_rules() {
        assert_eq!(normalize_name("Chrome.EXE"), "chrome.exe");
        assert!(is_protected("SVCHOST.exe", OWN));
        assert!(is_protected("System", OWN));
        assert!(is_protected("[System Process]", OWN));
        assert!(is_protected("TinyLimit.exe", OWN));
        assert!(!is_protected("chrome.exe", OWN));
        assert!(!is_protected("svchost.exe.bak", OWN));
        let mut limits = Limits::new();
        limits.set(&setting("Chrome.exe", 5, 0), 0).unwrap();
        assert_ne!(limits.slot_of("CHROME.EXE"), 0);
        assert_eq!(limits.slot_of("chrome.ex"), 0);
        assert_eq!(limits.slot_of("xchrome.exe"), 0);
    }

    #[test]
    fn rate_rules() {
        assert!(rates_are_valid(1, 0));
        assert!(rates_are_valid(0, 4_000_000));
        assert!(!rates_are_valid(0, 0));
        assert!(!rates_are_valid(4_000_001, 0));
    }

    #[test]
    fn limits_file_round_trips() {
        let settings = vec![setting("chrome.exe", 500, 200), setting("some app.exe", 0, 100)];
        let text = format_limits_file(true, &settings);
        assert_eq!(text, "remember on\n500 200 chrome.exe\n0 100 some app.exe\n");
        let parsed = parse_limits_file(&text, OWN);
        assert!(parsed.remember);
        assert_eq!(parsed.settings, settings);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn limits_file_skips_each_kind_of_bad_line() {
        let text = "remember on\n\
            500 200 chrome.exe\n\
            garbage\n\
            x 5 bad.exe\n\
            0 0 zero.exe\n\
            4000001 0 big.exe\n\
            5 5 svchost.exe\n\
            5 5 TinyLimit.exe\n\
            9 9 CHROME.exe\n\
            7 7 \n";
        let parsed = parse_limits_file(text, OWN);
        assert_eq!(parsed.settings, vec![setting("chrome.exe", 500, 200)]);
        assert_eq!(parsed.skipped, 8);
    }

    #[test]
    fn limits_file_skips_lines_after_the_255th() {
        let mut text = String::from("remember on\n");
        for number in 0..256 {
            text.push_str(&format!("1 1 app{number}.exe\n"));
        }
        let parsed = parse_limits_file(&text, OWN);
        assert_eq!(parsed.settings.len(), 255);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn remember_off_loads_no_limits_and_holds_one_line() {
        assert_eq!(format_limits_file(false, &[setting("a.exe", 1, 1)]), "remember off\n");
        let parsed = parse_limits_file("remember off\n5 5 chrome.exe\n", OWN);
        assert!(!parsed.remember);
        assert!(parsed.settings.is_empty());
        let empty = parse_limits_file("", OWN);
        assert!(empty.remember && empty.settings.is_empty());
    }

    #[test]
    fn limits_table_add_replace_remove_reuse_and_refuse() {
        let mut limits = Limits::new();
        let first = limits.set(&setting("a.exe", 10, 0), 0).unwrap();
        let second = limits.set(&setting("b.exe", 10, 0), 0).unwrap();
        assert_eq!((first, second), (1, 2));
        assert_eq!(limits.set(&setting("A.exe", 20, 5), 0).unwrap(), first);
        assert_eq!(limits.count(), 2);
        limits.remove(first);
        assert_eq!(limits.slot_of("a.exe"), 0);
        assert_eq!(limits.set(&setting("c.exe", 1, 0), 0).unwrap(), first);
        for number in 3..=MAX_LIMITS {
            limits.set(&setting(&format!("app{number}.exe"), 1, 0), 0).unwrap();
        }
        assert_eq!(limits.count(), MAX_LIMITS);
        assert_eq!(limits.set(&setting("one-too-many.exe", 1, 0), 0), Err(SetError::Full));
        assert_eq!(limits.set(&setting("c.exe", 9, 0), 0).unwrap(), first);
    }

    #[test]
    fn changing_a_rate_resets_only_that_budget() {
        let mut limits = Limits::new();
        let slot = limits.set(&setting("a.exe", 1, 1), 0).unwrap();
        limits.charge(slot, false, 100_000, 0);
        limits.charge(slot, true, 100_000, 0);
        limits.set(&setting("a.exe", 1, 2), 77).unwrap();
        let limit = limits.slots[slot as usize].as_ref().unwrap();
        assert!(limit.down.next_ns > 77);
        assert_eq!(limit.up.next_ns, 77);
    }
}
