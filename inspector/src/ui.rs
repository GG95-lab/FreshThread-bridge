//! Native text UI. No console host, WebView, admin mode or persistent observer.
use super::{
    model::{Connection, Group, grouped_rows, private_path, restore_selection, safe_text},
    names, process, snapshot,
};
use std::time::Instant;
use windows::{
    Win32::{
        Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::*,
        System::{LibraryLoader::GetModuleHandleW, SystemInformation::GetLocalTime},
        UI::{Controls::*, HiDpi::*, Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
    },
    core::{PCWSTR, w},
};

const BACKGROUND: COLORREF = COLORREF(0x00171311);
const BLUE: COLORREF = COLORREF(0x00f0b98f);
const MUTED: COLORREF = COLORREF(0x00ba9781);
const HELP: &str = "Shows the current Windows TCP connections and local UDP endpoints for matched programs in this Windows session.\r\n\r\nShort connections between samples, exited processes and inaccessible processes may be missed. A local UDP endpoint does not identify its destination.\r\n\r\nAddresses do not identify the request's purpose. WebView2 is a Microsoft runtime and can carry app requests. Codex traffic does not establish that FreshThread initiated it.\r\n\r\nNames are hints from the local Windows DNS cache; shared IPs do not prove a hostname. No payload reading, network DNS lookups, uploads or saved history. Closing this window stops observation. Pause stops sampling.";

struct View {
    summary: HWND,
    header: HWND,
    list: HWND,
    detail: HWND,
    footer: HWND,
    font: HFONT,
    summary_font: HFONT,
    rows: Vec<Connection>,
    display_rows: Vec<Option<usize>>,
    groups: Vec<Vec<usize>>,
    names: names::Reader,
    selected: usize,
    paused: bool,
    help: bool,
    status: String,
    time: String,
    started: Instant,
    dpi: u32,
}
impl Drop for View {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(self.font.into());
            let _ = DeleteObject(self.summary_font.into());
        }
    }
}

fn text(hwnd: HWND, value: &str) {
    unsafe {
        let _ = SetWindowTextW(hwnd, PCWSTR(process::wide(value).as_ptr()));
    }
}
fn clock() -> String {
    let t = unsafe { GetLocalTime() };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}
fn field(value: &str, width: usize) -> String {
    if value.chars().count() > width && width > 0 {
        format!("{}…", safe_text(value, width - 1))
    } else {
        safe_text(value, width)
    }
}
fn row_label(row: &Connection, width: usize, cache: &names::Cache) -> String {
    let destination = if row.protocol.starts_with("UDP") {
        &row.local
    } else {
        &row.remote
    };
    let hint = row.remote_ip().and_then(|ip| cache.entries.get(&ip));
    let destination = if !row.local_only() {
        hint.and_then(|names| names.first())
            .map(|name| {
                format!(
                    "{name}{}",
                    if hint.unwrap().len() > 1 {
                        " (+names)"
                    } else {
                        " (cached)"
                    }
                )
            })
            .unwrap_or_else(|| destination.clone())
    } else {
        row.local.clone()
    };
    let state = if row.this_pc_only() {
        "this PC only"
    } else if row.state == "listen" {
        "waiting"
    } else if row.protocol.starts_with("UDP") {
        "target unknown"
    } else {
        "connection"
    };
    format!(
        "{}  {}  {}",
        field(row.identity.group.label(), 13),
        field(&destination, width.saturating_sub(33).max(8)),
        field(state, 14)
    )
}
impl View {
    fn selected_group(&self) -> Option<&Vec<usize>> {
        self.groups
            .iter()
            .find(|group| group.contains(&self.selected))
    }
    fn group_label(&self, index: usize, width: usize) -> String {
        let row = &self.rows[index];
        let Some(group) = self
            .groups
            .iter()
            .find(|group| group.first() == Some(&index))
        else {
            return row_label(row, width, &self.names.cache);
        };
        let mut destinations = std::collections::BTreeSet::new();
        for i in group {
            let row = &self.rows[*i];
            if row.remote_tcp() {
                let hint = row
                    .remote_ip()
                    .and_then(|ip| self.names.cache.entries.get(&ip));
                destinations.insert(match hint {
                    Some(names) if names.len() == 1 => format!("{} (name hint)", names[0]),
                    _ => row.remote.clone(),
                });
            }
        }
        let destination = match destinations.len() {
            0 if group.iter().all(|i| self.rows[*i].this_pc_only()) => "This PC only".into(),
            0 => "No remote destination identified".into(),
            1 => destinations.into_iter().next().unwrap(),
            count => format!("{count} destinations"),
        };
        let count = group.len();
        let suffix = if group
            .iter()
            .any(|i| self.rows[*i].protocol.starts_with("UDP") || self.rows[*i].state == "listen")
        {
            if count == 1 { "entry" } else { "entries" }
        } else {
            if count == 1 {
                "connection"
            } else {
                "connections"
            }
        };
        let prefix = format!("{} → ", row.identity.group.label());
        let ending = format!(" ({count} {suffix})");
        format!(
            "{prefix}{}{ending}",
            field(
                &destination,
                width
                    .saturating_sub(prefix.chars().count() + ending.len())
                    .max(4)
            )
        )
    }
    fn px(&self, n: i32) -> i32 {
        (n as i64 * self.dpi as i64 / 96) as i32
    }
    fn details(&self) {
        if self.help {
            text(self.detail, HELP);
            return;
        }
        let Some(row) = self.rows.get(self.selected) else {
            text(
                self.detail,
                "No matching endpoint is visible in this sample.\r\nThis does not establish that there was no earlier activity.",
            );
            return;
        };
        let meaning = match row.identity.group {
            Group::FreshThread => "FreshThread program",
            Group::WebView => "Related WebView2 runtime; may carry app requests",
            Group::Codex => "Codex; request origin is not established",
            Group::Related => "Related child process; purpose is not established",
        };
        let cached = row
            .remote_ip()
            .and_then(|ip| self.names.cache.entries.get(&ip))
            .map(|names| names.join(", "))
            .unwrap_or_else(|| "No matching name in the sampled local cache".into());
        let scope = if row.this_pc_only() {
            "Local only — only this PC can connect"
        } else if row.state == "listen" {
            "Waiting for connections; may accept other devices, depending on firewall settings"
        } else if row.local_only() {
            "No remote destination identified"
        } else if row.protocol.starts_with("UDP") {
            "UDP local endpoint; destination is not available"
        } else {
            "Remote TCP connection; direction and purpose are not identified"
        };
        text(
            self.detail,
            &format!(
                "{meaning} · {}\r\n{scope}\r\nProgram   {}\r\nLocal     {}\r\nRemote    {}\r\nProtocol  {}    PID {}    State {}\r\nName hints: {cached}\r\nNames are not proof of the destination. Enter: next connection.",
                self.selected_group()
                    .map(|g| format!(
                        "connection {} of {}",
                        g.iter().position(|i| *i == self.selected).unwrap_or(0) + 1,
                        g.len()
                    ))
                    .unwrap_or_default(),
                private_path(&row.identity.path),
                row.local,
                row.remote,
                row.protocol,
                row.identity.pid,
                row.state
            ),
        );
    }
    fn paint_rows(&self) {
        let mut rect = RECT::default();
        unsafe {
            let _ = GetClientRect(self.list, &mut rect);
        }
        let width = ((rect.right - rect.left) / self.px(8).max(1)).max(40) as usize;
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, Some(WPARAM(0)), None);
            SendMessageW(self.list, LB_RESETCONTENT, None, None);
            for row_index in &self.display_rows {
                let label = row_index
                    .map(|index| self.group_label(index, width))
                    .unwrap_or_else(|| "── Not FreshThread · related programs ──".into());
                let value = process::wide(&label);
                let item = SendMessageW(
                    self.list,
                    LB_ADDSTRING,
                    None,
                    Some(LPARAM(value.as_ptr() as isize)),
                )
                .0;
                let style = row_index
                    .map(|i| {
                        if self.rows[i].identity.group == Group::FreshThread {
                            0
                        } else {
                            2
                        }
                    })
                    .unwrap_or(1);
                SendMessageW(
                    self.list,
                    LB_SETITEMDATA,
                    Some(WPARAM(item as usize)),
                    Some(LPARAM(style)),
                );
            }
            let selection = self
                .display_rows
                .iter()
                .position(|i| {
                    *i == self
                        .selected_group()
                        .and_then(|g| g.first().copied())
                        .or(Some(self.selected))
                })
                .unwrap_or(usize::MAX);
            SendMessageW(self.list, LB_SETCURSEL, Some(WPARAM(selection)), None);
            SendMessageW(self.list, WM_SETREDRAW, Some(WPARAM(1)), None);
            let _ = InvalidateRect(Some(self.list), None, true);
        }
        self.details();
    }
    fn header(&self) {
        let own = self
            .rows
            .iter()
            .filter(|r| r.identity.group == Group::FreshThread && r.remote_tcp())
            .count();
        let mode = if self.paused { "PAUSED" } else { "WATCHING" };
        let summary = if !self.status.is_empty() {
            "FreshThread activity: observation incomplete".into()
        } else if self.paused {
            "Observation paused — showing the last sample".into()
        } else if own == 0 {
            "No external FreshThread connections observed".into()
        } else {
            format!(
                "FreshThread: {own} external connection{} observed",
                if own == 1 { "" } else { "s" }
            )
        };
        text(self.summary, &summary);
        unsafe {
            SetWindowLongPtrW(
                self.summary,
                GWLP_USERDATA,
                isize::from(self.status.is_empty() && !self.paused && own == 0),
            );
        }
        text(
            self.header,
            &format!(
                "FRESHTHREAD · NETWORK ACTIVITY   {mode}\r\nSample {} · Open {}s  {}\r\nPROGRAM / OBSERVED DESTINATIONS",
                self.time,
                self.started.elapsed().as_secs(),
                self.status
            ),
        );
    }
    fn sample(&mut self) {
        if self.paused {
            return;
        }
        let previous = self.rows.get(self.selected).cloned();
        self.status.clear();
        let processes = match process::collect() {
            Ok(p) => p,
            Err(_) => {
                self.status = "Partial view: process list unavailable".into();
                Default::default()
            }
        };
        let (mut rows, errors) = snapshot::collect(&processes);
        if !errors.is_empty() {
            self.status = "Partial view: some tables unavailable".into();
        }
        rows.sort_by(|a, b| {
            (
                a.identity.group != Group::FreshThread,
                a.identity.pid,
                &a.protocol,
                &a.remote,
                &a.local,
            )
                .cmp(&(
                    b.identity.group != Group::FreshThread,
                    b.identity.pid,
                    &b.protocol,
                    &b.remote,
                    &b.local,
                ))
        });
        // Bounded UI/memory; disclose truncation instead of presenting it as complete.
        if rows.len() > 2048 {
            rows.truncate(2048);
            self.status = "Showing first 2048 endpoints".into();
        }
        self.time = clock();
        let names_changed = self.names.update(
            rows.iter()
                .filter(|r| r.remote_tcp())
                .filter_map(Connection::remote_ip)
                .collect(),
        );
        let rows_changed = rows != self.rows;
        if rows_changed {
            self.selected = restore_selection(&rows, previous.as_ref());
            self.rows = rows;
        }
        self.display_rows.clear();
        self.groups = grouped_rows(&self.rows);
        let mut related_header = false;
        for group in &self.groups {
            let index = group[0];
            let row = &self.rows[index];
            if row.identity.group != Group::FreshThread && !related_header {
                self.display_rows.push(None);
                related_header = true;
            }
            self.display_rows.push(Some(index));
        }
        // Refresh detail timestamps even when the connection rows are unchanged.
        if names_changed || rows_changed {
            self.paint_rows();
        } else {
            self.details();
        }
        self.header();
    }
    fn layout(&mut self, hwnd: HWND) {
        unsafe {
            let dpi = GetDpiForWindow(hwnd).max(96);
            if dpi != self.dpi || self.font.is_invalid() {
                let font = CreateFontW(
                    -((14 * dpi / 96) as i32),
                    0,
                    0,
                    0,
                    400,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    FIXED_PITCH.0 as u32,
                    w!("Consolas"),
                );
                if !font.is_invalid() {
                    for control in [self.header, self.list, self.detail, self.footer] {
                        SendMessageW(
                            control,
                            WM_SETFONT,
                            Some(WPARAM(font.0 as usize)),
                            Some(LPARAM(1)),
                        );
                    }
                    if !self.font.is_invalid() {
                        let _ = DeleteObject(self.font.into());
                    }
                    self.font = font;
                }
                let summary_font = CreateFontW(
                    -((16 * dpi / 96) as i32),
                    0,
                    0,
                    0,
                    700,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    FIXED_PITCH.0 as u32,
                    w!("Consolas"),
                );
                if !summary_font.is_invalid() {
                    SendMessageW(
                        self.summary,
                        WM_SETFONT,
                        Some(WPARAM(summary_font.0 as usize)),
                        Some(LPARAM(1)),
                    );
                    if !self.summary_font.is_invalid() {
                        let _ = DeleteObject(self.summary_font.into());
                    }
                    self.summary_font = summary_font;
                }
                self.dpi = dpi;
                SendMessageW(
                    self.list,
                    LB_SETITEMHEIGHT,
                    Some(WPARAM(0)),
                    Some(LPARAM(self.px(21) as isize)),
                );
            }
            let mut r = RECT::default();
            let _ = GetClientRect(hwnd, &mut r);
            let margin = self.px(18);
            let width = (r.right - margin * 2).max(1);
            let head = self.px(102);
            let foot = self.px(70);
            let detail = self.px(180);
            let list = (r.bottom - margin * 2 - head - foot - detail).max(1);
            let summary_height = self.px(30);
            let _ = MoveWindow(self.summary, margin, margin, width, summary_height, true);
            let _ = MoveWindow(
                self.header,
                margin,
                margin + summary_height,
                width,
                head - summary_height,
                true,
            );
            let _ = MoveWindow(self.list, margin, margin + head, width, list, true);
            let _ = MoveWindow(
                self.detail,
                margin,
                margin + head + list,
                width,
                detail,
                true,
            );
            let _ = MoveWindow(
                self.footer,
                margin,
                (r.bottom - margin - foot).max(0),
                width,
                foot,
                true,
            );
            self.paint_rows();
        }
    }
}

unsafe extern "system" fn procedure(hwnd: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // Reentrant paint/DPI/destruction messages never borrow View. Control APIs
    // can synchronously send these while a sampling/layout borrow is active.
    match message {
        WM_MEASUREITEM => unsafe {
            let item = &mut *(lp.0 as *mut MEASUREITEMSTRUCT);
            item.itemHeight = 21 * GetDpiForWindow(hwnd).max(96) / 96;
            return LRESULT(1);
        },
        WM_DRAWITEM => unsafe {
            let item = &*(lp.0 as *const DRAWITEMSTRUCT);
            if item.itemID == u32::MAX {
                return LRESULT(1);
            }
            let style = item.itemData;
            let selected = item.itemState.0 & ODS_SELECTED.0 != 0 && style != 1;
            let background = if selected {
                COLORREF(0x00432c1c)
            } else {
                BACKGROUND
            };
            SetDCBrushColor(item.hDC, background);
            FillRect(item.hDC, &item.rcItem, HBRUSH(GetStockObject(DC_BRUSH).0));
            SetBkColor(item.hDC, background);
            SetTextColor(item.hDC, if style == 0 { BLUE } else { MUTED });
            let font = SendMessageW(item.hwndItem, WM_GETFONT, None, None);
            let old = SelectObject(item.hDC, HGDIOBJ(font.0 as *mut _));
            let length = SendMessageW(
                item.hwndItem,
                LB_GETTEXTLEN,
                Some(WPARAM(item.itemID as usize)),
                None,
            )
            .0;
            if (0..4096).contains(&length) {
                let mut buffer = vec![0u16; length as usize + 1];
                SendMessageW(
                    item.hwndItem,
                    LB_GETTEXT,
                    Some(WPARAM(item.itemID as usize)),
                    Some(LPARAM(buffer.as_mut_ptr() as isize)),
                );
                let mut rect = item.rcItem;
                DrawTextW(
                    item.hDC,
                    &mut buffer[..length as usize],
                    &mut rect,
                    DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS,
                );
            }
            SelectObject(item.hDC, old);
            return LRESULT(1);
        },
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => unsafe {
            let dc = HDC(wp.0 as *mut _);
            let child = HWND(lp.0 as *mut _);
            let color =
                if GetDlgCtrlID(child) == 7001 && GetWindowLongPtrW(child, GWLP_USERDATA) == 1 {
                    COLORREF(0x00a5d79c)
                } else {
                    BLUE
                };
            SetTextColor(dc, color);
            SetBkColor(dc, BACKGROUND);
            SetDCBrushColor(dc, BACKGROUND);
            return LRESULT(GetStockObject(DC_BRUSH).0 as isize);
        },
        WM_ERASEBKGND => unsafe {
            let dc = HDC(wp.0 as *mut _);
            let mut rect = RECT::default();
            let _ = GetClientRect(hwnd, &mut rect);
            SetDCBrushColor(dc, BACKGROUND);
            FillRect(dc, &rect, HBRUSH(GetStockObject(DC_BRUSH).0));
            return LRESULT(1);
        },
        WM_GETMINMAXINFO => unsafe {
            let dpi = GetDpiForWindow(hwnd).max(96);
            let info = &mut *(lp.0 as *mut MINMAXINFO);
            info.ptMinTrackSize.x = (660 * dpi / 96) as i32;
            info.ptMinTrackSize.y = (580 * dpi / 96) as i32;
            return LRESULT(0);
        },
        WM_DPICHANGED => unsafe {
            let r = &*(lp.0 as *const RECT);
            let _ = SetWindowPos(
                hwnd,
                None,
                r.left,
                r.top,
                r.right - r.left,
                r.bottom - r.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            return LRESULT(0);
        },
        WM_CLOSE => unsafe {
            let _ = DestroyWindow(hwnd);
            return LRESULT(0);
        },
        WM_DESTROY => unsafe {
            let _ = KillTimer(Some(hwnd), 1);
            PostQuitMessage(0);
            return LRESULT(0);
        },
        _ => {}
    }
    // Only input/timer/layout messages borrow state; native painting is above.
    let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut View;
    if !ptr.is_null() {
        match message {
            WM_TIMER => {
                unsafe { &mut *ptr }.sample();
                return LRESULT(0);
            }
            WM_SIZE => {
                unsafe { &mut *ptr }.layout(hwnd);
                return LRESULT(0);
            }
            WM_COMMAND if (wp.0 >> 16) as u32 == LBN_SELCHANGE => {
                let view = unsafe { &mut *ptr };
                let n = unsafe { SendMessageW(view.list, LB_GETCURSEL, None, None) }.0;
                if n >= 0 {
                    let mut position = n as usize;
                    if view.display_rows.get(position) == Some(&None) {
                        let old = view
                            .display_rows
                            .iter()
                            .position(|r| {
                                *r == view.selected_group().and_then(|g| g.first().copied())
                            })
                            .unwrap_or(0);
                        position = if position < old && position > 0 {
                            position - 1
                        } else {
                            position + 1
                        };
                        unsafe {
                            SendMessageW(view.list, LB_SETCURSEL, Some(WPARAM(position)), None);
                        }
                    }
                    if let Some(Some(index)) = view.display_rows.get(position) {
                        view.selected = *index;
                    }
                    view.help = false;
                    view.details();
                }
                return LRESULT(0);
            }
            _ => {}
        }
    }
    unsafe { DefWindowProcW(hwnd, message, wp, lp) }
}

pub fn run() -> windows::core::Result<()> {
    run_window(true, |_| {})
}

fn run_window(visible: bool, ready: impl FnOnce(HWND)) -> windows::core::Result<()> {
    unsafe {
        // A separate process; no change to Codex/FreshThread DPI settings.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let instance = GetModuleHandleW(None)?;
        let class = w!("FreshThreadNetworkInspector");
        let registered = RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(procedure),
            hInstance: instance.into(),
            lpszClassName: class,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            ..Default::default()
        });
        if registered == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("FreshThread — Network activity"),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            960,
            680,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        let result = (|| -> windows::core::Result<()> {
            let child = |class: PCWSTR, style: WINDOW_STYLE| {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    class,
                    w!(""),
                    WS_CHILD | WS_VISIBLE | style,
                    0,
                    0,
                    1,
                    1,
                    Some(hwnd),
                    None,
                    Some(instance.into()),
                    None,
                )
            };
            let summary = child(w!("STATIC"), WINDOW_STYLE(0))?;
            SetWindowLongPtrW(summary, GWLP_ID, 7001);
            let header = child(w!("STATIC"), WINDOW_STYLE(0))?;
            let list = child(
                w!("LISTBOX"),
                WS_TABSTOP
                    | WINDOW_STYLE(
                        (LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS)
                            as u32,
                    ),
            )?;
            let detail = child(
                w!("EDIT"),
                WS_TABSTOP | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY) as u32),
            )?;
            let footer = child(w!("STATIC"), WINDOW_STYLE(0))?;
            let mut view = Box::new(View {
                summary,
                header,
                list,
                detail,
                footer,
                font: HFONT::default(),
                summary_font: HFONT::default(),
                rows: Vec::new(),
                display_rows: Vec::new(),
                groups: Vec::new(),
                names: names::Reader::new(),
                selected: 0,
                paused: false,
                help: false,
                status: String::new(),
                time: clock(),
                started: Instant::now(),
                dpi: 96,
            });
            text(
                footer,
                "────────────────────────────────────────────────────────────────\r\n↑↓ select · Enter details / next connection · P pause · ? help · Q close\r\nBrief traffic can be missed. UDP destinations are not shown.",
            );
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (&mut *view as *mut View) as isize);
            view.layout(hwnd);
            view.sample();
            if visible {
                let _ = ShowWindow(hwnd, SW_SHOW);
                let _ = SetFocus(Some(list));
            }
            if SetTimer(Some(hwnd), 1, 1000, None) == 0 {
                let _ = DestroyWindow(hwnd);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                return Err(windows::core::Error::from_thread());
            }
            ready(hwnd);
            let mut msg = MSG::default();
            loop {
                let result = GetMessageW(&mut msg, None, 0, 0).0;
                if result <= 0 {
                    break;
                }
                if msg.message == WM_KEYDOWN {
                    match msg.wParam.0 as u32 {
                        0x51 | 0x1b => {
                            let _ = DestroyWindow(hwnd);
                            continue;
                        }
                        0x50 => {
                            view.paused = !view.paused;
                            view.names.set_paused(view.paused);
                            if view.paused {
                                let _ = KillTimer(Some(hwnd), 1);
                            } else {
                                view.sample();
                                if SetTimer(Some(hwnd), 1, 1000, None) == 0 {
                                    view.paused = true;
                                    view.status = "Sampling timer unavailable".into();
                                }
                            }
                            view.header();
                            continue;
                        }
                        0x70 | 0xbf => {
                            view.help = !view.help;
                            view.details();
                            let _ = SetFocus(Some(detail));
                            continue;
                        }
                        0x0d => {
                            view.help = false;
                            if GetFocus() == detail
                                && let Some(group) = view.selected_group()
                            {
                                let position =
                                    group.iter().position(|i| *i == view.selected).unwrap_or(0);
                                view.selected = group[(position + 1) % group.len()];
                            }
                            view.details();
                            let _ = SetFocus(Some(detail));
                            continue;
                        }
                        0x09 => {
                            let _ = SetFocus(Some(if GetFocus() == list { detail } else { list }));
                            continue;
                        }
                        _ => {}
                    }
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            if IsWindow(Some(hwnd)).as_bool() {
                let _ = DestroyWindow(hwnd);
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            Ok(())
        })();
        if IsWindow(Some(hwnd)).as_bool() {
            let _ = DestroyWindow(hwnd);
        }
        let _ = UnregisterClassW(class, Some(instance.into()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_window_has_no_scrollbars_and_keeps_controls_inside_at_minimum_size() {
        run_window(false, |hwnd| unsafe {
            let dpi = GetDpiForWindow(hwnd).max(96);
            let _ = SetWindowPos(
                hwnd,
                None,
                0,
                0,
                (660 * dpi / 96) as i32,
                (580 * dpi / 96) as i32,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
            let mut parent = RECT::default();
            GetWindowRect(hwnd, &mut parent).unwrap();
            let view = &*(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const View);
            for child in [
                hwnd,
                view.summary,
                view.header,
                view.list,
                view.detail,
                view.footer,
            ] {
                let style = GetWindowLongW(child, GWL_STYLE) as u32;
                assert_eq!(style & (WS_VSCROLL.0 | WS_HSCROLL.0), 0);
                let mut rect = RECT::default();
                GetWindowRect(child, &mut rect).unwrap();
                assert!(rect.left >= parent.left && rect.right <= parent.right);
                assert!(rect.top >= parent.top && rect.bottom <= parent.bottom);
            }
            assert_eq!(
                GetWindowLongW(view.detail, GWL_STYLE) as u32 & ES_AUTOHSCROLL as u32,
                0
            );
            assert_ne!(
                GetWindowLongW(view.detail, GWL_STYLE) as u32 & ES_READONLY as u32,
                0
            );
            let view = &mut *(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut View);
            view.paused = true;
            view.time = "paused fixture".into();
            view.sample();
            assert_eq!(view.time, "paused fixture");
            view.paused = false;
            view.sample();
            assert_ne!(view.time, "paused fixture");
            view.paused = true;
            let row = |group| Connection {
                identity: super::super::model::Identity {
                    pid: 1,
                    started: 1,
                    path: "fixture.exe".into(),
                    group,
                },
                protocol: "TCP4",
                local: "127.0.0.1:1".into(),
                remote: "192.0.2.1:443".into(),
                state: "established".into(),
                bytes: None,
            };
            view.rows = vec![
                row(Group::FreshThread),
                row(Group::Codex),
                row(Group::Codex),
            ];
            view.groups = grouped_rows(&view.rows);
            view.display_rows = vec![Some(0), None, Some(1)];
            view.selected = 0;
            view.paint_rows();
            let list = view.list;
            // Real list selection notifications skip the decorative group row
            // in both directions and keep the detail's model index correct.
            SendMessageW(list, LB_SETCURSEL, Some(WPARAM(1)), None);
            SendMessageW(
                hwnd,
                WM_COMMAND,
                Some(WPARAM((LBN_SELCHANGE as usize) << 16)),
                None,
            );
            let view = &mut *(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut View);
            assert_eq!(view.selected, 1);
            assert_eq!(SendMessageW(list, LB_GETCURSEL, None, None).0, 2);
            // Cycling to a non-representative member must still allow Up to
            // cross the group separator back to FreshThread.
            view.selected = 2;
            SendMessageW(list, LB_SETCURSEL, Some(WPARAM(1)), None);
            SendMessageW(
                hwnd,
                WM_COMMAND,
                Some(WPARAM((LBN_SELCHANGE as usize) << 16)),
                None,
            );
            let view = &mut *(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut View);
            assert_eq!(view.selected, 0);
            assert_eq!(SendMessageW(list, LB_GETCURSEL, None, None).0, 0);
            PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)).unwrap();
        })
        .unwrap();
    }
    #[test]
    fn long_fields_are_explicitly_shortened_not_allowed_to_overrun_columns() {
        assert_eq!(field("abcdef", 4), "abc…");
        assert_eq!(field("abc", 4), "abc ");
        assert_eq!(field("abc", 0), "");
        assert!(!field("a\nb", 5).contains('\n'));
    }
}
