//! Native text UI. No console host, WebView, admin mode or persistent observer.
use super::{
    model::{Connection, Group, safe_text},
    process, snapshot,
};
use std::time::Instant;
use windows::{
    Win32::{
        Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::*,
        System::{LibraryLoader::GetModuleHandleW, SystemInformation::GetLocalTime},
        UI::{HiDpi::*, Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
    },
    core::{PCWSTR, w},
};

const BACKGROUND: COLORREF = COLORREF(0x00171311);
const BLUE: COLORREF = COLORREF(0x00f0b98f);
const HELP: &str = "Shows the current Windows TCP connections and local UDP endpoints for matched programs in this Windows session.\r\n\r\nShort connections between samples, exited processes and inaccessible processes may be missed. A local UDP endpoint does not identify its destination.\r\n\r\nAddresses do not identify the request's purpose. WebView2 is a Microsoft runtime and can carry app requests. Codex traffic does not establish that FreshThread initiated it.\r\n\r\nNo payload reading, DNS lookups, uploads or saved history. Closing this window stops observation. Pause stops sampling.";

struct View {
    header: HWND,
    list: HWND,
    detail: HWND,
    footer: HWND,
    font: HFONT,
    rows: Vec<Connection>,
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
fn row_label(row: &Connection, width: usize) -> String {
    let destination = if row.protocol.starts_with("UDP") {
        &row.local
    } else {
        &row.remote
    };
    format!(
        "{}  {}  {}",
        field(row.identity.group.label(), 13),
        field(destination, width.saturating_sub(30).max(8)),
        field(&row.state, 12)
    )
}
impl View {
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
        text(
            self.detail,
            &format!(
                "{meaning}\r\nProgram   {}\r\nLocal     {}\r\nRemote    {}\r\nProtocol  {}    PID {}    Sample {} (local time)\r\nPurpose   Not identified by this connection snapshot",
                row.identity.path.replace(['\r', '\n'], " "),
                row.local,
                row.remote,
                row.protocol,
                row.identity.pid,
                self.time
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
            for row in &self.rows {
                let value = process::wide(&row_label(row, width));
                SendMessageW(
                    self.list,
                    LB_ADDSTRING,
                    None,
                    Some(LPARAM(value.as_ptr() as isize)),
                );
            }
            SendMessageW(self.list, LB_SETCURSEL, Some(WPARAM(self.selected)), None);
            SendMessageW(self.list, WM_SETREDRAW, Some(WPARAM(1)), None);
            let _ = InvalidateRect(Some(self.list), None, true);
        }
        self.details();
    }
    fn header(&self) {
        let own = self
            .rows
            .iter()
            .filter(|r| r.identity.group == Group::FreshThread)
            .count();
        let mode = if self.paused { "PAUSED" } else { "WATCHING" };
        text(
            self.header,
            &format!(
                "FRESHTHREAD · NETWORK ACTIVITY   {mode}\r\nFreshThread: {own} visible endpoints · Related programs: {}\r\nSample {} · Open {}s  {}\r\n────────────────────────────────────────────────────────────────\r\nPROGRAM        ADDRESS / UDP LOCAL ENDPOINT          STATE",
                self.rows.len() - own,
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
        if rows != self.rows {
            self.selected = previous
                .as_ref()
                .and_then(|old| rows.iter().position(|r| r == old))
                .unwrap_or(0);
            self.rows = rows;
            self.paint_rows();
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
                self.dpi = dpi;
            }
            let mut r = RECT::default();
            let _ = GetClientRect(hwnd, &mut r);
            let margin = self.px(18);
            let width = (r.right - margin * 2).max(1);
            let head = self.px(144);
            let foot = self.px(70);
            let detail = self.px(160);
            let list = (r.bottom - margin * 2 - head - foot - detail).max(1);
            let _ = MoveWindow(self.header, margin, margin, width, head, true);
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
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => unsafe {
            let dc = HDC(wp.0 as *mut _);
            SetTextColor(dc, BLUE);
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
                    view.selected = n as usize;
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
            let header = child(w!("STATIC"), WINDOW_STYLE(0))?;
            let list = child(
                w!("LISTBOX"),
                WS_TABSTOP | WINDOW_STYLE((LBS_NOTIFY | LBS_NOINTEGRALHEIGHT) as u32),
            )?;
            let detail = child(
                w!("EDIT"),
                WS_TABSTOP | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY) as u32),
            )?;
            let footer = child(w!("STATIC"), WINDOW_STYLE(0))?;
            let mut view = Box::new(View {
                header,
                list,
                detail,
                footer,
                font: HFONT::default(),
                rows: Vec::new(),
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
                "────────────────────────────────────────────────────────────────\r\n↑↓ select · Enter details · P pause · ? help · Q close\r\nSnapshots may miss short connections. Wheel / PgUp PgDn scroll.",
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
            for child in [hwnd, view.header, view.list, view.detail, view.footer] {
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
