#![cfg_attr(not(test), windows_subsystem = "windows")]
mod model;
#[cfg(windows)]
mod names;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod snapshot;
#[cfg(windows)]
mod ui;

fn main() {
    #[cfg(windows)]
    if ui::run().is_err() {
        // No elevated fallback, private backend or network error reporting.
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                None,
                windows::core::w!("The network activity window could not be opened."),
                windows::core::w!("FreshThread"),
                windows::Win32::UI::WindowsAndMessaging::MB_OK,
            );
        }
    }
}
