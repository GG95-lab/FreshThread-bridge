use super::model::{Group, Identity};
use std::{collections::HashMap, path::Path};
use windows::{
    Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    },
    core::PWSTR,
};

pub struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
pub fn filetime(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn session(pid: u32) -> Option<u32> {
    let mut value = 0;
    unsafe {
        windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut value).ok()?;
    }
    Some(value)
}

pub fn details(pid: u32) -> Option<(String, u64)> {
    unsafe {
        let handle = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut length,
        )
        .ok()?;
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user).ok()?;
        Some((
            String::from_utf16_lossy(&path[..length as usize]),
            filetime(created),
        ))
    }
}

pub fn direct_group(path: &str, bridge: &Path) -> Option<Group> {
    let target = Path::new(path);
    let name = target.file_name()?.to_str()?.to_ascii_lowercase();
    let directory = target.parent()?.to_string_lossy().to_ascii_lowercase();
    let own_directory = bridge.parent()?.to_string_lossy().to_ascii_lowercase();
    // A filename alone is not enough to call an arbitrary process FreshThread.
    let installed = directory == own_directory;
    let managed = directory.ends_with("\\com.freshthread.desktop\\integration\\bin");
    if (installed && name == "freshthread-desktop.exe")
        || (managed && name.starts_with("freshthread-integration-") && name.ends_with(".exe"))
    {
        return Some(Group::FreshThread);
    }
    // This identifies the Codex application family, not the purpose of a request.
    if name == "codex.exe"
        && (directory.contains("\\openai.codex_") || directory.contains("\\codex\\"))
    {
        return Some(Group::Codex);
    }
    None
}

pub fn collect() -> Result<HashMap<u32, Identity>, &'static str> {
    let bridge = std::env::current_exe().map_err(|_| "observer_path_unavailable")?;
    let own_session = session(std::process::id()).ok_or("observer_session_unavailable")?;
    let mut parents = HashMap::new();
    let mut names = HashMap::new();
    unsafe {
        let snapshot = Handle(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|_| "process_list_unavailable")?,
        );
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        Process32FirstW(snapshot.0, &mut entry).map_err(|_| "process_list_unavailable")?;
        loop {
            let end = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            names.insert(
                entry.th32ProcessID,
                String::from_utf16_lossy(&entry.szExeFile[..end]).to_ascii_lowercase(),
            );
            parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            if Process32NextW(snapshot.0, &mut entry).is_err() {
                break;
            }
        }
    }
    let mut found = HashMap::new();
    for (&pid, name) in &names {
        if pid == std::process::id() || session(pid) != Some(own_session) {
            continue;
        }
        if !(name == "codex.exe"
            || name == "freshthread-desktop.exe"
            || name.starts_with("freshthread-integration-"))
        {
            continue;
        }
        if let Some((path, started)) = details(pid)
            && !path.eq_ignore_ascii_case(&bridge.to_string_lossy())
            && let Some(group) = direct_group(&path, &bridge)
        {
            found.insert(
                pid,
                Identity {
                    pid,
                    started,
                    path,
                    group,
                },
            );
        }
    }
    // Resolve descendants by actual ancestry and creation time, not all WebView2
    // processes on the machine. A recycled parent PID must not adopt a child.
    for _ in 0..16 {
        let mut added = Vec::new();
        for (&pid, &parent) in &parents {
            if pid == std::process::id() || found.contains_key(&pid) {
                continue;
            }
            let Some(owner) = found.get(&parent) else {
                continue;
            };
            if let Some((path, started)) = details(pid)
                && started >= owner.started
                && session(pid) == Some(own_session)
                && !path.eq_ignore_ascii_case(&bridge.to_string_lossy())
            {
                let group = if names
                    .get(&pid)
                    .is_some_and(|name| name == "msedgewebview2.exe")
                {
                    Group::WebView
                } else {
                    Group::Related
                };
                added.push((
                    pid,
                    Identity {
                        pid,
                        started,
                        path,
                        group,
                    },
                ));
            }
        }
        if added.is_empty() {
            break;
        }
        found.extend(added);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_unrelated_same_name_executable_is_not_adopted() {
        let bridge = Path::new(r"C:\Apps\FreshThread\freshthread-bridge.exe");
        assert_eq!(
            direct_group(r"C:\Apps\FreshThread\freshthread-desktop.exe", bridge),
            Some(Group::FreshThread)
        );
        assert_eq!(
            direct_group(r"C:\Other\freshthread-desktop.exe", bridge),
            None
        );
        assert_eq!(direct_group(r"C:\Other\msedgewebview2.exe", bridge), None);
        assert_eq!(direct_group(r"C:\Other\codex.exe", bridge), None);
    }
}
