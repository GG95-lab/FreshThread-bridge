//! Read the documented local DNS cache provider; never issue a DNS request.
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use windows::{
    Win32::System::{Com::*, Variant::*, Wmi::*},
    core::{BSTR, w},
};

#[derive(Default)]
pub struct Cache {
    pub entries: HashMap<IpAddr, Vec<String>>,
    pub status: &'static str,
}

pub struct Reader {
    request: mpsc::SyncSender<Vec<IpAddr>>,
    result: mpsc::Receiver<Cache>,
    stopped: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    next: Instant,
    pub cache: Cache,
}
impl Reader {
    pub fn new() -> Self {
        let (request, requests) = mpsc::sync_channel::<Vec<IpAddr>>(1);
        let (results, result) = mpsc::sync_channel(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let pause = paused.clone();
        // This worker belongs to this short-lived viewer process. No join on
        // the UI thread: a stalled Windows provider must not trap Q/close.
        // Process exit tears down COM even if a provider ignores cancellation.
        let _ = std::thread::Builder::new()
            .name("local-dns-cache".into())
            .spawn(move || {
                if unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_err() {
                    return;
                }
                while let Ok(wanted) = requests.recv() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    if pause.load(Ordering::Acquire) {
                        continue;
                    }
                    let cache = collect(&wanted, &pause).unwrap_or_else(|_| Cache {
                        status: "DNS cache unavailable; showing addresses",
                        ..Default::default()
                    });
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = results.try_send(cache);
                }
                unsafe {
                    CoUninitialize();
                }
            });
        Self {
            request,
            result,
            stopped,
            paused,
            next: Instant::now(),
            cache: Cache {
                status: "Names: local DNS cache only",
                ..Default::default()
            },
        }
    }
    pub fn set_paused(&mut self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
        if !paused {
            self.next = Instant::now();
        }
    }
    pub fn update(&mut self, wanted: Vec<IpAddr>) -> bool {
        if self.paused.load(Ordering::Acquire) {
            return false;
        }
        let mut changed = false;
        match self.result.try_recv() {
            Ok(cache) => {
                self.cache = cache;
                changed = true;
            }
            Err(mpsc::TryRecvError::Disconnected)
                if self.cache.status != "DNS cache unavailable; showing addresses" =>
            {
                self.cache = Cache {
                    status: "DNS cache unavailable; showing addresses",
                    ..Default::default()
                };
                changed = true;
            }
            _ => {}
        }
        if Instant::now() >= self.next && !wanted.is_empty() {
            let _ = self.request.try_send(wanted);
            self.next = Instant::now() + Duration::from_secs(15);
        }
        changed
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }
}

fn property(
    object: &IWbemClassObject,
    name: windows::core::PCWSTR,
) -> windows::core::Result<String> {
    unsafe {
        let mut value = VARIANT::default();
        object.Get(name, 0, &mut value, None, None)?;
        let mut buffer = [0u16; 512];
        let converted = VariantToString(&value, &mut buffer);
        let _ = VariantClear(&mut value);
        converted?;
        Ok(String::from_utf16_lossy(
            &buffer[..buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len())],
        ))
    }
}
fn insert(cache: &mut Cache, wanted: &HashSet<IpAddr>, data: &str, name: &str) {
    let Ok(ip) = data.parse::<IpAddr>() else {
        return;
    };
    if !wanted.contains(&ip)
        || name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
    {
        return;
    }
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return;
    }
    let names = cache.entries.entry(ip).or_default();
    if !names.contains(&name) && names.len() < 8 {
        names.push(name);
        names.sort();
    }
}
fn collect(wanted: &[IpAddr], stop: &AtomicBool) -> windows::core::Result<Cache> {
    unsafe {
        if stop.load(Ordering::Acquire) {
            return Ok(Cache::default());
        }
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let empty = BSTR::new();
        let services = locator.ConnectServer(
            &BSTR::from("ROOT\\StandardCimv2"),
            &empty,
            &empty,
            &empty,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &empty,
            None,
        )?;
        // Use the caller's existing local Windows identity; no elevation,
        // credentials, remote server or machine-wide COM policy changes.
        CoSetProxyBlanket(
            &services,
            10,
            0,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;
        if stop.load(Ordering::Acquire) {
            return Ok(Cache::default());
        }
        let rows = services.ExecQuery(&BSTR::from("WQL"), &BSTR::from("SELECT Name, Data FROM MSFT_DNSClientCache WHERE (Type = 1 OR Type = 28) AND Status = 0 AND TimeToLive > 0"), WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, None)?;
        let wanted: HashSet<_> = wanted.iter().copied().collect();
        let mut cache = Cache {
            status: "Names: local DNS cache hints",
            ..Default::default()
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        for index in 0..4096 {
            if stop.load(Ordering::Acquire) {
                break;
            }
            if Instant::now() >= deadline {
                cache.status = "DNS cache partial; names are hints";
                break;
            }
            let mut objects = [None];
            let mut count = 0;
            let outcome = rows.Next(50, &mut objects, &mut count);
            outcome.ok()?;
            if let Some(object) = objects[0].take() {
                if let (Ok(data), Ok(name)) =
                    (property(&object, w!("Data")), property(&object, w!("Name")))
                {
                    insert(&mut cache, &wanted, &data, &name);
                }
            } else if outcome.0 == WBEM_S_FALSE.0 {
                break;
            }
            if index == 4095 {
                cache.status = "DNS cache partial; names are hints";
            }
        }
        Ok(cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_cache_provider_can_be_read_without_a_network_lookup() {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok().unwrap();
        }
        let result = collect(&[], &AtomicBool::new(false))
            .map(|_| ())
            .map_err(|e| e.code());
        unsafe {
            CoUninitialize();
        }
        assert!(result.is_ok(), "local DNS provider: {:?}", result.err());
    }
    #[test]
    fn cache_hints_preserve_shared_addresses_and_reject_unrelated_or_unsafe_names() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let wanted = HashSet::from([ip]);
        let mut cache = Cache::default();
        insert(&mut cache, &wanted, "192.0.2.1", "one.example");
        insert(&mut cache, &wanted, "192.0.2.1", "two.example");
        insert(&mut cache, &wanted, "192.0.2.2", "unrelated.example");
        insert(&mut cache, &wanted, "192.0.2.1", "bad\nname");
        assert_eq!(cache.entries[&ip], ["one.example", "two.example"]);
        assert_eq!(cache.entries.len(), 1);
    }
}
