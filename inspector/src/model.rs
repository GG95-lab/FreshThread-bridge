use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub pid: u32,
    pub started: u64,
    pub path: String,
    pub group: Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    FreshThread,
    WebView,
    Codex,
    Related,
}
impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Self::FreshThread => "FreshThread",
            Self::WebView => "WebView2",
            Self::Codex => "Codex",
            Self::Related => "Related process",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Connection {
    pub identity: Identity,
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub bytes: Option<u32>,
}

impl Connection {
    pub fn remote_ip(&self) -> Option<IpAddr> {
        self.remote
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|a| a.ip())
    }
    pub fn local_only(&self) -> bool {
        self.state == "listen"
            || self
                .remote_ip()
                .is_some_and(|ip| ip.is_loopback() || ip.is_unspecified())
    }
    pub fn remote_tcp(&self) -> bool {
        self.protocol.starts_with("TCP") && !self.local_only() && self.remote_ip().is_some()
    }
    pub fn this_pc_only(&self) -> bool {
        if self.state == "listen" || self.protocol.starts_with("UDP") {
            return self
                .local
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|address| address.ip().is_loopback());
        }
        self.remote_ip().is_some_and(|ip| ip.is_loopback())
    }
}

pub fn grouped_rows(rows: &[Connection]) -> Vec<Vec<usize>> {
    let mut result: Vec<Vec<usize>> = Vec::new();
    let mut groups = std::collections::HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        let group = *groups.entry(row.identity.group).or_insert_with(|| {
            result.push(Vec::new());
            result.len() - 1
        });
        result[group].push(index);
    }
    result
}

pub fn restore_selection(rows: &[Connection], previous: Option<&Connection>) -> usize {
    previous
        .and_then(|old| {
            rows.iter()
                .position(|row| {
                    row.identity == old.identity
                        && row.protocol == old.protocol
                        && row.local == old.local
                        && row.remote == old.remote
                })
                .or_else(|| {
                    rows.iter()
                        .position(|row| row.identity.group == old.identity.group)
                })
        })
        .unwrap_or(0)
}

pub fn private_path(path: &str) -> String {
    // Display only the executable name. Profile roots and arbitrary parent
    // directories can both contain names or private workspace identifiers.
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or("program")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub fn address(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

pub fn endpoint(bytes: &[u8], port: u16) -> Option<String> {
    Some(match address(bytes)? {
        IpAddr::V4(ip) => format!("{ip}:{port}"),
        IpAddr::V6(ip) => format!("[{ip}]:{port}"),
    })
}

pub fn safe_text(input: &str, width: usize) -> String {
    // Prevent executable paths or unknown fields from injecting console controls.
    let mut value: String = input
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(width)
        .collect();
    value.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(value.chars().count()),
    ));
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoints_preserve_ipv6_and_reject_unknown_lengths() {
        assert_eq!(
            endpoint(&[127, 0, 0, 1], 443).as_deref(),
            Some("127.0.0.1:443")
        );
        assert_eq!(endpoint(&[0; 16], 53).as_deref(), Some("[::]:53"));
        assert_eq!(endpoint(&[0; 8], 80), None);
    }
    #[test]
    fn console_data_cannot_inject_control_sequences() {
        assert_eq!(safe_text("A\x1b[2J\n", 10), "A [2J     ");
        assert_eq!(safe_text("long", 2), "lo");
    }
    #[test]
    fn listeners_loopback_and_udp_are_not_counted_as_remote_tcp() {
        let mut row = Connection {
            identity: Identity {
                pid: 1,
                started: 1,
                path: "fixture.exe".into(),
                group: Group::FreshThread,
            },
            protocol: "TCP4",
            local: "0.0.0.0:80".into(),
            remote: "0.0.0.0:0".into(),
            state: "listen".into(),
            bytes: None,
        };
        assert!(row.local_only());
        assert!(!row.this_pc_only());
        row.local = "127.0.0.1:80".into();
        assert!(row.this_pc_only());
        row.local = "[::]:80".into();
        assert!(!row.this_pc_only());
        row.local = "[::1]:80".into();
        assert!(row.this_pc_only());
        assert!(!row.remote_tcp());
        row.state = "established".into();
        row.remote = "127.0.0.1:1234".into();
        assert!(row.local_only());
        assert!(!row.remote_tcp());
        row.remote = "[2001:db8::1]:443".into();
        assert!(!row.local_only());
        assert!(row.remote_tcp());
        row.protocol = "UDP6";
        row.remote = "unavailable".into();
        assert!(!row.remote_tcp());
        assert!(!row.local_only());
    }
    #[test]
    fn displayed_program_does_not_disclose_profile_or_workspace() {
        assert_eq!(
            private_path(r"C:\Users\private-user\private-project\app.exe"),
            "app.exe"
        );
        assert_eq!(private_path("/home/private/app.exe"), "app.exe");
    }
    #[test]
    fn grouped_connections_keep_selection_across_state_changes_and_disappearance() {
        let row = |group, pid| Connection {
            identity: Identity {
                pid,
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
        let mut rows = vec![
            row(Group::FreshThread, 1),
            row(Group::Codex, 2),
            row(Group::WebView, 3),
            row(Group::Codex, 4),
        ];
        assert_eq!(grouped_rows(&rows), vec![vec![0], vec![1, 3], vec![2]]);
        let previous = rows[3].clone();
        rows[3].state = "close-wait".into();
        assert_eq!(restore_selection(&rows, Some(&previous)), 3);
        rows.pop();
        assert_eq!(restore_selection(&rows, Some(&previous)), 1);
        rows.retain(|row| row.identity.group != Group::Codex);
        assert_eq!(restore_selection(&rows, Some(&previous)), 0);
        assert_eq!(restore_selection(&[], Some(&previous)), 0);
    }
}
