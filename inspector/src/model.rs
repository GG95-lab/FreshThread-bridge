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
}
