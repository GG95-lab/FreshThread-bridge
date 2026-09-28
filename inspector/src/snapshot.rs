use super::{
    model::{Connection, Identity, endpoint},
    process,
};
use std::collections::HashMap;
use windows::Win32::NetworkManagement::IpHelper::*;

// IP Helper returns fixed-size OWNER_PID rows after a DWORD count. Copy rows
// with read_unaligned; never form aligned references into a byte allocation.
fn table<T: Copy>(family: u32, tcp: bool) -> Result<Vec<T>, &'static str> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut bytes = vec![0u8; size as usize];
        let ptr = (!bytes.is_empty()).then(|| bytes.as_mut_ptr().cast());
        let code = unsafe {
            if tcp {
                GetExtendedTcpTable(ptr, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(ptr, &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        if code == 122 {
            if size > 8 * 1024 * 1024 {
                return Err("connection_table_too_large");
            }
            continue;
        }
        if code != 0 || bytes.len() < 4 {
            return Err("connection_table_unavailable");
        }
        let count = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        let length = std::mem::size_of::<T>();
        if count > bytes.len().saturating_sub(4) / length {
            return Err("connection_table_invalid");
        }
        return Ok((0..count)
            .map(|i| unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(4 + i * length).cast::<T>())
            })
            .collect());
    }
    Err("connection_table_changing")
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}
fn state(value: u32) -> String {
    match value {
        1 => "closed",
        2 => "listen",
        3 => "syn-sent",
        4 => "syn-received",
        5 => "established",
        6 => "fin-wait-1",
        7 => "fin-wait-2",
        8 => "close-wait",
        9 => "closing",
        10 => "last-ack",
        11 => "time-wait",
        12 => "delete",
        _ => "unknown",
    }
    .into()
}
fn identity(pid: u32, processes: &HashMap<u32, Identity>) -> Option<Identity> {
    let entry = processes.get(&pid)?;
    // A socket snapshot may race process exit/PID reuse. Do not attach the old
    // identity to the new process merely because the numeric PID is equal.
    let (path, started) = process::details(pid)?;
    (started == entry.started && path.eq_ignore_ascii_case(&entry.path)).then(|| entry.clone())
}

pub fn collect(processes: &HashMap<u32, Identity>) -> (Vec<Connection>, Vec<&'static str>) {
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    macro_rules! table_rows {
        ($ty:ty,$family:expr,$tcp:expr,$body:expr) => {
            match table::<$ty>($family, $tcp) {
                Ok(values) => {
                    for value in values {
                        if let Some(id) = identity(value.dwOwningPid, processes) {
                            ($body)(value, id, &mut rows);
                        }
                    }
                }
                Err(code) => errors.push(code),
            }
        };
    }
    table_rows!(MIB_TCPROW_OWNER_PID, 2, true, |r: MIB_TCPROW_OWNER_PID,
                                                id: Identity,
                                                rows: &mut Vec<
        Connection,
    >| {
        rows.push(Connection {
            identity: id,
            protocol: "TCP4",
            local: endpoint(&r.dwLocalAddr.to_ne_bytes(), port(r.dwLocalPort)).unwrap(),
            remote: endpoint(&r.dwRemoteAddr.to_ne_bytes(), port(r.dwRemotePort)).unwrap(),
            state: state(r.dwState),
            bytes: None,
        });
    });
    table_rows!(
        MIB_TCP6ROW_OWNER_PID,
        23,
        true,
        |r: MIB_TCP6ROW_OWNER_PID, id: Identity, rows: &mut Vec<Connection>| {
            rows.push(Connection {
                identity: id,
                protocol: "TCP6",
                local: scoped(&r.ucLocalAddr, r.dwLocalScopeId, port(r.dwLocalPort)),
                remote: scoped(&r.ucRemoteAddr, r.dwRemoteScopeId, port(r.dwRemotePort)),
                state: state(r.dwState),
                bytes: None,
            });
        }
    );
    table_rows!(MIB_UDPROW_OWNER_PID, 2, false, |r: MIB_UDPROW_OWNER_PID,
                                                 id: Identity,
                                                 rows: &mut Vec<
        Connection,
    >| {
        rows.push(Connection {
            identity: id,
            protocol: "UDP4",
            local: endpoint(&r.dwLocalAddr.to_ne_bytes(), port(r.dwLocalPort)).unwrap(),
            remote: "not available in snapshot".into(),
            state: "bound endpoint".into(),
            bytes: None,
        });
    });
    table_rows!(
        MIB_UDP6ROW_OWNER_PID,
        23,
        false,
        |r: MIB_UDP6ROW_OWNER_PID, id: Identity, rows: &mut Vec<Connection>| {
            rows.push(Connection {
                identity: id,
                protocol: "UDP6",
                local: scoped(&r.ucLocalAddr, r.dwLocalScopeId, port(r.dwLocalPort)),
                remote: "not available in snapshot".into(),
                state: "bound endpoint".into(),
                bytes: None,
            });
        }
    );
    rows.sort_by(|a, b| {
        (a.identity.pid, &a.protocol, &a.remote).cmp(&(b.identity.pid, &b.protocol, &b.remote))
    });
    (rows, errors)
}
fn scoped(bytes: &[u8; 16], scope: u32, port: u16) -> String {
    if scope == 0 {
        endpoint(bytes, port).unwrap()
    } else {
        format!("[{}%{scope}]:{port}", std::net::Ipv6Addr::from(*bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_identity() -> Identity {
        let pid = std::process::id();
        let (path, started) = process::details(pid).unwrap();
        Identity {
            pid,
            path,
            started,
            group: super::super::model::Group::FreshThread,
        }
    }

    #[test]
    fn native_snapshot_finds_local_tcp_but_rejects_reused_pid_identity() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let identity = own_identity();
        let processes = HashMap::from([(identity.pid, identity.clone())]);
        let (rows, errors) = collect(&processes);
        assert!(
            errors.is_empty(),
            "native IP Helper tables must be readable: {errors:?}"
        );
        assert!(rows.iter().any(|row| row.protocol == "TCP4"
            && row.local == client.local_addr().unwrap().to_string()
            && row.remote == listener.local_addr().unwrap().to_string()
            && row.state == "established"));
        let reused = Identity {
            started: identity.started + 1,
            ..identity
        };
        assert!(collect(&HashMap::from([(reused.pid, reused)])).0.is_empty());
    }

    #[test]
    fn native_udp_snapshot_does_not_invent_a_remote_destination() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let identity = own_identity();
        let (rows, errors) = collect(&HashMap::from([(identity.pid, identity)]));
        assert!(errors.is_empty());
        let row = rows
            .iter()
            .find(|row| {
                row.protocol == "UDP4" && row.local == socket.local_addr().unwrap().to_string()
            })
            .unwrap();
        assert_eq!(row.remote, "not available in snapshot");
        assert_eq!(row.bytes, None);
    }
    #[test]
    fn network_order_ports_and_scoped_ipv6_are_preserved() {
        assert_eq!(port(0xbb01), 443);
        assert_eq!(scoped(&[0; 16], 3, 53), "[::%3]:53");
    }
}
