//! Content-free subprocess fixture, compiled by the activation integration test.
use std::io::{BufRead, Write};
fn main() {
    let executable = std::env::current_exe().unwrap();
    let name = executable.file_name().unwrap().to_string_lossy();
    let events = executable.with_extension("events");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let initialized = line.contains("mcp_initialized");
        let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&events).unwrap();
        writeln!(log, "{}:{}", if initialized { "initialize" } else { "request" }, std::process::id()).unwrap();
        if line.contains("slow") { std::thread::sleep(std::time::Duration::from_millis(250)); }
        if line.contains("uncertain") { std::process::exit(1); }
        let result = if initialized {
            format!("{{\"observed\":{}}}", !executable.with_extension("notready").exists())
        } else if line.contains("\"operation\":\"checkpoint\"") {
            "{\"checkpoint_recorded\":true,\"replayed\":false,\"probe_status\":null,\"retention_basis_points\":null,\"recommendation_authority\":false}".to_owned()
        } else { format!("{{\"engine\":\"{name}\",\"pid\":{}}}", std::process::id()) };
        println!("{{\"protocol\":1,\"result\":{result}}}");
        std::io::stdout().flush().unwrap();
    }
}
