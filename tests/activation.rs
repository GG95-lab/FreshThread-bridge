use freshthread_bridge::{
    activation::{ActiveBackend, Source},
    hex,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn fixture_executable() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("freshthread-bridge-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let output = root.join("engine.exe");
        let status = Command::new("rustc")
            .args(["--edition=2024", "-o"])
            .arg(&output)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/engine.rs"))
            .status()
            .unwrap();
        assert!(status.success());
        output
    })
}

struct Fixture {
    root: PathBuf,
    bridge: PathBuf,
    bridge_digest: String,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "freshthread-activation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let bridge = root.join("bin/bridge.exe");
        std::fs::write(&bridge, b"bridge test identity").unwrap();
        let bridge_digest = hex(&Sha256::digest(std::fs::read(&bridge).unwrap()));
        Self {
            root,
            bridge,
            bridge_digest,
        }
    }
    fn receipt(&self, version: &str) -> Value {
        let mut bytes = std::fs::read(fixture_executable()).unwrap();
        bytes.extend(version.as_bytes());
        let digest = hex(&Sha256::digest(&bytes));
        let path = self.root.join("bin").join(format!(
            "freshthread-integration-{version}-{}.exe",
            &digest[..12]
        ));
        std::fs::copy(fixture_executable(), &path).unwrap();
        std::fs::write(path, bytes).unwrap();
        json!({"schema_version":1,"app_version":version,"launcher_sha256":digest,"bridge_sha256":self.bridge_digest,"plugin_version":"fixture","mcp_contract":"v2","mcp_restart_policy_version":4})
    }
    fn publish(&self, receipt: &Value) {
        std::fs::write(
            self.root.join("integration-state.json"),
            serde_json::to_vec(receipt).unwrap(),
        )
        .unwrap();
    }
    fn start(&self) -> ActiveBackend {
        ActiveBackend::start(
            Source::managed(self.bridge.clone(), Some("fixture".into())).unwrap(),
            "--freshthread-plugin-generation",
            "fixture",
        )
        .unwrap()
    }
    fn events(&self, receipt: &Value) -> PathBuf {
        self.root.join("bin").join(format!(
            "freshthread-integration-{}-{}.events",
            receipt["app_version"].as_str().unwrap(),
            &receipt["launcher_sha256"].as_str().unwrap()[..12]
        ))
    }
}

#[tokio::test]
async fn live_child_switch_preserves_request_boundary_and_does_no_idle_restarts() {
    let fixture = Fixture::new();
    let old = fixture.receipt("1.0.0");
    let new = fixture.receipt("1.0.1");
    fixture.publish(&old);
    let mut backend = fixture.start();
    backend.initialized().await.unwrap();
    let original = backend.request("probe", Value::Null).await.unwrap();
    for _ in 0..25 {
        assert!(!backend.refresh().await.unwrap());
    }
    assert_eq!(
        std::fs::read_to_string(fixture.events(&old))
            .unwrap()
            .lines()
            .count(),
        2
    );
    let backend = Arc::new(Mutex::new(backend));
    let request_backend = backend.clone();
    let request = tokio::spawn(async move {
        request_backend
            .lock()
            .await
            .request("slow", Value::Null)
            .await
            .unwrap()
    });
    // The receipt changes while the first child's request is in progress.
    for _ in 0..100 {
        if std::fs::read_to_string(fixture.events(&old))
            .unwrap()
            .lines()
            .count()
            == 3
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!request.is_finished());
    fixture.publish(&new);
    let mut current = backend.lock().await;
    assert!(current.refresh().await.unwrap());
    let completed = request.await.unwrap();
    assert_eq!(completed["pid"], original["pid"]);
    let next = current.request("probe", Value::Null).await.unwrap();
    assert_ne!(next["pid"], original["pid"]);
    assert!(next["engine"].as_str().unwrap().contains("1.0.1"));
    assert_eq!(
        std::fs::read_to_string(fixture.events(&old))
            .unwrap()
            .lines()
            .count(),
        3
    );
    assert_eq!(
        std::fs::read_to_string(fixture.events(&new))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[tokio::test]
async fn bad_candidate_is_rejected_without_poisoning_recovery_or_claiming_ready() {
    let fixture = Fixture::new();
    let old = fixture.receipt("2.0.0");
    fixture.publish(&old);
    let mut backend = fixture.start();
    backend.initialized().await.unwrap();
    let mut bad = fixture.receipt("2.0.1");
    let valid = bad.clone();
    bad["bridge_sha256"] = json!("a".repeat(64));
    fixture.publish(&bad);
    assert_eq!(backend.refresh().await, Err("integration_restart_required"));
    assert!(!fixture.events(&valid).exists());
    bad = valid.clone();
    bad["app_version"] = json!("../escape");
    fixture.publish(&bad);
    assert_eq!(backend.refresh().await, Err("invalid_activation"));
    bad = valid.clone();
    bad["mcp_contract"] = json!("v3");
    fixture.publish(&bad);
    assert_eq!(backend.refresh().await, Err("integration_restart_required"));
    fixture.publish(&valid);
    let target = Source::managed(fixture.bridge.clone(), Some("fixture".into()))
        .unwrap()
        .target()
        .unwrap();
    let path = fixture.root.join("bin").join(target.name);
    let saved = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"tampered").unwrap();
    assert_eq!(backend.refresh().await, Err("backend_hash_mismatch"));
    assert!(!fixture.events(&valid).exists());
    std::fs::write(&path, saved).unwrap();
    // A valid different activation bypasses the failed candidate's bounded backoff.
    let recovered = fixture.receipt("2.0.2");
    fixture.publish(&recovered);
    assert!(backend.refresh().await.unwrap());
    assert!(
        backend.request("probe", Value::Null).await.unwrap()["engine"]
            .as_str()
            .unwrap()
            .contains("2.0.2")
    );
}

#[tokio::test]
async fn uncertain_write_is_not_replayed_after_child_failure() {
    let fixture = Fixture::new();
    let old = fixture.receipt("3.0.0");
    fixture.publish(&old);
    let mut backend = fixture.start();
    backend.initialized().await.unwrap();
    assert!(backend.request("uncertain", Value::Null).await.is_err());
    let new = fixture.receipt("3.0.1");
    fixture.publish(&new);
    assert!(backend.refresh().await.unwrap());
    assert_eq!(
        std::fs::read_to_string(fixture.events(&new))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(fixture.events(&old))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[tokio::test]
async fn unconfirmed_child_is_not_activated_and_retry_is_bounded() {
    let fixture = Fixture::new();
    let old = fixture.receipt("5.0.0");
    let new = fixture.receipt("5.0.1");
    fixture.publish(&old);
    let mut backend = fixture.start();
    backend.initialized().await.unwrap();
    let marker = fixture.events(&new).with_extension("notready");
    std::fs::write(&marker, b"").unwrap();
    fixture.publish(&new);
    assert_eq!(backend.refresh().await, Err("backend_not_ready"));
    for _ in 0..25 {
        assert_eq!(backend.refresh().await, Err("backend_not_ready"));
    }
    assert_eq!(
        std::fs::read_to_string(fixture.events(&new))
            .unwrap()
            .lines()
            .count(),
        1
    );
    std::fs::remove_file(marker).unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(backend.refresh().await.unwrap());
    assert!(
        backend.request("probe", Value::Null).await.unwrap()["engine"]
            .as_str()
            .unwrap()
            .contains("5.0.1")
    );
}

#[tokio::test]
async fn real_mcp_stdio_connection_survives_idle_engine_update() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut fixture = Fixture::new();
    std::fs::copy(env!("CARGO_BIN_EXE_freshthread-bridge"), &fixture.bridge).unwrap();
    fixture.bridge_digest = hex(&Sha256::digest(std::fs::read(&fixture.bridge).unwrap()));
    let old = fixture.receipt("4.0.0");
    let new = fixture.receipt("4.0.1");
    fixture.publish(&old);
    let mut command = tokio::process::Command::new(&fixture.bridge);
    command
        .args([
            "--managed-backend",
            "--codex-mcp",
            "--freshthread-plugin-generation",
            "fixture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    let mut child = command.spawn().unwrap();
    let bridge_pid = child.id();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}});
    input
        .write_all(format!("{initialize}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(
        serde_json::from_str::<Value>(&line)
            .unwrap()
            .get("result")
            .is_some(),
        "{line}"
    );
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    for _ in 0..200 {
        if fixture.events(&old).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(fixture.events(&old).exists());
    fixture.publish(&new);
    for _ in 0..200 {
        if fixture.events(&new).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        fixture.events(&new).exists(),
        "the idle bridge must activate without a Codex restart or tool call"
    );
    assert_eq!(child.id(), bridge_pid);
    assert!(child.try_wait().unwrap().is_none());
    let fact = json!({"fact_key":"test","text":"Synthetic activation test"});
    let checkpoint = json!({"trigger":"periodic","current_goal":fact,"current_phase":fact,"preferred_user_language":"en","active_constraints":[],"decisions":[],"verified_completed_work":[],"files":[],"checks":[],"open_failures":[],"resolved_failures":[],"unknowns":[],"do_not_repeat":[],"next_expected_step":fact,"next_action_disposition":"complete"});
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"record_session_integrity","arguments":checkpoint,"_meta":{"threadId":"fixture-task","x-codex-turn-metadata":{"thread_id":"fixture-task","turn_id":"fixture-turn"}}}});
    input
        .write_all(format!("{call}\n").as_bytes())
        .await
        .unwrap();
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert!(reply.get("error").is_none(), "{reply}");
    assert_ne!(reply["result"]["isError"], json!(true), "{reply}");
    assert!(reply.to_string().contains("checkpoint_recorded"), "{reply}");
    assert_eq!(
        std::fs::read_to_string(fixture.events(&new))
            .unwrap()
            .lines()
            .count(),
        2
    );
    input.shutdown().await.unwrap();
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
