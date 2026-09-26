use freshthread_bridge::{
    checkpoint::{CheckpointResult, project_meta},
    command_key, hooks,
};
use serde_json::json;
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn root_identity_is_required_and_unrelated_metadata_is_removed() {
    let input = json!({"threadId":"task","x-codex-turn-metadata":{"thread_id":"task","turn_id":"turn","private":"SECRET"},"private":"SECRET"});
    let meta = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(
        project_meta(&meta).unwrap(),
        json!({"threadId":"task","x-codex-turn-metadata":{"thread_id":"task","turn_id":"turn"}})
    );
    let mut child = input;
    child["x-codex-turn-metadata"]["parent_thread_id"] = json!("parent");
    assert!(project_meta(&serde_json::from_value(child).unwrap()).is_err());
}

#[test]
fn command_key_matches_existing_domain_separated_hmac_contract() {
    // Independent known-answer fixture, generated with Python hmac/sha256.
    assert_eq!(
        command_key("cargo test", &[7; 32]).unwrap(),
        "c2bef8a0ae78a5d3584d054764ddcc644890f608ee86da89881d4546eed02c8a"
    );
    assert_ne!(
        command_key("cargo test", &[7; 32]).unwrap(),
        command_key("cargo test", &[8; 32]).unwrap()
    );
}

#[test]
fn stops_never_forward_content_and_invalid_events_are_rejected() {
    let payload = json!({"hook_event_name":"Stop","session_id":"task","turn_id":"turn","stop_hook_active":true,"last_assistant_message":"SECRET"});
    let projected = hooks::lifecycle(&serde_json::to_vec(&payload).unwrap(), true).unwrap();
    assert!(!projected.to_string().contains("SECRET"));
    assert!(
        hooks::lifecycle(br#"{"hook_event_name":"Other","session_id":"task"}"#, false).is_err()
    );
}

#[test]
fn engine_cannot_return_arbitrary_content_as_checkpoint_status() {
    let result = json!({"checkpoint_recorded":true,"replayed":false,"probe_status":null,"retention_basis_points":null,"recommendation_authority":false,"private":"SECRET"});
    assert!(serde_json::from_value::<CheckpointResult>(result).is_err());
    let result: CheckpointResult=serde_json::from_value(json!({"checkpoint_recorded":true,"replayed":false,"probe_status":"arbitrary message","retention_basis_points":null,"recommendation_authority":false})).unwrap();
    assert!(result.validate().is_err());
}

#[test]
fn non_verifier_hook_does_not_launch_or_hash_the_private_engine() {
    fn invoke(command: &str) -> std::process::Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_freshthread-bridge"))
            .args([
                "--backend",
                "freshthread-integration-missing.exe",
                "--backend-sha256",
                &"a".repeat(64),
                "--codex-post-tool-use",
                "--freshthread-hook-contract",
                "v1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let payload = json!({"hook_event_name":"PostToolUse","session_id":"task","turn_id":"turn",
            "cwd":"C:\\fixture","tool_use_id":"tool","tool_name":"shell_command",
            "tool_input":{"command":command},"tool_response":{"exit_code":0,"output":"SECRET_OUTPUT"}});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&payload).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    let ignored = invoke("echo synthetic");
    assert!(ignored.status.success());
    assert!(ignored.stdout.is_empty());
    assert!(ignored.stderr.is_empty());
    let forwarded = invoke("cargo test");
    let diagnostic = String::from_utf8_lossy(&forwarded.stderr);
    // A clean CI runner has no FreshThread installation key; an installed
    // developer profile can reach the deliberately missing backend instead.
    assert!(
        diagnostic.contains("reason=key_unavailable")
            || diagnostic.contains("reason=backend_unavailable"),
        "unexpected fixed bridge status: {diagnostic}"
    );
    assert!(!diagnostic.contains("SECRET_OUTPUT"));
}
