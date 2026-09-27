#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use freshthread_bridge::{
    activation::{ActiveBackend, RECHECK_INTERVAL, Source, Target},
    checkpoint::{Checkpoint, CheckpointResult, project_meta},
    hooks,
};
use rmcp::{
    ErrorData, ServiceExt, handler::server::wrapper::Parameters, model::Meta, tool, tool_router,
    transport::stdio,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct Server {
    backend: Arc<Mutex<ActiveBackend>>,
}

#[tool_router(server_handler)]
impl Server {
    #[tool(
        description = "Record one local, encrypted FreshThread semantic checkpoint for the exact current Codex session and turn. Call when FreshThread requests it, at a genuine phase transition, and before finishing a due turn. Preserve stable fact_key values for unchanged propositions, explicitly supersede replaced facts, include every still-active durable user permission and prohibition in active_constraints, and always provide a truthful next_expected_step plus next_action_disposition. Use continue only when the target should immediately resume already-authorized same-task work; use complete when no work remains; name next_action_dependency for a user wait or external block. Never invent completion, evidence, decisions, or failures. The tool is measurement-only and has no recommendation or execution authority."
    )]
    async fn record_session_integrity(
        &self,
        meta: Meta,
        Parameters(input): Parameters<Checkpoint>,
    ) -> Result<String, ErrorData> {
        input.validate().map_err(invalid)?;
        let meta = project_meta(&meta).map_err(invalid)?;
        let response = self
            .backend
            .lock()
            .await
            .request("checkpoint", json!({"meta":meta,"input":input}))
            .await
            .map_err(unavailable)?;
        let result: CheckpointResult =
            serde_json::from_value(response).map_err(|_| unavailable("invalid_engine_response"))?;
        result.validate().map_err(unavailable)?;
        serde_json::to_string(&result).map_err(|_| unavailable("invalid_engine_response"))
    }
}
fn invalid(code: &'static str) -> ErrorData {
    ErrorData::invalid_params(code, None)
}
fn unavailable(code: &'static str) -> ErrorData {
    ErrorData::internal_error(code, None)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(code) = run().await {
        eprintln!("freshthread bridge status=unavailable reason={code}");
        // Hooks remain non-blocking. In particular Stop may not trap a Codex turn.
        if std::env::args().any(|a| a == "--codex-stop-hook") {
            println!("{{}}");
        }
    }
}

async fn run() -> Result<(), &'static str> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let managed = args.len() == 4 && args[0] == "--managed-backend";
    if !managed && (args.len() != 7 || args[0] != "--backend" || args[2] != "--backend-sha256") {
        return Err("invalid_arguments");
    }
    let offset = if managed { 1 } else { 4 };
    let mode = args[offset].as_str();
    let contract = args[offset + 1].as_str();
    let value = args[offset + 2].as_str();
    let mcp = mode == "--codex-mcp";
    if mcp {
        if contract != "--freshthread-plugin-generation" || !freshthread_bridge::bounded(value) {
            return Err("invalid_arguments");
        }
    } else if !matches!(
        mode,
        "--codex-lifecycle-hook" | "--codex-stop-hook" | "--codex-post-tool-use"
    ) || contract != "--freshthread-hook-contract"
        || value != "v1"
    {
        return Err("invalid_arguments");
    }
    let hook_input = if mcp {
        None
    } else {
        Some(read_hook_input().await?)
    };
    // Non-verifier tool calls carry no observation. Skip the backend hash and
    // process launch entirely, and never send a null projection to the engine.
    let post_tool = if mode == "--codex-post-tool-use" {
        let projected = hooks::post_tool(hook_input.as_ref().ok_or("invalid_hook")?)?;
        if projected.is_none() {
            return Ok(());
        }
        projected
    } else {
        None
    };
    let bridge = std::env::current_exe().map_err(|_| "invalid_backend_path")?;
    let source = if managed {
        Source::managed(bridge, mcp.then(|| value.to_owned()))?
    } else {
        Source::Fixed {
            bridge,
            target: Target {
                name: args[1].clone(),
                digest: args[3].clone(),
            },
        }
    };
    let mut backend = ActiveBackend::start(source, contract, value)?;
    if mcp {
        let backend = Arc::new(Mutex::new(backend));
        let service = Server {
            backend: backend.clone(),
        }
        .serve(stdio())
        .await
        .map_err(|_| "mcp_start_failed")?;
        // Just as in the original integration, only a completed MCP handshake counts as pickup.
        if let Err(code) = backend.lock().await.initialized().await {
            if !managed {
                return Err(code);
            }
            eprintln!("freshthread bridge activation=waiting reason={code}");
        }
        let waiting = service.waiting();
        tokio::pin!(waiting);
        let mut interval = tokio::time::interval(RECHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous_error = None;
        loop {
            tokio::select! {
                result = &mut waiting => { result.map_err(|_| "mcp_stopped")?; break; }
                _ = interval.tick(), if managed => {
                    let error = backend.lock().await.refresh().await.err();
                    if error != previous_error {
                        if let Some(code) = error { eprintln!("freshthread bridge activation=waiting reason={code}"); }
                        previous_error = error;
                    }
                }
            }
        }
        return Ok(());
    }
    let bytes = hook_input.ok_or("invalid_hook")?;
    match mode {
        "--codex-post-tool-use" => {
            backend
                .request("post_tool", post_tool.ok_or("invalid_hook")?)
                .await?;
        }
        "--codex-stop-hook" => {
            backend
                .request("stop", hooks::lifecycle(&bytes, true)?)
                .await?;
            println!("{{}}");
        }
        _ => {
            let projected = hooks::lifecycle(&bytes, false)?;
            let event = projected["hook_event_name"]
                .as_str()
                .ok_or("invalid_hook")?
                .to_owned();
            let response = backend.request("lifecycle", projected).await?;
            if response.get("remind").and_then(Value::as_bool) == Some(true) {
                println!(
                    "{}",
                    json!({"hookSpecificOutput":{"hookEventName":event,"additionalContext":freshthread_bridge::REMINDER}})
                );
            }
        }
    }
    Ok(())
}

async fn read_hook_input() -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
    use tokio::io::AsyncReadExt;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::io::stdin()
            .take((freshthread_bridge::MAX_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| "hook_timeout")?
    .map_err(|_| "hook_input_failed")?;
    if bytes.len() > freshthread_bridge::MAX_FRAME_BYTES {
        return Err("input_too_large");
    }
    Ok(bytes)
}
