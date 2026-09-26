use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

pub struct Backend {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    failed: bool,
}

pub fn verified_backend(bridge: &Path, name: &str, digest: &str) -> Result<PathBuf, &'static str> {
    if !name.starts_with("freshthread-integration-")
        || !name.ends_with(".exe")
        || name.contains(['/', '\\', ':'])
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("invalid_backend_identity");
    }
    let parent = bridge
        .parent()
        .ok_or("invalid_backend_path")?
        .canonicalize()
        .map_err(|_| "invalid_backend_path")?;
    let path = parent
        .join(name)
        .canonicalize()
        .map_err(|_| "backend_unavailable")?;
    if path.parent() != Some(parent.as_path())
        || path == bridge.canonicalize().map_err(|_| "invalid_backend_path")?
    {
        return Err("invalid_backend_path");
    }
    let mut file = std::fs::File::open(&path)
        .map_err(|_| "backend_unavailable")?
        .take(256 * 1024 * 1024 + 1);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| "backend_unavailable")?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 256 * 1024 * 1024 {
            return Err("backend_too_large");
        }
        hasher.update(&buffer[..count]);
    }
    if crate::hex(&hasher.finalize()) != digest {
        return Err("backend_hash_mismatch");
    }
    Ok(path)
}

impl Backend {
    pub fn spawn(path: &Path, contract: &str, value: &str) -> Result<Self, &'static str> {
        let mut command = Command::new(path);
        command
            .args(["--freshthread-bridge-backend", contract, value])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        let mut child = command.spawn().map_err(|_| "backend_start_failed")?;
        let input = child.stdin.take().ok_or("backend_start_failed")?;
        let output = BufReader::new(child.stdout.take().ok_or("backend_start_failed")?);
        Ok(Self {
            child,
            input,
            output,
            failed: false,
        })
    }

    pub async fn request(
        &mut self,
        operation: &str,
        payload: Value,
    ) -> Result<Value, &'static str> {
        if self.failed {
            return Err("backend_unavailable");
        }
        let mut bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(
                &json!({"protocol":crate::PROTOCOL,"operation":operation,"payload":payload}),
            )
            .map_err(|_| "invalid_request")?,
        );
        if bytes.len() >= crate::MAX_FRAME_BYTES {
            return Err("input_too_large");
        }
        bytes.push(b'\n');
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            self.input
                .write_all(&bytes)
                .await
                .map_err(|_| "backend_unavailable")?;
            self.input
                .flush()
                .await
                .map_err(|_| "backend_unavailable")?;
            let mut response = zeroize::Zeroizing::new(Vec::new());
            (&mut self.output)
                .take((crate::MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut response)
                .await
                .map_err(|_| "backend_unavailable")?;
            if response.len() > crate::MAX_FRAME_BYTES || response.last() != Some(&b'\n') {
                return Err("invalid_response");
            }
            let envelope: Value =
                serde_json::from_slice(&response).map_err(|_| "invalid_response")?;
            if envelope.get("protocol").and_then(Value::as_u64) != Some(crate::PROTOCOL as u64) {
                return Err("invalid_response");
            }
            envelope.get("result").cloned().ok_or("engine_rejected")
        })
        .await
        .unwrap_or(Err("backend_timeout"));
        // Never retry an uncertain checkpoint write or consume a late reply for a new request.
        if result.is_err() && !matches!(result, Err("engine_rejected")) {
            self.failed = true;
            let _ = self.child.kill().await;
        }
        result
    }
}
