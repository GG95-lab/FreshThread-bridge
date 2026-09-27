//! Keep the public MCP connection alive while changing only its private child.
//! The desktop atomically publishes its existing integration receipt after it
//! has staged the hash-addressed files. No raw hook input crosses this boundary.
use crate::transport::{Backend, verified_backend};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

pub const RECHECK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub digest: String,
}

pub enum Source {
    Fixed {
        bridge: PathBuf,
        target: Target,
    },
    Managed {
        bridge: PathBuf,
        digest: String,
        generation: Option<String>,
    },
}

#[derive(Deserialize)]
struct Receipt {
    schema_version: u16,
    app_version: String,
    launcher_sha256: String,
    bridge_sha256: String,
    plugin_version: String,
    mcp_contract: String,
    mcp_restart_policy_version: u16,
}

impl Source {
    pub fn managed(bridge: PathBuf, generation: Option<String>) -> Result<Self, &'static str> {
        let mut bytes = Vec::new();
        std::fs::File::open(&bridge)
            .map_err(|_| "bridge_unavailable")?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "bridge_unavailable")?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err("bridge_invalid");
        }
        let digest = crate::hex(&Sha256::digest(bytes));
        Ok(Self::Managed {
            bridge,
            digest,
            generation,
        })
    }

    fn bridge(&self) -> &std::path::Path {
        match self {
            Self::Fixed { bridge, .. } | Self::Managed { bridge, .. } => bridge,
        }
    }

    pub fn target(&self) -> Result<Target, &'static str> {
        let Self::Managed {
            bridge,
            digest,
            generation,
        } = self
        else {
            let Self::Fixed { target, .. } = self else {
                unreachable!()
            };
            return Ok(target.clone());
        };
        let bin = bridge
            .parent()
            .filter(|p| p.file_name().is_some_and(|n| n == "bin"))
            .ok_or("invalid_activation_path")?;
        let root = bin.parent().ok_or("invalid_activation_path")?;
        let mut bytes = Vec::new();
        std::fs::File::open(root.join("integration-state.json"))
            .map_err(|_| "activation_unavailable")?
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "activation_unavailable")?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err("activation_too_large");
        }
        let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| "invalid_activation")?;
        if receipt.schema_version != 1
            || receipt.mcp_restart_policy_version != 4
            || receipt.mcp_contract != "v2"
            || receipt.bridge_sha256 != *digest
            || generation
                .as_ref()
                .is_some_and(|g| *g != receipt.plugin_version)
        {
            return Err("integration_restart_required");
        }
        if receipt.app_version.is_empty()
            || receipt.app_version.len() > 64
            || !receipt
                .app_version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c))
            || receipt.launcher_sha256.len() != 64
            || !receipt
                .launcher_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("invalid_activation");
        }
        Ok(Target {
            name: format!(
                "freshthread-integration-{}-{}.exe",
                receipt.app_version,
                &receipt.launcher_sha256[..12]
            ),
            digest: receipt.launcher_sha256,
        })
    }
}

pub struct ActiveBackend {
    source: Source,
    target: Target,
    backend: Backend,
    contract: String,
    value: String,
    initialized: bool,
    confirmed: bool,
    retry: Option<(Target, Instant, Duration, &'static str)>,
}

impl ActiveBackend {
    pub fn start(source: Source, contract: &str, value: &str) -> Result<Self, &'static str> {
        let target = source.target()?;
        let path = verified_backend(source.bridge(), &target.name, &target.digest)?;
        let backend = Backend::spawn(&path, contract, value)?;
        Ok(Self {
            source,
            target,
            backend,
            contract: contract.to_owned(),
            value: value.to_owned(),
            initialized: false,
            confirmed: false,
            retry: None,
        })
    }

    pub async fn initialized(&mut self) -> Result<(), &'static str> {
        self.initialized = true;
        let result = self.backend.request("mcp_initialized", Value::Null).await?;
        if result.get("observed").and_then(Value::as_bool) != Some(true) {
            return Err("backend_not_ready");
        }
        self.confirmed = true;
        Ok(())
    }

    // The caller holds the same mutex for requests and activation. A request
    // already in flight finishes exactly once before a new child is selected.
    pub async fn refresh(&mut self) -> Result<bool, &'static str> {
        let target = self.source.target()?;
        if target == self.target && self.backend.healthy() && (!self.initialized || self.confirmed)
        {
            return Ok(false);
        }
        if let Some((failed, after, _, code)) = &self.retry
            && failed == &target
            && Instant::now() < *after
        {
            return Err(*code);
        }
        let candidate = async {
            let path = verified_backend(self.source.bridge(), &target.name, &target.digest)?;
            let mut candidate = Backend::spawn(&path, &self.contract, &self.value)?;
            if self.initialized {
                let reply = candidate.request("mcp_initialized", Value::Null).await?;
                if reply.get("observed").and_then(Value::as_bool) != Some(true) {
                    return Err("backend_not_ready");
                }
            }
            Ok::<_, &'static str>(candidate)
        }
        .await;
        match candidate {
            Ok(candidate) => {
                let mut previous = std::mem::replace(&mut self.backend, candidate);
                self.target = target;
                self.confirmed = self.initialized;
                self.retry = None;
                previous.shutdown().await;
                Ok(true)
            }
            Err(code) => {
                let delay = self
                    .retry
                    .as_ref()
                    .filter(|(failed, ..)| failed == &target)
                    .map_or(RECHECK_INTERVAL, |(_, _, delay, _)| {
                        (*delay * 2).min(Duration::from_secs(30))
                    });
                self.retry = Some((target, Instant::now() + delay, delay, code));
                Err(code)
            }
        }
    }

    pub async fn request(
        &mut self,
        operation: &str,
        payload: Value,
    ) -> Result<Value, &'static str> {
        self.refresh().await?;
        // An uncertain write is returned as an error, never replayed on a new child.
        self.backend.request(operation, payload).await
    }
}
