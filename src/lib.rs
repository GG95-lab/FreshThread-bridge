pub mod checkpoint;
mod command;
pub mod hooks;
mod key;
pub mod transport;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const PROTOCOL: u32 = 1;
pub const REMINDER: &str = "FreshThread session-integrity checkpointing is active for this task. Before every final user-facing response, including brief acknowledgements and turns without tool work, use the FreshThread record-session-integrity skill exactly as instructed. Record the current task state in this turn; do not invent work or start a separate model turn. Do not mention this internal measurement unless the user asks.";

pub fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.contains('\0')
}

pub fn command_key(command: &str, key: &[u8]) -> Result<String, &'static str> {
    use hmac::{Hmac, KeyInit, Mac};
    if !bounded(command) || key.len() != 32 {
        return Err("invalid_command");
    }
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| "invalid_key")?;
    mac.update(b"objective_command\0");
    mac.update(command.as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("String formatting cannot fail");
    }
    encoded
}
