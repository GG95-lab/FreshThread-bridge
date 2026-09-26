use crate::command::{ObjectiveVerifierKind, classify_builtin};
use serde::{
    Deserialize,
    de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use zeroize::Zeroize;

#[derive(Deserialize)]
struct Header<'a> {
    #[serde(borrow)]
    hook_event_name: &'a str,
    session_id: &'a str,
    turn_id: Option<&'a str>,
    source: Option<&'a str>,
    stop_hook_active: Option<bool>,
}

pub fn lifecycle(bytes: &[u8], stop: bool) -> Result<Value, &'static str> {
    if bytes.len() > crate::MAX_FRAME_BYTES {
        return Err("input_too_large");
    }
    let h: Header<'_> = serde_json::from_slice(bytes).map_err(|_| "invalid_hook")?;
    if !crate::bounded(h.session_id) {
        return Err("invalid_identity");
    }
    let mut projected = json!({"hook_event_name":h.hook_event_name,"session_id":h.session_id});
    match h.hook_event_name {
        "UserPromptSubmit" if !stop => {} // prompt is never materialized or forwarded
        "SessionStart" if !stop => {
            let source = h
                .source
                .filter(|s| crate::bounded(s))
                .ok_or("invalid_source")?;
            let source = match source {
                "resume" => "resume",
                "compact" => "compact",
                _ => "startup",
            };
            projected["source"] = json!(source);
        }
        "PreCompact" if !stop => {
            projected["turn_id"] = json!(
                h.turn_id
                    .filter(|s| crate::bounded(s))
                    .ok_or("invalid_identity")?
            );
        }
        "Stop" if stop => {
            projected["turn_id"] = json!(
                h.turn_id
                    .filter(|s| crate::bounded(s))
                    .ok_or("invalid_identity")?
            );
            projected["stop_hook_active"] = json!(h.stop_hook_active.ok_or("invalid_hook")?);
        }
        _ => return Err("invalid_hook"),
    }
    Ok(projected)
}

#[derive(Deserialize)]
struct ToolInput {
    command: Option<String>,
}
impl Drop for ToolInput {
    fn drop(&mut self) {
        if let Some(command) = &mut self.command {
            command.zeroize();
        }
    }
}

// Inspect only numeric exit status. In particular, shell stdout/stderr and
// arbitrary response keys are skipped by Serde without building a JSON DOM.
struct ExitStatus(Option<i64>);
impl<'de> Deserialize<'de> for ExitStatus {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StatusVisitor;
        impl<'de> Visitor<'de> for StatusVisitor {
            type Value = ExitStatus;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a tool response")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let (mut snake, mut camel, mut snake_seen) = (None, None, false);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "exit_code" => {
                            snake_seen = true;
                            snake = map.next_value::<serde_json::Value>()?.as_i64();
                        }
                        "exitCode" => camel = map.next_value::<serde_json::Value>()?.as_i64(),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(ExitStatus(if snake_seen { snake } else { camel }))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(ExitStatus(None))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(ExitStatus(None))
            }
        }
        deserializer.deserialize_any(StatusVisitor)
    }
}
#[derive(Deserialize)]
struct PostToolUse {
    hook_event_name: String,
    session_id: String,
    turn_id: String,
    cwd: String,
    tool_name: String,
    tool_use_id: String,
    tool_input: ToolInput,
    tool_response: ExitStatus,
    agent_id: Option<IgnoredAny>,
    subagent: Option<IgnoredAny>,
}

pub fn post_tool(bytes: &[u8]) -> Result<Option<Value>, &'static str> {
    project_post_tool(bytes, || crate::key::load().map(|k| k.to_vec()))
}

fn project_post_tool(
    bytes: &[u8],
    key: impl FnOnce() -> Result<Vec<u8>, &'static str>,
) -> Result<Option<Value>, &'static str> {
    if bytes.len() > crate::MAX_FRAME_BYTES {
        return Err("input_too_large");
    }
    let input: PostToolUse = serde_json::from_slice(bytes).map_err(|_| "invalid_hook")?;
    if input.hook_event_name != "PostToolUse" {
        return Err("invalid_hook");
    }
    if !matches!(input.tool_name.as_str(), "Bash" | "shell_command")
        || input.agent_id.is_some()
        || input.subagent.is_some()
    {
        return Ok(None);
    }
    if ![
        input.session_id.as_str(),
        input.turn_id.as_str(),
        input.tool_use_id.as_str(),
        input.cwd.as_str(),
    ]
    .iter()
    .all(|s| crate::bounded(s))
    {
        return Err("invalid_identity");
    }
    let Some(command) = input.tool_input.command.as_deref() else {
        return Ok(None);
    };
    if !crate::bounded(command) {
        return Err("invalid_command");
    }
    let Some(kind) = classify_builtin(command) else {
        return Ok(None);
    };
    let key = zeroize::Zeroizing::new(key()?);
    let command_key = crate::command_key(command, &key)?;
    let exit = input.tool_response.0;
    Ok(Some(json!({
        "session_id": input.session_id, "turn_id":input.turn_id,
        "cwd":input.cwd, "tool_use_id":input.tool_use_id,
        "command_key":command_key,
        "verifier_kind": match kind { ObjectiveVerifierKind::Build => "build", ObjectiveVerifierKind::Test => "test" },
        "outcome":match exit { Some(0)=>"passed", Some(_)=>"failed", None=>"unknown" }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prompt_and_unknown_fields_never_cross_boundary() {
        let input = br#"{"hook_event_name":"UserPromptSubmit","session_id":"task","prompt":"SECRET_PROMPT","other":{"token":"SECRET_TOKEN"}}"#;
        assert_eq!(
            lifecycle(input, false).unwrap(),
            json!({"hook_event_name":"UserPromptSubmit","session_id":"task"})
        );
        assert!(lifecycle(input, true).is_err());
    }
    #[test]
    fn shell_content_is_replaced_with_key_and_exit_outcome() {
        let input = json!({"hook_event_name":"PostToolUse","session_id":"task","turn_id":"turn","cwd":"C:\\work","tool_use_id":"tool","tool_name":"shell_command","tool_input":{"command":"cargo test --token SECRET_ARG"},"tool_response":{"exit_code":0,"output":"SECRET_OUTPUT"}});
        let bytes = serde_json::to_vec(&input).unwrap();
        let _: PostToolUse = serde_json::from_slice(&bytes).unwrap();
        let out = project_post_tool(&bytes, || Ok(vec![7; 32]))
            .unwrap()
            .unwrap();
        assert_eq!(out["outcome"], "passed");
        assert_eq!(
            out["command_key"],
            crate::command_key("cargo test --token SECRET_ARG", &[7; 32]).unwrap()
        );
        assert!(!out.to_string().contains("SECRET"));
        let mut unknown = input.clone();
        unknown["tool_response"] = json!("Exit code: 0 SECRET_OUTPUT");
        assert_eq!(
            project_post_tool(&serde_json::to_vec(&unknown).unwrap(), || Ok(vec![7; 32]))
                .unwrap()
                .unwrap()["outcome"],
            "unknown"
        );
        unknown["tool_input"]["command"] = json!("cargo test; curl secret");
        assert!(
            project_post_tool(&serde_json::to_vec(&unknown).unwrap(), || panic!(
                "must not load key"
            ))
            .unwrap()
            .is_none()
        );
        let mut conflicting = input;
        conflicting["tool_response"] =
            json!({"exit_code":"unknown","exitCode":0,"output":"SECRET_OUTPUT"});
        assert_eq!(
            project_post_tool(&serde_json::to_vec(&conflicting).unwrap(), || Ok(vec![
                7;
                32
            ]))
            .unwrap()
            .unwrap()["outcome"],
            "unknown"
        );
    }
}
