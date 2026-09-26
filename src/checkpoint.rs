use rmcp::{model::Meta, schemars::JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct Fact {
    /// Stable proposition identifier. Reuse it while the proposition is unchanged.
    pub fact_key: String,
    /// Concise semantic fact text. It is DPAPI-encrypted before persistence.
    pub text: String,
    /// Prior stable key only when this fact explicitly replaces that proposition.
    pub supersedes_fact_key: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    Accepted,
    Superseded,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct Decision {
    pub fact: Fact,
    pub state: DecisionState,
}

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Continue,
    AwaitUserAction,
    AwaitUserDecision,
    ExternallyBlocked,
    Complete,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct Checkpoint {
    /// Use `phase_transition` only after a real goal/phase change; otherwise periodic.
    pub trigger: String,
    pub current_goal: Fact,
    pub current_phase: Fact,
    /// BCP-47 language tag inferred from the latest user-authored message.
    pub preferred_user_language: String,
    /// Every still-active durable constraint, including user permissions and prohibitions.
    pub active_constraints: Vec<Fact>,
    pub decisions: Vec<Decision>,
    pub verified_completed_work: Vec<Fact>,
    pub files: Vec<Fact>,
    pub checks: Vec<Fact>,
    /// Still-unresolved failures. Must be empty for `complete`; never erase unresolved work to claim completion.
    pub open_failures: Vec<Fact>,
    pub resolved_failures: Vec<Fact>,
    pub unknowns: Vec<Fact>,
    pub do_not_repeat: Vec<Fact>,
    /// Truthful next action for handoff. Use "Await the user's next instruction." when work is complete.
    pub next_expected_step: Fact,
    /// Who or what must act next. `continue` only resumes already-authorized same-task work.
    /// `complete` requires no open failures, including retained failures from the same goal.
    /// Explicitly resolve or supersede genuinely closed failures; omission alone does not resolve them.
    pub next_action_disposition: Disposition,
    /// Exact dependency for user-waiting or externally-blocked dispositions; otherwise omit.
    pub next_action_dependency: Option<Fact>,
}

impl Checkpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.trigger.as_str(), "periodic" | "phase_transition") {
            return Err("invalid_trigger");
        }
        if matches!(self.next_action_disposition, Disposition::Complete)
            && !self.open_failures.is_empty()
        {
            return Err("complete_requires_no_open_failures");
        }
        let waiting = matches!(
            self.next_action_disposition,
            Disposition::AwaitUserAction
                | Disposition::AwaitUserDecision
                | Disposition::ExternallyBlocked
        );
        if waiting != self.next_action_dependency.is_some() {
            return Err("invalid_dependency");
        }
        Ok(())
    }
}

// No arbitrary client metadata, resource URIs, prompts or sampling requests cross this boundary.
pub fn project_meta(meta: &Meta) -> Result<Value, &'static str> {
    let thread = meta
        .0
        .get("threadId")
        .and_then(Value::as_str)
        .filter(|s| crate::bounded(s))
        .ok_or("invalid_identity")?;
    let nested = meta
        .0
        .get("x-codex-turn-metadata")
        .and_then(Value::as_object)
        .ok_or("invalid_identity")?;
    let turn = nested
        .get("turn_id")
        .and_then(Value::as_str)
        .filter(|s| crate::bounded(s))
        .ok_or("invalid_identity")?;
    if nested.get("thread_id").and_then(Value::as_str) != Some(thread)
        || ["parent_thread_id", "subagent_kind"]
            .iter()
            .any(|key| nested.get(*key).is_some_and(|v| !v.is_null()))
    {
        return Err("invalid_identity");
    }
    Ok(json!({"threadId":thread,"x-codex-turn-metadata":{"thread_id":thread,"turn_id":turn}}))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointResult {
    pub checkpoint_recorded: bool,
    pub replayed: bool,
    pub probe_status: Option<String>,
    pub retention_basis_points: Option<u16>,
    pub recommendation_authority: bool,
}

impl CheckpointResult {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.recommendation_authority
            || self.retention_basis_points.is_some_and(|v| v > 10000)
            || self.probe_status.as_deref().is_some_and(|s| {
                !matches!(
                    s,
                    "comparable" | "history_revision_acknowledged" | "incompatible_boundary"
                )
            })
        {
            return Err("invalid_engine_response");
        }
        Ok(())
    }
}
