#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};

use serde::{Deserialize, Serialize};

/// A single record from a lease event stream.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Event {
    /// Globally increasing event sequence number.
    pub seq: u64,
    /// Event time in Unix milliseconds (or any consistently monotonic millisecond clock).
    pub at_ms: u64,
    /// Logical resource protected by the lease.
    pub resource: String,
    /// Lease transition or protected action.
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Supported lease transitions and protected actions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// Install a new owner with a strictly increasing fencing epoch.
    Grant {
        owner: String,
        epoch: u64,
        lease_until_ms: u64,
    },
    /// Extend the current owner's deadline without changing its epoch.
    Renew {
        owner: String,
        epoch: u64,
        lease_until_ms: u64,
    },
    /// Revoke the current owner and epoch.
    Revoke { owner: String, epoch: u64 },
    /// Record an operation that required a valid lease.
    Action {
        owner: String,
        epoch: u64,
        operation: String,
    },
}

/// Stable machine-readable violation identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    SequenceNotIncreasing,
    TimeWentBackwards,
    EpochNotIncreasing,
    GrantAlreadyExpired,
    RenewWithoutLease,
    RenewWrongOwner,
    RenewWrongEpoch,
    RenewAfterExpiry,
    RenewDidNotExtend,
    RenewDeadlineNotFuture,
    RevokeWithoutLease,
    RevokeWrongOwner,
    RevokeWrongEpoch,
    ActionWithoutLease,
    ActionWrongOwner,
    ActionStaleEpoch,
    ActionFutureEpoch,
    ActionAfterExpiry,
}

impl fmt::Display for FindingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        f.write_str(serialized.as_str().ok_or(fmt::Error)?)
    }
}

/// One rule violation tied to its source line and event identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: FindingCode,
    pub line: usize,
    pub seq: u64,
    pub resource: String,
    pub message: String,
}

/// Complete deterministic audit result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub events_read: usize,
    pub resources_seen: usize,
    pub violations: Vec<Finding>,
}

impl Report {
    /// Returns true when the stream contains no lease safety violations.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Failure to read or decode an input stream.
#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    InvalidJson {
        line: usize,
        source: serde_json::Error,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "could not read event stream: {error}"),
            Self::InvalidJson { line, source } => {
                write!(f, "invalid JSON on non-empty line {line}: {source}")
            }
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidJson { source, .. } => Some(source),
        }
    }
}

impl From<io::Error> for AuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    owner: String,
    epoch: u64,
    until_ms: u64,
}

#[derive(Debug, Default)]
struct ResourceState {
    highest_epoch: Option<u64>,
    active: Option<Lease>,
}

/// Audits newline-delimited JSON lease events in input order.
///
/// Empty lines are ignored. `grace_ms` extends only the time allowed for renewals and actions;
/// it never relaxes owner or epoch matching.
///
/// # Errors
///
/// Returns [`AuditError::Io`] when the stream cannot be read and [`AuditError::InvalidJson`]
/// when a non-empty line is not a complete, valid event.
pub fn audit(reader: impl Read, grace_ms: u64) -> Result<Report, AuditError> {
    let mut states: BTreeMap<String, ResourceState> = BTreeMap::new();
    let mut resources = BTreeSet::new();
    let mut violations = Vec::new();
    let mut events_read = 0;
    let mut previous_seq = None;
    let mut previous_time = None;

    for (zero_based_line, line_result) in BufReader::new(reader).lines().enumerate() {
        let line_number = zero_based_line + 1;
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let event: Event =
            serde_json::from_str(&line).map_err(|source| AuditError::InvalidJson {
                line: line_number,
                source,
            })?;
        events_read += 1;
        resources.insert(event.resource.clone());

        if previous_seq.is_some_and(|seq| event.seq <= seq) {
            push_finding(
                &mut violations,
                &event,
                line_number,
                FindingCode::SequenceNotIncreasing,
                format!(
                    "sequence {} is not greater than previous sequence {}",
                    event.seq,
                    previous_seq.unwrap_or_default()
                ),
            );
        }
        if previous_time.is_some_and(|at_ms| event.at_ms < at_ms) {
            push_finding(
                &mut violations,
                &event,
                line_number,
                FindingCode::TimeWentBackwards,
                format!(
                    "timestamp {} is earlier than previous timestamp {}",
                    event.at_ms,
                    previous_time.unwrap_or_default()
                ),
            );
        }
        previous_seq = Some(event.seq);
        previous_time = Some(event.at_ms);

        let state = states.entry(event.resource.clone()).or_default();
        apply_event(state, &event, line_number, grace_ms, &mut violations);
    }

    Ok(Report {
        events_read,
        resources_seen: resources.len(),
        violations,
    })
}

fn apply_event(
    state: &mut ResourceState,
    event: &Event,
    line: usize,
    grace_ms: u64,
    violations: &mut Vec<Finding>,
) {
    match &event.kind {
        EventKind::Grant {
            owner,
            epoch,
            lease_until_ms,
        } => apply_grant(
            state,
            event,
            line,
            owner,
            *epoch,
            *lease_until_ms,
            violations,
        ),
        EventKind::Renew {
            owner,
            epoch,
            lease_until_ms,
        } => apply_renew(
            state,
            event,
            line,
            owner,
            *epoch,
            *lease_until_ms,
            grace_ms,
            violations,
        ),
        EventKind::Revoke { owner, epoch } => {
            apply_revoke(state, event, line, owner, *epoch, violations);
        }
        EventKind::Action {
            owner,
            epoch,
            operation,
        } => apply_action(
            state, event, line, owner, *epoch, operation, grace_ms, violations,
        ),
    }
}

fn apply_grant(
    state: &mut ResourceState,
    event: &Event,
    line: usize,
    owner: &str,
    epoch: u64,
    lease_until_ms: u64,
    violations: &mut Vec<Finding>,
) {
    let epoch_valid = state.highest_epoch.is_none_or(|highest| epoch > highest);
    let deadline_valid = lease_until_ms > event.at_ms;

    if !epoch_valid {
        push_finding(
            violations,
            event,
            line,
            FindingCode::EpochNotIncreasing,
            format!(
                "grant epoch {epoch} is not greater than highest epoch {}",
                state.highest_epoch.unwrap_or_default()
            ),
        );
    }
    if !deadline_valid {
        push_finding(
            violations,
            event,
            line,
            FindingCode::GrantAlreadyExpired,
            format!(
                "grant deadline {lease_until_ms} is not later than event time {}",
                event.at_ms
            ),
        );
    }

    if epoch_valid {
        state.highest_epoch = Some(epoch);
    }
    if epoch_valid && deadline_valid {
        state.active = Some(Lease {
            owner: owner.to_owned(),
            epoch,
            until_ms: lease_until_ms,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_renew(
    state: &mut ResourceState,
    event: &Event,
    line: usize,
    owner: &str,
    epoch: u64,
    lease_until_ms: u64,
    grace_ms: u64,
    violations: &mut Vec<Finding>,
) {
    let Some(active) = state.active.as_ref() else {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewWithoutLease,
            "renewal has no active lease".to_owned(),
        );
        return;
    };

    let owner_matches = owner == active.owner;
    let epoch_matches = epoch == active.epoch;
    let before_expiry = event.at_ms <= active.until_ms.saturating_add(grace_ms);
    let extends = lease_until_ms > active.until_ms;
    let future_deadline = lease_until_ms > event.at_ms;

    if !owner_matches {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewWrongOwner,
            format!(
                "owner {owner:?} does not match active owner {:?}",
                active.owner
            ),
        );
    }
    if !epoch_matches {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewWrongEpoch,
            format!("epoch {epoch} does not match active epoch {}", active.epoch),
        );
    }
    if !before_expiry {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewAfterExpiry,
            format!(
                "renewal at {} is later than lease deadline {} plus {grace_ms} ms grace",
                event.at_ms, active.until_ms
            ),
        );
    }
    if !extends {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewDidNotExtend,
            format!(
                "renewal deadline {lease_until_ms} does not extend active deadline {}",
                active.until_ms
            ),
        );
    }
    if !future_deadline {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RenewDeadlineNotFuture,
            format!(
                "renewal deadline {lease_until_ms} is not later than event time {}",
                event.at_ms
            ),
        );
    }

    if owner_matches && epoch_matches && before_expiry && extends && future_deadline {
        state
            .active
            .as_mut()
            .expect("active lease checked above")
            .until_ms = lease_until_ms;
    }
}

fn apply_revoke(
    state: &mut ResourceState,
    event: &Event,
    line: usize,
    owner: &str,
    epoch: u64,
    violations: &mut Vec<Finding>,
) {
    let Some(active) = state.active.as_ref() else {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RevokeWithoutLease,
            "revocation has no active lease".to_owned(),
        );
        return;
    };

    let owner_matches = owner == active.owner;
    let epoch_matches = epoch == active.epoch;
    if !owner_matches {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RevokeWrongOwner,
            format!(
                "owner {owner:?} does not match active owner {:?}",
                active.owner
            ),
        );
    }
    if !epoch_matches {
        push_finding(
            violations,
            event,
            line,
            FindingCode::RevokeWrongEpoch,
            format!("epoch {epoch} does not match active epoch {}", active.epoch),
        );
    }
    if owner_matches && epoch_matches {
        state.active = None;
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_action(
    state: &ResourceState,
    event: &Event,
    line: usize,
    owner: &str,
    epoch: u64,
    operation: &str,
    grace_ms: u64,
    violations: &mut Vec<Finding>,
) {
    let Some(active) = state.active.as_ref() else {
        push_finding(
            violations,
            event,
            line,
            FindingCode::ActionWithoutLease,
            format!("operation {operation:?} has no active lease"),
        );
        return;
    };

    if owner != active.owner {
        push_finding(
            violations,
            event,
            line,
            FindingCode::ActionWrongOwner,
            format!(
                "operation {operation:?} owner {owner:?} does not match active owner {:?}",
                active.owner
            ),
        );
    }
    if epoch < active.epoch {
        push_finding(
            violations,
            event,
            line,
            FindingCode::ActionStaleEpoch,
            format!(
                "operation {operation:?} epoch {epoch} is stale; active epoch is {}",
                active.epoch
            ),
        );
    } else if epoch > active.epoch {
        push_finding(
            violations,
            event,
            line,
            FindingCode::ActionFutureEpoch,
            format!(
                "operation {operation:?} epoch {epoch} is ahead of active epoch {}",
                active.epoch
            ),
        );
    }
    if event.at_ms > active.until_ms.saturating_add(grace_ms) {
        push_finding(
            violations,
            event,
            line,
            FindingCode::ActionAfterExpiry,
            format!(
                "operation {operation:?} at {} is later than lease deadline {} plus {grace_ms} ms grace",
                event.at_ms, active.until_ms
            ),
        );
    }
}

fn push_finding(
    findings: &mut Vec<Finding>,
    event: &Event,
    line: usize,
    code: FindingCode,
    message: String,
) {
    findings.push(Finding {
        code,
        line,
        seq: event.seq,
        resource: event.resource.clone(),
        message,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_text(input: &str) -> Report {
        audit(input.as_bytes(), 0).expect("fixture should parse")
    }

    #[test]
    fn accepts_clean_failover_stream() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":100,"resource":"gateway","type":"grant","owner":"a","epoch":7,"lease_until_ms":200}
{"seq":2,"at_ms":120,"resource":"gateway","type":"action","owner":"a","epoch":7,"operation":"dispatch"}
{"seq":3,"at_ms":150,"resource":"gateway","type":"renew","owner":"a","epoch":7,"lease_until_ms":260}
{"seq":4,"at_ms":180,"resource":"gateway","type":"grant","owner":"b","epoch":8,"lease_until_ms":300}
{"seq":5,"at_ms":190,"resource":"gateway","type":"action","owner":"b","epoch":8,"operation":"dispatch"}
"#,
        );

        assert!(report.is_clean());
        assert_eq!(report.events_read, 5);
        assert_eq!(report.resources_seen, 1);
    }

    #[test]
    fn catches_stale_owner_after_failover() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":100,"resource":"gateway","type":"grant","owner":"a","epoch":1,"lease_until_ms":200}
{"seq":2,"at_ms":150,"resource":"gateway","type":"grant","owner":"b","epoch":2,"lease_until_ms":250}
{"seq":3,"at_ms":160,"resource":"gateway","type":"action","owner":"a","epoch":1,"operation":"commit"}
"#,
        );

        let codes: Vec<_> = report
            .violations
            .iter()
            .map(|finding| finding.code)
            .collect();
        assert_eq!(
            codes,
            vec![FindingCode::ActionWrongOwner, FindingCode::ActionStaleEpoch]
        );
    }

    #[test]
    fn catches_action_after_expiry() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":10,"resource":"r","type":"grant","owner":"a","epoch":1,"lease_until_ms":20}
{"seq":2,"at_ms":21,"resource":"r","type":"action","owner":"a","epoch":1,"operation":"write"}
"#,
        );
        assert_eq!(report.violations[0].code, FindingCode::ActionAfterExpiry);
    }

    #[test]
    fn grace_window_is_explicit_and_saturating() {
        let input = r#"{"seq":1,"at_ms":10,"resource":"r","type":"grant","owner":"a","epoch":1,"lease_until_ms":20}
{"seq":2,"at_ms":25,"resource":"r","type":"action","owner":"a","epoch":1,"operation":"write"}
"#;
        assert!(!audit(input.as_bytes(), 4).expect("valid input").is_clean());
        assert!(audit(input.as_bytes(), 5).expect("valid input").is_clean());
    }

    #[test]
    fn rejects_non_increasing_epoch_without_replacing_active_lease() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":10,"resource":"r","type":"grant","owner":"a","epoch":4,"lease_until_ms":30}
{"seq":2,"at_ms":12,"resource":"r","type":"grant","owner":"b","epoch":4,"lease_until_ms":40}
{"seq":3,"at_ms":13,"resource":"r","type":"action","owner":"a","epoch":4,"operation":"write"}
"#,
        );
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].code, FindingCode::EpochNotIncreasing);
    }

    #[test]
    fn invalid_renewal_does_not_extend_lease() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":10,"resource":"r","type":"grant","owner":"a","epoch":1,"lease_until_ms":20}
{"seq":2,"at_ms":15,"resource":"r","type":"renew","owner":"b","epoch":1,"lease_until_ms":30}
{"seq":3,"at_ms":25,"resource":"r","type":"action","owner":"a","epoch":1,"operation":"write"}
"#,
        );
        let codes: Vec<_> = report
            .violations
            .iter()
            .map(|finding| finding.code)
            .collect();
        assert!(codes.contains(&FindingCode::RenewWrongOwner));
        assert!(codes.contains(&FindingCode::ActionAfterExpiry));
    }

    #[test]
    fn revoke_removes_active_lease_but_preserves_epoch_fence() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":10,"resource":"r","type":"grant","owner":"a","epoch":2,"lease_until_ms":40}
{"seq":2,"at_ms":15,"resource":"r","type":"revoke","owner":"a","epoch":2}
{"seq":3,"at_ms":16,"resource":"r","type":"action","owner":"a","epoch":2,"operation":"write"}
{"seq":4,"at_ms":17,"resource":"r","type":"grant","owner":"b","epoch":2,"lease_until_ms":50}
"#,
        );
        assert_eq!(
            report
                .violations
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            vec![
                FindingCode::ActionWithoutLease,
                FindingCode::EpochNotIncreasing
            ]
        );
    }

    #[test]
    fn resources_have_independent_lease_state() {
        let report = audit_text(
            r#"{"seq":1,"at_ms":10,"resource":"a","type":"grant","owner":"node","epoch":1,"lease_until_ms":50}
{"seq":2,"at_ms":11,"resource":"b","type":"grant","owner":"node","epoch":1,"lease_until_ms":50}
{"seq":3,"at_ms":12,"resource":"a","type":"action","owner":"node","epoch":1,"operation":"write"}
{"seq":4,"at_ms":13,"resource":"b","type":"action","owner":"node","epoch":1,"operation":"write"}
"#,
        );
        assert!(report.is_clean());
        assert_eq!(report.resources_seen, 2);
    }

    #[test]
    fn reports_sequence_and_clock_regressions() {
        let report = audit_text(
            r#"{"seq":2,"at_ms":20,"resource":"r","type":"grant","owner":"a","epoch":1,"lease_until_ms":30}
{"seq":2,"at_ms":19,"resource":"r","type":"action","owner":"a","epoch":1,"operation":"write"}
"#,
        );
        assert_eq!(
            report
                .violations
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            vec![
                FindingCode::SequenceNotIncreasing,
                FindingCode::TimeWentBackwards
            ]
        );
    }

    #[test]
    fn malformed_json_reports_physical_line_number() {
        let error = audit("\n{}\n".as_bytes(), 0).expect_err("event is incomplete");
        assert!(error.to_string().contains("line 2"));
    }
}
