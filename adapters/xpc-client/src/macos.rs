use std::{collections::BTreeMap, ffi::CString, fs::File, os::fd::AsRawFd as _, ptr::NonNull};
use vellum_semantic_helper_protocol::{
    SemanticHelperReplyV1, SemanticHelperRequestV1, SemanticHelperSessionPhaseV1,
    SemanticHelperSessionRefV1, SemanticHelperSnapshotDigestV1,
};
use vellum_semantic_helper_wire::{decode_helper_reply_v1, encode_helper_request_v1};

pub const SEMANTIC_HELPER_XPC_SERVICE_NAME_V1: &str = "com.gantbd.vellum.semantic-helper";
const SEMANTIC_HELPER_XPC_TIMEOUT_MILLIS_V1: u64 = 30_000;

#[derive(Clone, Eq, PartialEq)]
pub struct QualifiedSemanticHelperXpcIdentityV1 {
    requirement: CString,
}

impl std::fmt::Debug for QualifiedSemanticHelperXpcIdentityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QualifiedSemanticHelperXpcIdentityV1(<redacted>)")
    }
}

impl QualifiedSemanticHelperXpcIdentityV1 {
    /// Build the sole accepted designated requirement from an Apple Team ID.
    pub fn new(team_id: &str) -> Option<Self> {
        if team_id.len() != 10
            || !team_id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return None;
        }
        let requirement = format!(
            "identifier \"{SEMANTIC_HELPER_XPC_SERVICE_NAME_V1}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team_id}\""
        );
        Some(Self {
            requirement: CString::new(requirement).ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticHelperXpcConnectErrorV1 {
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticHelperXpcExchangeErrorV1 {
    SnapshotCapabilityRequired,
    UnexpectedSnapshotCapability,
    DuplicateSession,
    UnknownSession,
    Encode,
    OutcomeUnknown,
    Fenced,
    InvalidReply,
    ReplyBindingMismatch,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticHelperXpcUsageV1 {
    pub attempts: u64,
    pub replies: u64,
    pub outcome_unknown: u64,
    pub refused: u64,
    pub helper_refusals: u64,
    pub invalid_replies: u64,
    pub request_bytes: u64,
    pub reply_bytes: u64,
    pub counter_saturated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionBinding {
    Starting(SemanticHelperSnapshotDigestV1),
    Ready(SemanticHelperSnapshotDigestV1),
    Uncertain(SemanticHelperSnapshotDigestV1),
    Stopping(SemanticHelperSnapshotDigestV1),
}

impl SessionBinding {
    const fn digest(self) -> SemanticHelperSnapshotDigestV1 {
        match self {
            Self::Starting(value)
            | Self::Ready(value)
            | Self::Uncertain(value)
            | Self::Stopping(value) => value,
        }
    }
}

pub struct SemanticHelperXpcClientV1 {
    native: NativeConnection,
    sessions: BTreeMap<SemanticHelperSessionRefV1, SessionBinding>,
    usage: SemanticHelperXpcUsageV1,
    fenced: bool,
}

impl std::fmt::Debug for SemanticHelperXpcClientV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SemanticHelperXpcClientV1(<redacted>)")
    }
}

impl SemanticHelperXpcClientV1 {
    pub fn connect(
        identity: &QualifiedSemanticHelperXpcIdentityV1,
    ) -> Result<Self, SemanticHelperXpcConnectErrorV1> {
        Ok(Self {
            native: NativeConnection::connect(identity)?,
            sessions: BTreeMap::new(),
            usage: SemanticHelperXpcUsageV1::default(),
            fenced: false,
        })
    }

    pub fn usage(&self) -> SemanticHelperXpcUsageV1 {
        self.usage
    }

    /// Execute exactly one XPC exchange. Transport failure is outcome-unknown
    /// and is never retried by this adapter.
    pub fn exchange(
        &mut self,
        request: &SemanticHelperRequestV1,
        snapshot_directory: Option<&File>,
    ) -> Result<SemanticHelperReplyV1, SemanticHelperXpcExchangeErrorV1> {
        increment(&mut self.usage.attempts, &mut self.usage.counter_saturated);
        if self.fenced {
            return refuse(&mut self.usage, SemanticHelperXpcExchangeErrorV1::Fenced);
        }
        let (session, exchange, expected_snapshot, start) = request_binding(request);
        match (start, snapshot_directory.is_some()) {
            (true, false) => {
                return refuse(
                    &mut self.usage,
                    SemanticHelperXpcExchangeErrorV1::SnapshotCapabilityRequired,
                );
            }
            (false, true) => {
                return refuse(
                    &mut self.usage,
                    SemanticHelperXpcExchangeErrorV1::UnexpectedSnapshotCapability,
                );
            }
            _ => {}
        }
        if start && self.sessions.contains_key(&session) {
            return refuse(
                &mut self.usage,
                SemanticHelperXpcExchangeErrorV1::DuplicateSession,
            );
        }
        if !start && !self.sessions.contains_key(&session) {
            return refuse(
                &mut self.usage,
                SemanticHelperXpcExchangeErrorV1::UnknownSession,
            );
        }
        let previous_binding = self.sessions.get(&session).copied();
        let frame = match encode_helper_request_v1(request) {
            Ok(frame) => frame,
            Err(_) => return refuse(&mut self.usage, SemanticHelperXpcExchangeErrorV1::Encode),
        };
        add(
            &mut self.usage.request_bytes,
            frame.len(),
            &mut self.usage.counter_saturated,
        );
        if start {
            self.sessions
                .insert(session, SessionBinding::Starting(expected_snapshot));
        } else if matches!(request, SemanticHelperRequestV1::Stop { .. }) {
            let digest = self.sessions[&session].digest();
            self.sessions
                .insert(session, SessionBinding::Stopping(digest));
        }
        let reply_frame = match self.native.exchange(&frame, snapshot_directory) {
            Ok(reply) => reply,
            Err(()) => {
                let digest = self.sessions[&session].digest();
                self.sessions
                    .insert(session, SessionBinding::Uncertain(digest));
                increment(
                    &mut self.usage.outcome_unknown,
                    &mut self.usage.counter_saturated,
                );
                self.fenced = true;
                return Err(SemanticHelperXpcExchangeErrorV1::OutcomeUnknown);
            }
        };
        add(
            &mut self.usage.reply_bytes,
            reply_frame.len(),
            &mut self.usage.counter_saturated,
        );
        let reply = match decode_helper_reply_v1(&reply_frame) {
            Ok(reply) => reply,
            Err(_) => {
                let digest = self.sessions[&session].digest();
                self.sessions
                    .insert(session, SessionBinding::Uncertain(digest));
                increment(
                    &mut self.usage.invalid_replies,
                    &mut self.usage.counter_saturated,
                );
                return Err(SemanticHelperXpcExchangeErrorV1::InvalidReply);
            }
        };
        if !reply_matches(&reply, exchange, session, self.sessions[&session].digest()) {
            let digest = self.sessions[&session].digest();
            self.sessions
                .insert(session, SessionBinding::Uncertain(digest));
            increment(
                &mut self.usage.invalid_replies,
                &mut self.usage.counter_saturated,
            );
            return Err(SemanticHelperXpcExchangeErrorV1::ReplyBindingMismatch);
        }
        match &reply {
            SemanticHelperReplyV1::Status {
                phase, snapshot, ..
            } => match phase {
                SemanticHelperSessionPhaseV1::Starting => {
                    self.sessions
                        .insert(session, SessionBinding::Starting(*snapshot));
                }
                SemanticHelperSessionPhaseV1::Ready => {
                    self.sessions
                        .insert(session, SessionBinding::Ready(*snapshot));
                }
                SemanticHelperSessionPhaseV1::Stopping => {
                    self.sessions
                        .insert(session, SessionBinding::Stopping(*snapshot));
                }
                SemanticHelperSessionPhaseV1::Stopped | SemanticHelperSessionPhaseV1::Failed => {
                    self.sessions.remove(&session);
                }
            },
            SemanticHelperReplyV1::Refused { .. } if start => {
                increment(
                    &mut self.usage.helper_refusals,
                    &mut self.usage.counter_saturated,
                );
                self.sessions.remove(&session);
            }
            SemanticHelperReplyV1::Refused { .. } => {
                increment(
                    &mut self.usage.helper_refusals,
                    &mut self.usage.counter_saturated,
                );
                if let Some(previous) = previous_binding {
                    self.sessions.insert(session, previous);
                }
            }
        }
        increment(&mut self.usage.replies, &mut self.usage.counter_saturated);
        Ok(reply)
    }
}

fn request_binding(
    request: &SemanticHelperRequestV1,
) -> (
    SemanticHelperSessionRefV1,
    vellum_semantic_helper_protocol::SemanticHelperExchangeRefV1,
    SemanticHelperSnapshotDigestV1,
    bool,
) {
    match request {
        SemanticHelperRequestV1::Start {
            exchange,
            session,
            snapshot,
            ..
        } => (*session, *exchange, snapshot.digest(), true),
        SemanticHelperRequestV1::Poll { exchange, session }
        | SemanticHelperRequestV1::Stop { exchange, session } => (
            *session,
            *exchange,
            SemanticHelperSnapshotDigestV1::new([1; 32]).unwrap(),
            false,
        ),
    }
}

fn reply_matches(
    reply: &SemanticHelperReplyV1,
    exchange: vellum_semantic_helper_protocol::SemanticHelperExchangeRefV1,
    session: SemanticHelperSessionRefV1,
    snapshot: SemanticHelperSnapshotDigestV1,
) -> bool {
    match reply {
        SemanticHelperReplyV1::Status {
            exchange: actual_exchange,
            session: actual_session,
            snapshot: actual_snapshot,
            ..
        } => {
            *actual_exchange == exchange
                && *actual_session == session
                && *actual_snapshot == snapshot
        }
        SemanticHelperReplyV1::Refused {
            exchange: actual_exchange,
            session: actual_session,
            ..
        } => *actual_exchange == exchange && *actual_session == session,
    }
}

struct NativeConnection(NonNull<std::ffi::c_void>);

impl NativeConnection {
    fn connect(
        identity: &QualifiedSemanticHelperXpcIdentityV1,
    ) -> Result<Self, SemanticHelperXpcConnectErrorV1> {
        let service = CString::new(SEMANTIC_HELPER_XPC_SERVICE_NAME_V1)
            .map_err(|_| SemanticHelperXpcConnectErrorV1::Unavailable)?;
        native::connect(&service, &identity.requirement)
            .map(Self)
            .map_err(|_| SemanticHelperXpcConnectErrorV1::Unavailable)
    }

    fn exchange(&mut self, frame: &[u8], snapshot: Option<&File>) -> Result<Vec<u8>, ()> {
        native::exchange(
            self.0,
            frame,
            snapshot.map_or(-1, |file| file.as_raw_fd()),
            SEMANTIC_HELPER_XPC_TIMEOUT_MILLIS_V1,
        )
    }
}

impl Drop for NativeConnection {
    fn drop(&mut self) {
        native::invalidate(self.0);
    }
}

#[allow(unsafe_code)]
mod native {
    use std::{
        ffi::{CStr, c_char, c_void},
        ptr::NonNull,
        slice,
    };

    unsafe extern "C" {
        #[cfg(test)]
        fn vellum_semantic_helper_xpc_protocol_available() -> i32;
        fn vellum_semantic_helper_xpc_connect(
            service_name: *const c_char,
            code_signing_requirement: *const c_char,
            error_out: *mut i32,
        ) -> *mut c_void;
        fn vellum_semantic_helper_xpc_exchange(
            connection: *mut c_void,
            request_bytes: *const u8,
            request_length: usize,
            snapshot_fd: i32,
            timeout_millis: u64,
            reply_bytes_out: *mut *mut u8,
            reply_length_out: *mut usize,
        ) -> i32;
        fn vellum_semantic_helper_xpc_free_bytes(bytes: *mut u8);
        fn vellum_semantic_helper_xpc_invalidate(connection: *mut c_void);
    }

    #[cfg(test)]
    pub(super) fn protocol_available() -> bool {
        // SAFETY: This takes no pointers and only queries the protocol object
        // emitted by the linked Objective-C bridge translation unit.
        unsafe { vellum_semantic_helper_xpc_protocol_available() == 1 }
    }

    pub(super) fn connect(service: &CStr, requirement: &CStr) -> Result<NonNull<c_void>, ()> {
        let mut error = 0;
        // SAFETY: Both strings are live NUL-terminated inputs and `error` is a
        // valid out pointer for the duration of this synchronous call.
        let pointer = unsafe {
            vellum_semantic_helper_xpc_connect(service.as_ptr(), requirement.as_ptr(), &mut error)
        };
        NonNull::new(pointer).filter(|_| error == 0).ok_or(())
    }

    pub(super) fn exchange(
        connection: NonNull<c_void>,
        request: &[u8],
        snapshot_fd: i32,
        timeout_millis: u64,
    ) -> Result<Vec<u8>, ()> {
        let mut reply = std::ptr::null_mut();
        let mut length = 0_usize;
        // SAFETY: The connection comes from `connect`; request and out pointers
        // remain valid for this synchronous call. The bridge owns its copy.
        let status = unsafe {
            vellum_semantic_helper_xpc_exchange(
                connection.as_ptr(),
                request.as_ptr(),
                request.len(),
                snapshot_fd,
                timeout_millis,
                &mut reply,
                &mut length,
            )
        };
        if status != 0 || (length != 0 && reply.is_null()) {
            return Err(());
        }
        let result = if length == 0 {
            Vec::new()
        } else {
            // SAFETY: A successful bridge call returns exactly `length`
            // initialized bytes allocated by the bridge.
            unsafe { slice::from_raw_parts(reply, length) }.to_vec()
        };
        // SAFETY: The bridge allocated this pointer with `malloc`; NULL is
        // accepted by `free` for an empty reply.
        unsafe { vellum_semantic_helper_xpc_free_bytes(reply) };
        Ok(result)
    }

    pub(super) fn invalidate(connection: NonNull<c_void>) {
        // SAFETY: This consumes the single retained native connection exactly
        // once from `NativeConnection::drop`.
        unsafe { vellum_semantic_helper_xpc_invalidate(connection.as_ptr()) };
    }
}

fn increment(value: &mut u64, saturated: &mut bool) {
    add(value, 1_usize, saturated);
}

fn refuse<T>(
    usage: &mut SemanticHelperXpcUsageV1,
    error: SemanticHelperXpcExchangeErrorV1,
) -> Result<T, SemanticHelperXpcExchangeErrorV1> {
    increment(&mut usage.refused, &mut usage.counter_saturated);
    Err(error)
}

fn add(value: &mut u64, amount: usize, saturated: &mut bool) {
    let amount = u64::try_from(amount).unwrap_or(u64::MAX);
    let (next, overflow) = value.overflowing_add(amount);
    if overflow {
        *value = u64::MAX;
        *saturated = true;
    } else {
        *value = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_fixed_bounded_and_redacted() {
        assert!(native::protocol_available());
        assert!(QualifiedSemanticHelperXpcIdentityV1::new("ABCDE12345").is_some());
        for invalid in ["", "abcde12345", "ABCDE1234-", "ABCDE123456"] {
            assert!(QualifiedSemanticHelperXpcIdentityV1::new(invalid).is_none());
        }
        let identity = QualifiedSemanticHelperXpcIdentityV1::new("ABCDE12345").unwrap();
        let debug = format!("{identity:?}");
        assert!(!debug.contains("ABCDE"));
        assert!(!debug.contains(SEMANTIC_HELPER_XPC_SERVICE_NAME_V1));
    }

    #[test]
    fn reply_binding_requires_exact_exchange_session_and_snapshot() {
        use vellum_semantic_helper_protocol::{
            SemanticHelperExchangeRefV1, SemanticHelperRefusalV1,
        };
        let exchange = SemanticHelperExchangeRefV1::new([1; 16]).unwrap();
        let session = SemanticHelperSessionRefV1::new([2; 16]).unwrap();
        let snapshot = SemanticHelperSnapshotDigestV1::new([3; 32]).unwrap();
        let ready = SemanticHelperReplyV1::Status {
            exchange,
            session,
            snapshot,
            phase: SemanticHelperSessionPhaseV1::Ready,
        };
        assert!(reply_matches(&ready, exchange, session, snapshot));
        assert!(!reply_matches(
            &ready,
            SemanticHelperExchangeRefV1::new([4; 16]).unwrap(),
            session,
            snapshot
        ));
        let refused = SemanticHelperReplyV1::Refused {
            exchange,
            session,
            refusal: SemanticHelperRefusalV1::ProviderFailed,
        };
        assert!(reply_matches(&refused, exchange, session, snapshot));
    }
}
