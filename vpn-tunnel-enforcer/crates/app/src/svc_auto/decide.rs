//! The coordinator's pure rules: the session as automation sees it, owner admission on top of
//! the lane, and the lane's answers in automation's terms.
use vpnte_automation::coordinator::{
    ConnectRequest, OpError, ProxyEndpoint, RuntimeId, SessionInfo, SessionKind,
};
use vpnte_base::types::Owner;
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::{ConnError, ConnectTarget, SessionView, StopCause};

/// The lane's session in automation's terms: capture (TUN / system proxy) x upstream (a server
/// of the list / a local proxy). A rebuilt session whose server is unknown has no profile.
pub fn session_info(view: &SessionView) -> SessionInfo {
    let server = view.server_id();
    let kind = match view.mode {
        SessionMode::Hard => SessionKind::LocalProxyHard,
        SessionMode::Direct => SessionKind::Direct,
        SessionMode::Soft if server.is_some() => SessionKind::SoftDirect,
        SessionMode::Soft => SessionKind::Soft,
    };
    SessionInfo {
        kind,
        owner: view.owner,
        profile_id: server.map(str::to_owned),
        runtime_id: RuntimeId(view.generation.unwrap_or(0)),
        mode: view.adaptive,
    }
}

/// What a connect does with the session that runs now (`Coordinator` contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Nothing runs: start.
    Start,
    /// The very session runs: nothing restarts; a higher caller takes it over.
    Already { adopt: bool },
    /// Another server of the same kind: a protected switch keeps the capture.
    Switch,
    /// Another kind of session: stop it, then start.
    Replace,
    /// The running session's owner is higher.
    Refuse,
}

pub fn admit_connect(session: Option<&SessionInfo>, owner: Owner, req: &ConnectRequest) -> Admit {
    let Some(s) = session else {
        return Admit::Start;
    };
    let same_kind = s.kind == req.kind();
    if same_kind && s.profile_id.as_deref() == req.profile_id() {
        return Admit::Already {
            adopt: owner > s.owner,
        };
    }
    if owner < s.owner {
        Admit::Refuse
    } else if same_kind && s.kind.server() {
        Admit::Switch
    } else {
        Admit::Replace
    }
}

/// `Ok(true)`: stop the session; `Ok(false)`: nothing runs; a lower owner never stops a higher
/// owner's session.
pub fn admit_disconnect(session: Option<&SessionInfo>, owner: Owner) -> Result<bool, OpError> {
    match session {
        None => Ok(false),
        Some(s) if owner < s.owner => Err(OpError::Conflict),
        Some(_) => Ok(true),
    }
}

/// Why `owner` stops a session (history outcome).
pub fn stop_cause(owner: Owner) -> StopCause {
    match owner {
        Owner::Manual => StopCause::User,
        Owner::Schedule => StopCause::Schedule,
        _ => StopCause::Preempted,
    }
}

/// The lane target of a request; a local proxy is already resolved (`endpoint`).
pub fn target(req: &ConnectRequest, endpoint: Option<&ProxyEndpoint>) -> Option<ConnectTarget> {
    let local = endpoint.map(|ep| (ep.addr.to_string(), ep.kind));
    Some(match req {
        ConnectRequest::Direct { profile_id } => ConnectTarget::DirectVpn {
            profile_id: Some(profile_id.clone()),
        },
        ConnectRequest::SoftDirect { profile_id } => ConnectTarget::SoftVpn {
            profile_id: Some(profile_id.clone()),
        },
        ConnectRequest::LocalProxyHard { .. } => {
            let (addr, kind) = local?;
            ConnectTarget::LocalProxy { addr, kind }
        }
        ConnectRequest::Soft { .. } => {
            let (addr, kind) = local?;
            ConnectTarget::Soft { addr, kind }
        }
    })
}

/// The session kind a lane target produces.
pub fn target_kind(target: &ConnectTarget) -> SessionKind {
    match target {
        ConnectTarget::DirectVpn { .. } => SessionKind::Direct,
        ConnectTarget::SoftVpn { .. } => SessionKind::SoftDirect,
        ConnectTarget::LocalProxy { .. } => SessionKind::LocalProxyHard,
        ConnectTarget::Soft { .. } => SessionKind::Soft,
    }
}

/// The lane's refusal or failure in automation's terms.
pub fn op_error(err: ConnError) -> OpError {
    match err {
        ConnError::Refused(_) => OpError::Conflict,
        ConnError::NoServer(_) => OpError::ProfileUnavailable,
        ConnError::Cancelled(_) => OpError::Cancelled,
        ConnError::Timeout(_) => OpError::Timeout,
        ConnError::Failed(e) => OpError::Failed(e.into()),
    }
}
