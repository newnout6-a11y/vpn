//! Windows Firewall leftovers (spec §6.6 step 3, review D4): the old kill switch's
//! `VPNTE-killswitch*` rules and the profile outbound defaults it changed, and sing-box's own
//! `sing-tun (<engine path>)` inbound rules, which sing-tun adds for its system TCP stack and
//! never removes. Rules are only ever deleted, never written.
use std::path::{Path, PathBuf};

use vpnte_winnet::wfp::FwProfile;
use windows::Win32::Foundation::E_ACCESSDENIED;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH, VariantClear};
use windows::core::{BSTR, Interface};

use super::com::Com;
use super::journal::{FirewallJournal, Journals, Outbound};
use super::report::{CleanupReport, Outcome, StepId, StepRecord};

/// Name prefix of every rule the old kill switch wrote (the COM `Name` is the display name, so
/// rules of the older NetSecurity code path match too).
pub(crate) const RULE_PREFIX: &str = "VPNTE-killswitch";
/// File name of the engine in the resources dir of an install.
pub(crate) const ENGINE_EXE: &str = "sing-box.exe";

pub(crate) const PROFILES: [FwProfile; 3] =
    [FwProfile::Domain, FwProfile::Private, FwProfile::Public];

/// A profile's default outbound action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Allow,
    Block,
}

/// `Name` starts with `VPNTE-killswitch`, ordinal ignore case.
pub(crate) fn is_owned_rule(name: &str) -> bool {
    name.get(..RULE_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(RULE_PREFIX))
}

/// `sing-tun (<path>)` for one of our engines: an install's `sing-box.exe` in `engines`, or an
/// old staged copy `<runtime>\<instance>\tun-runtime\vpnte-sing-box.exe`. sing-tun names the
/// rule after `filepath.Abs(argv[0])`, so the path keeps the launcher's spelling: compare
/// ignoring case and a `\\?\` prefix.
pub(crate) fn is_singtun_rule(name: &str, engines: &[PathBuf], runtime: &Path) -> bool {
    let Some(path) = rule_path(name) else {
        return false;
    };
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    if engines
        .iter()
        .any(|e| e.to_str().is_some_and(|e| eq_ci(e, path)))
    {
        return true;
    }
    let Some(root) = runtime.to_str() else {
        return false;
    };
    let root = root.trim_end_matches('\\');
    let rest = match path.get(..root.len()) {
        Some(head) if eq_ci(head, root) => &path[root.len()..],
        _ => return false,
    };
    let parts: Vec<&str> = rest.split('\\').collect();
    matches!(parts.as_slice(), ["", instance, dir, exe]
        if !instance.is_empty() && *instance != "." && *instance != ".."
            && dir.eq_ignore_ascii_case("tun-runtime")
            && exe.eq_ignore_ascii_case("vpnte-sing-box.exe"))
}

/// What to do with the profile defaults (spec §6.6 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProfilePlan {
    /// Legacy strict evidence: every profile now at Block goes back to Allow (B31: the old boot
    /// task set Block without a journal, so saved values cannot be trusted).
    ResetBlocks,
    /// Restore the journal's values (`NotConfigured` → Allow: COM cannot write it and the local
    /// default outbound is Allow).
    Restore(Vec<(FwProfile, Action)>),
    /// Our rules exist without a usable journal: all three to Allow, with a warning.
    AllowAll,
    /// Foreign policy: never touched (a remaining Block is reported by the protection status).
    Untouched,
}

pub(crate) fn plan(
    strict_evidence: bool,
    journal: Option<&FirewallJournal>,
    owned_rules: bool,
) -> ProfilePlan {
    if strict_evidence {
        return ProfilePlan::ResetBlocks;
    }
    if let Some(journal) = journal {
        let restore = journal.profiles.iter().map(|&(profile, saved)| {
            let action = match saved {
                Outbound::Block => Action::Block,
                Outbound::Allow | Outbound::NotConfigured => Action::Allow,
            };
            (profile, action)
        });
        return ProfilePlan::Restore(restore.collect());
    }
    match owned_rules {
        true => ProfilePlan::AllowAll,
        false => ProfilePlan::Untouched,
    }
}

/// The writes `plan` needs given the `current` defaults (unchanged profiles are not written).
pub(crate) fn writes(
    plan: &ProfilePlan,
    current: &[(FwProfile, Action)],
) -> Vec<(FwProfile, Action)> {
    let differs = |&(profile, action): &(FwProfile, Action)| {
        current.iter().any(|&(p, a)| p == profile && a != action)
    };
    let wanted: Vec<(FwProfile, Action)> = match plan {
        ProfilePlan::ResetBlocks | ProfilePlan::AllowAll => {
            PROFILES.iter().map(|&p| (p, Action::Allow)).collect()
        }
        ProfilePlan::Restore(list) => list.clone(),
        ProfilePlan::Untouched => Vec::new(),
    };
    wanted.into_iter().filter(differs).collect()
}

/// Paths compare case-insensitively on Windows.
fn eq_ci(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// Removal rounds before giving up (each round re-enumerates).
const MAX_ROUNDS: usize = 8;

/// The firewall policy object (in-proc COM). Field order: the interface is released before
/// COM is left.
struct Policy {
    policy: INetFwPolicy2,
    _com: Com,
}

impl Policy {
    fn open() -> windows::core::Result<Self> {
        let com = Com::enter(false);
        // SAFETY: COM is initialised on this thread for the lifetime of `com`.
        let policy = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)? };
        Ok(Self { policy, _com: com })
    }

    /// Every rule name, duplicates kept (the old app wrote two rules per loopback name).
    fn rule_names(&self) -> windows::core::Result<Vec<String>> {
        // SAFETY: live interface pointers; each VARIANT is cleared after its dispatch pointer
        // was cloned (AddRef), so nothing leaks or is released twice.
        unsafe {
            let items: IEnumVARIANT = self.policy.Rules()?._NewEnum()?.cast()?;
            let mut names = Vec::new();
            loop {
                let mut slot = [VARIANT::default()];
                let mut fetched = 0u32;
                let hr = items.Next(&mut slot, &mut fetched);
                hr.ok()?;
                if fetched == 0 {
                    break;
                }
                let inner = &slot[0].Anonymous.Anonymous;
                let dispatch = match inner.vt {
                    VT_DISPATCH => (*inner.Anonymous.pdispVal).clone(),
                    _ => None,
                };
                VariantClear(&mut slot[0])?;
                if let Some(rule) = dispatch.and_then(|d| d.cast::<INetFwRule>().ok()) {
                    names.push(rule.Name()?.to_string());
                }
            }
            Ok(names)
        }
    }

    /// Deletes every rule `owned` matches and re-enumerates until none is left: `Remove`
    /// takes a name and several rules may share it.
    fn remove(&self, owned: impl Fn(&str) -> bool) -> Result<usize, String> {
        let mut removed = 0;
        for _ in 0..MAX_ROUNDS {
            let names = self
                .rule_names()
                .map_err(|e| format!("rules unreadable: {e}"))?;
            let names: Vec<String> = names.into_iter().filter(|n| owned(n)).collect();
            if names.is_empty() {
                return Ok(removed);
            }
            // SAFETY: live interface pointer.
            let rules =
                unsafe { self.policy.Rules() }.map_err(|e| format!("rules unreadable: {e}"))?;
            for name in &names {
                // SAFETY: plain COM call; the BSTR outlives it.
                match unsafe { rules.Remove(&BSTR::from(name.as_str())) } {
                    Ok(()) => removed += 1,
                    Err(e) if e.code() == E_ACCESSDENIED => {
                        return Err(format!("removal denied: {e}"));
                    }
                    // Typically the name went with an earlier call; the next round decides.
                    Err(e) => tracing::debug!(error = %e, "firewall rule removal failed"),
                }
            }
        }
        Err("rules still present after repeated removal".into())
    }

    fn outbound(&self, profile: FwProfile) -> windows::core::Result<Action> {
        // SAFETY: live interface pointer; a single profile bit.
        let action = unsafe {
            self.policy
                .get_DefaultOutboundAction(profile_type(profile))?
        };
        Ok(match action {
            NET_FW_ACTION_BLOCK => Action::Block,
            _ => Action::Allow,
        })
    }

    /// Writes and reads back.
    fn set_outbound(&self, profile: FwProfile, action: Action) -> Result<(), String> {
        let value = match action {
            Action::Allow => NET_FW_ACTION_ALLOW,
            Action::Block => NET_FW_ACTION_BLOCK,
        };
        // SAFETY: live interface pointer; a single profile bit and a valid action.
        unsafe {
            self.policy
                .put_DefaultOutboundAction(profile_type(profile), value)
        }
        .map_err(|e| format!("{profile:?}: {e}"))?;
        match self.outbound(profile) {
            Ok(read) if read == action => Ok(()),
            Ok(read) => Err(format!("{profile:?}: reads back {read:?}")),
            Err(e) => Err(format!("{profile:?}: read-back failed: {e}")),
        }
    }
}

fn profile_type(profile: FwProfile) -> NET_FW_PROFILE_TYPE2 {
    match profile {
        FwProfile::Domain => NET_FW_PROFILE2_DOMAIN,
        FwProfile::Private => NET_FW_PROFILE2_PRIVATE,
        FwProfile::Public => NET_FW_PROFILE2_PUBLIC,
    }
}

/// Step 3: profile defaults first, then the old kill switch's rules. Sets the report's
/// Windows Firewall notice flags.
pub(crate) fn clean_kill_switch(journals: &Journals, report: &mut CleanupReport) -> StepRecord {
    let step = StepId::Firewall;
    let failed = |detail: String| StepRecord::new(step, Outcome::Failed, detail);
    let policy = match Policy::open() {
        Ok(p) => p,
        Err(e) => return failed(format!("Windows Firewall unavailable: {e}")),
    };
    let owned = match policy.rule_names() {
        Ok(names) => names.iter().any(|n| is_owned_rule(n)),
        Err(e) => return failed(format!("rules unreadable: {e}")),
    };
    let plan = plan(journals.strict_evidence(), journals.firewall.valid(), owned);
    let mut current = Vec::new();
    for profile in PROFILES {
        match policy.outbound(profile) {
            Ok(action) => current.push((profile, action)),
            Err(e) => return failed(format!("{profile:?} profile unreadable: {e}")),
        }
    }
    let mut done = Vec::new();
    let mut errors = Vec::new();
    for (profile, action) in writes(&plan, &current) {
        match policy.set_outbound(profile, action) {
            Ok(()) => done.push(format!("{profile:?} -> {action:?}")),
            Err(e) => errors.push(e),
        }
    }
    let changed_profiles = !done.is_empty();
    report.firewall_reset |= plan == ProfilePlan::ResetBlocks && changed_profiles;
    report.firewall_allow_all |= plan == ProfilePlan::AllowAll && changed_profiles;
    let mut profiles = match done.is_empty() {
        true => format!("profiles unchanged ({})", plan_name(&plan)),
        false => format!("profiles {} ({})", done.join(", "), plan_name(&plan)),
    };
    if let (ProfilePlan::Restore(_), Some(journal)) = (&plan, journals.firewall.valid())
        && !journal.skipped.is_empty()
    {
        profiles.push_str(&format!("; skipped: {}", journal.skipped.join(", ")));
    }
    if !errors.is_empty() {
        // Keep the rules: removing the old LAN / DHCP / loopback allows under a Block that
        // could not be reset would cut more traffic than it frees.
        let detail = format!("{profiles}; failed: {}; rules kept", errors.join("; "));
        return failed(detail).changed(changed_profiles);
    }
    match policy.remove(is_owned_rule) {
        Ok(removed) => {
            let detail = format!("{profiles}; {removed} {RULE_PREFIX}* rules removed");
            StepRecord::new(step, Outcome::Done, detail).changed(changed_profiles || removed > 0)
        }
        Err(e) => failed(format!("{profiles}; {e}")).changed(changed_profiles),
    }
}

fn plan_name(plan: &ProfilePlan) -> &'static str {
    match plan {
        ProfilePlan::ResetBlocks => "old strict mode: Block reset to Allow",
        ProfilePlan::Restore(_) => "restored from firewall.json",
        ProfilePlan::AllowAll => "rules without a journal: all Allow",
        ProfilePlan::Untouched => "no evidence: left as is",
    }
}

/// sing-box's `sing-tun (<path>)` rules for our engine paths (also run by uninstall). Paths
/// that still exist are compared in their long, canonical spelling too, so a rule named after
/// an 8.3 or differently cased launch path is found.
pub(crate) fn clean_singtun(engines: &[PathBuf], runtime: &Path) -> StepRecord {
    let step = StepId::SingTunRules;
    let mut known = engines.to_vec();
    known.extend(engines.iter().filter_map(|e| long_path(e)));
    let runtimes: Vec<PathBuf> = std::iter::once(runtime.to_path_buf())
        .chain(long_path(runtime))
        .collect();
    let ours = |name: &str| {
        let Some(path) = rule_path(name) else {
            return false;
        };
        // sing-tun names its rule after an absolute path; a relative one would be resolved
        // against our working directory.
        let long = Some(Path::new(path))
            .filter(|p| p.is_absolute())
            .and_then(long_path)
            .map(|p| p.display().to_string());
        std::iter::once(path.to_string()).chain(long).any(|p| {
            let name = format!("sing-tun ({p})");
            runtimes.iter().any(|r| is_singtun_rule(&name, &known, r))
        })
    };
    let removed = Policy::open()
        .map_err(|e| format!("Windows Firewall unavailable: {e}"))
        .and_then(|policy| policy.remove(ours));
    match removed {
        Ok(0) => StepRecord::new(step, Outcome::Done, "no sing-tun rules of our engines"),
        Ok(n) => StepRecord::new(step, Outcome::Done, format!("{n} sing-tun rules removed"))
            .changed(true),
        Err(e) => StepRecord::new(step, Outcome::Failed, e),
    }
}

/// The path inside `sing-tun (<path>)`.
fn rule_path(name: &str) -> Option<&str> {
    name.strip_prefix("sing-tun (")?.strip_suffix(')')
}

/// The long, canonical spelling of an existing local path (`\\?\` removed; network paths are
/// never ours).
pub(crate) fn long_path(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let text = canonical.to_str()?;
    let local = text
        .strip_prefix(r"\\?\")
        .filter(|t| !t.starts_with(r"UNC\"))?;
    Some(PathBuf::from(local))
}

#[cfg(test)]
mod tests;
