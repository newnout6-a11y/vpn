//! Per-user link schemes (`vless://`, `sing-box://`, …) under `HKCU\Software\Classes`: a link
//! opened in a browser or a messenger starts `"<exe>" --open-link "<link>"`. Free schemes are
//! taken without asking (installer, first start); a scheme another program answers is taken only
//! when the user asks, and that program's per-user key is kept aside and put back when ours goes.
//! A record (`HKCU\Software\VPN Tunnel Enforcer\LinkSchemes`: one value per scheme = the exact
//! command we wrote) lets the uninstaller and the toggle remove exactly what we wrote. Per user:
//! no rights needed (NOADMIN §3), HKLM is only read. *Blocking* (registry), fast.
use std::path::Path;

use crate::registry::{self, Access, Hive, Key, View};

/// Link schemes the app opens: share links of the protocols it runs, then [`CLIENT_SCHEMES`].
pub const SCHEMES: [&str; 14] = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "sing-box",
    "clash",
    "v2raytun",
    "hiddify",
    "happ",
    "incy",
];

/// Other clients' import links (`sing-box://import-remote-profile`, `clash://install-config`,
/// `v2raytun://import/`, `hiddify://import/`, `happ://add/`, `incy://`): providers' «add to
/// Happ» buttons then work on a PC without that client. Taken by default only while free and
/// given back when the client registers machine-wide later (Happ writes HKLM, which our
/// per-user key would hide from this user); one the user took on purpose stays ours.
pub const CLIENT_SCHEMES: [&str; 6] = ["sing-box", "clash", "v2raytun", "hiddify", "happ", "incy"];

/// The flag our registered command hands the link over with (the app's `args`).
pub const OPEN_LINK_FLAG: &str = "--open-link";

/// The record of what this user's copies registered.
const RECORD: &str = r"Software\VPN Tunnel Enforcer\LinkSchemes";
/// Under the record: other programs' per-user keys we replaced on the user's request.
const PREVIOUS: &str = "Previous";
/// Under the record: one value per client scheme we hold only while its client is absent.
const WHILE_FREE: &str = "WhileFree";
/// Under the record: one value per scheme this user's record has offered (taken then when it was
/// free); a scheme added to [`SCHEMES`] later is new to the record (psmall-b7).
const OFFERED: &str = "Offered";
/// Schemes added after the first records were written (29c9e26): a record without [`OFFERED`]
/// has offered every other one.
const ADDED_LATER: [&str; 2] = ["happ", "incy"];
/// The user's handler choices for URL schemes (read only: Windows protects them with a hash).
const CHOICES: &str = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations";

/// Who answers a scheme now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// Nobody: a link of this scheme opens nothing.
    Free,
    /// We do (this copy or another copy of the app that we recorded).
    Ours,
    /// Another program; its name when the registration names one (`Happ`, `Hiddify`).
    Other(Option<String>),
    /// The program the user picked in Windows' chooser (`UserChoice` ProgId): Windows reaches no
    /// class key then, so only the user can change it, in Windows' default-apps settings.
    Chosen(String),
}

/// What [`Registrar::take`] achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Took {
    /// Links of the scheme open this app now.
    Ours,
    /// The user's Windows choice keeps the scheme with this program (its ProgId); nothing was
    /// written.
    Chosen(String),
}

/// One scheme and who answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeState {
    pub scheme: &'static str,
    pub owner: Owner,
}

/// What [`Registrar::ensure`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ensured {
    /// Free schemes registered now (the first run for this user).
    pub registered: Vec<&'static str>,
    /// Our schemes pointed at this exe again (it moved, or an upgrade replaced it).
    pub repointed: usize,
    /// Client schemes given back: their client registered machine-wide since we took them free.
    pub released: Vec<&'static str>,
}

impl Ensured {
    /// Something was written or removed: Explorer should hear of it.
    pub fn changed(&self) -> bool {
        !self.registered.is_empty() || self.repointed > 0 || !self.released.is_empty()
    }
}

/// Where the keys live; [`Registrar::current_user`] in the app, a throw-away key in tests.
#[derive(Debug, Clone)]
pub struct Registrar {
    /// HKCU path of the per-user classes (`Software\Classes`).
    classes: String,
    /// The machine-wide classes, only read (`HKLM\Software\Classes`).
    machine: (Hive, String),
    /// HKCU path of the record.
    record: String,
    /// HKCU path of the user's protocol choices (`…\Shell\Associations\UrlAssociations`).
    choices: String,
    /// The real classes: Explorer is told about changes ([`Registrar::notify_shell`]).
    shell: bool,
}

impl Registrar {
    /// This user's classes and record; machine-wide registrations are read from HKLM.
    pub fn current_user() -> Self {
        Self {
            classes: r"Software\Classes".into(),
            machine: (Hive::LocalMachine, r"Software\Classes".into()),
            record: RECORD.into(),
            choices: CHOICES.into(),
            shell: true,
        }
    }

    /// Everything under one HKCU key: `<root>\Classes`, `<root>\Machine` (stands in for HKLM),
    /// `<root>\Record` and `<root>\Choices`. For tests: never point it at the real classes.
    pub fn under(root: &str) -> Self {
        Self {
            classes: format!(r"{root}\Classes"),
            machine: (Hive::CurrentUser, format!(r"{root}\Machine")),
            record: format!(r"{root}\Record"),
            choices: format!(r"{root}\Choices"),
            shell: false,
        }
    }

    /// The command line registered for `exe`; `%1` is the link Windows fills in.
    pub fn command(exe: &Path) -> String {
        format!("\"{}\" {OPEN_LINK_FLAG} \"%1\"", exe.display())
    }

    /// `true` once this user ran the first registration (the record exists, even empty): later
    /// starts and installs respect what the user turned off.
    pub fn initialized(&self) -> windows::core::Result<bool> {
        Ok(open(Hive::CurrentUser, &self.record)?.is_some())
    }

    /// Who answers each of [`SCHEMES`], in that order.
    pub fn states(&self, exe: &Path) -> windows::core::Result<Vec<SchemeState>> {
        SCHEMES
            .iter()
            .map(|&scheme| {
                Ok(SchemeState {
                    scheme,
                    owner: self.owner(scheme, exe)?,
                })
            })
            .collect()
    }

    /// Who answers `scheme`: the program the user picked in Windows' chooser (its `UserChoice`
    /// wins over every class key, so a registration of ours would not be reached), else the
    /// class keys ([`Registrar::class_owner`]).
    pub fn owner(&self, scheme: &str, exe: &Path) -> windows::core::Result<Owner> {
        match self.user_choice(scheme) {
            Some(prog_id) => Ok(Owner::Chosen(prog_id)),
            None => self.class_owner(scheme, exe),
        }
    }

    /// Who the class keys name: our recorded command (or this exe's command) in the per-user key
    /// is ours; any other per-user key, or a machine-wide one, is another program's.
    fn class_owner(&self, scheme: &str, exe: &Path) -> windows::core::Result<Owner> {
        if let Some(key) = open(Hive::CurrentUser, &self.scheme_path(scheme))? {
            let command = command_of(&key);
            return Ok(if self.is_ours(scheme, command.as_deref(), exe)? {
                Owner::Ours
            } else {
                Owner::Other(owner_name(&key, command.as_deref()))
            });
        }
        match self.machine_key(scheme)? {
            Some(key) => Ok(Owner::Other(owner_name(&key, command_of(&key).as_deref()))),
            None => Ok(Owner::Free),
        }
    }

    /// The machine-wide registration of `scheme` (only read: another program's).
    fn machine_key(&self, scheme: &str) -> windows::core::Result<Option<Key>> {
        let (hive, root) = &self.machine;
        open(*hive, &format!(r"{root}\{scheme}"))
    }

    /// `command` (of a per-user key or a saved one) is the one we recorded, or this exe's.
    fn is_ours(
        &self,
        scheme: &str,
        command: Option<&str>,
        exe: &Path,
    ) -> windows::core::Result<bool> {
        let Some(command) = command else {
            return Ok(false);
        };
        Ok(command.eq_ignore_ascii_case(&Self::command(exe))
            || self.recorded(scheme)?.as_deref() == Some(command))
    }

    fn scheme_path(&self, scheme: &str) -> String {
        format!(r"{}\{scheme}", self.classes)
    }

    /// The ProgId the user chose for `scheme` when it names another handler than the scheme's
    /// own class key (a classic registration chosen there records the scheme itself). Unreadable
    /// counts as no choice: the class keys then decide.
    fn user_choice(&self, scheme: &str) -> Option<String> {
        let path = format!(r"{}\{scheme}\UserChoice", self.choices);
        let prog_id = open(Hive::CurrentUser, &path)
            .ok()??
            .string("ProgId")
            .ok()??;
        let prog_id = prog_id.trim();
        (!prog_id.is_empty() && !prog_id.eq_ignore_ascii_case(scheme)).then(|| prog_id.to_owned())
    }

    fn previous_path(&self, scheme: &str) -> String {
        format!(r"{}\{PREVIOUS}\{scheme}", self.record)
    }

    /// The command we recorded for `scheme`.
    fn recorded(&self, scheme: &str) -> windows::core::Result<Option<String>> {
        match open(Hive::CurrentUser, &self.record)? {
            Some(record) => record.string(scheme),
            None => Ok(None),
        }
    }
}

fn open(hive: Hive, path: &str) -> windows::core::Result<Option<Key>> {
    Key::open(hive, path, Access::Read, View::Native)
}

fn create(path: &str) -> windows::core::Result<Key> {
    Key::create(Hive::CurrentUser, path, View::Native).map(|(key, _)| key)
}

fn delete_tree(path: &str) -> windows::core::Result<bool> {
    registry::delete_tree(Hive::CurrentUser, path, View::Native)
}

impl Registrar {
    /// The first run for this user (installer or app start) registers every free scheme (and
    /// records a key of this exe left without a record, so uninstall finds it); later runs point
    /// our schemes at `exe` again (an upgrade, a moved portable copy) and register only schemes
    /// new to the record (added by an upgrade) that are free, so what the user turned off stays
    /// off. A client scheme taken while free goes back to its client once that registered
    /// machine-wide ([`Registrar::give_back`]).
    pub fn ensure(&self, exe: &Path) -> windows::core::Result<Ensured> {
        if !self.initialized()? {
            return self.adopt(exe);
        }
        let mut done = Ensured {
            released: self.give_back(exe)?,
            ..Ensured::default()
        };
        for scheme in self.new_schemes()? {
            if self.owner(scheme, exe)? == Owner::Free {
                self.write(scheme, exe)?;
                self.mark_while_free(scheme)?;
                done.registered.push(scheme);
            }
        }
        self.mark_offered()?;
        let command = Self::command(exe);
        for scheme in self.recorded_schemes()? {
            let current = open(Hive::CurrentUser, &self.scheme_path(&scheme))?;
            let current = current.as_ref().and_then(command_of);
            if self.class_owner(&scheme, exe)? == Owner::Ours
                && current.as_deref() != Some(&command)
            {
                self.write(&scheme, exe)?;
                done.repointed += 1;
            }
        }
        Ok(done)
    }

    /// Client schemes taken only while free go back to their client once it registered
    /// machine-wide (Happ writes HKLM, which our per-user key would hide from this user); one the
    /// user took on purpose stays ours. Cheap reads: run at start, when the links panel is read
    /// and when a client's link arrives, so a client installed while the app runs gets its links
    /// at once, portable copies included (psmall-b6). The schemes given back.
    pub fn give_back(&self, exe: &Path) -> windows::core::Result<Vec<&'static str>> {
        let mut released = Vec::new();
        for scheme in CLIENT_SCHEMES {
            if self.while_free(scheme)?
                && self.class_owner(scheme, exe)? == Owner::Ours
                && self.machine_key(scheme)?.is_some()
            {
                self.remove(scheme, exe)?;
                released.push(scheme);
            }
        }
        Ok(released)
    }

    /// Every free scheme and every scheme of ours opens `exe` from now on (the first run, or a
    /// portable copy's «open links here»); other programs' schemes stay theirs.
    pub fn adopt(&self, exe: &Path) -> windows::core::Result<Ensured> {
        // A client that registered machine-wide since gets its scheme back first.
        let mut done = Ensured {
            released: self.give_back(exe)?,
            ..Ensured::default()
        };
        create(&self.record)?;
        self.mark_offered()?;
        let command = Self::command(exe);
        for scheme in SCHEMES {
            match self.owner(scheme, exe)? {
                Owner::Free => {
                    self.write(scheme, exe)?;
                    self.mark_while_free(scheme)?;
                    done.registered.push(scheme);
                }
                Owner::Ours => {
                    let current = open(Hive::CurrentUser, &self.scheme_path(scheme))?;
                    let moved = current.as_ref().and_then(command_of).as_deref() != Some(&command);
                    // Rewritten also when unchanged: an unrecorded key of this exe gets its record.
                    self.write(scheme, exe)?;
                    done.repointed += usize::from(moved);
                }
                Owner::Other(_) | Owner::Chosen(_) => {}
            }
        }
        Ok(done)
    }

    /// Registers `scheme` for `exe` on the user's request, also when another program's class key
    /// names it: that program's per-user key is kept aside and put back by
    /// [`Registrar::unregister`]; a machine-wide one needs nothing kept (ours overrides it for
    /// this user only). A Windows choice of another program is the user's to change in Windows:
    /// nothing is written then ([`Took::Chosen`]; Windows would not reach a class key anyway).
    pub fn take(&self, scheme: &str, exe: &Path) -> windows::core::Result<Took> {
        let scheme = known(scheme)?;
        if let Some(prog_id) = self.user_choice(scheme) {
            return Ok(Took::Chosen(prog_id));
        }
        let path = self.scheme_path(scheme);
        let previous = self.previous_path(scheme);
        let class = self.class_owner(scheme, exe)?;
        create(&self.record)?;
        match open(Hive::CurrentUser, &path)? {
            // Another program's per-user key: the newest one is what comes back.
            Some(theirs) if class != Owner::Ours => {
                delete_tree(&previous)?;
                copy_tree(&theirs, &previous)?;
                drop(theirs);
                delete_tree(&path)?;
            }
            Some(_) => {}
            // No per-user key: a key kept from an earlier take belongs to a program that removed
            // its registration since; bringing it back later would revive a dead handler.
            None => {
                delete_tree(&previous)?;
            }
        }
        self.write(scheme, exe)?;
        // Taken on purpose: no longer given back when its client turns up.
        self.unmark(scheme)?;
        Ok(Took::Ours)
    }

    /// Removes our registration of `scheme` (recorded, or carrying this exe's command) and puts
    /// back the key we replaced. A registration another program made since stays (only our
    /// record of it goes). `false`: nothing of ours.
    pub fn unregister(&self, scheme: &str, exe: &Path) -> windows::core::Result<bool> {
        self.remove(known(scheme)?, exe)
    }

    /// [`Registrar::unregister`] for a name that is a valid scheme, also one this build does not
    /// list (a newer version recorded it).
    fn remove(&self, scheme: &str, exe: &Path) -> windows::core::Result<bool> {
        let path = self.scheme_path(scheme);
        let current = open(Hive::CurrentUser, &path)?;
        let ours = self.is_ours(
            scheme,
            current.as_ref().and_then(command_of).as_deref(),
            exe,
        )?;
        drop(current);
        if !ours && self.recorded(scheme)?.is_none() {
            return Ok(false);
        }
        let previous = self.previous_path(scheme);
        if ours {
            delete_tree(&path)?;
            if let Some(saved) = open(Hive::CurrentUser, &previous)?
                && !self.is_ours(scheme, command_of(&saved).as_deref(), exe)?
            {
                copy_tree(&saved, &path)?;
            }
        }
        // Kept for a key the other program has replaced again meanwhile: outdated either way.
        delete_tree(&previous)?;
        self.forget(scheme)?;
        Ok(ours)
    }

    /// Uninstall of the copy at `exe`: removes the schemes recorded for it (another copy's stay)
    /// and the record once nothing is left in it. Answers the schemes removed.
    pub fn unregister_for(&self, exe: &Path) -> windows::core::Result<Vec<String>> {
        let command = Self::command(exe);
        let mut removed = Vec::new();
        for scheme in self.recorded_schemes()? {
            let mine = self
                .recorded(&scheme)?
                .is_some_and(|c| c.eq_ignore_ascii_case(&command));
            if !mine {
                continue;
            }
            // A name only a newer version lists is still ours to remove; a value that is no
            // scheme name addresses no class key, so only the value goes.
            if !valid_scheme(&scheme) {
                self.forget(&scheme)?;
            } else if self.remove(&scheme, exe)? {
                removed.push(scheme);
            }
        }
        let empty = match open(Hive::CurrentUser, &self.record)? {
            Some(record) => {
                let previous = record.open_subkey(PREVIOUS, Access::Read)?;
                record.value_names()?.iter().all(String::is_empty)
                    && previous.map_or(Ok(true), |p| p.is_empty())?
            }
            None => false,
        };
        if empty {
            delete_tree(&self.record)?;
            // `Software\VPN Tunnel Enforcer` holds nothing else of ours.
            if let Some((parent, _)) = self.record.rsplit_once('\\')
                && open(Hive::CurrentUser, parent)?.map_or(Ok(false), |k| k.is_empty())?
            {
                registry::delete_key(Hive::CurrentUser, parent, View::Native)?;
            }
        }
        Ok(removed)
    }

    /// Writes our key for `scheme` (any older key of ours goes first). The record is written
    /// before the key: an interrupted write then leaves nothing unrecorded behind.
    fn write(&self, scheme: &str, exe: &Path) -> windows::core::Result<()> {
        let command = Self::command(exe);
        create(&self.record)?.set_string(scheme, &command)?;
        let path = self.scheme_path(scheme);
        delete_tree(&path)?;
        let key = create(&path)?;
        key.set_string("", &format!("URL:{scheme} link"))?;
        key.set_string("URL Protocol", "")?;
        create(&format!(r"{path}\DefaultIcon"))?
            .set_string("", &format!("\"{}\",0", exe.display()))?;
        create(&format!(r"{path}\shell\open\command"))?.set_string("", &command)
    }

    /// Schemes the record lists (value names; the default value is not one).
    fn recorded_schemes(&self) -> windows::core::Result<Vec<String>> {
        let Some(record) = open(Hive::CurrentUser, &self.record)? else {
            return Ok(Vec::new());
        };
        Ok(record
            .value_names()?
            .into_iter()
            .filter(|name| !name.is_empty())
            .collect())
    }
}

impl Registrar {
    /// Drops the record value `name` and its while-free mark (nothing else).
    fn forget(&self, name: &str) -> windows::core::Result<()> {
        if let Some(record) = Key::open(
            Hive::CurrentUser,
            &self.record,
            Access::ReadWrite,
            View::Native,
        )? {
            record.delete_value(name)?;
        }
        self.unmark(name)
    }

    fn while_free_path(&self) -> String {
        format!(r"{}\{WHILE_FREE}", self.record)
    }

    /// A client scheme just taken because it was free is held only while it stays so.
    fn mark_while_free(&self, scheme: &str) -> windows::core::Result<()> {
        if CLIENT_SCHEMES.contains(&scheme) {
            create(&self.while_free_path())?.set_string(scheme, "")?;
        }
        Ok(())
    }

    fn offered_path(&self) -> String {
        format!(r"{}\{OFFERED}", self.record)
    }

    /// Schemes of [`SCHEMES`] this user's record has not offered yet.
    fn new_schemes(&self) -> windows::core::Result<Vec<&'static str>> {
        let Some(offered) = open(Hive::CurrentUser, &self.offered_path())? else {
            return Ok(ADDED_LATER.to_vec());
        };
        let mut new = Vec::new();
        for scheme in SCHEMES {
            if offered.string(scheme)?.is_none() {
                new.push(scheme);
            }
        }
        Ok(new)
    }

    fn mark_offered(&self) -> windows::core::Result<()> {
        let offered = create(&self.offered_path())?;
        SCHEMES
            .iter()
            .try_for_each(|scheme| offered.set_string(scheme, ""))
    }

    /// `scheme` was taken only because it was free (a client scheme at the first run).
    fn while_free(&self, scheme: &str) -> windows::core::Result<bool> {
        Ok(match open(Hive::CurrentUser, &self.while_free_path())? {
            Some(marks) => marks.string(scheme)?.is_some(),
            None => false,
        })
    }

    fn unmark(&self, scheme: &str) -> windows::core::Result<()> {
        let path = self.while_free_path();
        if let Some(marks) = Key::open(Hive::CurrentUser, &path, Access::ReadWrite, View::Native)? {
            marks.delete_value(scheme)?;
        }
        Ok(())
    }
}

/// RFC 3986 scheme syntax: a letter, then letters, digits, `+`, `-`, `.` (so never a path).
fn valid_scheme(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Only [`SCHEMES`] are ever written: a name from the UI never addresses another class key.
fn known(scheme: &str) -> windows::core::Result<&'static str> {
    SCHEMES
        .into_iter()
        .find(|s| s.eq_ignore_ascii_case(scheme))
        .ok_or_else(|| windows::Win32::Foundation::E_INVALIDARG.into())
}

/// Copies every value and subkey of `from` to the HKCU key `to` (created).
fn copy_tree(from: &Key, to: &str) -> windows::core::Result<()> {
    let target = create(to)?;
    for name in from.value_names()? {
        if let Some(value) = from.value(&name)? {
            target.set(&name, &value)?;
        }
    }
    for name in from.subkey_names()? {
        if let Some(child) = from.open_subkey(&name, Access::Read)? {
            copy_tree(&child, &format!(r"{to}\{name}"))?;
        }
    }
    Ok(())
}

impl Registrar {
    /// Tells Explorer and open file dialogs that associations changed (after a change of the
    /// real classes; a test registrar has nothing to refresh).
    pub fn notify_shell(&self) {
        use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
        if self.shell {
            // SAFETY: an event without items; no pointers are passed.
            unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
        }
    }
}

#[cfg(test)]
mod tests;

/// `shell\open\command` of a scheme key. Another program's key may hold anything: a value of an
/// unexpected type reads as "no command" (the key then counts as that program's, untouched).
fn command_of(key: &Key) -> Option<String> {
    let command = key
        .open_subkey(r"shell\open\command", Access::Read)
        .ok()??;
    command.string("").ok().flatten()
}

/// The program a registration names: the file stem of the command's program (`Happ`), else the
/// key's description without its `URL:` prefix (`Hiddify Protocol`).
fn owner_name(key: &Key, command: Option<&str>) -> Option<String> {
    let program = command.and_then(|c| {
        let c = c.trim_start();
        let path = match c.strip_prefix('"') {
            Some(rest) => rest.split('"').next(),
            None => c.split_whitespace().next(),
        }?;
        let stem = Path::new(path)
            .file_stem()?
            .to_string_lossy()
            .trim()
            .to_owned();
        (!stem.is_empty()).then_some(stem)
    });
    program.or_else(|| {
        let text = key.string("").ok().flatten()?;
        let text = text.trim();
        let text = text.strip_prefix("URL:").unwrap_or(text).trim();
        (!text.is_empty()).then(|| text.to_owned())
    })
}
