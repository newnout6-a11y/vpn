//! The wizard's state machine, free of Dioxus: navigation, the key check (the latest text wins),
//! proxy detection once per session, and the choices «Завершить» sends.
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;

use super::{Connection, KeyCheck, KeyText, LocalProxy, Routing, WizardChoices, WizardDefaults};

/// The screens, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Welcome,
    Connect,
    Routing,
    Protection,
    Done,
}

impl Step {
    pub const ALL: [Step; 5] = [
        Step::Welcome,
        Step::Connect,
        Step::Routing,
        Step::Protection,
        Step::Done,
    ];

    /// Position from 0.
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn next(self) -> Option<Step> {
        Self::ALL.get(self.index() + 1).copied()
    }

    pub fn prev(self) -> Option<Step> {
        self.index().checked_sub(1).map(|i| Self::ALL[i])
    }

    /// Catalog key of the short name in the step ruler.
    pub const fn label_key(self) -> &'static str {
        match self {
            Step::Welcome => "ui.wizard.steps.welcome",
            Step::Connect => "ui.wizard.steps.connect",
            Step::Routing => "ui.wizard.steps.routing",
            Step::Protection => "ui.wizard.steps.protection",
            Step::Done => "ui.wizard.steps.done",
        }
    }
}

/// What the key field knows about its current text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum KeyStatus {
    /// Not checked since the last edit.
    #[default]
    Idle,
    Checking,
    /// The backend found servers in exactly the current text.
    Valid(KeyCheck),
    /// Checked: no usable key in it.
    Invalid,
    /// The check itself failed (network, subscription server); the message says why.
    Failed(Msg),
}

/// Search for another VPN client's local proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Detect {
    #[default]
    NotRun,
    Running,
    Found(LocalProxy),
    NotFound,
    Failed(Msg),
}

/// Everything the wizard shows and will apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub step: Step,
    pub lang: Lang,
    pub connection: Connection,
    pub routing: Routing,
    pub kill_switch: KillSwitchLevel,
    pub autostart: bool,
    /// Servers already in the list.
    pub servers: usize,
    key_text: KeyText,
    key: KeyStatus,
    /// Bumped by every edit and every check: a result for an older text is dropped.
    seq: u64,
    pub detect: Detect,
}

impl Model {
    /// A fresh wizard in `lang`, starting from the current settings.
    pub fn new(lang: Lang, current: &WizardDefaults) -> Self {
        Self {
            step: Step::Welcome,
            lang,
            connection: current.connection,
            routing: current.routing,
            kill_switch: current.kill_switch,
            autostart: current.autostart,
            servers: current.servers,
            key_text: KeyText(String::new()),
            key: KeyStatus::Idle,
            seq: 0,
            detect: Detect::NotRun,
        }
    }

    /// Moves forward; `false` on the last screen.
    pub fn forward(&mut self) -> bool {
        self.step.next().map(|s| self.step = s).is_some()
    }

    /// Moves back; `false` on the first screen.
    pub fn backward(&mut self) -> bool {
        self.step.prev().map(|s| self.step = s).is_some()
    }

    /// Detection runs once per wizard session, on the first visit of the Connect screen.
    pub fn wants_detection(&self) -> bool {
        self.step == Step::Connect && self.detect == Detect::NotRun
    }

    /// Marks a search as started; `false` while one is running.
    pub fn begin_detect(&mut self) -> bool {
        if self.detect == Detect::Running {
            return false;
        }
        self.detect = Detect::Running;
        true
    }

    pub fn end_detect(&mut self, result: Result<Option<LocalProxy>, Msg>) {
        self.detect = match result {
            Ok(Some(proxy)) => Detect::Found(proxy),
            Ok(None) => Detect::NotFound,
            Err(msg) => Detect::Failed(msg),
        };
    }

    pub fn key_text(&self) -> &str {
        &self.key_text.0
    }

    pub fn key_status(&self) -> &KeyStatus {
        &self.key
    }

    /// An edit: the text is no longer the checked one, and a check in flight no longer counts.
    pub fn edit_key(&mut self, text: String) {
        if text == self.key_text.0 {
            return;
        }
        self.key_text = KeyText(text);
        self.key = KeyStatus::Idle;
        self.seq += 1;
    }

    /// Starts a check of the trimmed text: `(seq, text)` for the backend, `None` when the field is
    /// blank or a check is running.
    pub fn begin_check(&mut self) -> Option<(u64, String)> {
        let text = self.key_text.0.trim();
        if text.is_empty() || self.key == KeyStatus::Checking {
            return None;
        }
        let text = text.to_owned();
        self.seq += 1;
        self.key = KeyStatus::Checking;
        Some((self.seq, text))
    }

    /// The backend's answer for check `seq`; ignored when the text changed since.
    pub fn end_check(&mut self, seq: u64, result: Result<KeyCheck, Msg>) {
        if seq != self.seq {
            return;
        }
        self.key = match result {
            Ok(check) if check.servers > 0 => KeyStatus::Valid(check),
            Ok(_) => KeyStatus::Invalid,
            Err(msg) => KeyStatus::Failed(msg),
        };
    }

    /// Text in the field that will NOT be imported (not checked, rejected or failed).
    pub fn key_left_unchecked(&self) -> bool {
        self.connection == Connection::Key
            && !self.key_text.0.trim().is_empty()
            && !matches!(self.key, KeyStatus::Valid(_))
    }

    /// What «Завершить» applies.
    pub fn choices(&self) -> WizardChoices {
        let key = match (self.connection, &self.key) {
            (Connection::Key, KeyStatus::Valid(_)) => {
                Some(KeyText(self.key_text.0.trim().to_owned()))
            }
            _ => None,
        };
        WizardChoices {
            lang: self.lang,
            connection: self.connection,
            routing: self.routing,
            key,
            kill_switch: self.kill_switch,
            autostart: self.autostart,
        }
    }
}
