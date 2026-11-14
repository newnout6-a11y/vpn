//! Table, empty / loading / error states, dialogs and the job slot with fake data.
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_ui::lang::tr;
use vpnte_ui::launch::DemoArgs;
use vpnte_ui::t;

use super::*;

/// One fake row of the table demo.
#[derive(Clone, PartialEq)]
pub(super) struct DemoServer {
    name: &'static str,
    proto: &'static str,
    ping: Option<u32>,
    tone: Tone,
}

pub(super) const SERVERS: [DemoServer; 5] = [
    DemoServer {
        name: "Netherlands · Amsterdam",
        proto: "VLESS",
        ping: Some(38),
        tone: Tone::Ok,
    },
    DemoServer {
        name: "Germany · Frankfurt",
        proto: "Trojan",
        ping: Some(31),
        tone: Tone::Ok,
    },
    DemoServer {
        name: "Poland · Warsaw · PL · HYSTERIA2 · reality-tcp",
        proto: "Hysteria2",
        ping: Some(47),
        tone: Tone::Warn,
    },
    DemoServer {
        name: "Sweden · Stockholm",
        proto: "SS",
        ping: None,
        tone: Tone::Unknown,
    },
    DemoServer {
        name: "USA · New York",
        proto: "VMess",
        ping: None,
        tone: Tone::Fail,
    },
];

pub(super) fn tone_text(tone: Tone) -> String {
    match tone {
        Tone::Ok => t!("ui.widgets.demo.online"),
        Tone::Warn => t!("ui.widgets.demo.warn"),
        Tone::Fail => t!("ui.widgets.demo.offline"),
        Tone::Unknown | Tone::Neutral => t!("ui.widgets.notChecked"),
    }
}

#[component]
pub(super) fn TableDemo() -> Element {
    let mut asc = use_signal(|| true);
    let mut selected = use_signal(|| "Germany · Frankfurt");
    let mut rows = SERVERS.to_vec();
    rows.sort_by_key(|r| r.ping.unwrap_or(u32::MAX));
    if !asc() {
        rows.reverse();
    }
    rsx! {
        Panel { id: "demo-table", title: t!("ui.widgets.demo.table"), flush: true,
            Table { caption: t!("ui.widgets.demo.table"),
                thead {
                    tr {
                        HeadCell { label: t!("ui.widgets.demo.colServer") }
                        HeadCell { label: t!("ui.widgets.demo.colProto"), width: "96px" }
                        HeadCell {
                            label: t!("ui.widgets.demo.colPing"),
                            align: Align::End,
                            sort: Some(if asc() { Sort::Asc } else { Sort::Desc }),
                            on_sort: move |_| asc.toggle(),
                        }
                        HeadCell { label: t!("ui.widgets.demo.colState"), align: Align::End }
                    }
                }
                tbody {
                    for row in rows {
                        tr { key: "{row.name}", class: if selected() == row.name { "is-selected" },
                            Cell { grow: true,
                                button {
                                    r#type: "button",
                                    class: "w-btn is-link",
                                    style: "font:inherit;letter-spacing:inherit;text-transform:none;color:inherit;text-decoration:none;max-width:100%",
                                    onclick: move |_| selected.set(row.name),
                                    Trunc { text: row.name, max: 28 }
                                }
                            }
                            Cell { mono: true, muted: true, "{row.proto}" }
                            Cell { align: Align::End, mono: true,
                                if let Some(ping) = row.ping { "{ping}" } else { "—" }
                            }
                            Cell { align: Align::End,
                                Badge { tone: row.tone, {tone_text(row.tone)} }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn StatesDemo() -> Element {
    // The first read fails, the retry succeeds: shows Loading → Failed → Ready.
    let calls = use_hook(|| std::rc::Rc::new(std::cell::Cell::new(0_u32)));
    let loader = use_load(move || {
        let call = calls.get();
        calls.set(call + 1);
        async move {
            tokio::time::sleep(Duration::from_millis(900)).await;
            if call == 0 {
                Err(AppError::new(ErrorKind::Permission))
            } else {
                Ok(vec![
                    "11.11 12:04 · 94.2 / 41.7",
                    "10.11 21:40 · 88.0 / 39.9",
                ])
            }
        }
    });
    rsx! {
        Panel { id: "demo-states", title: t!("ui.widgets.demo.states"), flush: true,
            Loading { label: t!("ui.widgets.demo.loading") }
            LoadError {
                text: t!("ui.widgets.demo.loadFailed"),
                retry_label: t!("common.retry"),
                on_retry: move |_| {},
            }
            EmptyState {
                title: t!("ui.widgets.demo.empty"),
                detail: t!("ui.widgets.demo.emptyDetail"),
                Button { small: true, kind: ButtonKind::Ghost, {t!("ui.widgets.demo.runTest")} }
            }
            div { id: "demo-live-load",
                {
                    match loader.state() {
                        Load::Loading => rsx! {
                            Loading { label: t!("ui.widgets.demo.loading") }
                        },
                        Load::Failed(err) => rsx! {
                            LoadError {
                                text: tr(&err.msg),
                                retry_label: t!("common.retry"),
                                on_retry: move |_| loader.reload(),
                            }
                        },
                        Load::Ready(lines) => rsx! {
                            for line in lines {
                                div { class: "w-load swiss-mono", "{line}" }
                            }
                        },
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn DialogsDemo() -> Element {
    let toasts = Toasts::use_context();
    let scene = use_context::<DemoArgs>().scene.unwrap_or_default();
    let mut modal = use_signal(|| scene == "modal");
    let mut confirm = use_signal(|| scene == "confirm");
    let mut clearing = use_signal(|| false);
    let mut link = use_signal(String::new);
    let mut proto = use_signal(|| Some("vless"));
    let protocols = vec![
        SelectOption::new("vless", "VLESS"),
        SelectOption::new("trojan", "Trojan"),
        SelectOption::new("ss", "Shadowsocks"),
        SelectOption::new("hy2", "Hysteria2"),
    ];
    rsx! {
        Panel { id: "demo-dialogs", title: t!("ui.widgets.demo.dialogs"),
            div { class: "wd-stack",
                div { class: "wd-line",
                    Button {
                        id: "open-modal",
                        kind: ButtonKind::Ghost,
                        onclick: move |_| modal.set(true),
                        {t!("ui.widgets.demo.openModal")}
                    }
                    Button {
                        id: "open-confirm",
                        kind: ButtonKind::Danger,
                        onclick: move |_| confirm.set(true),
                        {t!("ui.widgets.demo.openConfirm")}
                    }
                }
                div { class: "wd-line",
                    for kind in [ToastKind::Success, ToastKind::Error, ToastKind::Warning, ToastKind::Info] {
                        Button {
                            small: true,
                            kind: ButtonKind::Ghost,
                            id: "toast-{kind.name()}",
                            onclick: move |_| {
                                let (title, desc) = match kind {
                                    ToastKind::Success => (t!("ui.widgets.demo.toastSuccess"), None),
                                    ToastKind::Error => (
                                        t!("ui.widgets.demo.toastError"),
                                        Some(t!("ui.widgets.demo.toastErrorDesc")),
                                    ),
                                    ToastKind::Warning => (t!("ui.widgets.demo.toastWarning"), None),
                                    ToastKind::Info => (t!("ui.widgets.demo.toastInfo"), None),
                                };
                                toasts.push(kind, title, desc);
                            },
                            "{kind.name()}"
                        }
                    }
                }
            }
        }
        Modal {
            open: modal(),
            title: t!("ui.widgets.demo.modalTitle"),
            description: t!("ui.widgets.demo.modalDesc"),
            close_label: t!("common.close"),
            on_close: move |_| modal.set(false),
            footer: rsx! {
                Button { kind: ButtonKind::Ghost, onclick: move |_| modal.set(false), {t!("common.cancel")} }
                Button {
                    onclick: move |_| {
                        modal.set(false);
                        toasts.success(t!("ui.widgets.demo.toastSuccess"), None);
                    },
                    {t!("common.save")}
                }
            },
            div { class: "wd-stack",
                Field { label: t!("ui.widgets.demo.subscription"),
                    TextInput {
                        value: link(),
                        oninput: move |v| link.set(v),
                        mono: true,
                        placeholder: "vless://…",
                        initial_focus: true,
                    }
                }
                Field { label: t!("ui.widgets.demo.colProto"),
                    Select {
                        options: protocols,
                        value: proto(),
                        on_change: move |v| proto.set(Some(v)),
                        placeholder: t!("ui.widgets.choose"),
                    }
                }
            }
        }
        ConfirmDialog {
            open: confirm(),
            title: t!("ui.widgets.demo.confirmTitle"),
            message: t!("ui.widgets.demo.confirmText"),
            confirm_label: t!("ui.widgets.demo.clear"),
            cancel_label: t!("common.cancel"),
            danger: true,
            busy: clearing(),
            on_cancel: move |_| confirm.set(false),
            on_confirm: move |_| {
                clearing.set(true);
                spawn(async move {
                    tokio::time::sleep(Duration::from_millis(900)).await;
                    clearing.set(false);
                    confirm.set(false);
                    toasts.success(t!("ui.widgets.demo.toastSuccess"), None);
                });
            },
        }
    }
}

/// A fake two-second operation that honours its token.
pub(super) async fn fake_job(token: CancellationToken, fail: bool) -> AppResult<u32> {
    tokio::select! {
        () = token.cancelled() => Err(AppError::cancelled()),
        () = tokio::time::sleep(Duration::from_secs(2)) => {
            if fail { Err(AppError::new(ErrorKind::Network)) } else { Ok(42) }
        }
    }
}

#[component]
pub(super) fn JobDemo() -> Element {
    let job = use_job::<u32>();
    let running = job.running();
    let status = if running {
        t!("ui.widgets.demo.jobRunning")
    } else {
        match job.last() {
            None => t!("ui.widgets.demo.jobIdle"),
            Some(Ok(value)) => t!("ui.widgets.demo.jobDone", value = value),
            Some(Err(err)) => tr(&err.msg),
        }
    };
    rsx! {
        Panel { id: "demo-job", title: t!("ui.widgets.demo.job"),
            div { class: "wd-stack",
                div { class: "wd-line",
                    Button {
                        id: "job-start",
                        busy: running,
                        onclick: move |_| job.start(|token| fake_job(token, false)),
                        {t!("ui.widgets.demo.jobStart")}
                    }
                    Button {
                        id: "job-fail",
                        kind: ButtonKind::Ghost,
                        disabled: running,
                        onclick: move |_| job.start(|token| fake_job(token, true)),
                        {t!("ui.widgets.demo.jobFail")}
                    }
                    Button {
                        id: "job-cancel",
                        kind: ButtonKind::Link,
                        disabled: !running,
                        onclick: move |_| job.cancel(),
                        {t!("ui.widgets.demo.jobCancel")}
                    }
                }
                p { id: "job-status", class: "swiss-mono wd-note", "{status}" }
                if running {
                    ProgressBar { value: None, label: t!("ui.widgets.demo.jobRunning") }
                }
            }
        }
    }
}
