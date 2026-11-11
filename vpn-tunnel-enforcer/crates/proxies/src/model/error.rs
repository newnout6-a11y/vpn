//! The error of every proxy operation: an HTTP-like category plus the English `detail` the
//! control API returns verbatim (its CLI and automation clients match on these texts).
use vpnte_base::{AppError, ErrorKind, Msg};

/// Failure of a proxy operation. The `String` is the wire `detail`; it never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    /// 400: bad input (the old `RangeError`).
    #[error("{0}")]
    BadRequest(String),
    /// 403: unknown or expired lease token.
    #[error("{0}")]
    Forbidden(String),
    /// 404.
    #[error("{0}")]
    NotFound(String),
    /// 409: a lease, a busy slot or port.
    #[error("{0}")]
    Conflict(String),
    /// 503: no free healthy route.
    #[error("{0}")]
    Unavailable(String),
    /// A failed server-group health check, with the status of its category.
    #[error("{1}")]
    Upstream(u16, String),
    /// 500: engine spawn, readiness or endpoint resolution failed.
    #[error("{0}")]
    Engine(String),
}

impl ProxyError {
    /// HTTP status of the control API response.
    pub fn http_status(&self) -> u16 {
        match self {
            ProxyError::BadRequest(_) => 400,
            ProxyError::Forbidden(_) => 403,
            ProxyError::NotFound(_) => 404,
            ProxyError::Conflict(_) => 409,
            ProxyError::Unavailable(_) => 503,
            ProxyError::Upstream(status, _) => *status,
            ProxyError::Engine(_) => 500,
        }
    }

    /// `error` field of the JSON error body.
    pub fn code(&self) -> &'static str {
        match self.http_status() {
            409 => "conflict",
            403 => "forbidden",
            _ => "external-proxy-error",
        }
    }

    /// The wire text (`detail` of the JSON body, the whole body in text mode).
    pub fn detail(&self) -> &str {
        match self {
            ProxyError::BadRequest(d)
            | ProxyError::Forbidden(d)
            | ProxyError::NotFound(d)
            | ProxyError::Conflict(d)
            | ProxyError::Unavailable(d)
            | ProxyError::Upstream(_, d)
            | ProxyError::Engine(d) => d,
        }
    }

    /// Maps a failed group health check the way the old API did: a validation fault means "no
    /// such group or it is empty" (404); any other category keeps its status with the generic
    /// message of the category, never the cause (it can carry paths or OS text).
    pub fn group_health(kind: ErrorKind) -> Self {
        // Wire texts of the old `ipcError(category)` (Russian by default); clients match on them.
        let (status, text) = match kind {
            ErrorKind::Validation => (404, "Группа не найдена или пуста"),
            ErrorKind::Conflict => (409, "Операция недоступна в текущем состоянии"),
            ErrorKind::Permission => (403, "Недостаточно прав для операции"),
            ErrorKind::Network => (502, "Сетевая операция не выполнена"),
            ErrorKind::Internal => (500, "Не удалось выполнить операцию"),
            ErrorKind::Cancelled => (409, "Операция отменена"),
            ErrorKind::Timeout => (504, "Истекло время выполнения операции"),
        };
        ProxyError::Upstream(status, text.into())
    }

    fn app_kind(&self) -> ErrorKind {
        match self.http_status() {
            400 | 403 | 404 => ErrorKind::Validation,
            409 | 503 => ErrorKind::Conflict,
            502 => ErrorKind::Network,
            504 => ErrorKind::Timeout,
            _ => ErrorKind::Internal,
        }
    }

    fn i18n_key(&self) -> &'static str {
        match self {
            ProxyError::BadRequest(_) => "proxies.error.badRequest",
            ProxyError::Forbidden(_) => "proxies.error.forbidden",
            ProxyError::NotFound(_) => "proxies.error.notFound",
            ProxyError::Conflict(_) => "proxies.error.conflict",
            ProxyError::Unavailable(_) => "proxies.error.unavailable",
            ProxyError::Upstream(..) => "proxies.error.upstream",
            ProxyError::Engine(_) => "proxies.error.engine",
        }
    }
}

/// For the UI: a localized sentence per category with the wire text as `{{detail}}` (the old
/// card showed the same backend text under its own headline).
impl From<ProxyError> for AppError {
    fn from(err: ProxyError) -> Self {
        let msg = Msg::new(err.i18n_key()).arg("detail", err.detail());
        AppError::msg(err.app_kind(), msg).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-00-004 (spec external-proxy §7.1): group health faults keep their category as an HTTP
    /// status and never expose the raw cause.
    #[test]
    fn group_health_faults_map_to_statuses() {
        let e = ProxyError::group_health(ErrorKind::Conflict);
        assert_eq!((e.http_status(), e.code()), (409, "conflict"));
        assert_eq!(e.detail(), "Операция недоступна в текущем состоянии");
        let e = ProxyError::group_health(ErrorKind::Permission);
        assert_eq!((e.http_status(), e.code()), (403, "forbidden"));
        assert_eq!(e.detail(), "Недостаточно прав для операции");
        let e = ProxyError::group_health(ErrorKind::Validation);
        assert_eq!((e.http_status(), e.code()), (404, "external-proxy-error"));
        assert_eq!(e.detail(), "Группа не найдена или пуста");
        for (kind, status) in [
            (ErrorKind::Network, 502),
            (ErrorKind::Internal, 500),
            (ErrorKind::Cancelled, 409),
            (ErrorKind::Timeout, 504),
        ] {
            assert_eq!(ProxyError::group_health(kind).http_status(), status);
        }
    }

    #[test]
    fn statuses_codes_and_app_errors() {
        let cases = [
            (
                ProxyError::BadRequest("b".into()),
                400,
                "external-proxy-error",
            ),
            (ProxyError::Forbidden("f".into()), 403, "forbidden"),
            (
                ProxyError::NotFound("n".into()),
                404,
                "external-proxy-error",
            ),
            (ProxyError::Conflict("c".into()), 409, "conflict"),
            (
                ProxyError::Unavailable("u".into()),
                503,
                "external-proxy-error",
            ),
            (ProxyError::Engine("e".into()), 500, "external-proxy-error"),
        ];
        for (err, status, code) in cases {
            assert_eq!((err.http_status(), err.code()), (status, code));
        }
        let app: AppError = ProxyError::Conflict("Slot 2 is already leased".into()).into();
        assert_eq!(app.kind, ErrorKind::Conflict);
        let msg = app.user_msg();
        assert_eq!(msg.key, "proxies.error.conflict");
        assert_eq!(msg.args[0].1, "Slot 2 is already leased");
        let app: AppError = ProxyError::Engine("x".into()).into();
        assert_eq!(app.kind, ErrorKind::Internal);
        assert_eq!(ProxyError::Upstream(504, "t".into()).to_string(), "t");
    }

    /// AT-09-011 (ru/en parity): the fragment is valid JSON, both languages have the same keys,
    /// every key used here exists and keeps the `{{detail}}` placeholder.
    #[test]
    fn locale_fragments_cover_every_error_key() {
        fn leaves(prefix: &str, v: &serde_json::Value, out: &mut Vec<(String, String)>) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, v) in map {
                        let key = if prefix.is_empty() {
                            k.clone()
                        } else {
                            format!("{prefix}.{k}")
                        };
                        leaves(&key, v, out);
                    }
                }
                other => out.push((prefix.to_owned(), other.as_str().unwrap_or("").to_owned())),
            }
        }
        let read = |text: &str| {
            let v: serde_json::Value = serde_json::from_str(text).unwrap();
            let mut out = Vec::new();
            leaves("", &v, &mut out);
            out.sort();
            out
        };
        let ru = read(include_str!("../../locales/proxies-model.ru.json"));
        let en = read(include_str!("../../locales/proxies-model.en.json"));
        let names = |l: &[(String, String)]| l.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
        assert_eq!(names(&ru), names(&en));
        for (_, text) in ru.iter().chain(&en) {
            assert!(text.contains("{{detail}}"), "{text}");
        }
        let all = [
            ProxyError::BadRequest(String::new()),
            ProxyError::Forbidden(String::new()),
            ProxyError::NotFound(String::new()),
            ProxyError::Conflict(String::new()),
            ProxyError::Unavailable(String::new()),
            ProxyError::Upstream(500, String::new()),
            ProxyError::Engine(String::new()),
        ];
        assert_eq!(all.len(), ru.len());
        for err in all {
            assert!(
                names(&ru).iter().any(|k| k == err.i18n_key()),
                "{}",
                err.i18n_key()
            );
        }
    }
}
