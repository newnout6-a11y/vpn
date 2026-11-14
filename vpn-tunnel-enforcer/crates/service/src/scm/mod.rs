//! The Service Control Manager: registration ([`manage`]) and running as a service
//! ([`dispatch`]). Choice recorded: the `windows` crate directly (no `windows-service`
//! dependency): the handful of SCM calls are small and already covered by the workspace's
//! `windows` build.

pub mod dispatch;
pub mod manage;

#[cfg(test)]
mod tests {
    use super::manage::{command_line, exe_of_command_line};
    use std::path::Path;

    #[test]
    fn the_command_line_is_quoted_and_parses_back() {
        let exe = Path::new(r"C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe");
        let line = command_line(exe);
        assert_eq!(
            line,
            r#""C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe" run"#
        );
        assert_eq!(exe_of_command_line(&line).as_deref(), Some(exe));
        assert_eq!(exe_of_command_line(r"C:\unquoted.exe run"), None);
    }
}
