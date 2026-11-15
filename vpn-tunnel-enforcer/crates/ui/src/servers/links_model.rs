//! View models of links and QR codes from phones and messengers (RU-2026 item 4): the QR code of
//! a key the user asked to show, and who answers each link scheme in Windows.
use std::fmt::Write as _;

/// A QR code as its modules, row by row (`dark[y * size + x]`), without the quiet zone. It is a
/// key in another form: `Debug` prints the size only.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct QrCode {
    pub size: u32,
    pub dark: Vec<bool>,
}

impl std::fmt::Debug for QrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrCode")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl QrCode {
    /// SVG path data in module units: one rectangle per horizontal run of dark modules (a few
    /// hundred commands instead of thousands of squares).
    pub fn path(&self) -> String {
        let size = self.size as usize;
        let mut d = String::new();
        for (y, row) in self.dark.chunks(size.max(1)).enumerate() {
            let mut x = 0;
            while x < row.len() {
                if !row[x] {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < row.len() && row[x] {
                    x += 1;
                }
                let _ = write!(d, "M{start} {y}h{}v1h-{}z", x - start, x - start);
            }
        }
        d
    }
}

/// Who answers a link scheme in Windows for this user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemeOwner {
    /// Nobody: such a link opens nothing.
    Free,
    /// This app.
    Ours,
    /// Another program, named when its registration says which.
    Other(Option<String>),
    /// The program the user picked in Windows (its ProgId): only Windows' settings change it.
    Chosen(String),
}

/// One link scheme of the panel (`vless`, `hiddify`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkScheme {
    pub scheme: String,
    pub owner: SchemeOwner,
}

/// The link panel's data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkSchemes {
    /// Who answers each scheme, in the app's order.
    pub list: Vec<LinkScheme>,
    /// A copy run without installation: it registers links only when the user asks (deleting
    /// its folder would otherwise leave links pointing at nothing).
    pub portable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_of_dark_modules_become_one_rectangle_each() {
        let qr = QrCode {
            size: 3,
            dark: vec![true, true, false, false, false, false, true, false, true],
        };
        assert_eq!(qr.path(), "M0 0h2v1h-2zM0 2h1v1h-1zM2 2h1v1h-1z");
        assert_eq!(QrCode::default().path(), "");
        assert_eq!(format!("{qr:?}"), "QrCode { size: 3, .. }");
    }
}
