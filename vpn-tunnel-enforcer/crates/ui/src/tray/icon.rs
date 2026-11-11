//! Tray icon variants generated from the app icon: a coloured status badge in the lower right
//! corner (cut out of the icon so it reads on light and dark taskbars), or the greyed icon when
//! protection is off. The old tray always showed the plain app icon (L-02).
use image::imageops::{self, FilterType};
use image::{ImageFormat, RgbaImage};

use super::model::Badge;

/// Badge colours of the old fallback shield (`tray.ts:52-57`).
const GREEN: [u8; 3] = [0x22, 0xc5, 0x5e];
const AMBER: [u8; 3] = [0xf5, 0x9e, 0x0b];
const RED: [u8; 3] = [0xef, 0x44, 0x44];

/// One image of an `.ico` file.
#[derive(Debug, PartialEq, Eq)]
pub struct IcoEntry<'a> {
    /// Width in px (square icons).
    pub size: u32,
    /// The stored image (PNG in our icon).
    pub data: &'a [u8],
}

/// Reads the directory of an `.ico` file; entries that point outside the file are skipped.
pub fn ico_entries(ico: &[u8]) -> Vec<IcoEntry<'_>> {
    let u16_at = |at: usize| {
        ico.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        ico.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if u16_at(0) != Some(0) || u16_at(2) != Some(1) {
        return Vec::new();
    }
    let count = usize::from(u16_at(4).unwrap_or(0));
    (0..count)
        .filter_map(|i| {
            let at = 6 + 16 * i;
            // 0 in the width byte means 256
            let size = match *ico.get(at)? {
                0 => 256,
                w => u32::from(w),
            };
            let len = usize::try_from(u32_at(at + 8)?).ok()?;
            let offset = usize::try_from(u32_at(at + 12)?).ok()?;
            let data = ico.get(offset..offset.checked_add(len)?)?;
            Some(IcoEntry { size, data })
        })
        .collect()
}

/// The app icon at `size` px: the smallest stored image that is at least that big (an image
/// stored at a small size stays sharper than the 256 px one scaled down), resized when needed.
pub fn base_icon(ico: &[u8], size: u32) -> Option<RgbaImage> {
    let entries = ico_entries(ico);
    let entry = entries
        .iter()
        .filter(|e| e.size >= size)
        .min_by_key(|e| e.size)
        .or_else(|| entries.iter().max_by_key(|e| e.size))?;
    let image = image::load_from_memory_with_format(entry.data, ImageFormat::Png)
        .map_err(|err| tracing::warn!(%err, "tray icon image not decoded"))
        .ok()?
        .to_rgba8();
    if image.width() == size && image.height() == size {
        Some(image)
    } else {
        Some(imageops::resize(&image, size, size, FilterType::Lanczos3))
    }
}

/// The icon for a status colour.
pub fn variant(base: &RgbaImage, badge: Badge) -> RgbaImage {
    match badge {
        Badge::Off => greyed(base),
        Badge::Green => badged(base, GREEN),
        Badge::Amber => badged(base, AMBER),
        Badge::Red => badged(base, RED),
    }
}

/// Luminance only, alpha kept: the icon says "not protecting" without a badge.
fn greyed(base: &RgbaImage) -> RgbaImage {
    let mut out = base.clone();
    for px in out.pixels_mut() {
        let [r, g, b, a] = px.0;
        let luma = (299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b) + 500) / 1000;
        let luma = luma.min(255) as u8;
        px.0 = [luma, luma, luma, a];
    }
    out
}

/// Geometry of the badge for an icon of `size` px: centre, disc radius, cut-out ring width.
fn badge_geometry(size: u32) -> (f32, f32, f32) {
    let size = size as f32;
    let radius = size * 0.25;
    let ring = (size / 16.0).max(1.0);
    let centre = size - radius;
    (centre, radius, ring)
}

/// Fraction of the pixel `(x, y)` inside the disc around `(c, c)` (4×4 supersampling).
fn coverage(x: u32, y: u32, c: f32, radius: f32) -> f32 {
    const N: u32 = 4;
    let mut inside = 0;
    for sy in 0..N {
        for sx in 0..N {
            let px = x as f32 + (sx as f32 + 0.5) / N as f32 - c;
            let py = y as f32 + (sy as f32 + 0.5) / N as f32 - c;
            if px * px + py * py <= radius * radius {
                inside += 1;
            }
        }
    }
    inside as f32 / (N * N) as f32
}

/// Draws the badge disc with a transparent ring around it (premultiplied compositing).
fn badged(base: &RgbaImage, colour: [u8; 3]) -> RgbaImage {
    let mut out = base.clone();
    let (c, radius, ring) = badge_geometry(base.width());
    let outer = radius + ring;
    let first = (c - outer).floor().max(0.0) as u32;
    for y in first..out.height() {
        for x in first..out.width() {
            let cut = coverage(x, y, c, outer);
            if cut == 0.0 {
                continue;
            }
            let disc = coverage(x, y, c, radius);
            let [r, g, b, a] = out.get_pixel(x, y).0;
            let keep = (f32::from(a) / 255.0) * (1.0 - cut) * (1.0 - disc);
            let alpha = disc + keep;
            let mix = |base: u8, badge: u8| {
                if alpha <= 0.0 {
                    return 0;
                }
                let v = (f32::from(badge) * disc + f32::from(base) * keep) / alpha;
                v.round().clamp(0.0, 255.0) as u8
            };
            let px = [
                mix(r, colour[0]),
                mix(g, colour[1]),
                mix(b, colour[2]),
                (alpha * 255.0).round().clamp(0.0, 255.0) as u8,
            ];
            out.put_pixel(x, y, image::Rgba(px));
        }
    }
    out
}

/// Size of a notification-area icon in px: the small-icon metric at the system DPI, which is the
/// DPI the taskbar draws at (16 at 100 %, 32 at 200 %).
pub fn tray_icon_size() -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSMICON};
    // SAFETY: no pointers; returns 0 on failure.
    let px = unsafe { GetSystemMetrics(SM_CXSMICON) };
    u32::try_from(px).unwrap_or(0).clamp(16, 64)
}

/// The four icon variants, made once from the embedded app icon.
pub struct TrayIcons {
    icons: Vec<(Badge, dioxus::desktop::trayicon::Icon)>,
}

impl TrayIcons {
    /// Variants at `size` px from `assets/icon.ico` (the same file as the exe's icon resource).
    pub fn new(size: u32) -> Option<TrayIcons> {
        let ico = crate::assets::file("icon.ico")?;
        let base = base_icon(ico, size)?;
        let icons = [Badge::Off, Badge::Green, Badge::Amber, Badge::Red]
            .into_iter()
            .filter_map(|badge| {
                let image = variant(&base, badge);
                let icon = dioxus::desktop::trayicon::Icon::from_rgba(image.into_raw(), size, size)
                    .map_err(|err| tracing::warn!(%err, ?badge, "tray icon variant rejected"))
                    .ok()?;
                Some((badge, icon))
            })
            .collect();
        Some(TrayIcons { icons })
    }

    /// The icon for `badge`.
    pub fn get(&self, badge: Badge) -> Option<dioxus::desktop::trayicon::Icon> {
        self.icons
            .iter()
            .find(|(b, _)| *b == badge)
            .map(|(_, icon)| icon.clone())
    }
}

/// A variant as PNG bytes (the demo page shows them).
pub fn variant_png(badge: Badge, size: u32) -> Option<Vec<u8>> {
    let base = base_icon(crate::assets::file("icon.ico")?, size)?;
    let mut png = std::io::Cursor::new(Vec::new());
    variant(&base, badge)
        .write_to(&mut png, ImageFormat::Png)
        .map_err(|err| tracing::warn!(%err, "tray icon PNG not encoded"))
        .ok()?;
    Some(png.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ico() -> &'static [u8] {
        include_bytes!("../../assets/icon.ico")
    }

    #[test]
    fn reads_the_app_icon_directory() {
        let sizes: Vec<u32> = ico_entries(ico()).iter().map(|e| e.size).collect();
        assert_eq!(sizes, [16, 32, 48, 64, 128, 256]);
        assert!(
            ico_entries(ico())
                .iter()
                .all(|e| e.data.starts_with(b"\x89PNG"))
        );
        // not an icon / truncated entries
        assert!(ico_entries(b"\x89PNG\r\n\x1a\n").is_empty());
        let mut cut = ico()[..6 + 16].to_vec();
        cut[4] = 1;
        assert!(ico_entries(&cut).is_empty());
    }

    #[test]
    fn picks_the_nearest_stored_size() {
        for size in [16, 20, 24, 32, 40, 48, 64] {
            let image = base_icon(ico(), size).expect("decodes");
            assert_eq!(image.dimensions(), (size, size));
        }
        // 300 px is bigger than every entry: the 256 px image is scaled up
        assert_eq!(base_icon(ico(), 300).expect("decodes").width(), 300);
    }

    #[test]
    fn badge_is_drawn_into_a_cut_out_corner() {
        let base = base_icon(ico(), 32).expect("decodes");
        let red = variant(&base, Badge::Red);
        let (c, radius, ring) = badge_geometry(32);
        // badge centre carries the colour, fully opaque
        let centre = red.get_pixel(c as u32, c as u32).0;
        assert_eq!(centre, [RED[0], RED[1], RED[2], 255]);
        // inside the ring the icon is cut out: the opaque purple tile is transparent there
        let ring_x = (c - radius - ring / 2.0) as u32;
        assert_eq!(base.get_pixel(ring_x, c as u32).0[3], 255);
        assert!(red.get_pixel(ring_x, c as u32).0[3] < 128);
        // the top left quarter is untouched
        for y in 0..16 {
            for x in 0..16 {
                assert_eq!(red.get_pixel(x, y), base.get_pixel(x, y));
            }
        }
        // every colour gets its own badge
        assert_eq!(
            variant(&base, Badge::Green).get_pixel(c as u32, c as u32).0,
            [GREEN[0], GREEN[1], GREEN[2], 255]
        );
        assert_eq!(
            variant(&base, Badge::Amber).get_pixel(c as u32, c as u32).0,
            [AMBER[0], AMBER[1], AMBER[2], 255]
        );
    }

    #[test]
    fn off_is_the_grey_icon() {
        let base = base_icon(ico(), 16).expect("decodes");
        let grey = variant(&base, Badge::Off);
        for (g, b) in grey.pixels().zip(base.pixels()) {
            let [r, gr, bl, a] = g.0;
            assert_eq!((r, a), (gr, b.0[3]));
            assert_eq!(r, bl);
        }
    }

    #[test]
    fn variants_encode_as_png() {
        let png = variant_png(Badge::Amber, 32).expect("encodes");
        assert!(png.starts_with(b"\x89PNG"));
        let back = image::load_from_memory(&png).expect("decodes").to_rgba8();
        assert_eq!(back.dimensions(), (32, 32));
    }
}
