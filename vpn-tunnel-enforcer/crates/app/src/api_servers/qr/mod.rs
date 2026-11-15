//! QR codes from and for phones (RU-2026 item 4). Export: the share key that
//! `Servers::shareable_profile` allows (a provider-hidden key never becomes a QR code), as modules
//! for the page to draw. Import: a picture the user picked or the screen the user asked to read,
//! decoded with rqrr; only texts that can carry a key, a link or a config are kept. Pure Rust, no
//! rights; the decoded texts are keys, so they are never logged.
use std::io::Cursor;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use fast_qr::{ECL, QRBuilder};
use image::imageops::{self, FilterType};
use image::{GenericImage, GenericImageView, GrayImage, ImageFormat, ImageReader, Luma};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_ui::servers::QrCode;

pub(super) mod screen;
#[cfg(test)]
pub(super) mod tests;

/// Largest picture file read for QR codes (a phone photo is a few MB).
pub(super) const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Largest side of a decoded picture: three 4K screens side by side are 11 520 wide.
const MAX_SIDE: u32 = 16_384;

/// The QR code of `text`: error correction M (a phone camera reading a screen), else L when the
/// key is too long for M; longer than any QR code holds -> `app.phones.qr.tooLong`.
pub(super) fn encode(text: &str) -> AppResult<QrCode> {
    for ecl in [ECL::M, ECL::L] {
        if let Ok(qr) = QRBuilder::new(text).ecl(ecl).build() {
            let dark = qr.data[..qr.size * qr.size]
                .iter()
                .map(|module| module.value())
                .collect();
            let size = u32::try_from(qr.size).unwrap_or(u32::MAX);
            return Ok(QrCode { size, dark });
        }
    }
    Err(AppError::validation(Msg::new("app.phones.qr.tooLong")))
}

/// Longest side rqrr reads: larger pictures are scaled down first (a phone photo is about 4000 px
/// and its QR code stays readable; every copy rqrr makes of the picture stays small).
const DECODE_SIDE: u32 = 4096;
/// Time for every pass over one picture (see [`Budgeted`]).
const BUDGET: Duration = Duration::from_secs(4);

/// Texts of the QR codes in a greyscale picture. A second pass reads light-on-dark codes (dark
/// themes show them inverted). `app.phones.qr.slow` when the picture took longer than [`BUDGET`].
pub(super) fn decode_gray(picture: GrayImage) -> AppResult<Vec<String>> {
    decode_until(picture, Instant::now() + BUDGET)
}

pub(super) fn decode_until(picture: GrayImage, deadline: Instant) -> AppResult<Vec<String>> {
    let picture = fit(picture);
    let found = read(picture.clone(), deadline)?;
    if !found.is_empty() {
        return Ok(found);
    }
    let mut inverted = picture;
    image::imageops::invert(&mut inverted);
    read(inverted, deadline)
}

/// `picture` with its longest side at most [`DECODE_SIDE`].
fn fit(picture: GrayImage) -> GrayImage {
    let (width, height) = picture.dimensions();
    let long = width.max(height);
    if long <= DECODE_SIDE {
        return picture;
    }
    let scale = |side: u32| {
        let scaled = u64::from(side) * u64::from(DECODE_SIDE) / u64::from(long);
        u32::try_from(scaled).unwrap_or(DECODE_SIDE).max(1)
    };
    imageops::resize(&picture, scale(width), scale(height), FilterType::Triangle)
}

/// One rqrr pass; the budget's unwind ends it early.
fn read(pixels: GrayImage, deadline: Instant) -> AppResult<Vec<String>> {
    let pass = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut image = rqrr::PreparedImage::prepare(Budgeted { pixels, deadline });
        image
            .detect_grids()
            .into_iter()
            .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
            .collect::<Vec<_>>()
    }));
    match pass {
        Ok(texts) => Ok(texts),
        Err(payload) if payload.is::<OverBudget>() => {
            Err(AppError::validation(Msg::new("app.phones.qr.slow")))
        }
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// The unwind payload that ends a pass past its deadline.
struct OverBudget;

/// The picture rqrr works on. rqrr copies the whole picture for every candidate group of finder
/// patterns, so a picture tiled with finder patterns (a crafted file, a busy screen) runs for
/// minutes to hours (measured: 720 px, 33 s; 800 px, 55 s). Every copy checks the deadline and,
/// past it, unwinds out of rqrr: `resume_unwind` runs no panic hook, so no crash notice either.
struct Budgeted {
    pixels: GrayImage,
    deadline: Instant,
}

impl Clone for Budgeted {
    fn clone(&self) -> Self {
        if Instant::now() >= self.deadline {
            std::panic::resume_unwind(Box::new(OverBudget));
        }
        Self {
            pixels: self.pixels.clone(),
            deadline: self.deadline,
        }
    }
}

impl GenericImageView for Budgeted {
    type Pixel = Luma<u8>;

    fn dimensions(&self) -> (u32, u32) {
        self.pixels.dimensions()
    }

    fn get_pixel(&self, x: u32, y: u32) -> Luma<u8> {
        *self.pixels.get_pixel(x, y)
    }
}

impl GenericImage for Budgeted {
    fn get_pixel_mut(&mut self, x: u32, y: u32) -> &mut Luma<u8> {
        self.pixels.get_pixel_mut(x, y)
    }

    fn put_pixel(&mut self, x: u32, y: u32, pixel: Luma<u8>) {
        self.pixels.put_pixel(x, y, pixel);
    }

    fn blend_pixel(&mut self, x: u32, y: u32, pixel: Luma<u8>) {
        self.pixels.put_pixel(x, y, pixel);
    }
}

/// Picture formats read for QR codes, by magic number. The `image` build carries more decoders
/// (dioxus-desktop turns its default formats on, and Cargo features only add up); EXR, TIFF, HDR
/// and the rest never see bytes from a messenger.
const FORMATS: [ImageFormat; 5] = [
    ImageFormat::Png,
    ImageFormat::Jpeg,
    ImageFormat::Gif,
    ImageFormat::Bmp,
    ImageFormat::WebP,
];

/// Texts of the QR codes in a picture file (PNG, JPEG, GIF, BMP, WebP).
pub(super) fn decode_picture(bytes: &[u8]) -> AppResult<Vec<String>> {
    let unreadable = || AppError::validation(Msg::new("app.phones.qr.unreadable"));
    let format = image::guess_format(bytes)
        .ok()
        .filter(|format| FORMATS.contains(format))
        .ok_or_else(unreadable)?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    reader.limits(limits);
    let picture = reader.decode().map_err(|_| unreadable())?.into_luma8();
    decode_gray(picture)
}

/// The texts that can carry a key, a subscription or a config, one per line for the add dialog
/// (where the user confirms). `app.phones.qr.none`: no QR code at all; `app.phones.qr.nothing`:
/// QR codes, but none of them holds a key or a link (a web page, a payment code).
pub(super) fn importable(texts: Vec<String>) -> AppResult<String> {
    if texts.is_empty() {
        return Err(AppError::validation(Msg::new("app.phones.qr.none")));
    }
    let mut kept: Vec<String> = Vec::new();
    for text in texts {
        let text = text.trim();
        let useful = text.contains("://") || text.starts_with('{') || text.contains("[Interface]");
        if useful && !kept.iter().any(|k| k == text) {
            kept.push(text.to_owned());
        }
    }
    if kept.is_empty() {
        return Err(AppError::validation(Msg::new("app.phones.qr.nothing")));
    }
    Ok(kept.join("\n"))
}
