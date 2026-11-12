//! QR round trips with obvious fake keys (RU-2026 item 4): encode, draw, decode; pictures in
//! memory; the filter of what reaches the add dialog.
use super::*;

/// An obvious fake key (all-zero UUID, RFC 2606 host).
pub(in crate::api_servers) const KEY: &str = "vless://00000000-0000-4000-8000-000000000000@qr.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00&type=tcp#Phone%20test";

/// `qr` drawn as a square greyscale picture: `scale` pixels per module and the 4-module quiet
/// zone; dark modules black (white when `inverted`, on black). Answers the side and the pixels.
pub(in crate::api_servers) fn draw(qr: &QrCode, scale: usize, inverted: bool) -> (usize, Vec<u8>) {
    let size = qr.size as usize;
    let side = (size + 8) * scale;
    let (dark, light) = if inverted { (255, 0) } else { (0, 255) };
    let mut luma = vec![light; side * side];
    for (i, _) in qr.dark.iter().enumerate().filter(|(_, d)| **d) {
        let (x, y) = (i % size + 4, i / size + 4);
        for dy in 0..scale {
            let row = (y * scale + dy) * side;
            luma[row + x * scale..row + (x + 1) * scale].fill(dark);
        }
    }
    (side, luma)
}

fn key_of(err: AppError) -> String {
    err.user_msg().key.into_owned()
}

/// Decodes a greyscale picture given as rows of bytes.
fn decode_luma(width: usize, height: usize, luma: &[u8]) -> Vec<String> {
    let (w, h) = (
        u32::try_from(width).unwrap(),
        u32::try_from(height).unwrap(),
    );
    decode_gray(GrayImage::from_raw(w, h, luma.to_vec()).unwrap()).unwrap()
}

#[test]
fn a_key_survives_encode_and_decode() {
    let qr = encode(KEY).unwrap();
    assert!(qr.size >= 21);
    assert_eq!(qr.dark.len(), (qr.size * qr.size) as usize);
    let (side, luma) = draw(&qr, 4, false);
    assert_eq!(decode_luma(side, side, &luma), [KEY]);
}

/// Dark themes show codes light on dark: the second pass reads them.
#[test]
fn light_on_dark_codes_are_read_too() {
    let (side, luma) = draw(&encode(KEY).unwrap(), 4, true);
    assert_eq!(decode_luma(side, side, &luma), [KEY]);
}

/// A key too long for correction level M still fits at L; beyond any QR code it is refused.
#[test]
fn long_keys_use_low_correction_and_longer_ones_are_refused() {
    let long = format!(
        "vless://00000000-0000-4000-8000-000000000000@h.example:443#{}",
        "a".repeat(2400)
    );
    let qr = encode(&long).unwrap();
    // Version 40 at M holds 2331 bytes: this key needed the fallback to L.
    assert!(QRBuilder::new(long.as_str()).ecl(ECL::M).build().is_err());
    let (side, luma) = draw(&qr, 3, false);
    assert_eq!(decode_luma(side, side, &luma), [long]);
    assert_eq!(
        key_of(encode(&"a".repeat(3000)).unwrap_err()),
        "app.phones.qr.tooLong"
    );
}

/// Screenshots (PNG) and phone photos (JPEG, lossy) decode; anything else is refused politely.
#[test]
fn picture_files_round_trip() {
    let (side, luma) = draw(&encode(KEY).unwrap(), 4, false);
    let side = u32::try_from(side).unwrap();
    let picture = image::GrayImage::from_raw(side, side, luma).unwrap();
    for format in [image::ImageFormat::Png, image::ImageFormat::Jpeg] {
        let mut bytes = Vec::new();
        picture
            .write_to(&mut Cursor::new(&mut bytes), format)
            .unwrap();
        assert_eq!(decode_picture(&bytes).unwrap(), [KEY], "{format:?}");
    }
    let refused = decode_picture(b"not a picture").unwrap_err();
    assert_eq!(key_of(refused), "app.phones.qr.unreadable");
}

/// Two codes on one screen are both read.
#[test]
fn every_code_of_a_picture_is_read() {
    let other = "trojan://fake-password@two.example.com:443?sni=two.example.com#Two";
    let (side_a, a) = draw(&encode(KEY).unwrap(), 4, false);
    let (side_b, b) = draw(&encode(other).unwrap(), 4, false);
    let (width, height) = (side_a + side_b, side_a.max(side_b));
    let mut luma = vec![255u8; width * height];
    for y in 0..height {
        if y < side_a {
            luma[y * width..y * width + side_a].copy_from_slice(&a[y * side_a..(y + 1) * side_a]);
        }
        if y < side_b {
            let row = y * width + side_a;
            luma[row..row + side_b].copy_from_slice(&b[y * side_b..(y + 1) * side_b]);
        }
    }
    let mut found = decode_luma(width, height, &luma);
    found.sort();
    let mut expected = vec![KEY.to_owned(), other.to_owned()];
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn only_texts_that_can_carry_a_key_reach_the_dialog() {
    assert_eq!(
        key_of(importable(Vec::new()).unwrap_err()),
        "app.phones.qr.none"
    );
    let noise = vec!["WIFI:T:WPA;S:cafe;P:x;;".to_owned(), "hello".to_owned()];
    assert_eq!(
        key_of(importable(noise).unwrap_err()),
        "app.phones.qr.nothing"
    );
    let texts = [
        " vless://a@b.example:1#x ",
        "hello",
        "vless://a@b.example:1#x",
        "[Interface]\nPrivateKey = x",
        r#"{"outbounds":[]}"#,
        "https://sub.example/s",
    ];
    let kept = importable(texts.iter().map(|t| (*t).to_owned()).collect()).unwrap();
    assert_eq!(
        kept,
        "vless://a@b.example:1#x\n[Interface]\nPrivateKey = x\n{\"outbounds\":[]}\nhttps://sub.example/s"
    );
}

/// The capture reads the screens without any rights; a session without a desktop (a service)
/// fails with its own message instead of a fake empty picture.
#[test]
fn the_screen_can_be_read() {
    match screen::capture() {
        Ok(shot) => assert!(shot.width() > 0 && shot.height() > 0),
        Err(err) => assert_eq!(key_of(err), "app.phones.qr.screenFailed"),
    }
}

/// A picture tiled with finder patterns and no QR code: rqrr tries every pair of neighbours
/// (2 px modules, 30 px pitch, the reviewers' probe).
fn finder_lattice(n: u32) -> GrayImage {
    let mut picture = GrayImage::from_pixel(n * 30, n * 30, Luma([255]));
    for (cx, cy) in (0..n).flat_map(|i| (0..n).map(move |j| (i * 30 + 4, j * 30 + 4))) {
        for (mx, my) in (0..7).flat_map(|x| (0..7).map(move |y| (x, y))) {
            let ring = mx == 0 || my == 0 || mx == 6 || my == 6;
            let stone = (2..=4).contains(&mx) && (2..=4).contains(&my);
            if ring || stone {
                for (px, py) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                    picture.put_pixel(cx + mx * 2 + px, cy + my * 2 + py, Luma([0]));
                }
            }
        }
    }
    picture
}

/// phones-a2 / b2: a crafted picture cannot hold the add dialog: the work ends at the deadline
/// with its own message (the page then clears its reading state).
#[test]
fn a_picture_full_of_finder_patterns_ends_at_the_deadline() {
    let started = Instant::now();
    let refused = decode_until(finder_lattice(24), started + Duration::from_millis(300));
    assert_eq!(key_of(refused.unwrap_err()), "app.phones.qr.slow");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

/// phones-a2: a picture larger than the decode side is scaled down first and still read.
#[test]
fn large_pictures_are_scaled_down_and_read() {
    let (side, luma) = draw(&encode(KEY).unwrap(), 4, false);
    let side = u32::try_from(side).unwrap();
    let code = GrayImage::from_raw(side, side, luma).unwrap();
    let mut wide = GrayImage::from_pixel(DECODE_SIDE * 2, side * 2, Luma([255]));
    image::imageops::overlay(
        &mut wide,
        &image::imageops::resize(&code, side * 2, side * 2, FilterType::Nearest),
        100,
        0,
    );
    assert_eq!(fit(wide.clone()).width(), DECODE_SIDE);
    assert_eq!(decode_gray(wide).unwrap(), [KEY]);
}

/// phones-a8: only PNG, JPEG, GIF, BMP and WebP reach a decoder; the other formats compiled into
/// `image` (TIFF here, by its magic number) are refused before decoding.
#[test]
fn only_the_five_picture_formats_are_decoded() {
    let (side, luma) = draw(&encode(KEY).unwrap(), 4, false);
    let side = u32::try_from(side).unwrap();
    // GIF has no grey encoder: every file is written in colour, as a phone would.
    let picture =
        image::DynamicImage::ImageLuma8(GrayImage::from_raw(side, side, luma).unwrap()).into_rgb8();
    for format in [ImageFormat::Gif, ImageFormat::Bmp] {
        let mut bytes = Vec::new();
        picture
            .write_to(&mut Cursor::new(&mut bytes), format)
            .unwrap();
        assert_eq!(decode_picture(&bytes).unwrap(), [KEY], "{format:?}");
    }
    let mut tiff = Vec::new();
    picture
        .write_to(&mut Cursor::new(&mut tiff), ImageFormat::Tiff)
        .unwrap();
    assert_eq!(image::guess_format(&tiff).unwrap(), ImageFormat::Tiff);
    assert_eq!(
        key_of(decode_picture(&tiff).unwrap_err()),
        "app.phones.qr.unreadable"
    );
}
