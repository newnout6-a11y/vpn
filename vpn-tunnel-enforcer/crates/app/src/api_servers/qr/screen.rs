//! The whole desktop (every monitor) as one greyscale picture, for reading QR codes the user has
//! on screen (a messenger window, a provider's web page). GDI `BitBlt` of the virtual screen: the
//! user's own session, no rights; the process is per-monitor DPI aware, so the pixels are
//! physical. Called only on the user's click, after the page hid our own window.
use image::GrayImage;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
    CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, HBITMAP, HDC,
    HGDIOBJ, ReleaseDC, SRCCOPY, SelectObject,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

/// Captures every monitor now, in grey. *Blocking* (tens of milliseconds).
pub(in crate::api_servers) fn capture() -> AppResult<GrayImage> {
    // SAFETY: plain metric reads.
    let (x, y, w, h) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    let (Ok(width), Ok(height)) = (usize::try_from(w), usize::try_from(h)) else {
        return Err(failed());
    };
    if width == 0 || height == 0 {
        return Err(failed());
    }
    // SAFETY: the screen DC of no window; released by the guard.
    let screen = ScreenDc(unsafe { GetDC(None) });
    if screen.0.is_invalid() {
        return Err(failed());
    }
    // SAFETY: a memory DC compatible with the live screen DC; deleted by the guard.
    let memory = MemoryDc(unsafe { CreateCompatibleDC(Some(screen.0)) });
    // SAFETY: a bitmap of the screen's format; deleted by the guard (after it is deselected).
    let bitmap = Bitmap(unsafe { CreateCompatibleBitmap(screen.0, w, h) });
    if memory.0.is_invalid() || bitmap.0.is_invalid() {
        return Err(failed());
    }
    // SAFETY: both handles are live; the previous object is selected back below.
    let previous = unsafe { SelectObject(memory.0, HGDIOBJ(bitmap.0.0)) };
    // CAPTUREBLT includes layered windows (most messengers draw their windows layered).
    // SAFETY: both DCs are live and the rectangle is the virtual screen's.
    let copied = unsafe {
        BitBlt(
            memory.0,
            0,
            0,
            w,
            h,
            Some(screen.0),
            x,
            y,
            SRCCOPY | CAPTUREBLT,
        )
    };
    // SAFETY: puts the DC's own bitmap back, so ours can be read and deleted.
    unsafe { SelectObject(memory.0, previous) };
    copied.map_err(|e| failed().with_source(e))?;
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            // Negative: rows top-down, as the decoder reads them.
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bgra = vec![0u8; width * height * 4];
    // SAFETY: the buffer holds `height` rows of `width` 32-bit pixels, as `info` describes.
    let lines = unsafe {
        GetDIBits(
            memory.0,
            bitmap.0,
            0,
            h.unsigned_abs(),
            Some(bgra.as_mut_ptr().cast()),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    if lines != h {
        return Err(failed());
    }
    let luma = bgra
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&[b, g, r, _]| {
            let (b, g, r) = (u32::from(b), u32::from(g), u32::from(r));
            // ITU-R BT.601 weights; the sum of the weights is 1000, so this fits a byte.
            ((r * 299 + g * 587 + b * 114) / 1000) as u8
        })
        .collect();
    GrayImage::from_raw(w.unsigned_abs(), h.unsigned_abs(), luma).ok_or_else(failed)
}

fn failed() -> AppError {
    AppError::msg(ErrorKind::Internal, Msg::new("app.phones.qr.screenFailed"))
}

struct ScreenDc(HDC);

impl Drop for ScreenDc {
    fn drop(&mut self) {
        // SAFETY: the DC came from `GetDC(None)` and is released once.
        unsafe { ReleaseDC(None, self.0) };
    }
}

struct MemoryDc(HDC);

impl Drop for MemoryDc {
    fn drop(&mut self) {
        // SAFETY: the DC came from `CreateCompatibleDC` and is deleted once.
        let _ = unsafe { DeleteDC(self.0) };
    }
}

struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        // SAFETY: the bitmap is no longer selected into a DC and is deleted once.
        let _ = unsafe { DeleteObject(HGDIOBJ(self.0.0)) };
    }
}
