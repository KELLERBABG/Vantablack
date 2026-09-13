//! The application's own icon, and just enough ICO parsing to hand it to
//! `tao` and `tray-icon`.
//!
//! Windows takes a window's taskbar icon from the executable's resources, but
//! only once the window asks for it — `tao`'s `with_window_icon` is what puts
//! the icon into `WM_SETICON`. That needs RGBA bytes at runtime, and the
//! binary already carries an icon file, so this module decodes it instead of
//! carrying the pixels twice or pulling in an image crate.
//!
//! Only the classic DIB form is understood (BITMAPINFOHEADER + bottom-up BGRA,
//! optional 1-bit AND mask), which is what [`crate::ghost::icon::UI_ICON`]
//! contains. PNG-compressed ICO entries are deliberately rejected rather than
//! half-parsed: an icon that silently renders as garbage is worse than one that
//! logs why it did not load.

/// The icon embedded for the window and the system tray: 32 px and 64 px
/// entries, which is all the desktop UI needs. The full multi-resolution file
/// (`assets/icon.ico`) belongs to the executable's Windows resources instead of
/// the binary's data section.
pub const UI_ICON: &[u8] = include_bytes!("../../assets/icon-ui.ico");

/// A decoded, straight-alpha RGBA icon bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconRgba {
    pub width: u32,
    pub height: u32,
    /// `width * height * 4` bytes, row-major, top-down, RGBA.
    pub rgba: Vec<u8>,
}

fn u16le(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn u32le(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

fn i32le(data: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

/// Decode one DIB-form ICO entry into RGBA, or `None` if it uses a form this
/// module does not implement.
fn decode_dib(data: &[u8], offset: usize) -> Option<IconRgba> {
    if data.get(offset..offset + 8) == Some(b"\x89PNG\r\n\x1a\n") {
        tracing::debug!("Icon entry is PNG-compressed; not supported, skipping");
        return None;
    }
    let header_size = u32le(data, offset)? as usize;
    if header_size < 40 {
        return None;
    }
    let width = i32le(data, offset + 4)?;
    // An ICO's BITMAPINFOHEADER declares twice the real height: the XOR bitmap
    // and the AND mask are stacked.
    let doubled_height = i32le(data, offset + 8)?;
    let bit_count = u16le(data, offset + 14)?;
    let compression = u32le(data, offset + 16)?;
    if width <= 0 || doubled_height <= 0 || compression != 0 || bit_count != 32 {
        tracing::debug!(
            width,
            height = doubled_height,
            bit_count,
            compression,
            "Unsupported icon entry; skipping"
        );
        return None;
    }
    let (width, height) = (width as u32, (doubled_height as u32) / 2);
    if height == 0 {
        return None;
    }

    let pixels =
        data.get(offset + header_size..offset + header_size + (width * height * 4) as usize)?;
    let mut rgba = vec![0u8; (width * height * 4) as usize];
    for y in 0..height {
        // DIB rows are stored bottom-up.
        let src_row = ((height - 1 - y) * width * 4) as usize;
        let dst_row = (y * width * 4) as usize;
        for x in 0..width as usize {
            let s = src_row + x * 4;
            let d = dst_row + x * 4;
            rgba[d] = pixels[s + 2]; // B -> R
            rgba[d + 1] = pixels[s + 1]; // G
            rgba[d + 2] = pixels[s]; // R -> B
            rgba[d + 3] = pixels[s + 3]; // A
        }
    }
    Some(IconRgba {
        width,
        height,
        rgba,
    })
}

/// Decode every entry of an ICO file, skipping any it cannot read.
pub fn decode_ico(data: &[u8]) -> Vec<IconRgba> {
    let count = match u16le(data, 4) {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    if u16le(data, 0) != Some(0) || u16le(data, 2) != Some(1) {
        tracing::debug!("Not an ICO file (bad reserved/type fields)");
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let entry = 6 + i * 16;
        let Some(offset) = u32le(data, entry + 12).map(|v| v as usize) else {
            continue;
        };
        if let Some(image) = decode_dib(data, offset) {
            out.push(image);
        }
    }
    out
}

/// Choose the best entry for a requested pixel size: the smallest one that is
/// at least `wanted`, or the largest available if none is.
pub fn best_for(images: &[IconRgba], wanted: u32) -> Option<&IconRgba> {
    images
        .iter()
        .filter(|i| i.width >= wanted)
        .min_by_key(|i| i.width)
        .or_else(|| images.iter().max_by_key(|i| i.width))
}

/// The embedded UI icon scaled for `wanted` pixels, ready to hand to the
/// window/tray constructor.
pub fn ui_icon(wanted: u32) -> Option<IconRgba> {
    let images = decode_ico(UI_ICON);
    match best_for(&images, wanted) {
        Some(icon) => Some(icon.clone()),
        None => {
            tracing::warn!("Embedded application icon could not be decoded");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(icon: &IconRgba, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * icon.width + x) * 4) as usize;
        [
            icon.rgba[i],
            icon.rgba[i + 1],
            icon.rgba[i + 2],
            icon.rgba[i + 3],
        ]
    }

    #[test]
    fn the_embedded_icon_decodes_at_the_sizes_the_ui_asks_for() {
        let images = decode_ico(UI_ICON);
        let sizes: Vec<u32> = images.iter().map(|i| i.width).collect();
        assert_eq!(sizes, vec![32, 64], "UI icon should hold a 32 and a 64");
        for icon in &images {
            assert_eq!(icon.width, icon.height);
            assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        }
    }

    #[test]
    fn decoded_pixels_look_like_the_mark() {
        let icon = ui_icon(64).expect("64 px entry");
        assert_eq!((icon.width, icon.height), (64, 64));
        // The corners are outside the rounded tile, so nothing is painted there.
        assert_eq!(pixel(&icon, 0, 0), [0, 0, 0, 0]);
        assert_eq!(pixel(&icon, 63, 0)[3], 0);
        // The tile is opaque and dark.
        let centre = pixel(&icon, 32, 32);
        assert_eq!(centre[3], 255, "tile centre should be opaque");
        assert!(
            centre[0] < 40 && centre[1] < 40 && centre[2] < 60,
            "tile should be dark, got {centre:?}"
        );

        // Walking outwards from the centre has to cross a bright cyan ring at
        // the radius the brand mark puts it (23.95 of 128 => ~12 px at 64 px).
        let (mut ring_at, mut brightest) = (0u32, [0u8; 4]);
        for x in 32..64 {
            let p = pixel(&icon, x, 32);
            if p[3] == 255 && p[2] > brightest[2] {
                brightest = p;
                ring_at = x - 32;
            }
        }
        assert!(
            (10..=14).contains(&ring_at),
            "ring should sit at ~12 px, found it at {ring_at}"
        );
        assert!(
            brightest[2] > 190 && brightest[0] < 130,
            "ring should be bright cyan, got {brightest:?}"
        );
    }

    #[test]
    fn sizes_are_chosen_the_way_a_hicon_would_be() {
        let images = decode_ico(UI_ICON);
        assert_eq!(best_for(&images, 16).unwrap().width, 32);
        assert_eq!(best_for(&images, 32).unwrap().width, 32);
        assert_eq!(best_for(&images, 48).unwrap().width, 64);
        assert_eq!(best_for(&images, 64).unwrap().width, 64);
        assert_eq!(best_for(&images, 512).unwrap().width, 64);
    }

    // ── the Windows resource script (assets/app.rc) ─────────────────────────

    /// The whole text of the resource script, compiled by `build.rs`.
    const APP_RC: &str = include_str!("../../assets/app.rc");

    /// The rest of the line that starts with `name` (after `VALUE`-style keys).
    fn rc_directive(rc: &str, name: &str) -> Option<String> {
        rc.lines()
            .map(str::trim)
            .find_map(|line| Some(line.strip_prefix(name)?.trim().to_string()))
    }

    /// The value of a `VALUE "key", ...` line, unquoted.
    fn rc_value(rc: &str, key: &str) -> Option<String> {
        rc.lines().map(str::trim).find_map(|line| {
            let rest = line.strip_prefix("VALUE")?.trim();
            let (k, v) = rest.split_once(',')?;
            (k.trim().trim_matches('"') == key).then(|| v.trim().trim_matches('"').to_string())
        })
    }

    /// The resource *id* matters as much as the contents: Windows fetches the
    /// version block with `FindResourceW(h, MAKEINTRESOURCE(1), RT_VERSION)`.
    /// Writing the symbol `VS_VERSION_INFO` instead of the literal `1` (which is
    /// what happens without `windows.h`) compiles the block under a string name
    /// that no shell API ever looks up, so Explorer's Details tab and the
    /// installer both see an unversioned file. This test is why that cannot
    /// come back unnoticed.
    #[test]
    fn version_resource_is_readable_by_the_shell() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            APP_RC.lines().any(|l| l.trim() == "1 VERSIONINFO"),
            "the version block must be compiled under ordinal 1, not a string name"
        );
        assert!(
            !APP_RC.contains("VS_VERSION_INFO VERSIONINFO"),
            "`VS_VERSION_INFO` is undefined without windows.h, so rc.exe would treat it as a name"
        );

        // FILEVERSION / PRODUCTVERSION are four comma-separated u16s.
        let mut quad: Vec<&str> = version.split('.').collect();
        while quad.len() < 4 {
            quad.push("0");
        }
        let quad = quad.join(",");
        for directive in ["FILEVERSION", "PRODUCTVERSION"] {
            assert_eq!(
                rc_directive(APP_RC, directive).as_deref(),
                Some(quad.as_str()),
                "{directive} must track Cargo.toml's version"
            );
        }
        for key in ["FileVersion", "ProductVersion"] {
            assert_eq!(
                rc_value(APP_RC, key).as_deref(),
                Some(version),
                "{key} must track Cargo.toml's version"
            );
        }

        // The strings the installer and the shell show for the product.
        for key in ["ProductName", "FileDescription", "CompanyName"] {
            assert_eq!(
                rc_value(APP_RC, key).as_deref(),
                Some("Global Ghost Net"),
                "{key} should name the product"
            );
        }
        assert_eq!(
            rc_value(APP_RC, "OriginalFilename").as_deref(),
            Some("ggn.exe")
        );
    }

    #[test]
    fn malformed_input_is_rejected_instead_of_panicking() {
        assert!(decode_ico(&[]).is_empty());
        assert!(decode_ico(b"not an icon at all").is_empty());
        // Valid header claiming an entry that points past the end of the file.
        let mut bogus = vec![0u8, 0, 1, 0, 1, 0];
        bogus.extend_from_slice(&[64, 64, 0, 0, 1, 0, 32, 0]);
        bogus.extend_from_slice(&100u32.to_le_bytes());
        bogus.extend_from_slice(&9999u32.to_le_bytes());
        assert!(decode_ico(&bogus).is_empty());
    }
}
