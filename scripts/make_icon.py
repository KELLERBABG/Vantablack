#!/usr/bin/env python3
"""Generate the Global Ghost Net application icons.

Renders the same mark as `assets/icon.svg` — a dark rounded tile with a cyan
ring (the network node) — as signed-distance-field rasterizations. One SDF
pass per size means every icon size is drawn at its native resolution instead
of being downscaled, which is what keeps the 16 px entry crisp.

Outputs
-------
assets/icon.ico     16, 24, 32, 48, 64, 128, 256  → Windows .exe resource
assets/icon-ui.ico  32, 64                        → embedded in the binary, used
                                                    for the window and tray icon
assets/icon-256.png 256                           → docs / README

Run from the repository root:

    python scripts/make_icon.py
"""

from __future__ import annotations

import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")

# Same palette as the site and the control center.
TILE = (0x04, 0x08, 0x12)
BORDER = (0x38, 0xBD, 0xF8)
INNER = (0x38, 0xBD, 0xF8)
GRAD_A = (0x38, 0xBD, 0xF8)  # cyan
GRAD_B = (0x22, 0xD3, 0xEE)  # keeps the ring legible at 16 px on a dark taskbar

# Geometry, in the SVG's 128-unit coordinate space.
UNITS = 128.0
TILE_INSET = 1.0  # the SVG strokes the tile boundary, so pull it inside the canvas
TILE_RADIUS = 27.0
BORDER_W = 2.0
INNER_INSET = 6.0
INNER_RADIUS = 22.0
INNER_W = 1.5
RING_MID = 23.95  # midpoint of the SVG ring (outer 26.6, inner 21.3)
RING_W = 5.32


def _clamp01(v: float) -> float:
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)


def _sd_round_box(px: float, py: float, half: float, radius: float) -> float:
    """Signed distance to a rounded box centred on the origin."""
    qx = abs(px) - (half - radius)
    qy = abs(py) - (half - radius)
    outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
    return outside + min(max(qx, qy), 0.0) - radius


def _lerp_rgb(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def _render(size: int) -> list[float]:
    """Render one icon size into a flat, straight-alpha RGBA buffer.

    Channels are 0-255 floats; `a` is coverage in 0-255 too.
    """
    k = size / UNITS
    buf = [0.0] * (size * size * 4)

    # Precompute the per-size geometry. Thin strokes vanish below ~32 px, so
    # they get a floor that keeps the mark readable instead of grey mush.
    # Below ~32 px the ring's inner hole would close up and the mark would read
    # as a blob with a dot, so small entries get a slightly larger, thinner ring.
    small = size <= 24
    ring_mid = RING_MID * k * (1.10 if small else 1.0)
    ring_half = max(RING_W * k, 1.9 if small else 2.0) / 2.0
    border_half = max(BORDER_W * k, 1.0) / 2.0
    inner_half = max(INNER_W * k, 1.0) / 2.0
    draw_inner = size >= 48
    draw_border = size >= 24
    tile_half = (UNITS - TILE_INSET * 2.0) / 2.0 * k
    inner_half_box = (UNITS - INNER_INSET * 2.0) / 2.0 * k

    center = size / 2.0

    def paint(i: int, col, cov: float) -> None:
        """Source-over one shape into pixel `i` with coverage `cov` in 0..1."""
        da = buf[i + 3] / 255.0
        oa = cov + da * (1.0 - cov)
        if oa <= 0.0:
            return
        for c in range(3):
            buf[i + c] = (col[c] * cov + buf[i + c] * da * (1.0 - cov)) / oa
        buf[i + 3] = oa * 255.0

    for y in range(size):
        py = y + 0.5
        row = y * size * 4
        for x in range(size):
            px = x + 0.5
            # Coordinates relative to the icon centre, in pixel units.
            rx = px - center
            ry = py - center
            i = row + x * 4

            # Diagonal gradient position, matching the SVG's (0,0)->(1,1) axis.
            t = _clamp01((px + py) / (2.0 * size))

            # 1. The dark tile.
            d_tile = _sd_round_box(rx, ry, tile_half, TILE_RADIUS * k)
            paint(i, TILE, _clamp01(0.5 - d_tile))

            # 2. Its hairline cyan border (dropped when it would be a smear).
            if draw_border:
                cov = _clamp01(0.5 - (abs(d_tile) - border_half))
                if cov > 0.0:
                    paint(i, BORDER, cov * 0.30)

            # 3. The decorative inner tile outline (a gradient, like the SVG).
            if draw_inner:
                d_inner = _sd_round_box(rx, ry, inner_half_box, INNER_RADIUS * k)
                cov = _clamp01(0.5 - (abs(d_inner) - inner_half))
                if cov > 0.0:
                    paint(i, _lerp_rgb(INNER, (0x1E, 0x29, 0x3B), t), cov * 0.60)

            # 4. The ring — the mark itself.
            d_ring = abs(math.hypot(rx, ry) - ring_mid) - ring_half
            cov = _clamp01(0.5 - d_ring)
            if cov > 0.0:
                paint(i, _lerp_rgb(GRAD_A, GRAD_B, t), cov)

    return buf


def _to_bgra_dib(size: int, buf: list[float]) -> bytes:
    """Serialize a render as a bottom-up 32-bit BGRA DIB (the ICO 'BMP' form)."""
    out = bytearray()
    def byte(v: float) -> int:
        return min(255, max(0, int(round(v))))

    for y in range(size - 1, -1, -1):  # DIB rows run bottom-up
        for x in range(size):
            i = (y * size + x) * 4
            out += bytes(
                (
                    byte(buf[i + 2]),
                    byte(buf[i + 1]),
                    byte(buf[i]),
                    byte(buf[i + 3]),
                )
            )
    # The AND mask is ignored for 32-bit icons with an alpha channel, but the
    # format requires it, and it must be zeroed so any consumer that does honour
    # it keeps every pixel.
    row_bytes = ((size + 31) // 32) * 4
    out += bytes(row_bytes * size)
    return bytes(out)


def _dib_header(size: int) -> bytes:
    # BITMAPINFOHEADER. biHeight is doubled: XOR bitmap + AND mask.
    return struct.pack(
        "<IiiHHIIiiII",
        40,
        size,
        size * 2,
        1,
        32,
        0,  # BI_RGB
        size * size * 4,
        0,
        0,
        0,
        0,
    )


def write_ico(path: str, sizes: list[int]) -> None:
    images = []
    for size in sizes:
        dib = _dib_header(size) + _to_bgra_dib(size, _render(size))
        images.append((size, dib))

    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    directory = b""
    for size, dib in images:
        dim = 0 if size >= 256 else size  # 0 means 256 in the ICO directory
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(dib), offset)
        offset += len(dib)

    with open(path, "wb") as fh:
        fh.write(header + directory)
        for _, dib in images:
            fh.write(dib)
    print(f"wrote {os.path.relpath(path, ROOT)} ({len(sizes)} sizes, {os.path.getsize(path)} bytes)")


def write_png(path: str, size: int) -> None:
    buf = _render(size)
    def byte(v: float) -> int:
        return min(255, max(0, int(round(v))))

    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            i = (y * size + x) * 4
            raw += bytes(
                (
                    byte(buf[i]),
                    byte(buf[i + 1]),
                    byte(buf[i + 2]),
                    byte(buf[i + 3]),
                )
            )

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"wrote {os.path.relpath(path, ROOT)} ({os.path.getsize(path)} bytes)")


def main() -> None:
    os.makedirs(ASSETS, exist_ok=True)
    write_ico(os.path.join(ASSETS, "icon.ico"), [16, 24, 32, 48, 64, 128, 256])
    # Only what the runtime needs: a 32 px tray icon and a 64 px window icon.
    write_ico(os.path.join(ASSETS, "icon-ui.ico"), [32, 64])
    write_png(os.path.join(ASSETS, "icon-256.png"), 256)


if __name__ == "__main__":
    main()
