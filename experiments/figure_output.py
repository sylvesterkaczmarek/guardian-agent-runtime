"""Canonical PNG encoding for checked reference figures.

Pillow wheels can use different zlib implementations on macOS and Linux. Keep the
Matplotlib Agg pixels unchanged, but use one explicit PNG filter and the standard
library's fixed-Huffman compressor instead of Pillow's platform-selected encoder.
No timestamps, paths or optional renderer metadata enter these presentation files.
"""

from __future__ import annotations

import struct
from pathlib import Path
import zlib

import numpy as np


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def rgba_png(pixels: np.ndarray) -> bytes:
    """Encode nonempty uint8 RGBA pixels with explicit, stable PNG choices."""
    if not isinstance(pixels, np.ndarray) or pixels.dtype != np.uint8 or pixels.ndim != 3 or pixels.shape[2] != 4:
        raise ValueError("pixels must be a uint8 height-by-width-by-four array")
    height, width, _ = pixels.shape
    if not 0 < height <= 10000 or not 0 < width <= 10000 or pixels.size > 64_000_000:
        raise ValueError("figure dimensions exceed the bounded reference renderer")
    rows = np.ascontiguousarray(pixels).reshape(height, width * 4)
    # PNG Sub filter preserves exact pixels while making flat plot regions compact.
    filtered = np.empty((height, width * 4 + 1), dtype=np.uint8)
    filtered[:, 0] = 1
    filtered[:, 1:5] = rows[:, :4]
    np.subtract(rows[:, 4:], rows[:, :-4], out=filtered[:, 5:])
    compressor = zlib.compressobj(level=9, wbits=15, memLevel=8, strategy=zlib.Z_FIXED)
    encoded = compressor.compress(filtered.tobytes()) + compressor.flush()
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", header) + _chunk(b"IDAT", encoded) + _chunk(b"IEND", b"")


def save_reference_png(figure, destination: Path, *, dpi: int = 180) -> None:
    figure.set_dpi(dpi)
    figure.canvas.draw()
    pixels = np.asarray(figure.canvas.buffer_rgba())
    destination.write_bytes(rgba_png(pixels))
