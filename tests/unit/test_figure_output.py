from io import BytesIO

import numpy as np
from PIL import Image
import pytest

from experiments.figure_output import rgba_png, save_reference_png


@pytest.mark.parametrize("shape", [(1, 1, 4), (3, 7, 4), (64, 80, 4)])
def test_canonical_png_preserves_every_rgba_byte(shape):
    pixels = np.random.default_rng(17).integers(0, 256, size=shape, dtype=np.uint8)
    encoded = rgba_png(pixels)
    with Image.open(BytesIO(encoded)) as decoded:
        assert decoded.mode == "RGBA"
        assert np.array_equal(np.asarray(decoded), pixels)
        assert not decoded.info
    assert encoded == rgba_png(pixels.copy())


def test_noncontiguous_image_is_encoded_without_reordering():
    pixels = np.random.default_rng(9).integers(0, 256, size=(16, 16, 4), dtype=np.uint8)[:, ::2]
    with Image.open(BytesIO(rgba_png(pixels))) as decoded:
        assert np.array_equal(np.asarray(decoded), pixels)


@pytest.mark.parametrize(
    "pixels",
    [np.zeros((1, 1, 3), dtype=np.uint8), np.zeros((0, 1, 4), dtype=np.uint8), np.zeros((1, 1, 4), dtype=float)],
)
def test_invalid_reference_image_is_rejected(pixels):
    with pytest.raises(ValueError):
        rgba_png(pixels)


def test_agg_output_is_exactly_preserved(tmp_path):
    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    figure, axes = plt.subplots(figsize=(2, 2))
    axes.plot([0, 1], [0, 1])
    path = tmp_path / "figure.png"
    save_reference_png(figure, path, dpi=60)
    expected = np.asarray(figure.canvas.buffer_rgba()).copy()
    with Image.open(path) as decoded:
        assert np.array_equal(np.asarray(decoded), expected)
    plt.close(figure)
