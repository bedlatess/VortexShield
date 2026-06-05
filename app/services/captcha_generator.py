from __future__ import annotations

import base64
import io
import math
import random
from dataclasses import dataclass
from typing import Literal

import numpy as np
from PIL import Image, ImageDraw, ImageFilter


SliderShape = Literal["square", "star", "moon"]


@dataclass(frozen=True, slots=True)
class SliderChallenge:
    bg_image: str
    slider_piece_b64: str
    target_x: int
    target_y: int
    piece_width: int
    piece_height: int
    shape: SliderShape
    width: int
    height: int


def generate_slider_challenge(width: int = 320, height: int = 160) -> SliderChallenge:
    """生成形状匹配滑块验证码。

    安全边界：
    - 背景、噪点、干扰线、拼图形状全部运行时动态合成，不依赖静态图库。
    - `target_x` 是最终判题答案，只能写入 Session/Redis，不允许返回给前端。
    - 前端只拿到带缺口的背景图和透明拼图块，后续根据滑块拖动距离提交校验。
    """

    rng = random.SystemRandom()
    piece_size = max(42, min(56, height // 3))
    shape = rng.choice(("square", "star", "moon"))

    # target_x 约束在右侧，避免缺口距离起点太近导致滑块难度过低。
    target_x = rng.randint(105, width - piece_size - 18)
    target_y = rng.randint(18, height - piece_size - 18)

    background = _create_slider_background(width, height, rng)
    mask = _create_shape_mask(piece_size, shape)
    piece = _cut_slider_piece(background, mask, target_x, target_y, piece_size)
    challenged_background = _draw_slider_hole(background, mask, target_x, target_y, piece_size)

    # 最后叠加少量前景扰动，避免缺口边缘成为稳定模板。
    challenged_background = _add_foreground_noise(challenged_background, rng)

    return SliderChallenge(
        bg_image=_image_to_data_uri(challenged_background.convert("RGB"), image_format="JPEG"),
        slider_piece_b64=_image_to_data_uri(piece, image_format="PNG"),
        target_x=target_x,
        target_y=target_y,
        piece_width=piece_size,
        piece_height=piece_size,
        shape=shape,
        width=width,
        height=height,
    )


def _create_slider_background(
    width: int,
    height: int,
    rng: random.SystemRandom,
) -> Image.Image:
    """初始化动态背景：多向渐变 + 噪点矩阵 + 曲线干扰。

    噪点使用 NumPy 一次性生成矩阵：
        pixel' = clamp(pixel + noise, 0, 255)
    这比逐像素 Python 循环更适合高并发服务。
    """

    left = np.array(
        [rng.randint(205, 232), rng.randint(218, 244), rng.randint(220, 246)],
        dtype=np.float32,
    )
    right = np.array(
        [rng.randint(220, 248), rng.randint(205, 238), rng.randint(202, 232)],
        dtype=np.float32,
    )
    vertical_tint = np.array(
        [rng.randint(-8, 10), rng.randint(-6, 12), rng.randint(-10, 8)],
        dtype=np.float32,
    )

    x_axis = np.linspace(0.0, 1.0, width, dtype=np.float32)
    y_axis = np.linspace(0.0, 1.0, height, dtype=np.float32)
    horizontal = left * (1.0 - x_axis[:, None]) + right * x_axis[:, None]
    background = np.repeat(horizontal[None, :, :], height, axis=0)
    background += (y_axis[:, None, None] - 0.5) * vertical_tint[None, None, :]

    noise = np.random.default_rng().normal(loc=0.0, scale=9.5, size=(height, width, 3))
    background = np.clip(background + noise, 0, 255).astype(np.uint8)

    image = Image.fromarray(background, "RGB").convert("RGBA")
    image = image.filter(ImageFilter.GaussianBlur(radius=0.18))
    draw = ImageDraw.Draw(image, "RGBA")

    for _ in range(rng.randint(5, 8)):
        _draw_bezier_interference(draw, width, height, rng)

    for _ in range(rng.randint(10, 16)):
        x = rng.randint(0, width - 1)
        y = rng.randint(0, height - 1)
        radius = rng.randint(8, 24)
        color = (
            rng.randint(120, 245),
            rng.randint(120, 245),
            rng.randint(120, 245),
            rng.randint(14, 28),
        )
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)

    return image


def _draw_bezier_interference(
    draw: ImageDraw.ImageDraw,
    width: int,
    height: int,
    rng: random.SystemRandom,
) -> None:
    """绘制三阶贝塞尔干扰线。

    曲线公式：
        B(t) = (1-t)^3P0 + 3(1-t)^2tP1 + 3(1-t)t^2P2 + t^3P3
    干扰线会穿过背景纹理和缺口附近，让目标检测模型难以通过稳定边缘回归出缺口框。
    """

    points = np.array(
        [
            [rng.randint(-30, width // 4), rng.randint(0, height)],
            [rng.randint(0, width), rng.randint(-30, height + 30)],
            [rng.randint(0, width), rng.randint(-30, height + 30)],
            [rng.randint((width * 3) // 4, width + 30), rng.randint(0, height)],
        ],
        dtype=np.float32,
    )

    curve_points: list[tuple[int, int]] = []
    for t in np.linspace(0.0, 1.0, 96):
        p = (
            ((1 - t) ** 3) * points[0]
            + 3 * ((1 - t) ** 2) * t * points[1]
            + 3 * (1 - t) * (t**2) * points[2]
            + (t**3) * points[3]
        )
        curve_points.append((int(p[0]), int(p[1])))

    draw.line(
        curve_points,
        fill=(
            rng.randint(55, 150),
            rng.randint(70, 165),
            rng.randint(85, 180),
            rng.randint(42, 82),
        ),
        width=rng.randint(1, 3),
        joint="curve",
    )


def _create_shape_mask(size: int, shape: SliderShape) -> Image.Image:
    """生成拼图块 alpha mask。

    mask 中 255 表示需要抠出的有效区域，0 表示透明区域。后续用同一张 mask 同时完成：
    - 从背景抠出真实纹理，生成透明拼图块；
    - 在背景同位置压暗/描边，形成缺口。
    这样能保证拼图块与缺口几何完全一致。
    """

    padding = max(4, size // 10)
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)

    if shape == "square":
        radius = max(6, size // 7)
        draw.rounded_rectangle(
            (padding, padding, size - padding, size - padding),
            radius=radius,
            fill=255,
        )
        notch_r = max(5, size // 8)
        cx = size - padding
        cy = size // 2
        draw.ellipse((cx - notch_r, cy - notch_r, cx + notch_r, cy + notch_r), fill=255)
        draw.ellipse(
            (padding - notch_r, cy - notch_r, padding + notch_r, cy + notch_r),
            fill=0,
        )
    elif shape == "star":
        center = size / 2
        outer = (size / 2) - padding
        inner = outer * 0.48
        points: list[tuple[float, float]] = []
        for index in range(10):
            angle = -math.pi / 2 + index * math.pi / 5
            radius = outer if index % 2 == 0 else inner
            points.append((center + radius * math.cos(angle), center + radius * math.sin(angle)))
        draw.polygon(points, fill=255)
    else:
        draw.ellipse((padding, padding, size - padding, size - padding), fill=255)
        # 月亮形通过“亮圆 - 偏移暗圆”的布尔差近似得到。
        cutout_shift = size // 4
        draw.ellipse(
            (padding + cutout_shift, padding - 2, size - padding + cutout_shift, size - padding + 2),
            fill=0,
        )

    return mask.filter(ImageFilter.GaussianBlur(radius=0.35))


def _cut_slider_piece(
    background: Image.Image,
    mask: Image.Image,
    target_x: int,
    target_y: int,
    size: int,
) -> Image.Image:
    """从背景中抠出拼图块。

    抠图公式可以理解为：
        piece_rgba.rgb = background[target_y:target_y+h, target_x:target_x+w]
        piece_rgba.alpha = shape_mask
    alpha 通道只保留形状内部，形状外透明，前端可以自由叠放拖动。
    """

    crop = background.crop((target_x, target_y, target_x + size, target_y + size)).convert("RGBA")
    piece = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    piece.paste(crop, (0, 0), mask)

    outline = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    outline_draw = ImageDraw.Draw(outline, "RGBA")
    outline_draw.bitmap((0, 0), mask, fill=(255, 255, 255, 58))
    edge = mask.filter(ImageFilter.FIND_EDGES).filter(ImageFilter.GaussianBlur(radius=0.35))
    edge_layer = Image.new("RGBA", (size, size), (255, 255, 255, 90))
    piece.alpha_composite(Image.composite(edge_layer, Image.new("RGBA", (size, size)), edge))
    piece = piece.filter(ImageFilter.UnsharpMask(radius=0.8, percent=115, threshold=3))
    return piece


def _draw_slider_hole(
    background: Image.Image,
    mask: Image.Image,
    target_x: int,
    target_y: int,
    size: int,
) -> Image.Image:
    """在背景上绘制半透明缺口和阴影。

    缺口不是简单涂黑，而是把 mask 区域做“压暗 + 模糊阴影 + 高亮边缘”：
    - 压暗让用户可见目标区域；
    - 模糊阴影破坏硬边缘；
    - 边缘高光保留可用性，避免人眼难以辨认。
    """

    result = background.copy().convert("RGBA")
    dark_patch = Image.new("RGBA", (size, size), (22, 28, 34, 112))
    result.alpha_composite(Image.composite(dark_patch, Image.new("RGBA", (size, size)), mask), (target_x, target_y))

    shadow_mask = mask.filter(ImageFilter.GaussianBlur(radius=2.2))
    shadow = Image.new("RGBA", (size, size), (0, 0, 0, 52))
    result.alpha_composite(Image.composite(shadow, Image.new("RGBA", (size, size)), shadow_mask), (target_x + 2, target_y + 2))

    edge = mask.filter(ImageFilter.FIND_EDGES).filter(ImageFilter.GaussianBlur(radius=0.45))
    highlight = Image.new("RGBA", (size, size), (255, 255, 255, 86))
    result.alpha_composite(Image.composite(highlight, Image.new("RGBA", (size, size)), edge), (target_x, target_y))
    return result


def _add_foreground_noise(image: Image.Image, rng: random.SystemRandom) -> Image.Image:
    noisy = image.copy().convert("RGBA")
    draw = ImageDraw.Draw(noisy, "RGBA")
    width, height = noisy.size

    for _ in range(180):
        x = rng.randint(0, width - 1)
        y = rng.randint(0, height - 1)
        radius = rng.choice((1, 1, 2))
        draw.ellipse(
            (x, y, x + radius, y + radius),
            fill=(
                rng.randint(75, 210),
                rng.randint(75, 210),
                rng.randint(75, 210),
                rng.randint(20, 62),
            ),
        )

    return noisy


def _image_to_data_uri(image: Image.Image, *, image_format: Literal["JPEG", "PNG"]) -> str:
    buffer = io.BytesIO()
    if image_format == "JPEG":
        image.convert("RGB").save(buffer, format="JPEG", quality=88, optimize=True)
        mime = "image/jpeg"
    else:
        image.save(buffer, format="PNG", optimize=True)
        mime = "image/png"
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:{mime};base64,{encoded}"
