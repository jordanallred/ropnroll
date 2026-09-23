#!/usr/bin/env python3
"""Regenerate docs/assets/demo.gif from real ropnroll CLI output.

Runs a fixed sequence of `ropnroll` commands against the repo's PE test
fixtures inside a pseudo-terminal (so Rich renders its normal colored
tables), replays the captured bytes through a `pyte` VT100 emulator, and
rasterizes each screen state with Pillow into an animated GIF. Every frame
is real tool output -- nothing here fabricates or edits what ropnroll
prints.

Requires `pyte` and `pillow` (not runtime dependencies of ropnroll itself):

    pip install pyte pillow
    python scripts/generate_demo_gif.py
"""

import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios

import pyte
from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = "tests/fixtures/pe/cli-64.exe"
OUT_PATH = os.path.join(REPO_ROOT, "docs", "assets", "demo.gif")

COLS, ROWS = 104, 34
FONT_SIZE = 16
PADDING = 14
FG_DEFAULT = (223, 226, 230)
BG_DEFAULT = (17, 19, 24)

PALETTE_16 = {
    "black": (30, 31, 36), "red": (224, 108, 117), "green": (124, 197, 129),
    "brown": (209, 154, 102), "blue": (97, 175, 239), "magenta": (198, 120, 221),
    "cyan": (86, 182, 194), "white": (220, 223, 228),
    "brightblack": (92, 99, 112), "brightred": (255, 133, 133),
    "brightgreen": (152, 220, 156), "brightbrown": (229, 192, 123),
    "brightblue": (130, 190, 255), "brightmagenta": (220, 150, 240),
    "brightcyan": (110, 210, 220), "brightwhite": (255, 255, 255),
}

# Rich draws its tables with box-drawing glyphs. Most monospace fonts render
# them with anti-aliasing gaps at small sizes, so draw the lines by hand
# instead -- the way real terminal emulators do it.
BOX_CHARS = {
    "─": dict(l="light", r="light"), "━": dict(l="heavy", r="heavy"),
    "│": dict(u="light", d="light"), "┃": dict(u="heavy", d="heavy"),
    "┌": dict(d="light", r="light"), "┐": dict(d="light", l="light"),
    "┏": dict(d="heavy", r="heavy"), "┓": dict(d="heavy", l="heavy"),
    "└": dict(u="light", r="light"), "┘": dict(u="light", l="light"),
    "┗": dict(u="heavy", r="heavy"), "┛": dict(u="heavy", l="heavy"),
    "├": dict(u="light", d="light", r="light"),
    "┤": dict(u="light", d="light", l="light"),
    "┣": dict(u="heavy", d="heavy", r="heavy"),
    "┫": dict(u="heavy", d="heavy", l="heavy"),
    "┬": dict(d="light", l="light", r="light"),
    "┳": dict(d="heavy", l="heavy", r="heavy"),
    "┴": dict(u="light", l="light", r="light"),
    "┻": dict(u="heavy", l="heavy", r="heavy"),
    "┼": dict(u="light", d="light", l="light", r="light"),
    "╋": dict(u="heavy", d="heavy", l="heavy", r="heavy"),
    "┡": dict(u="light", d="heavy", r="heavy"),
    "┩": dict(u="light", d="heavy", l="heavy"),
    "┢": dict(u="heavy", d="light", r="heavy"),
    "┪": dict(u="heavy", d="light", l="heavy"),
    "╇": dict(u="heavy", d="heavy", l="heavy", r="heavy"),
    "╈": dict(u="heavy", d="heavy", l="heavy", r="heavy"),
}

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
font_bold = ImageFont.truetype(FONT_BOLD_PATH, FONT_SIZE)

CHAR_W = font.getlength("M")
LINE_H = int(FONT_SIZE * 1.45)
IMG_W = int(PADDING * 2 + CHAR_W * COLS)
IMG_H = int(PADDING * 2 + LINE_H * ROWS + 40)

COMMANDS = [
    ("security", ["ropnroll", "security", FIXTURE], f"ropnroll security cli-64.exe"),
    (
        "scan",
        ["ropnroll", "scan", FIXTURE, "--regex", "pop r.x", "--limit", "6"],
        "ropnroll scan cli-64.exe --regex 'pop r.x' --limit 6",
    ),
    (
        "pivot",
        ["ropnroll", "pivot", FIXTURE, "--limit", "4"],
        "ropnroll pivot cli-64.exe --limit 4",
    ),
]


def run_in_pty(cmd, cwd):
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLUMNS"] = str(COLS)
    env["LINES"] = str(ROWS)

    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True,
    )
    os.close(slave_fd)

    chunks = []
    while True:
        r, _, _ = select.select([master_fd], [], [], 2.0)
        if master_fd not in r:
            if proc.poll() is not None:
                break
            continue
        try:
            data = os.read(master_fd, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    proc.wait()
    os.close(master_fd)
    return b"".join(chunks)


def draw_box_char(draw, x, y, w, h, spec, color):
    cx, cy = x + w / 2, y + h / 2
    segments = {
        "u": (cx, y, cx, cy), "d": (cx, cy, cx, y + h),
        "l": (x, cy, cx, cy), "r": (cx, cy, x + w, cy),
    }
    for direction, coords in segments.items():
        weight = spec.get(direction)
        if weight:
            draw.line(coords, fill=color, width=3 if weight == "heavy" else 1)


def resolve_color(c, default):
    if c in (None, "default"):
        return default
    if isinstance(c, str) and c in PALETTE_16:
        return PALETTE_16[c]
    if isinstance(c, str) and len(c) == 6:
        try:
            return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            return default
    return default


class Session:
    def __init__(self):
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.ByteStream(self.screen)
        self.frames = []

    def feed_text(self, text):
        self.stream.feed(text.encode())

    def feed_bytes(self, data):
        self.stream.feed(data)

    def snapshot(self, duration_ms):
        img = Image.new("RGB", (IMG_W, IMG_H), BG_DEFAULT)
        draw = ImageDraw.Draw(img)
        for i, col in enumerate([(255, 95, 86), (255, 189, 44), (39, 201, 63)]):
            draw.ellipse([PADDING + i * 22, 12, PADDING + i * 22 + 12, 24], fill=col)
        y0 = 40
        buf = self.screen.buffer
        for row in range(ROWS):
            line = buf[row]
            x = PADDING
            y = y0 + row * LINE_H
            for col in range(COLS):
                ch = line[col]
                data = ch.data or " "
                fg = resolve_color(ch.fg, FG_DEFAULT)
                bg = resolve_color(ch.bg, None)
                if ch.reverse:
                    fg, bg = (bg or BG_DEFAULT), (fg if fg != FG_DEFAULT else FG_DEFAULT)
                if bg:
                    draw.rectangle([x, y, x + CHAR_W, y + LINE_H], fill=bg)
                if data in BOX_CHARS:
                    draw_box_char(draw, x, y, CHAR_W, LINE_H, BOX_CHARS[data], fg)
                elif data != " ":
                    draw.text((x, y + 2), data, font=font_bold if ch.bold else font, fill=fg)
                x += CHAR_W
        self.frames.append((img, duration_ms))

    def save(self, path, tail_hold_ms=2400):
        imgs = [f[0] for f in self.frames]
        durs = [f[1] for f in self.frames]
        durs[-1] = tail_hold_ms
        # Share one quantized palette across frames -- keeps the accent
        # colors (including the fake window-chrome dots) intact and the
        # file small, instead of Pillow picking a per-frame palette.
        sample = Image.new("RGB", (IMG_W, IMG_H * 3 + 10))
        for i, idx in enumerate([len(imgs) // 3, 2 * len(imgs) // 3, len(imgs) - 1]):
            sample.paste(imgs[idx], (0, IMG_H * i))
        chrome_draw = ImageDraw.Draw(sample)
        for i, col in enumerate([(255, 95, 86), (255, 189, 44), (39, 201, 63)]):
            chrome_draw.rectangle([i * 10, IMG_H * 3, i * 10 + 8, IMG_H * 3 + 8], fill=col)
        pal_img = sample.quantize(colors=96, method=Image.MEDIANCUT)
        quantized = [im.quantize(palette=pal_img, dither=Image.NONE) for im in imgs]
        quantized[0].save(
            path, save_all=True, append_images=quantized[1:],
            duration=durs, loop=0, optimize=True, disposal=2,
        )
        print(f"wrote {path}: {len(imgs)} frames")


def type_command(sess, prompt, cmd, chars_per_frame=3, frame_ms=55):
    sess.feed_text(prompt)
    sess.snapshot(300)
    for i in range(0, len(cmd), chars_per_frame):
        sess.feed_text(cmd[i:i + chars_per_frame])
        sess.snapshot(frame_ms)
    sess.feed_text("\n")


def play_output(sess, raw_bytes, n_chunks=26, frame_ms=70, end_hold_ms=1900):
    n = len(raw_bytes)
    if n == 0:
        return
    step = max(1, n // n_chunks)
    pos = 0
    while pos < n:
        end = min(pos + step, n)
        sess.feed_bytes(raw_bytes[pos:end])
        sess.snapshot(frame_ms)
        pos = end
    sess.snapshot(end_hold_ms)


def main():
    sess = Session()
    for name, argv, display_cmd in COMMANDS:
        type_command(sess, "$ ", display_cmd)
        raw = run_in_pty(argv, REPO_ROOT)
        play_output(sess, raw)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    sess.save(OUT_PATH)


if __name__ == "__main__":
    sys.exit(main())
