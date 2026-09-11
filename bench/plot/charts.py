#!/usr/bin/env python3
"""Render the benchmark diagrams as SVG, using nothing but the standard library.

CONCEPT.md section 15.2 penciled in matplotlib here, under its weakest
justification -- "convenience". Two charts do not need a plotting stack: the
output is a few hundred lines of SVG, and writing it directly means anyone who
can run `python3` can reproduce the figures, with no wheel to install and nothing
to pin. That is the same argument the rest of the project makes about
dependencies, so it applies here too.

Each chart is emitted twice, for the light and the dark chart surface, because a
dark figure is a set of colours chosen for a dark background rather than an
inverted light one. Embed them with <picture> so the reader gets the one that
matches their theme.

Usage:
    python3 bench/plot/charts.py <results-dir>

Reads  <results-dir>/results.csv      (from summarise.py)
       <results-dir>/gateway-rss.csv  (from gateway-memory.sh)
Writes <results-dir>/throughput-{light,dark}.svg
       <results-dir>/memory-{light,dark}.svg
"""

from __future__ import annotations

import csv
import html
import re
import sys
from pathlib import Path

SIZE = re.compile(r"^([\d.]+)\s*([KMG]?i?B)$")

# The validated two-slot categorical palette, light and dark steps, plus the
# chart chrome. Both sets pass the lightness band, chroma floor, CVD separation,
# normal-vision floor and contrast checks against their own surface.
THEMES = {
    "light": {
        "surface": "#fcfcfb",
        "ink": "#0b0b0b",
        "ink_secondary": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "series": ["#2a78d6", "#eb6834"],
    },
    "dark": {
        "surface": "#1a1a19",
        "ink": "#ffffff",
        "ink_secondary": "#c3c2b7",
        "muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "series": ["#3987e5", "#d95926"],
    },
}

# Single quotes around the multi-word family on purpose: this string goes into an
# XML attribute, and double quotes would close it. The first version used them and
# produced an SVG no renderer would open.
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
SERIES_LABEL = {"direct": "Direct to the provider", "proxy": "Through the gateway"}


def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def text(x: float, y: float, content: object, *, fill: str, size: float = 11,
         anchor: str = "start", weight: str = "normal") -> str:
    """One text element. The font family is inherited from the root <svg>."""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" '
            f'fill="{fill}" text-anchor="{anchor}" font-weight="{weight}">{esc(content)}</text>')


def bar(x: float, y: float, w: float, h: float, fill: str, radius: float = 4) -> str:
    """A bar anchored to the baseline, with rounded data-ends only.

    The rounding is on the end the data reaches, never on the baseline end: a bar
    that is rounded at both ends reads as a floating pill and loses the visual
    anchor that makes lengths comparable.
    """
    if h <= 0.5:
        return ""
    r = min(radius, w / 2, h)
    return (f'<path d="M{x:.1f},{y + h:.1f} L{x:.1f},{y + r:.1f} '
            f'Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} '
            f'L{x + w - r:.1f},{y:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} '
            f'L{x + w:.1f},{y + h:.1f} Z" fill="{fill}"/>')


def nice_ceiling(value: float) -> float:
    """Round an axis maximum up to something a reader can divide by four."""
    if value <= 0:
        return 1.0
    magnitude = 10 ** (len(str(int(value))) - 1)
    for step in (1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def svg_document(width: float, height: float, theme: dict, body: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
            f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
            f'font-family="{FONT}" role="img">\n'
            f'<rect width="{width:.0f}" height="{height:.0f}" fill="{theme["surface"]}"/>\n'
            f'{body}\n</svg>\n')


def legend(x: float, y: float, theme: dict, labels: list[str]) -> str:
    """Two series always carry a legend; the swatch carries identity, the text
    stays in ink so colour is never the only channel."""
    out, cursor = [], x
    for i, label in enumerate(labels):
        out.append(f'<rect x="{cursor:.1f}" y="{y - 8:.1f}" width="10" height="10" '
                   f'rx="2" fill="{theme["series"][i]}"/>')
        out.append(text(cursor + 15, y, label, fill=theme["ink_secondary"], size=11))
        cursor += 22 + 6.6 * len(label)
    return "\n".join(out)


# --------------------------------------------------------------------------
# Throughput: small multiples, one panel per (object size, operation).
# --------------------------------------------------------------------------

def throughput_chart(rows: list[dict], theme: dict) -> str:
    panels: dict[tuple[str, str], dict[int, dict[str, dict]]] = {}
    for row in rows:
        key = (row["size"], row["op"])
        panels.setdefault(key, {}).setdefault(int(row["concurrency"]), {})[row["path"]] = row
    if not panels:
        return ""

    def sort_key(item):
        """Sort 1KiB before 10MiB before 1GiB, rather than lexically."""
        size, op = item
        match = SIZE.match(size)
        if not match:
            return (0, op)
        scale = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
        return (int(float(match.group(1)) * scale.get(match.group(2), 1)), op)

    keys = sorted(panels, key=sort_key)
    cols = min(2, len(keys))
    rows_n = (len(keys) + cols - 1) // cols

    pad_x, pad_top, panel_w, panel_h, gap = 58, 116, 300, 190, 56
    width = pad_x * 2 + panel_w * cols + gap * (cols - 1)
    height = pad_top + (panel_h + 74) * rows_n + 16

    out = [
        text(pad_x, 34, "Throughput: direct to the provider vs through the gateway",
             fill=theme["ink"], size=15, weight="600"),
        text(pad_x, 54, "MiB/s for 10 MiB objects, objects/s for 1 KiB objects. Higher is better.",
             fill=theme["ink_secondary"], size=11),
        legend(pad_x, 80, theme, [SERIES_LABEL["direct"], SERIES_LABEL["proxy"]]),
    ]

    for index, key in enumerate(keys):
        col, row_i = index % cols, index // cols
        ox = pad_x + col * (panel_w + gap)
        oy = pad_top + row_i * (panel_h + 74)
        size, op = key
        by_concurrency = panels[key]
        # 1 KiB objects are a request-rate story, not a bandwidth one; reporting
        # MiB/s there would hide the thing being measured.
        metric = "obj_s" if size.endswith("KiB") else "mib_s"
        unit = "obj/s" if metric == "obj_s" else "MiB/s"

        values = [float(r[metric] or 0) for conc in by_concurrency.values() for r in conc.values()]
        top = nice_ceiling(max(values) if values else 1)

        # The unit belongs in the title. Kept as a separate label beside the axis
        # it sat on the same baseline as the title and the two read as one line.
        out.append(text(ox, oy - 12, f"{size} objects, {op.upper()} ({unit})",
                        fill=theme["ink"], size=12, weight="600"))

        for tick in range(5):
            value = top * tick / 4
            y = oy + panel_h - panel_h * tick / 4
            out.append(f'<line x1="{ox:.1f}" y1="{y:.1f}" x2="{ox + panel_w:.1f}" y2="{y:.1f}" '
                       f'stroke="{theme["grid"]}" stroke-width="1"/>')
            out.append(text(ox - 8, y + 4, f"{value:,.0f}", fill=theme["muted"],
                            size=10, anchor="end"))
        out.append(f'<line x1="{ox:.1f}" y1="{oy + panel_h:.1f}" x2="{ox + panel_w:.1f}" '
                   f'y2="{oy + panel_h:.1f}" stroke="{theme["axis"]}" stroke-width="1"/>')

        concurrencies = sorted(by_concurrency)
        slot = panel_w / max(len(concurrencies), 1)
        # 2px of surface between the two bars of a group keeps them separate
        # marks rather than one two-tone block.
        bar_w = min(34, (slot - 26) / 2)
        for i, concurrency in enumerate(concurrencies):
            group_x = ox + slot * i + slot / 2
            for j, path in enumerate(("direct", "proxy")):
                row = by_concurrency[concurrency].get(path)
                if not row:
                    continue
                value = float(row[metric] or 0)
                h = panel_h * value / top if top else 0
                bx = group_x - bar_w - 1 + j * (bar_w + 2)
                out.append(bar(bx, oy + panel_h - h, bar_w, h, theme["series"][j]))
                # Direct labels: a handful per panel, not a number on every mark.
                out.append(text(bx + bar_w / 2, oy + panel_h - h - 6,
                                f"{value:,.0f}", fill=theme["ink_secondary"],
                                size=9, anchor="middle"))
            out.append(text(group_x, oy + panel_h + 16, f"{concurrency}",
                            fill=theme["ink_secondary"], size=11, anchor="middle"))
        out.append(text(ox + panel_w / 2, oy + panel_h + 34, "concurrent clients",
                        fill=theme["muted"], size=10, anchor="middle"))

    return svg_document(width, height, theme, "\n".join(out))


# --------------------------------------------------------------------------
# Memory: the gateway's resident set while a large object streams through it.
# --------------------------------------------------------------------------

PHASE_LABEL = {"upload": "upload", "download": "download"}


def memory_chart(samples: list[dict], theme: dict, payload: str) -> str:
    if not samples:
        return ""
    points = [(int(s["elapsed_ms"]) / 1000.0, int(s["rss_kib"]) / 1024.0, s["phase"])
              for s in samples]
    span = max(p[0] for p in points) or 1.0
    top = nice_ceiling(max(p[1] for p in points))

    pad_l, pad_r, pad_t, pad_b = 62, 24, 92, 56
    plot_w, plot_h = 660, 240
    width, height = pad_l + plot_w + pad_r, pad_t + plot_h + pad_b

    def sx(seconds: float) -> float:
        return pad_l + plot_w * seconds / span

    def sy(mib: float) -> float:
        return pad_t + plot_h - plot_h * mib / top

    out = [
        text(pad_l, 34, f"Gateway memory while {payload} streams through it",
             fill=theme["ink"], size=15, weight="600"),
        text(pad_l, 54, "Resident set of the gateway process. The scale is the "
                        "claim, not the shape: memory follows how many streams are "
                        "in flight, never how large they are.",
             fill=theme["ink_secondary"], size=11),
    ]

    # Shade the phases so the flat stretch is visibly the one doing the work.
    runs: list[tuple[str, float, float]] = []
    for seconds, _, phase in points:
        if runs and runs[-1][0] == phase:
            runs[-1] = (phase, runs[-1][1], seconds)
        else:
            runs.append((phase, seconds, seconds))
    for phase, start, end in runs:
        if phase not in PHASE_LABEL or end - start < 0.2:
            continue
        out.append(f'<rect x="{sx(start):.1f}" y="{pad_t:.1f}" '
                   f'width="{sx(end) - sx(start):.1f}" height="{plot_h:.1f}" '
                   f'fill="{theme["grid"]}" opacity="0.55"/>')
        out.append(text((sx(start) + sx(end)) / 2, pad_t - 8, PHASE_LABEL[phase],
                        fill=theme["muted"], size=10, anchor="middle"))

    for tick in range(5):
        value = top * tick / 4
        y = sy(value)
        out.append(f'<line x1="{pad_l:.1f}" y1="{y:.1f}" x2="{pad_l + plot_w:.1f}" '
                   f'y2="{y:.1f}" stroke="{theme["grid"]}" stroke-width="1"/>')
        out.append(text(pad_l - 8, y + 4, f"{value:,.0f}", fill=theme["muted"],
                        size=10, anchor="end"))
    out.append(text(pad_l - 8, pad_t - 26, "MiB", fill=theme["muted"], size=10, anchor="end"))

    out.append(f'<line x1="{pad_l:.1f}" y1="{pad_t + plot_h:.1f}" '
               f'x2="{pad_l + plot_w:.1f}" y2="{pad_t + plot_h:.1f}" '
               f'stroke="{theme["axis"]}" stroke-width="1"/>')
    for tick in range(6):
        seconds = span * tick / 5
        out.append(text(sx(seconds), pad_t + plot_h + 18, f"{seconds:,.0f}",
                        fill=theme["ink_secondary"], size=10, anchor="middle"))
    out.append(text(pad_l + plot_w / 2, pad_t + plot_h + 38, "seconds",
                    fill=theme["muted"], size=10, anchor="middle"))

    path = " ".join(f"{'M' if i == 0 else 'L'}{sx(s):.1f},{sy(m):.1f}"
                    for i, (s, m, _) in enumerate(points))
    out.append(f'<path d="{path}" fill="none" stroke="{theme["series"][0]}" '
               f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>')

    peak = max(points, key=lambda p: p[1])
    out.append(f'<circle cx="{sx(peak[0]):.1f}" cy="{sy(peak[1]):.1f}" r="4" '
               f'fill="{theme["series"][0]}" stroke="{theme["surface"]}" stroke-width="2"/>')
    out.append(text(sx(peak[0]) + 10, sy(peak[1]) + 4, f"peak {peak[1]:,.0f} MiB",
                    fill=theme["ink_secondary"], size=10))
    return svg_document(width, height, theme, "\n".join(out))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    results = Path(argv[1])
    written = []

    csv_path = results / "results.csv"
    if csv_path.exists():
        rows = list(csv.DictReader(csv_path.open()))
        for mode, theme in THEMES.items():
            svg = throughput_chart(rows, theme)
            if svg:
                target = results / f"throughput-{mode}.svg"
                target.write_text(svg)
                written.append(target)

    rss_path = results / "gateway-rss.csv"
    if rss_path.exists():
        samples = list(csv.DictReader(rss_path.open()))
        payload = (results / "payload-size.txt").read_text().strip() \
            if (results / "payload-size.txt").exists() else "a large object"
        for mode, theme in THEMES.items():
            svg = memory_chart(samples, theme, payload)
            if svg:
                target = results / f"memory-{mode}.svg"
                target.write_text(svg)
                written.append(target)

    if not written:
        print(f"nothing to plot in {results}", file=sys.stderr)
        return 1
    for target in written:
        print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
