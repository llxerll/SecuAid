"""마크다운 → PDF 변환 (제출용 기획서). 외부 도구 없이 fpdf2 + 시스템 한글 폰트 사용.

준비: pip install fpdf2
사용: python scripts/make_pdf.py docs/기획서_요약_1p.md out/기획서_요약.pdf
     --font 로 한글 폰트 경로를 지정할 수 있다(기본: Noto Sans CJK KR OTF).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FONT_CANDIDATES = (
    "/usr/share/fonts/pickle-hwp/NotoSansCJKkr-Regular.otf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "C:/Windows/Fonts/malgun.ttf",
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
)


def pick_font(explicit: str | None) -> str:
    if explicit:
        return explicit
    for p in FONT_CANDIDATES:
        if Path(p).exists():
            return p
    raise SystemExit("한글 폰트를 찾지 못했습니다. --font 로 지정하세요.")


def strip_inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"`(.+?)`", r"\1", text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r"\1 (\2)", text)
    return text


def build(md_path: Path, out_path: Path, font: str) -> None:
    from fpdf import FPDF

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_font("K", "", font)
    pdf.add_font("K", "B", font)
    pdf.add_page()
    pdf.set_margins(18, 16, 18)

    def write(text: str, size: int, bold: bool = False, gap: float = 2.0, color=(20, 24, 33)) -> None:
        pdf.set_font("K", "B" if bold else "", size)
        pdf.set_text_color(*color)
        pdf.multi_cell(0, size * 0.52, text)
        pdf.ln(gap)

    table: list[list[str]] = []

    def flush_table() -> None:
        nonlocal table
        if not table:
            return
        rows = [r for r in table if not all(set(c) <= set("-: ") for c in r)]
        body = rows[1:] if len(rows) > 1 else rows
        for row in body:
            cells = [strip_inline(c.strip()) for c in row]
            cells = [c for c in cells if c]
            if not cells:
                continue
            head, tail = cells[0], " — ".join(cells[1:])
            write(f"• {head}" + (f": {tail}" if tail else ""), 8.8, color=(60, 70, 90), gap=0.6)
        pdf.ln(1)
        table = []

    for raw in md_path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("|"):
            table.append([c for c in line.strip().strip("|").split("|")])
            continue
        flush_table()
        if not line.strip():
            pdf.ln(1.2)
            continue
        if line.startswith("# "):
            write(strip_inline(line[2:]), 17, bold=True, gap=3)
            pdf.set_draw_color(60, 110, 200)
            pdf.set_line_width(0.6)
            pdf.line(18, pdf.get_y(), 192, pdf.get_y())
            pdf.ln(2.5)
            continue
        if line.startswith("## "):
            write(strip_inline(line[3:]), 12.5, bold=True, gap=1.6, color=(24, 60, 130))
            continue
        if line.startswith("### "):
            write(strip_inline(line[4:]), 10.5, bold=True, gap=1.2)
            continue
        if line.startswith("> "):
            write(strip_inline(line[2:]), 8.8, color=(90, 100, 120), gap=0.6)
            continue
        if line.startswith("- "):
            write("• " + strip_inline(line[2:]), 9.5, gap=0.6)
            continue
        m = re.match(r"^(\d+)\.\s+(.*)$", line)
        if m:
            write(f"{m.group(1)}. " + strip_inline(m.group(2)), 9.5, gap=0.6)
            continue
        if line.startswith("---"):
            pdf.ln(1)
            continue
        write(strip_inline(line), 9.5, gap=1.0)

    flush_table()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))
    print(f"PDF 생성: {out_path} ({out_path.stat().st_size:,} bytes, {pdf.pages_count}쪽)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--font", default=None)
    args = ap.parse_args()
    build(Path(args.src), Path(args.out), pick_font(args.font))


if __name__ == "__main__":
    sys.exit(main())
