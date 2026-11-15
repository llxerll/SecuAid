"""기획서 v1.0 HTML → PDF 렌더러.

디자인은 docs/기획서_v1.0.html(HTML+CSS)에 있고, 이 스크립트는 폰트를 준비해
WeasyPrint로 A4 PDF를 만든다. (Playwright/Chromium이 있으면 --engine chromium)

사용:
    python scripts/make_pdf_v1.py docs/기획서_v1.0.html out/인시던트노트_기획서_v1.0.pdf
    python scripts/make_pdf_v1.py --font-dir ~/fonts/Pretendard ...
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

WEIGHTS = ("Regular", "Medium", "SemiBold", "Bold")
FONT_URL = "https://cdn.jsdelivr.net/npm/pretendard@1.3.9/dist/web/static/woff2/Pretendard-{w}.woff2"


def ensure_fonts(target: Path, font_dir: Path | None) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for w in WEIGHTS:
        dst = target / f"Pretendard-{w}.woff2"
        if dst.exists():
            continue
        if font_dir and (font_dir / dst.name).exists():
            shutil.copy(font_dir / dst.name, dst)
            continue
        try:
            with urllib.request.urlopen(FONT_URL.format(w=w), timeout=30) as r:
                dst.write_bytes(r.read())
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Pretendard-{w}.woff2 를 준비하지 못했습니다: {exc}\n--font-dir 로 지정하세요.")


def render_weasyprint(html_path: Path, out_path: Path, build_dir: Path) -> None:
    from weasyprint import HTML

    HTML(filename=str(build_dir / html_path.name), base_url=str(build_dir)).write_pdf(str(out_path))


def render_chromium(html_path: Path, out_path: Path, build_dir: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.goto((build_dir / html_path.name).as_uri(), wait_until="load")
        page.emulate_media(media="print")
        page.pdf(path=str(out_path), format="A4", print_background=True,
                 margin={"top": "0", "bottom": "0", "left": "0", "right": "0"})
        b.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="기획서 HTML 경로")
    ap.add_argument("out", help="출력 PDF 경로")
    ap.add_argument("--font-dir", default=None, help="Pretendard woff2가 있는 폴더(없으면 CDN에서 받음)")
    ap.add_argument("--engine", default="weasyprint", choices=("weasyprint", "chromium"))
    args = ap.parse_args()

    src = Path(args.src).resolve()
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        build = Path(tmp)
        ensure_fonts(build / "fonts", Path(args.font_dir).expanduser() if args.font_dir else None)
        shutil.copy(src, build / src.name)
        (render_chromium if args.engine == "chromium" else render_weasyprint)(src, out, build)

    print(f"PDF 생성: {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
