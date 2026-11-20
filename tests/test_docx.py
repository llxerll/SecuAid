"""DOCX 품질 테스트 — Windows PC Word·한컴오피스에서 한글이 깨지지 않는지 검증한다.

확인 항목
1. Normal·Heading 1~3·docDefaults 의 ascii/hAnsi/eastAsia/cs 폰트 슬롯이 모두 맑은 고딕
2. 테마 폰트 속성(asciiTheme 등)이 남아 명시 폰트를 덮지 않는지, 글꼴 목록(fontTable) 등록
3. A4·여백 20mm·상단 브랜드 안내·바닥글
4. `■`/`1.` 소제목 → Heading, `- ` 목록 → 실제 불릿, `|` 표 → Word 표, 〔미확인〕 강조
5. 한글 텍스트 보존과 다운로드 헤더(filename*=UTF-8)
"""
from __future__ import annotations

import io
import os
import re
import unittest
import zipfile
from urllib.parse import unquote

os.environ.setdefault("LINER_OFFLINE", "1")

import app as app_module  # noqa: E402
from incident_note.agent import Agent  # noqa: E402
from incident_note.docs import (BRAND_EN, BRAND_KO, DOCX_NOTICE,  # noqa: E402
                                FONT_EA, FONT_LATIN, Document, to_docx)
from incident_note.liner import LinerClient  # noqa: E402

try:
    from docx import Document as Docx  # type: ignore
    from docx.oxml.ns import qn  # type: ignore
    from lxml import etree  # type: ignore
    HAVE_DOCX = True
except Exception:  # noqa: BLE001
    HAVE_DOCX = False

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def open_docx(data: bytes):
    return Docx(io.BytesIO(data))


def rfonts_attr(rpr) -> dict:
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        return {}
    keys = ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs", "w:hint",
            "w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme")
    return {k: rf.get(qn(k)) for k in keys if rf.get(qn(k)) is not None}


@unittest.skipUnless(HAVE_DOCX, "python-docx 가 필요합니다")
class TestDocxQuality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent = Agent(client=LinerClient(api_key=None))
        agent.run_scenario("s1_bec_account_change")
        agent.compose_docs()
        cls.agent = agent
        cls.docs = {k: Document(v["id"], v["title"], v["kind"], v["body"])
                    for k, v in agent.case.docs.items()}
        cls.built = {k: to_docx(v) for k, v in cls.docs.items()}
        cls.timeline = open_docx(cls.built["tpl_timeline"])
        cls.report = open_docx(cls.built["tpl_intrusion_report"])
        cls.exec_page = open_docx(cls.built["tpl_exec_report"])
        cls.notice = open_docx(cls.built["T1_customer"])

    # ---------------------------------------------------------------- 폰트
    def test_all_style_font_slots_are_malgun(self):
        style_names = ("Normal", "Heading 1", "Heading 2", "Heading 3")
        for name in style_names:
            st = self.timeline.styles[name]
            fonts = rfonts_attr(st.element.rPr)
            self.assertEqual(fonts.get("w:eastAsia"), FONT_EA, f"{name} eastAsia")
            self.assertEqual(fonts.get("w:ascii"), FONT_LATIN, f"{name} ascii")
            self.assertEqual(fonts.get("w:hAnsi"), FONT_LATIN, f"{name} hAnsi")
            self.assertEqual(fonts.get("w:cs"), FONT_LATIN, f"{name} cs")
            for theme in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
                self.assertIsNone(fonts.get(theme), f"{name} 에 테마 폰트가 남아 있음")

    def test_doc_defaults_fonts_and_language(self):
        xml = zipfile.ZipFile(io.BytesIO(self.built["tpl_timeline"])).read("word/styles.xml")
        root = etree.fromstring(xml)
        rpr = root.find(f"{W}docDefaults/{W}rPrDefault/{W}rPr")
        fonts = rfonts_attr(rpr)
        self.assertEqual(fonts.get("w:eastAsia"), FONT_EA)
        self.assertEqual(fonts.get("w:ascii"), FONT_LATIN)
        lang = rpr.find(qn("w:lang"))
        self.assertIsNotNone(lang)
        self.assertEqual(lang.get(qn("w:eastAsia")), "ko-KR")

    def test_every_text_run_has_eastasia_font(self):
        """상속에 기대지 않고 모든 런에 eastAsia 폰트가 붙어 있어야 한다."""
        root = etree.fromstring(zipfile.ZipFile(io.BytesIO(self.built["tpl_timeline"])).read("word/document.xml"))
        checked = 0
        for run in root.iter(f"{W}r"):
            text = "".join(t.text or "" for t in run.iter(f"{W}t"))
            if not text.strip():
                continue
            rpr = run.find(f"{W}rPr")
            self.assertIsNotNone(rpr, f"rPr 없는 런: {text[:30]}")
            fonts = rfonts_attr(rpr)
            self.assertEqual(fonts.get("w:eastAsia"), FONT_EA, f"eastAsia 누락: {text[:30]}")
            self.assertEqual(fonts.get("w:ascii"), FONT_LATIN, f"ascii 누락: {text[:30]}")
            checked += 1
        self.assertGreater(checked, 20)

    def test_font_table_registers_malgun_gothic(self):
        xml = zipfile.ZipFile(io.BytesIO(self.built["tpl_timeline"])).read("word/fontTable.xml")
        root = etree.fromstring(xml)
        names = {f.get(f"{W}name") for f in root}
        self.assertIn(FONT_EA, names)
        self.assertIn(FONT_LATIN, names)
        entry = [f for f in root if f.get(f"{W}name") == FONT_EA][0]
        self.assertEqual(entry.find(f"{W}altName").get(f"{W}val"), FONT_LATIN)

    # ---------------------------------------------------------------- 판면
    def test_a4_page_with_20mm_margins(self):
        sec = self.timeline.sections[0]
        self.assertAlmostEqual(sec.page_width.mm, 210, delta=1)
        self.assertAlmostEqual(sec.page_height.mm, 297, delta=1)
        for side in (sec.top_margin, sec.bottom_margin, sec.left_margin, sec.right_margin):
            self.assertAlmostEqual(side.mm, 20, delta=0.6)
        self.assertAlmostEqual(sec.header_distance.mm, 10, delta=0.6)

    def test_brand_notice_and_title(self):
        texts = [p.text for p in self.timeline.paragraphs]
        self.assertTrue(any(DOCX_NOTICE == t for t in texts), texts[:3])
        self.assertTrue(any(f"{BRAND_EN} · {BRAND_KO}" in t for t in texts))
        heading = [p for p in self.timeline.paragraphs if p.style.name == "Heading 1"]
        self.assertEqual(len(heading), 1)
        self.assertEqual(heading[0].text, "사고 타임라인")

    def test_footer_has_brand_and_page_number(self):
        footer = self.timeline.sections[0].footer
        text = "\n".join(p.text for p in footer.paragraphs)
        self.assertIn(BRAND_KO, text)
        xml = zipfile.ZipFile(io.BytesIO(self.built["tpl_timeline"])).read("word/footer1.xml")
        self.assertIn(b"PAGE", xml)

    # ---------------------------------------------------------------- 구조
    def test_pipe_rows_become_real_table(self):
        self.assertEqual(len(self.timeline.tables), 1)
        table = self.timeline.tables[0]
        self.assertEqual(len(table.columns), 5)
        self.assertEqual([c.text for c in table.rows[0].cells],
                         ["시각(KST)", "원본(UTC)", "구분", "내용", "근거수준"])
        self.assertGreaterEqual(len(table.rows), 10)
        # 표 안의 한글·시각이 보존되는가
        first = table.rows[1].cells
        self.assertIn("2026-", first[0].text)
        self.assertIn("KST", first[0].text)
        # 표로 바뀌었으니 문단에 파이프가 남아 있으면 안 된다
        self.assertFalse(any("|" in p.text for p in self.timeline.paragraphs))

    def test_heading_and_bullets_are_real_styles(self):
        styles = [p.style.name for p in self.exec_page.paragraphs]
        self.assertIn("Heading 2", styles)
        self.assertIn("List Bullet 2", styles)
        headings = [p.text for p in self.exec_page.paragraphs if p.style.name == "Heading 2"]
        self.assertIn("1. 확인된 사실", headings)
        self.assertIn("4. 필요한 결정", headings)
        bullets = [p.text for p in self.exec_page.paragraphs if p.style.name.startswith("List Bullet")]
        self.assertTrue(any("은행 즉시 연락" in b for b in bullets))

    def test_numbered_fields_are_not_turned_into_headings(self):
        """'1. 신고인: …' 같은 항목은 소제목이 아니라 라벨+값 문단."""
        headings = [p.text for p in self.report.paragraphs if p.style.name.startswith("Heading")]
        self.assertFalse(any(t.startswith("1. 신고인") for t in headings), headings)
        fields = [p for p in self.report.paragraphs if p.text.startswith("1. 신고인:")]
        self.assertEqual(len(fields), 1)
        self.assertTrue(fields[0].runs[0].bold)

    def test_unknown_marks_are_highlighted(self):
        runs = [r for p in self.notice.paragraphs for r in p.runs if "〔미확인:" in r.text]
        self.assertTrue(runs, "〔미확인: …〕 강조 런이 없습니다")
        for run in runs:
            self.assertTrue(run.bold)
            self.assertEqual(str(run.font.color.rgb), "B42318")
            self.assertIn("w:shd", run._element.xml)

    def test_internal_review_notice_is_separated(self):
        texts = [p.text for p in self.notice.paragraphs]
        self.assertTrue(any(t.startswith("▼ 여기부터는 내부 검토용") for t in texts))
        # '=' 구분선이 본문 텍스트로 남지 않는다
        self.assertFalse(any(set(t) == {"="} and len(t) > 10 for t in texts))
        self.assertFalse(any(set(t) == {"-"} and len(t) > 10 for t in texts))

    def test_korean_text_is_preserved(self):
        text = "\n".join(p.text for p in self.report.paragraphs)
        for fragment in ("침해사고 최초신고서 초안", "인지 일시", "개인정보", "미확인"):
            self.assertIn(fragment, text)

    def test_every_document_renders(self):
        self.assertGreaterEqual(len(self.docs), 8)
        for doc_id, data in self.built.items():
            self.assertTrue(data and data.startswith(b"PK"), doc_id)
            opened = open_docx(data)
            self.assertTrue(any(p.style.name == "Heading 1" for p in opened.paragraphs), doc_id)
            self.assertGreater(len(opened.paragraphs), 5, doc_id)


@unittest.skipUnless(HAVE_DOCX, "python-docx 가 필요합니다")
class TestDocxDownloadHttp(unittest.TestCase):
    """HTTP 다운로드 — 한글 파일명(filename*)과 DOCX 바이너리."""

    @classmethod
    def setUpClass(cls):
        cls.client = app_module.app.test_client()
        cls.sid = cls.client.post("/api/session", json={}).get_json()["session"]
        cls.client.post(f"/api/{cls.sid}/scenario/s1_bec_account_change", json={})

    def test_docx_download_headers_and_bytes(self):
        res = self.client.get(f"/api/{self.sid}/doc/tpl_intrusion_report.docx")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.data.startswith(b"PK"))
        cd = res.headers["Content-Disposition"]
        self.assertIn('filename="ShieldMate72_tpl_intrusion_report.docx"', cd)
        self.assertIn("attachment", cd)
        star = re.search(r"filename\*=UTF-8''([^;]+)", cd)
        self.assertIsNotNone(star, cd)
        decoded = unquote(star.group(1))
        self.assertTrue(decoded.startswith("실드메이트72_"), decoded)
        self.assertTrue(decoded.endswith(".docx"), decoded)

    def test_md_download_headers(self):
        res = self.client.get(f"/api/{self.sid}/doc/tpl_timeline")
        self.assertEqual(res.status_code, 200)
        self.assertIn("filename*=UTF-8''", res.headers["Content-Disposition"])
        self.assertIn("사고 타임라인", res.data.decode("utf-8"))

    def test_zip_contains_docx_and_report(self):
        res = self.client.get(f"/api/{self.sid}/docs.zip")
        self.assertEqual(res.status_code, 200)
        names = zipfile.ZipFile(io.BytesIO(res.data)).namelist()
        self.assertIn("00_사건_리포트.md", names)
        self.assertTrue(any(n.endswith(".docx") for n in names), names)
        self.assertIn("filename*=UTF-8''", res.headers["Content-Disposition"])
        report = zipfile.ZipFile(io.BytesIO(res.data)).read("00_사건_리포트.md").decode("utf-8")
        self.assertIn(BRAND_KO, report)

    def test_docx_is_readable_from_http_bytes(self):
        res = self.client.get(f"/api/{self.sid}/doc/tpl_timeline.docx")
        opened = open_docx(res.data)
        self.assertEqual(opened.tables[0].rows[0].cells[0].text, "시각(KST)")
        fonts = rfonts_attr(opened.styles["Normal"].element.rPr)
        self.assertEqual(fonts.get("w:eastAsia"), FONT_EA)


if __name__ == "__main__":
    unittest.main()
