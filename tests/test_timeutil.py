"""시간대 변환 단위 테스트 — v0.2의 naive datetime 버그 회귀 방지."""
import unittest
from datetime import datetime, timezone

from incident_note.timeutil import (KST, human_delta, kst_label, parse_kst_local,
                                    parse_ts, utc_label)


class TestParse(unittest.TestCase):
    def test_z_suffix(self):
        dt = parse_ts("2026-11-16T01:14:22Z")
        self.assertEqual(dt, datetime(2026, 11, 16, 1, 14, 22, tzinfo=timezone.utc))

    def test_offset(self):
        dt = parse_ts("2026-11-19T09:05:00+09:00")
        self.assertEqual(utc_label(dt), "2026-11-19T00:05:00Z")

    def test_naive_is_utc_not_server_local(self):
        # v0.2: naive 값을 astimezone()으로 바꿔 서버 로컬 시간으로 해석하는 버그가 있었다.
        dt = parse_ts("2026-11-16 01:14:22")
        self.assertEqual(utc_label(dt), "2026-11-16T01:14:22Z")

    def test_naive_as_kst_when_asked(self):
        dt = parse_ts("2026-11-19 09:05", assume_utc=False)
        self.assertEqual(utc_label(dt), "2026-11-19T00:05:00Z")

    def test_syslog_with_year(self):
        dt = parse_ts("Nov 16 11:22:03", assume_utc=False, default_year=2026)
        self.assertEqual(utc_label(dt), "2026-11-16T02:22:03Z")

    def test_empty(self):
        self.assertIsNone(parse_ts(""))

    def test_bad_format_raises(self):
        with self.assertRaises(ValueError):
            parse_ts("어제 새벽쯤")


class TestLabel(unittest.TestCase):
    def test_kst_label_has_weekday_and_tz(self):
        dt = parse_ts("2026-11-19T00:05:00Z")
        self.assertEqual(kst_label(dt), "2026-11-19(목) 09:05 KST")

    def test_weekday_boundary(self):
        # 2026-11-20T00:05Z = KST 09:05, 금요일
        self.assertIn("(금)", kst_label(parse_ts("2026-11-20T00:05:00Z")))

    def test_parse_kst_local(self):
        dt = parse_kst_local("2026-11-19 09:05")
        self.assertEqual(kst_label(dt), "2026-11-19(목) 09:05 KST")

    def test_human_delta(self):
        now = parse_ts("2026-11-18T00:00:00Z")
        later = parse_ts("2026-11-20T00:05:00Z")
        self.assertEqual(human_delta(later, now), "2일 5분 남음")
        self.assertTrue(human_delta(now, later).startswith("경과"))


if __name__ == "__main__":
    unittest.main()
