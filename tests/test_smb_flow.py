"""v0.10 실제 중소기업 담당자 시뮬레이션에서 나온 결함의 회귀 테스트 (키 없이 실행)."""
from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone

os.environ.setdefault("LINER_OFFLINE", "1")

from incident_note import evidence, nlu  # noqa: E402
from incident_note.agent import Agent  # noqa: E402

NOW = datetime(2026, 11, 20, 8, 13, tzinfo=timezone.utc)   # 17:13 KST


def agent():
    return Agent()


class TestKoreanTime(unittest.TestCase):
    def test_relative_times(self):
        cases = {
            "오늘 오전 10시쯤 전화 받았어요": (20, 10, 0),
            "어제 저녁 7시에 퇴근할 땐 괜찮았어요": (19, 19, 0),
            "오늘 아침 8시 반에 발견했어요": (20, 8, 30),
            "오후 3시 20분": (20, 15, 20),
            "30분 전에 알았어요": (20, 16, 43),
        }
        for text, (d, h, m) in cases.items():
            t = nlu.parse_time(text, NOW)
            self.assertEqual((t.day, t.hour, t.minute), (d, h, m), text)
        self.assertIsNone(nlu.parse_time("직원은 12명이고", NOW))

    def test_discovery_event(self):
        evs = nlu.extract_events("어제 저녁 7시에 퇴근할 땐 괜찮았어요. 오늘 아침 8시 반에 발견했어요", NOW)
        self.assertEqual([e["discovery"] for e in evs], [False, True])


class TestPlainLanguageFacts(unittest.TestCase):
    def test_negated_transfer_is_not_done(self):
        a = agent()
        a.handle("거래처에서 우리가 계좌를 바꿨냐고 전화가 왔어요")
        b = a.handle("거래처는 아직 돈 안 보냈대요")
        self.assertEqual(a.case.value("transfer_status"), "none")
        self.assertNotEqual(b["severity"]["level"], "P1")

    def test_headcount_is_not_affected_people(self):
        a = agent()
        a.handle("직원은 12명이고 쇼핑몰도 운영해요. 고객 정보는 메일에 거의 없어요")
        self.assertEqual(a.case.value("org_size"), 12)
        self.assertIsNone(a.case.value("affected_count"))
        self.assertIs(a.case.value("is_ict_service_provider"), True)
        self.assertEqual(a.case.level("personal_data_leak"), "추정")
        self.assertNotIn("이름·연락처·주소", str(a.case.value("pi_data_types")))

    def test_bec_call_alone_is_not_ato(self):
        a = agent()
        b = a.handle("거래처에서 우리가 보낸 메일로 계좌번호가 바뀌었다고 전화가 왔어요")
        self.assertIn(a.case.value("incident_type"), (None, "unknown"))
        self.assertTrue(b["actions"])                      # 그래도 지금 할 일은 나온다
        self.assertIn("지급", b["actions"][0]["action"] + b["actions"][1]["action"])

    def test_stated_discovery_time_becomes_aware_time(self):
        a = agent()
        a.handle("출근했더니 파일이 다 이상한 확장자로 바뀌고 열리지가 않아요")
        a.handle("오늘 아침 8시 반에 발견했어요")
        self.assertEqual(a.case.aware_at.astimezone(nlu.KST).strftime("%H:%M"), "08:30")
        self.assertEqual(a.case.fact("aware_at").source, "사용자 진술(발견 시각)")
        self.assertTrue(a.case.events)

    def test_plain_ransomware_words(self):
        a = agent()
        b = a.handle("출근했더니 컴퓨터 파일이 다 이상한 확장자로 바뀌고 열리지가 않아요. 돈 보내라는 메모장이 떠 있어요")
        self.assertEqual(b["category"]["id"], "CAT04_RANSOMWARE")
        self.assertEqual(b["severity"]["level"], "P1")
        self.assertFalse(any("메일 도메인" in q for q in b["missing"]))   # 랜섬웨어에 메일 질문을 하지 않는다
        w = a.handle("돈 주면 풀어준다는데 그냥 주는 게 낫지 않나요?")["warnings"]
        self.assertTrue(any("지불은 권고하지" in x for x in w))

    def test_plugged_backup_is_at_risk(self):
        a = agent()
        a.handle("파일이 이상한 확장자로 바뀌었어요")
        a.handle("백업은 외장하드에 있는데 꽂혀 있었어요")
        self.assertEqual(a.case.value("backup_status"), "at_risk")

    def test_spam_lockout_is_ato(self):
        b = agent().handle("직원 계정으로 스팸이 대량 발송됐다고 MS에서 메일이 왔어요. 계정이 잠겼대요")
        self.assertEqual(b["category"]["id"], "CAT02_MAIL_ACCOUNT_ATO")
        self.assertIn("m365", b["evidence"]["platforms"][0]["id"])

    def test_more_plain_language_types(self):
        cases = {
            "홈페이지 회원 정보가 털린 것 같아요. 관리자 페이지에 모르는 계정이 생겼어요": ("CAT07_WEB_DB_LEAK", "web_hosting"),
            "쇼핑몰 접속이 안 돼요. 트래픽이 폭주한다고 호스팅 업체에서 연락 왔어요": ("CAT09_DDOS_OUTAGE", "web_hosting"),
            "개발자가 AWS 키를 깃허브에 올렸대요. 요금이 갑자기 많이 나왔어요": ("CAT06_CLOUD_KEY_LEAK", "cloud"),
            "퇴사한 직원이 고객 명단을 USB로 가져간 것 같아요": ("CAT08_INSIDER_LEAK", None),
        }
        for text, (cat, platform) in cases.items():
            b = agent().handle(text)
            self.assertEqual((b.get("category") or {}).get("id"), cat, text)
            if platform:
                self.assertEqual(b["evidence"]["platforms"][0]["id"], platform, text)
            self.assertFalse(any("돈이 나갔" in q for q in b["missing"]), text)   # 돈 얘기가 없으면 송금을 묻지 않는다

    def test_no_category_still_has_actions(self):
        b = agent().handle("뭔가 이상한 일이 생긴 것 같아요")
        self.assertTrue(b["actions"])


class TestEvidenceHelper(unittest.TestCase):
    def test_platform_detection_and_order(self):
        a = agent()
        a.handle("저희는 가비아 메일 써요. 로그가 뭔지 모르겠어요")
        b = a.board()
        self.assertEqual(b["evidence"]["platforms"][0]["id"], "kr_mail")
        self.assertIn("[증거 확보]", a.handle("로그는 어디서 확인하나요")["reply"])

    def test_status_and_request_letter(self):
        a = agent()
        a.handle("오늘 오전 10시쯤 거래처에서 전화 받았어요")
        self.assertTrue(evidence.set_status(a.case, "KR_LOGIN", "cannot"))
        self.assertFalse(evidence.set_status(a.case, "NOPE", "have"))
        letter = evidence.request_letter(a.case, "kr_mail")
        self.assertIn("보존", letter["body"])
        self.assertIn("〔미확인: 회사명〕", letter["body"])
        restored = Agent.from_token(a.snapshot_token())
        self.assertEqual(restored.case.evidence, {"KR_LOGIN": "cannot"})

    def test_manual_events_in_timeline_doc(self):
        a = agent()
        a.handle("오늘 오전 10시쯤 전화 받았어요")
        a.add_event(datetime(2026, 11, 19, 7, 40, tzinfo=timezone.utc), "거래처에 계좌 변경 메일이 나감", "추정", "사용자 기록")
        docs = a.compose_docs(wait_law=False)
        body = docs["tpl_timeline"]["body"]
        self.assertIn("거래처에 계좌 변경 메일이 나감", body)
        self.assertIn("증거 확보 현황", body)
        self.assertLess(body.index("거래처에 계좌 변경 메일이 나감"), body.index("전화 받았어요"))


if __name__ == "__main__":
    unittest.main()
