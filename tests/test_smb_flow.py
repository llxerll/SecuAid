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


class TestNoKnowledgeFlow(unittest.TestCase):
    """v0.11 — 시계는 사건 시작과 함께, 질문은 버튼으로."""

    def test_clock_starts_on_category_pick(self):
        a = agent()
        b = a.apply_category("CAT04_RANSOMWARE", guide=False)
        self.assertIsNotNone(b["case"]["aware_iso"])
        self.assertEqual(a.case.level("aware_at"), "추정")
        self.assertTrue(any(d["due_iso"] for d in b["deadlines"]["items"]))
        self.assertEqual(b["asks"][0]["id"], "aware")       # 실제 안 시각을 먼저 묻는다

    def test_clock_starts_on_vague_first_message(self):
        b = agent().handle("뭔가 이상해요")
        self.assertIsNotNone(b["case"]["aware_iso"])

    def test_every_answer_button_is_understood(self):
        expect = {
            ("transfer", "이미 보냈대요"): ("transfer_status", "done"),
            ("transfer", "안 보냈대요"): ("transfer_status", "none"),
            ("backup", "연결돼 있었어요"): ("backup_status", "at_risk"),
            ("backup", "백업 없어요"): ("backup_status", "none"),
            ("hosts", "2~5대"): ("encrypted_hosts", 3),
            ("pi", "없어요"): ("personal_data_leak", "none"),
            ("pi", "많이 있어요(1천 명 이상)"): ("affected_count", 1000),
            ("ict", "네, 운영해요"): ("is_ict_service_provider", True),
            ("ict", "아니요"): ("is_ict_service_provider", False),
        }
        for (qid, label), (key, val) in expect.items():
            say = dict(Agent.ASK_OPTIONS[qid])[label]
            a = agent()
            a.handle("거래처에서 계좌 변경 메일 관련 연락이 왔어요")
            a.handle(say)
            self.assertEqual(a.case.value(key), val, (qid, label))

    def test_skip_and_correct_aware(self):
        a = agent()
        a.apply_category("CAT04_RANSOMWARE", guide=False)
        a.skip_ask("backup")
        self.assertNotIn("backup", [x["id"] for x in a.asks()])
        self.assertIn("백업", " ".join(a._missing_questions()))     # 브리핑에는 여전히 '모름'으로 남는다
        self.assertTrue(a.set_aware_from_text("오늘 아침 8시 반"))
        self.assertEqual(a.case.level("aware_at"), "확인")
        self.assertNotIn("aware", [x["id"] for x in a.asks()])
        self.assertFalse(a.set_aware_from_text("언젠가"))
        restored = Agent.from_token(a.snapshot_token())
        self.assertIn("backup", restored.case.skipped)


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


class TestActionHowto(unittest.TestCase):
    """v0.12 — 할 일마다 '어떻게 하나요?'(준비물·순서·전화 대본) 내장 안내가 붙는다."""

    def test_match_requires_every_group(self):
        from incident_note import playbook
        self.assertEqual(playbook.howto_for("송금 은행 공식 대표번호로 지급정지·회수 요청")["id"], "H_BANK_RECALL")
        self.assertIsNone(playbook.howto_for("지급정지 여부를 나중에 검토"))   # '회수/리콜' 묶음이 없다

    def test_howto_items_are_complete(self):
        from incident_note import playbook
        ids = [h["id"] for h in playbook.howto_items()]
        self.assertEqual(len(ids), len(set(ids)))
        for h in playbook.howto_items():
            self.assertTrue(h["title"] and h["steps"] and h["match"], h["id"])

    def test_urgent_actions_have_howto(self):
        for sc in ("s1_bec_account_change", "s4_ransomware"):
            b = Agent().run_scenario(sc)
            first = b["actions"][:3]
            self.assertTrue(all(a["howto"] for a in first), [a["action"][:30] for a in first])
            for a in b["actions"]:
                if a["howto"]:
                    self.assertIn(a["howto"], b["howto"])          # 보드에 본문이 함께 실린다
            self.assertNotIn("match", next(iter(b["howto"].values())))

    def test_plain_language_bec_first_action_has_script(self):
        ag = agent()
        b = ag.handle("거래처에서 저희 메일로 계좌번호가 바뀌었다고 전화 왔어요. 이미 1,870만 원을 보냈대요")
        top = b["actions"][0]
        self.assertEqual(top["howto"], "H_BANK_RECALL")
        self.assertIn("지급정지", b["howto"]["H_BANK_RECALL"]["script"])
