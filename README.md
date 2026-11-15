# 인시던트 노트 (Incident Note)

> 이메일 침해 초동대응 에이전트 — 보안 담당자가 없는 회사의 첫 72시간을 지키는 AI
> Liner .EXE-THON 2026 제출작 (v0.3)

메일 계정이 뚫린 날, 작은 회사의 IT 담당자는 무엇부터 해야 할지 모릅니다.
인시던트 노트는 **로그·메일 원본을 붙여넣으면** ① 침해 유형과 심각도를 판정하고, ② 지금 할 일과 하지 말 것을 순서대로 주며, ③ 법정 신고·통지 기한을 계산하고, ④ 통지문·신고서 초안을 만들어 주는 에이전트입니다.

**계산은 규칙 엔진이, 해석과 문장은 Liner가, 최종 판단과 발송은 사람이 합니다.**

---

## 1. 30초 실행

```bash
# 1) 의존성 (Flask 1개 + 선택: python-docx)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Liner API 키 설정 (https://platform.liner.com/ko/keys 에서 발급)
cp .env.example .env
#   .env 파일을 열어 LINER_API_KEY=sk_live_... 값을 채웁니다. (코드에는 절대 넣지 않습니다)

# 3) 실행
python app.py
#   → http://127.0.0.1:8000
```

키 없이도 동작합니다. `.env`에 키가 없으면 **규칙 기반 모드**로 자동 전환되어 판정·기한·문서는 그대로 나오고, Liner가 맡는 해석·문장·근거 인용만 꺼집니다.

CLI로 바로 확인하려면:

```bash
python run_demo.py                                  # S1 메인 시나리오
python run_demo.py --scenario s2_lookalike_domain   # 유사 도메인 사칭
python run_demo.py --scenario s3_selfhosted_root_out_of_scope
python run_demo.py --offline --out out/s1           # 키 없이 + 결과 저장
```

화면 사용법: 오른쪽 위에서 시나리오를 고르고 **[시나리오 실행]** → 왼쪽 대화에 직접 입력해도 됩니다(로그 CSV·`.eml` 원본 붙여넣기 지원). **[문서 초안 생성]** 을 누르면 통지문·신고서 10종이 만들어집니다.

---

## 2. Liner API를 쓰는 지점 (제출 기준: "Liner API 활용이 드러나야 함")

| 쓰는 곳 | 엔드포인트 | 모델/헤더 | 코드 위치 | 무엇을 대신하나 |
|---|---|---|---|---|
| 대화·판단 해석·문장 작성 | `POST /api/v1/chat/completions` | `liner-mark-1.3`, `Authorization: Bearer` | `incident_note/liner.py: chat()`, `agent.py: _narrate()` | 사용자의 말("거래처에서 계좌 바꿨냐고 전화가 왔어요")을 구조화된 사실로 바꾸고, 사건 브리핑 문장을 씁니다. **확인/추정/미확인을 구분**하고 JSON에 없는 수치·법령은 만들지 않도록 프롬프트로 제한합니다. |
| 법령·공지 최신성 확인 | `POST /api/v1/agents/search` | `x-api-key`, `stream: false` | `liner.py: search_agent()`, `agent.py: verify_law()` | 신고 기한의 근거(정보통신망법 §48조의3 24시간 / 개인정보보호법 §34조 72시간)를 **출처 링크와 함께** 재확인하고, 코드 규칙과 답변이 다르면 `drift`로 표시합니다. |
| 공식 창구·참고 자료 | `POST /api/v1/tools/search/web` | `x-api-key` | `liner.py: search_web()` | KISA 보호나라(118)·개인정보포털 등 신고 창구 링크를 결과 카드에 붙입니다. |

> **기획서 정정:** v0.9 기획서의 `Liner Legal Search` 는 실제로 존재하는 API명이 아닙니다. Liner Platform의 실제 구성은 Router API(`liner-mark-1.3` 등) + Tools API(Search·Visualization) + Agent API(Quick Answer·Search Agent·Deep Research·Visual Answer)이며, 이 프로젝트는 그중 위 3개를 실제로 호출합니다. (2026-11-15 `platform.liner.com` 문서와 라이브 호출로 검증)

**비용·지연:** Search Agent 1회 ≈ 25초, chat 1회 ≈ 2~3초. S1 시나리오 전체(5단계 + 문서) 실측 **약 45초**, 크레딧은 1회 실행당 수십 센트 수준입니다.

---

## 3. 데모 시나리오 3종 (모두 가상 데이터)

| 시나리오 | 무슨 일이 있었나 | 에이전트 정답 행동 | 데이터 |
|---|---|---|---|
| **S1** 영업관리 계정 탈취 → 계좌 변경 사칭 (메인) | M365 계정 AiTM 탈취 → 숨김 규칙 `..` 생성 → 거래처 3곳 + 214명 피싱 발송 → 거래처 전화로 인지 → 다음 날 아침 거래처가 1,870만 원 송금 | 판별 **ATO(확인)** → 송금 확인 시 **P1** → 은행 지급정지 최우선 → 신고 11/20 09:05, 통지 11/22 09:05 → 문서 10종 | `data/scenarios/s1_bec_account_change/` |
| **S2** 유사 도메인 사칭 | `hanbit-logistcs.example`(두 글자 다름)에서 우리 이름으로 계좌 변경 메일. 내부 로그인·발송 흔적 없음 | **유사 도메인(P4)** — 우리 계정 침해 아님, 신고 비해당 → 차단·고객 경고·DMARC 점검이 답 | `data/scenarios/s2_lookalike_domain/` |
| **S3** 메일 서버 root 탈취 (범위 밖) | SSH 무차별 대입 → root 장악 → 원격제어 에이전트 설치 → 로그 삭제 → 외부 3389 아웃바운드 | **모른다고 말함** — 재부팅·삭제 금지, 초동 조치 + **전문 대응 조직 호출**, 신고 기한만 계산 | `data/scenarios/s3_selfhosted_root_out_of_scope/` |

시나리오별 데모 발화는 각 폴더의 `README.md` 와 `scenario.json` 의 `demo_inputs` 에 있습니다. S2는 "**우리가 신고해야 하나요?**"라는 질문에 "비해당, 대신 할 일은 이것"이라고 답하는 장면을 보여 주기 위한 대조군입니다.

---

## 4. 구조

```
incident-note/
├─ app.py                     # Flask 웹 앱 (사건 보드 + 대화 API + 문서 다운로드)
├─ run_demo.py                # CLI 데모/리포트 생성
├─ templates/index.html       # 화면 (한 페이지)
├─ static/{style.css,app.js}  # 스타일·화면 로직 (의존성 없음)
├─ incident_note/
│   ├─ agent.py               # 오케스트레이터: 대화 → 사실 → 엔진 → 문서
│   ├─ case.py                # 사실(fact) + 확인/추정/미확인 + 출처
│   ├─ ingest.py              # 로그 인제스트(다중 붙여넣기·형식 자동 판별)
│   ├─ eml.py                 # EML 헤더 판독(ATO/스푸핑/유사 도메인)
│   ├─ detect.py              # 결정적 규칙 엔진(14규칙 + 서버 6규칙)
│   ├─ classify.py            # 유형 판정 + 근거·모르는 것
│   ├─ severity.py            # 심각도 P1~P4 + 격상 조건
│   ├─ deadline.py            # 신고·통지 기한 + 운영 연락
│   ├─ playbook.py            # 플레이북 → 지금 할 일 / 하지 말 것
│   ├─ docs.py                # 통지문·신고서·타임라인 초안
│   ├─ liner.py               # Liner API 클라이언트(재시도·오류 매핑·오프라인 폴백)
│   ├─ mask.py                # PII 마스킹(모델로 보내기 전)
│   └─ timeutil.py            # UTC→KST, D-day 계산
├─ data/
│   ├─ playbook_tree.json     # 플레이북 판단 구조(저작물 원문 아님, 구조화 데이터)
│   ├─ log_rules.json         # 메일 계정 침해 규칙 14종
│   ├─ log_rules_selfhosted.json # 자체 서버(root) 규칙 6종
│   ├─ reporting_rules.json   # 신고·통지 규칙 3종 + 운영 연락 5종
│   ├─ templates.json         # 통지 템플릿 6종 + 발송 전 통과표
│   └─ scenarios/             # 가상 시나리오 3종(로그·메일·정답지)
├─ tests/                     # 단위 + 시나리오 E2E + HTTP E2E + 라이브 API
├─ docs/기획서_요약_1p.md      # 제출용 1~2페이지 기획서 원고
├─ docs/기획서_v1.0.html       # 전체 기획서 v1.0 원본(HTML+CSS, 인쇄용)
├─ docs/인시던트노트_기획서_v1.0.pdf  # 위 원본을 렌더한 제출용 PDF(12쪽)
├─ scripts/make_pdf_v1.py      # HTML → A4 PDF 렌더러(Pretendard + WeasyPrint)
├─ docs/데모_시나리오_5분.md    # 5분 데모 영상 촬영 대본
├─ .env.example               # 키 이름만 있는 예시(값 없음)
└─ .gitignore                 # .env, *.zip, *.pdf 차단
```

---

## 5. 설계 원칙 (왜 LLM에게 다 맡기지 않았나)

| 원칙 | 구현 |
|---|---|
| **계산은 규칙, 판단·문장은 모델** | 심각도·기한·타임라인·탐지는 `severity/deadline/detect`의 결정적 코드. 같은 입력이면 같은 출력. LLM은 해석과 문장만. |
| **확인 / 추정 / 미확인을 섞지 않는다** | 모든 사실이 `Fact(value, level, source)` 이고, 문서·화면·응답이 수준을 항상 표시. 모르는 칸은 `미확인`으로 남기고 지어내지 않음. |
| **"결과 없음"을 "피해 없음"으로 쓰지 않는다** | 로그 종류가 빠지면 `notes`에 한계를 기록하고, 신고 판단은 `판단 보류`로 남김. |
| **민감정보를 밖으로 보내지 않는다** | `mask.py`가 주민번호·전화·계좌·카드·이메일(도메인 유지)을 토큰으로 바꾼 뒤 Liner로 전송하고, 응답에서 복원. |
| **발송은 사람이** | 문서는 초안 + 발송 전 통과표까지만. 링크 삽입 금지, "피해 없음" 단정 금지. |
| **모르면 모른다고 한다** | 서버 자체 장악은 플레이북 범위 밖 → 아는 척하지 않고 전문 대응 호출 + 기한 계산까지만. |

---

## 6. 테스트

```bash
# 단위 + 시나리오 E2E (키 불필요, 약 1초)
python -m unittest discover -s tests -p "test_*.py"

# 웹 UI·API E2E — 실제 서버를 띄워 HTTP로 검증하고 종료
python -m unittest tests.e2e_http -v

# Liner 실제 호출 테스트 (크레딧 소모, 약 15초)
LINER_LIVE=1 python -m unittest tests.test_live_liner -v
```

검증 항목(요약): 시간대 변환(naive를 서버 로컬로 오인하지 않음), PII 마스킹 왕복, 로그 형식 자동 판별·다중 붙여넣기, 규칙 14+6종 탐지와 오탐 방지(정상 발송·`Set-Mailbox` 오탐), 판별 3분류, 심각도 P2→P1 격상, 기한 계산(11/20·11/22 09:05), 문서에 링크·빈칸 없음, 화면 DOM id 정합, 시나리오 3종 기대값.

**v0.3 실측:** `73 tests OK` (단위·시나리오) + `8 tests OK` (HTTP E2E) + `4 tests OK` (Liner 라이브).

---

## 7. API 키·보안

- 키는 **환경변수로만** 읽습니다(`incident_note/liner.py: LinerClient.from_env()`). 소스·데이터·문서에 하드코딩 없음.
- `.env` 는 `.gitignore` 로 커밋 차단, 저장소에는 값 없는 `.env.example` 만 둡니다.
- 오류 메시지에 키가 섞이면 `***` 로 지웁니다.
- **심사팀 교체 실행:** `.env`(또는 셸 환경변수)의 `LINER_API_KEY` 만 바꾸면 됩니다. `LINER_MODEL` 로 모델도 교체 가능합니다.
- 로그·시나리오 데이터는 전부 가상입니다(RFC 5737 예약 IP, `.example` 도메인, 가상 은행·계좌).

---

## 8. 한계

- 법률 자문이 아닙니다. 신고·통지 판단은 규칙 + Liner 근거로 **초안**을 만들고, 최종 판단은 담당자/전문가가 합니다. 자동 제출은 하지 않습니다.
- M365(Entra·통합 감사·메시지 추적)와 Linux secure/방화벽 로그를 1차 지원합니다. Google Workspace·국내 호스팅 로그는 같은 정규화(`ingest.py`)에 파서를 추가하면 됩니다.
- 사건 상태는 메모리(세션)에 있습니다. 서버를 재시작하면 사라집니다(데모 목적).
- 실서비스에서는 사서함 원문을 서버에 두지 않고, 마스킹된 요약만 모델로 보내는 구조를 유지해야 합니다.

---

## 9. 제출물 체크리스트 (11/25 23:59 KST 마감)

> 저장소: https://github.com/llxerll/incident-note (제출 전까지 **private 전환 필요** — 현재 공개 상태)
> 기획서 PDF: 전체본 `docs/인시던트노트_기획서_v1.0.pdf`(12쪽, v0.3 실측 반영) · 요약본 `projects/인시던트노트_기획서요약_v0.3.pdf`
> 기획서 재생성: `pip install weasyprint` → `python scripts/make_pdf_v1.py docs/기획서_v1.0.html docs/인시던트노트_기획서_v1.0.pdf` (Pretendard 폰트는 CDN에서 자동 준비)

| 제출물 | 상태 |
|---|---|
| ① 소스코드 (공개 GitHub 저장소) | 이 저장소. 키 없음, README 실행법·Liner 사용 지점 포함 |
| ② 데모 영상 5분 이내 | `docs/데모_시나리오_5분.md` 대본대로 촬영 (문제 → 실제 동작 화면 → Liner 사용 지점) |
| ③ 기획서 PDF 1~2p | `docs/기획서_요약_1p.md` 를 PDF로 변환 |

---

## 10. v0.2 → v0.3 변경 내역

**버그·정합성**
1. `LR_IMPOSSIBLE_TRAVEL` 이 `CorrelationId` 만 보고 "60분 내 두 국가" 조건은 구현하지 않았던 문제 → 60분 규칙 구현, 정상 사내 IP가 의심 IP로 섞이던 오탐 수정.
2. `LR_HEADER_TRIAGE` 가 규칙 데이터에만 있고 EML 파서가 없던 문제 → `eml.py` 로 ATO/스푸핑/유사 도메인 판독 구현.
3. 감사 로그의 `Send` 오퍼레이션을 전혀 탐지하지 않던 문제 → 발송 탐지 추가(수신자 수, 계좌 키워드, 의심 IP 조건).
4. 모든 `Send`/`Set-Mailbox` 를 의심으로 잡던 오탐 → IP·전달 파라미터 조건 추가(정상 직원 발송 오탐 0건, 테스트로 고정).
5. 시간대 없는 값을 `astimezone()` 으로 서버 로컬 시간으로 해석하던 버그 → UTC 명시 해석 + KST 병기, 회귀 테스트 추가.
6. 메일 원문·로그 본문에 있는 단어("문서 공유")로 사용자 의도(문서 생성)를 잘못 읽던 문제 → 원문 길이·형식 기반 분기.
7. 시나리오 s3 제목 오기("시나리오 1") 및 `log_rules_selfhosted.json` 미구현 → 수정·추가.

**빠져 있던 기능**
8. 심각도 엔진(P1~P4)·격상 조건 신규 구현.
9. PII 마스킹 신규 구현(기획서 핵심 원칙).
10. 문서 생성(통지 6종 + 신고서 3종 + 경영진 보고 + 타임라인), 발송 전 통과표.
11. 웹 UI(사건 보드: 지금 할 일·기한·타임라인·판정·하지 말 것·문서).
12. Liner API 3종 실제 연동(키 없으면 자동 폴백), 법령 재확인·출처 카드.
13. 테스트 85개(단위·시나리오 73 + HTTP E2E 8 + 라이브 4) 및 시나리오 S2(대조군) 추가.
14. README·`.env.example`·1p 기획서·5분 데모 대본.

**알려진 차이**
- 기획서 6쪽의 "23건 탐지"는 v0.2 규칙 기준입니다. v0.3은 감사 로그 `Send` 를 추가로 잡아 S1에서 25건(중복 제거 후)을 보고합니다. 줄이 아니라 **왜 늘었는지**가 감사 기록으로 남습니다.
