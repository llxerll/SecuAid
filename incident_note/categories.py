"""10대 침해 사고 분류 — 유형 선택기·공통 초동조치·즉답 가이드의 단일 출처.

왜 필요한가
- 로그가 없어도 담당자는 "무슨 사고인지"는 안다. 그 한 줄에서 공통 초동조치(차단·보존·보고)와
  법정 기한(24h/72h)까지 바로 세워 주려면 유형별 기본값이 필요하다.
- 핵심 4종(S1 BEC·ATO, S2 유사도메인, S3 서버 root, 신규 S4 랜섬웨어)은 시나리오·결정적 규칙으로
  깊게 판정하고, 나머지 6종은 같은 엔진에 '유형 기본값'만 얹어 공통 흐름을 즉시 작동시킨다.

원칙
- 유형 선택은 '추정' 근거다(사용자 진술). 로그로 확인되면 확인으로 승격된다.
- 여기 문장은 Liner가 없어도 쓰는 규칙 기반 안내다. Liner Quick Answer가 켜져 있으면
  같은 질문에 대한 최신 출처 답변을 함께 보여 주고, 둘을 구분해 표기한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Category:
    id: str
    no: int
    name: str
    short: str
    deep: bool                      # 결정적 규칙·시나리오로 깊게 판정하는 핵심 4종
    incident_type: str              # classify.py 의 유형 코드
    base_severity: str              # 사실이 없을 때의 기본 심각도
    scenario: str | None = None
    guide: str = ""                 # Liner Quick Answer 에 던지는 질문
    offline_guide: str = ""         # 규칙 기반 안내(키 없이도 동작)
    first_15min: list[str] = field(default_factory=list)
    dont_do: list[str] = field(default_factory=list)
    deadline_focus: str = ""
    signals: list[str] = field(default_factory=list)   # 연관 탐지 규칙
    why_severity: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "no": self.no, "name": self.name, "short": self.short,
            "deep": self.deep, "incident_type": self.incident_type,
            "base_severity": self.base_severity, "scenario": self.scenario,
            "guide_question": self.guide, "offline_guide": self.offline_guide,
            "first_15min": self.first_15min, "dont_do": self.dont_do,
            "deadline_focus": self.deadline_focus, "signals": self.signals,
        }


CATEGORIES: tuple[Category, ...] = (
    Category(
        id="CAT01_BEC_ACCOUNT_CHANGE",
        no=1,
        name="이메일 BEC·계좌변경 사칭",
        short="BEC·계좌변경",
        deep=True,
        incident_type="ato",
        base_severity="P3",
        scenario="s1_bec_account_change",
        guide=("거래처 계좌 변경(BEC) 사칭 메일을 받은 한국 소규모 회사가 지금 10분 안에 해야 할 일과, "
               "송금 전과 송금 후에 달라지는 조치를 3문장 이내로 알려주세요."),
        offline_guide=("먼저 지급을 보류하고, 메일에 적힌 번호가 아니라 기존 거래 명세서·연락처 원장의 번호로 "
                       "거래처에 전화해 계좌 변경 사실을 확인합니다. 이미 송금했다면 송금 은행 공식 대표번호로 "
                       "지급정지·회수(리콜)를 요청하고 접수번호·담당자·통화 시각을 남깁니다. "
                       "확인 전에는 '사칭'으로도 '괜찮다'로도 단정하지 않고 확인/추정/미확인으로 나눠 기록합니다."),
        first_15min=[
            "해당 대금 지급 보류를 재무에 지시하고 보류 시각·승인자를 기록",
            "연락처 원장의 번호로 거래처에 전화 — 메일 속 새 번호·회신은 쓰지 않는다",
            "메일 원본(.eml, 헤더 포함)·첨부파일 보존 후 조직 전체 동일 메일 검색",
            "송금이 이미 실행됐다면 송금 은행 공식 번호로 지급정지·회수 요청, 경찰 사이버범죄 신고 병행",
        ],
        dont_do=[
            "메일·청구서에 적힌 '새 담당자 번호'로 진위 확인",
            "확인 전 계좌 변경을 원장에 반영하거나 2차 지급 실행",
            "공격자 메일에 회신해 확인 시도",
        ],
        deadline_focus="정보통신망법 24시간 신고는 '우리 계정 침해'가 확인될 때, 개인정보 유출 통지는 사서함 내용에 따라 판단",
        signals=["SIG_VENDOR_ACCOUNT_CHANGE", "SIG_CEO_TRANSFER", "SIG_INBOX_RULE"],
        why_severity="로그·송금이 확인되면 P1 — 송금 전이면 P2, 근거 없으면 P3",
    ),
    Category(
        id="CAT02_MAIL_ACCOUNT_ATO",
        no=2,
        name="메일·업무 계정 탈취(ATO)",
        short="계정 탈취(ATO)",
        deep=True,
        incident_type="ato",
        base_severity="P3",
        scenario="s1_bec_account_change",
        guide=("메일 계정이 탈취(ATO)된 한국 소규모 회사가 암호 변경만으로 끝내지 않으려면 "
               "어떤 접근 수단을 어떤 순서로 제거해야 하는지 3문장 이내로 알려주세요."),
        offline_guide=("암호 변경은 시작일 뿐입니다. 관리자 콘솔에서 계정을 일시 중지하고 모든 세션·새로고침 토큰을 "
                       "철회한 뒤, 앱 비밀번호·OAuth 동의·전달 규칙·위임·MFA 복구 수단의 낯선 항목을 순서대로 제거합니다. "
                       "각 조치 전에 설정 화면과 시각을 캡처해 두고, 이후 로그인 실패 기록으로 차단을 확인합니다."),
        first_15min=[
            "관리자 콘솔에서 의심 계정 일시 중지 + 모든 세션·토큰 철회(암호 변경만으로는 부족)",
            "업무 메일 밖의 안전한 대응 채널(전화·메신저) 개설 후 참여자 고정",
            "감사 로그에서 받은편지함 규칙·전달·위임·앱 동의 변경 이력 내보내기",
            "같은 피싱 메일을 받은 다른 직원·같은 IP 로그인 계정 조직 전체 검색",
        ],
        dont_do=[
            "암호만 바꾸고 세션·토큰·앱·규칙·위임을 그대로 두기",
            "침해된 계정으로 사고 공지·경고 메일 발송",
            "의심 PC에서 관리자 암호를 변경하거나 관리 콘솔 접속",
        ],
        deadline_focus="메일 서비스를 고객에게 제공하는 사업자면 침해 확인 시 24시간 내 최초 신고",
        signals=["SIG_FOREIGN_LOGIN", "SIG_IMPOSSIBLE_TRAVEL", "SIG_INBOX_RULE", "SIG_OAUTH_CONSENT"],
        why_severity="외부 발송·지속성 수단이 확인되면 P2, 관리자 계정·다수 계정이면 P1",
    ),
    Category(
        id="CAT03_LOOKALIKE_SPOOF",
        no=3,
        name="유사 도메인·스푸핑 사칭",
        short="유사도메인·스푸핑",
        deep=True,
        incident_type="lookalike",
        base_severity="P4",
        scenario="s2_lookalike_domain",
        guide=("우리 도메인과 비슷한 유사 도메인·스푸핑 메일을 받았을 때, 우리 계정 침해 여부를 "
               "어떻게 판별하고 무엇을 차단·신고해야 하는지 3문장 이내로 알려주세요."),
        offline_guide=("먼저 '우리 계정이 뚫린 것'과 '우리 이름을 도용한 것'을 가릅니다. 보낸편지함·메시지 추적·로그인 로그에 "
                       "발송·접근 흔적이 없고 From 도메인 철자가 다르면 유사 도메인 사칭으로 보고, 유사 도메인·발신자 차단과 "
                       "거래처·고객 경고, DMARC 정책 점검으로 처리합니다. 다만 사칭 메일이 내부 정보를 담고 있다면 계정 침해를 먼저 조사합니다."),
        first_15min=[
            "원본 메일(헤더 포함) 확보 — From 도메인 철자·SPF/DKIM/DMARC 결과·Reply-To 확인",
            "우리 계정 침해 여부 기본 점검: 보낸편지함·메시지 추적·로그인 로그",
            "유사 도메인·발신자 수신 차단 규칙 적용",
            "영향 고객·거래처에 공식 채널로 안내, 도메인 테이크다운·등록기관 신고 검토",
        ],
        dont_do=[
            "내부 정보가 담겼는데도 '외부 사칭'으로만 처리",
            "고객 문의마다 다른 답변",
            "'인증 통과 = 안전'으로 단정",
        ],
        deadline_focus="우리 시스템 침해가 없으면 침해사고 신고 비해당 — 대신 차단·경고·도메인 신고",
        signals=["SIG_LOOKALIKE", "SIG_VENDOR_ACCOUNT_CHANGE"],
        why_severity="계정 접근 흔적이 없으면 P4, 내부 정보·침해 흔적이 나오면 즉시 상향",
    ),
    Category(
        id="CAT04_RANSOMWARE",
        no=4,
        name="랜섬웨어 감염",
        short="랜섬웨어",
        deep=True,
        incident_type="ransom",
        base_severity="P1",
        scenario="s4_ransomware",
        guide=("랜섬웨어로 파일이 암호화된 한국 소규모 회사가 0~10분에 해야 할 일과, "
               "몸값을 지불하면 안 되는 이유, 백업·신고 순서를 4문장 이내로 알려주세요."),
        offline_guide=("감염 호스트를 네트워크에서 분리하되 전원은 끄지 않습니다(메모리·암호화 단서 보존). "
                       "백업 서버와 외부 저장장치를 즉시 떼어 내 오프라인 사본을 보호하고, 암호화 범위·시작 시각·랜섬노트를 촬영해 기록합니다. "
                       "몸값은 지불하지 않습니다 — 복호화 보장이 없고 추가 표적이 되며, 지불은 피해 확산을 돕습니다. "
                       "KISA 118에 상담·신고하고, 정보통신망법 24시간 신고와 개인정보 유출 72시간 통지를 사실에 맞춰 계산합니다."),
        first_15min=[
            "감염 호스트를 네트워크에서 분리(전원 차단 금지 — 화면·열린 창·랜섬노트를 촬영해 보존)",
            "백업 서버·NAS·외부 저장장치를 즉시 분리하고 오프라인 사본의 무결성 확인(읽기 전용)",
            "암호화 확장자·랜섬노트 경로·시작 시각·감염 호스트 수를 기록(EDR/파일 서버 로그)",
            "몸값 지불 금지·복구 도구(No More Ransom)·KISA 118 상담을 경영진에 보고하고 결정권자 지정",
        ],
        dont_do=[
            "몸값 지불 — 복호화 보장이 없고 추가 표적·자금 지원이 된다",
            "암호화된 서버 재부팅·포맷·복구 시도로 원본 단서와 로그를 소실",
            "백업이 연결된 상태로 계속 운영해 오프라인 사본까지 암호화",
            "랜섬노트의 연락처로 직접 협상하거나 지불 대행을 신뢰",
        ],
        deadline_focus="정보통신망법 24시간 신고(침해 확인), 개인정보 유출 시 72시간 통지·신고",
        signals=["RW_EXTENSION_MASS", "RW_RANSOM_NOTE", "RW_SHADOW_DELETE", "RW_BACKUP_TARGETED"],
        why_severity="파일 암호화·서비스 중단은 P1 — 복구 가능성과 무관하게 조직 전체 영향",
    ),
    Category(
        id="CAT05_SERVER_ROOT",
        no=5,
        name="서버 root·권한 탈취",
        short="서버 root",
        deep=True,
        incident_type="root",
        base_severity="P1",
        scenario="s3_selfhosted_root_out_of_scope",
        guide=("리눅스 메일 서버의 root 권한이 탈취된 정황이 있을 때, 재부팅·삭제를 피하면서 "
               "초동 조치와 전문 대응 호출까지 어떻게 진행해야 하는지 3문장 이내로 알려주세요."),
        offline_guide=("서버를 재부팅·재설치하거나 의심 프로세스·파일을 지우지 말고 메모리·로그·파일시스템을 그대로 보존합니다. "
                       "네트워크에서 분리할지는 서비스 영향과 함께 결정해 결정자·시각을 기록하고, 외부 사고대응 조직이나 "
                       "호스팅·메일 서비스 지원을 즉시 호출합니다. 우리는 차단·보존·보고까지만 하고 포렌식 결론은 전문가에게 넘깁니다."),
        first_15min=[
            "재부팅·재설치·의심 프로세스 삭제 금지 — 메모리·로그·파일 보존",
            "메일 게이트웨이 내부망 분리 여부를 결정(서비스 중단 영향 포함), 결정자·시각 기록",
            "전문 사고대응 조직 또는 CSP·메일 서비스 지원 즉시 호출",
            "업무 메일 밖의 안전한 대응 채널 개설, KISA 118 신고·보고 일정 확정",
        ],
        dont_do=[
            "재부팅·재설치·프로세스 즉시 삭제 — 메모리·흔적 소실",
            "침해된 서버에서 관리자 암호만 바꾸고 완료로 보고",
            "포렌식 결론을 추정으로 단정해 외부에 전파",
        ],
        deadline_focus="정보통신서비스 제공자면 인지 24시간 내 침해사고 최초 신고",
        signals=["SR_ROOT_LOGIN", "SR_PERSIST_SERVICE", "SR_LOG_TAMPER", "FW_OUTBOUND_RDP"],
        why_severity="관리자 권한 탈취는 피해 범위가 조직 전체로 번질 수 있어 P1",
    ),
    Category(
        id="CAT06_CLOUD_KEY_LEAK",
        no=6,
        name="클라우드·API 키 유출",
        short="클라우드·API키",
        deep=False,
        incident_type="cloud",
        base_severity="P2",
        guide=("AWS·GCP·SaaS API 키가 GitHub 등에 노출된 한국 소규모 회사가 "
               "가장 먼저 폐기·회수해야 할 것과 확인 순서를 3문장 이내로 알려주세요."),
        offline_guide=("키를 먼저 폐기(비활성화)하고 새 키로 교체합니다. 폐기 전 사용 흔적을 확인해야 하므로 "
                       "CloudTrail·감사 로그에서 해당 키의 호출 시각·IP·리소스를 내려받아 보존한 뒤 폐기하고, "
                       "노출 위치(GitHub 커밋·공개 저장소)에서 키를 제거하고 이력을 정리합니다. 과금·데이터 변경 흔적은 별도로 확인합니다."),
        first_15min=[
            "노출된 키 즉시 비활성화·교체, 새 키는 안전한 저장소(시크릿 매니저)로",
            "폐기 전 사용 로그(CloudTrail 등) 내려받아 호출 IP·리소스·시각 보존",
            "노출 경로 제거: 공개 저장소·커밋 이력·로그·스크린샷, 필요 시 저장소 비공개 전환",
            "비정상 리소스 생성(가상머신·과금·버킷 공개) 확인 및 되돌리기",
        ],
        dont_do=[
            "로그 확인 없이 키를 지워 사용 흔적을 함께 잃기",
            "같은 키를 다른 서비스에 재사용",
            "과금 알림만 보고 '피해 없음'으로 단정",
        ],
        deadline_focus="개인정보·고객 데이터 접근이 확인되면 72시간 통지·신고 판단",
        signals=[],
        why_severity="키로 실제 리소스·데이터 접근이 확인되면 P1",
    ),
    Category(
        id="CAT07_WEB_DB_LEAK",
        no=7,
        name="웹 애플리케이션·DB 유출",
        short="웹·DB 유출",
        deep=False,
        incident_type="webdb",
        base_severity="P2",
        guide=("웹 애플리케이션 취약점이나 SQL 인젝션으로 DB가 유출된 정황이 있을 때 "
               "차단·증거 보존·개인정보 신고 판단 순서를 3문장 이내로 알려주세요."),
        offline_guide=("웹서버 로그(WAF·access log)를 먼저 보존하고 취약 경로를 차단(룰·IP 차단·기능 비활성)합니다. "
                       "유출된 테이블·컬럼·행 수를 확인해 개인정보 항목과 정보주체 수를 산정하고, "
                       "1천 명 이상·민감정보·외부 불법접근 중 하나라도 해당하면 72시간 내 신고·통지를 검토합니다. "
                       "웹셸·추가 계정 등 잔류 수단을 점검하고, 서비스 재개 전에 패치와 검증을 합니다."),
        first_15min=[
            "웹서버·WAF·DB 감사 로그 즉시 내려받아 보존(보존 기간 짧은 것부터)",
            "취약 경로·IP 차단, 필요 시 해당 기능 일시 비활성화(서비스 영향 기록)",
            "유출 범위 산정: 테이블·컬럼·행 수, 개인정보 항목, 정보주체 수",
            "웹셸·추가 관리자 계정·백도어 점검, 패치 전 서비스 전면 재개 금지",
        ],
        dont_do=[
            "로그 보존 전 서버 재설치·DB 재구성",
            "유출 규모를 확인하지 않고 '일부'라고 축소 발표",
            "패치·검증 없이 서비스 재개",
        ],
        deadline_focus="개인정보 유출은 인지 72시간 내 신고·통지, 정보통신서비스 제공자면 24시간 내 침해 신고",
        signals=[],
        why_severity="1천 명 이상·민감정보·외부 불법접근이면 P1",
    ),
    Category(
        id="CAT08_INSIDER_LEAK",
        no=8,
        name="내부자 정보 유출",
        short="내부자 유출",
        deep=False,
        incident_type="insider",
        base_severity="P2",
        guide=("퇴사 예정 직원 등 내부자가 고객 정보·소스·계약서를 반출한 정황이 있을 때 "
               "증거 보존과 권한 회수, 법무 판단 순서를 3문장 이내로 알려주세요."),
        offline_guide=("계정·저장소 접근 로그와 반출 흔적(메일 첨부·USB·클라우드 업로드)을 먼저 보존합니다. "
                       "권한은 회수하되 증거를 지우지 않도록 계정 삭제 대신 비활성화하고, 법무·인사와 함께 "
                       "조사 범위·통지 의무를 정합니다. 개인정보가 포함됐다면 정보주체 통지·신고 요건을 별도로 판단하고, "
                       "내부 조사라는 이유로 법정 기한을 미루지 않습니다."),
        first_15min=[
            "접근·반출 로그 보존(메일·USB·클라우드·출력), 계정은 삭제 대신 비활성화",
            "법무·인사·개인정보 담당 소집, 조사 범위와 결정권자 지정",
            "반출 자료 목록화(고객 정보·계약·소스), 개인정보 포함 여부 확인",
            "필요 시 경찰·법률 자문 검토, 외부 공개·통지 문안은 승인 후",
        ],
        dont_do=[
            "계정을 바로 삭제해 접근·반출 기록을 상실",
            "본인에게 먼저 알려 증거 인멸 기회를 주기",
            "'내부 문제'라며 개인정보 통지·신고 판단을 생략",
        ],
        deadline_focus="개인정보 포함 시 72시간 통지·신고, 계약상 통지 의무도 함께 확인",
        signals=[],
        why_severity="대규모 고객정보·영업비밀이 확인되면 P1",
    ),
    Category(
        id="CAT09_DDOS_OUTAGE",
        no=9,
        name="DDoS·서비스 장애",
        short="DDoS·장애",
        deep=False,
        incident_type="ddos",
        base_severity="P3",
        guide=("DDoS로 서비스가 느려지거나 멈춘 한국 소규모 회사가 "
               "방어·통신사 연계·고객 안내 순서를 3문장 이내로 알려주세요."),
        offline_guide=("트래픽 패턴(출발지·포트·URI)을 기록하고 CDN·WAF·클라우드 방어를 켜서 우회·필터링합니다. "
                       "통신사·호스팅사·클라우드 지원에 사고 접수를 걸고 접수번호를 남기며, "
                       "서비스 상태 페이지·공지로 고객에게 사실만 안내합니다. 공격과 무관한 데이터 유출 흔적이 없는지도 함께 확인합니다."),
        first_15min=[
            "트래픽 패턴·시작 시각·임계치 기록(방어 장비·WAF 대시보드 캡처)",
            "CDN·WAF·클라우드 방어 활성화, 필요 시 비필수 기능·국가 차단",
            "통신사·호스팅사·클라우드 지원 사고 접수, 접수번호 확보",
            "고객 공지(사실만, 원인 단정 금지), 복구 후 재발 모니터링 담당 지정",
        ],
        dont_do=[
            "공격 트래픽을 막겠다며 전체 서비스 차단",
            "원인 확인 전 특정 집단·경쟁사 지목",
            "방어만 하고 데이터 유출 흔적 점검 생략",
        ],
        deadline_focus="침해로 인한 서비스 중단이면 24시간 신고 대상 여부 확인(단순 부하·장애는 별도)",
        signals=[],
        why_severity="장기 중단·매출 영향이면 P2, 데이터 침해 동반 시 P1",
    ),
    Category(
        id="CAT10_SUPPLY_CHAIN",
        no=10,
        name="공급망·악성코드 감염",
        short="공급망·악성코드",
        deep=False,
        incident_type="supply",
        base_severity="P2",
        guide=("협력사 업데이트 파일·PC 메신저로 악성코드가 퍼진 정황이 있을 때 "
               "확산 차단과 배포물 회수 순서를 3문장 이내로 알려주세요."),
        offline_guide=("감염 의심 PC를 네트워크에서 분리하고 실행된 파일·프로세스·연결 IP를 기록합니다. "
                       "같은 배포물(.exe·업데이트·첨부)을 받은 조직 내 사용자를 전수 확인해 격리하고, "
                       "협력사에 사실을 알려 배포 중단을 요청합니다. 자격증명 탈취형 악성코드라면 계정 세션 철회·암호 초기화와 "
                       "외부 로그인 흔적 확인을 함께 합니다."),
        first_15min=[
            "감염 PC 네트워크 분리(전원 차단 금지), 실행 파일·해시·연결 IP 기록",
            "같은 배포물 수신자 전수 확인·격리, 메일·메신저에서 배포물 회수",
            "협력사·배포처에 통보해 배포 중단 요청, 서명·해시 확인",
            "자격증명 탈취 여부 확인: 세션 철회·암호 초기화·외부 로그인 조사",
        ],
        dont_do=[
            "감염 PC를 바로 포맷해 실행 흔적·유포 경로 상실",
            "배포물을 다시 내려받아 '재설치'로 해결",
            "협력사에 알리지 않고 내부만 정리",
        ],
        deadline_focus="침해 확인 시 24시간 신고, 개인정보 유출 시 72시간 통지",
        signals=[],
        why_severity="다수 PC·서버 확산 또는 자격증명 탈취 확인 시 P1",
    ),
)

BY_ID = {c.id: c for c in CATEGORIES}
BY_NO = {c.no: c for c in CATEGORIES}

# 짧은 이름·시나리오 id·유형 코드로도 찾을 수 있게 별칭을 둔다(API·UI·테스트 편의).
ALIASES = {
    "bec": "CAT01_BEC_ACCOUNT_CHANGE", "account_change": "CAT01_BEC_ACCOUNT_CHANGE",
    "ato": "CAT02_MAIL_ACCOUNT_ATO", "lookalike": "CAT03_LOOKALIKE_SPOOF", "spoof": "CAT03_LOOKALIKE_SPOOF",
    "ransom": "CAT04_RANSOMWARE", "ransomware": "CAT04_RANSOMWARE", "root": "CAT05_SERVER_ROOT",
    "cloud": "CAT06_CLOUD_KEY_LEAK", "webdb": "CAT07_WEB_DB_LEAK", "insider": "CAT08_INSIDER_LEAK",
    "ddos": "CAT09_DDOS_OUTAGE", "supply": "CAT10_SUPPLY_CHAIN",
    "s1_bec_account_change": "CAT01_BEC_ACCOUNT_CHANGE",
    "s2_lookalike_domain": "CAT03_LOOKALIKE_SPOOF",
    "s3_selfhosted_root_out_of_scope": "CAT05_SERVER_ROOT",
    "s4_ransomware": "CAT04_RANSOMWARE",
}


def get(key: str | int | None) -> Category | None:
    if key is None:
        return None
    if isinstance(key, int):
        return BY_NO.get(key)
    k = str(key).strip()
    if k in BY_ID:
        return BY_ID[k]
    if k.isdigit():
        return BY_NO.get(int(k))
    return BY_ID.get(ALIASES.get(k.lower(), ""))


def all_categories() -> list[dict]:
    return [c.to_dict() for c in CATEGORIES]


def for_incident_type(incident_type: str | None) -> Category | None:
    if not incident_type:
        return None
    return get(ALIASES.get(str(incident_type).lower(), ""))


def suggest(det, case=None) -> list[dict]:
    """탐지된 규칙으로 관련 10대 유형을 추천한다(강제 선택 아님)."""
    rules = set(det.rules_hit()) if det is not None else set()
    out = []
    for cat in CATEGORIES:
        hits = [s for s in cat.signals if s and any(s in r or r in s for r in rules)]
        if cat.id == "CAT04_RANSOMWARE":
            hits += [r for r in rules if r.startswith("RW_") and r not in hits]
        if cat.id == "CAT05_SERVER_ROOT":
            hits += [r for r in rules if r.startswith(("SR_", "FW_")) and r not in hits]
        if hits:
            out.append({"id": cat.id, "no": cat.no, "name": cat.name, "hits": sorted(set(hits))})
    return out


KEYWORDS: dict[str, tuple[str, ...]] = {
    "CAT04_RANSOMWARE": ("랜섬웨어", "랜섬", "몸값", ".locked", "암호화", "복호화", "랜섬노트",
                         "확장자로 바뀌", "확장자가 바뀌", "이상한 확장자", "파일이 안 열", "열리지가 않", "열리지 않",
                         "돈 보내라", "돈을 보내라", "비트코인", "풀어준다"),
    "CAT07_WEB_DB_LEAK": ("sql 인젝션", "sql injection", "db 유출", "디비 털", "데이터베이스 유출", "웹셸", "웹 해킹"),
    "CAT06_CLOUD_KEY_LEAK": ("api 키", "api key", "액세스 키", "access key", "aws 키", "클라우드 키", "시크릿 키", "토큰 노출"),
    "CAT08_INSIDER_LEAK": ("내부자", "퇴사", "반출", "직원이 빼", "내부 직원", "영업비밀"),
    "CAT09_DDOS_OUTAGE": ("ddos", "디도스", "트래픽 폭주", "접속 폭주", "서비스 장애", "서버 다운"),
    "CAT10_SUPPLY_CHAIN": ("공급망", "협력사 업데이트", "악성코드", "악성 코드", "메신저로 파일", "업데이트 파일"),
    "CAT03_LOOKALIKE_SPOOF": ("유사 도메인", "비슷한 주소", "한 글자", "스푸핑", "spoof", "사칭 도메인"),
    "CAT02_MAIL_ACCOUNT_ATO": ("계정 탈취", "계정이 뚫", "비밀번호가 바뀜", "낯선 로그인", "받은편지함 규칙", "ato",
                               "해킹당", "해킹 당", "스팸이 대량", "대량 발송", "스팸 발송", "계정이 잠", "계정 잠금",
                               "로그인 알림", "해외 로그인", "비밀번호가 바뀌", "모르는 로그인", "내가 안 보낸 메일"),
    "CAT01_BEC_ACCOUNT_CHANGE": ("계좌 변경", "계좌를 바꿨", "계좌가 바뀌", "계좌번호가 바뀌", "입금 계좌", "송금 요청", "거래처에서",
                                 "계좌번호 변경", "대금 계좌"),
}
_ORDER = list(KEYWORDS)


def guess(text: str) -> Category | None:
    """대화 한 줄에서 10대 유형을 추정한다(확정 아님 — 추정 근거로만 쓴다)."""
    t = (text or "").lower()
    if not t:
        return None
    best, best_hits = None, 0
    for cid in _ORDER:
        hits = sum(1 for k in KEYWORDS[cid] if k in t)
        if hits > best_hits:
            best, best_hits = cid, hits
    return BY_ID.get(best) if best else None


def severity_hint(category_id: str | None) -> tuple[str, str]:
    cat = get(category_id)
    if not cat:
        return "P3", "유형 미선택 — 로그가 확보되면 재평가"
    return cat.base_severity, f"{cat.name} 유형 기본값 — {cat.why_severity}"
