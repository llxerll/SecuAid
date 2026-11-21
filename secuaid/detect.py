"""결정적 1차 탐지 엔진 — LLM 없이 로그만으로 사건을 세운다.

v0.2 대비 수정한 것
1. `LR_IMPOSSIBLE_TRAVEL`이 CorrelationId만 봤다. 규칙 문서의 "60분 내 두 국가" 조건을 실제로 구현했다.
2. `LR_HEADER_TRIAGE`가 규칙 파일에만 있고 구현이 없었다. eml.py 판독으로 연결했다.
3. 감사 로그의 `Send` 오퍼레이션을 전혀 탐지하지 않았다(메시지 추적만 봤다). 추가했다.
4. `Set-Mailbox`를 통째로 지속성으로 분류해 오탐이 났다. 전달(Forwarding) 파라미터가 있을 때만 잡는다.
5. 자체 메일 서버(root 탈취) 시나리오용 규칙이 없었다. syslog·방화벽 규칙을 추가했다.
6. 심각도(severity)·근거 신호(signal)·확인 수준을 결과에 담아 상위 판단에 넘긴다.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import ingest
from .timeutil import kst_label

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}
SEVERITY_KR = {"critical": "치명", "high": "높음", "medium": "보통", "info": "참고"}

MONEY_WORDS = ("계좌", "송금", "입금", "대금", "정산", "invoice", "payment", "bank", "remittance")
HIDE_FOLDERS = ("rss", "보관", "archive", "notes", "junk", "대화 기록", "임시", "deleted", "휴지통")
PERSIST_OPS = ("add app password", "consent to application", "add-mailboxpermission",
               "add authentication method", "new application", "add service principal")
DELETE_OPS = ("softdelete", "harddelete", "movetodeleteditems")
LEGACY_AUTH = ("exchange activesync", "imap", "pop", "other clients")


@dataclass
class Finding:
    rule_id: str
    ts: datetime | None
    summary: str
    severity: str
    source: str
    signal: str = ""
    evidence: str = "확인"
    actor: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "ts": self.ts.isoformat() if self.ts else None,
            "ts_kst": kst_label(self.ts),
            "summary": self.summary,
            "severity": self.severity,
            "severity_kr": SEVERITY_KR.get(self.severity, self.severity),
            "source": self.source,
            "signal": self.signal,
            "evidence": self.evidence,
            "actor": self.actor,
            "detail": self.detail,
        }


@dataclass
class DetectionResult:
    findings: list[Finding] = field(default_factory=list)
    suspect_ips: list[str] = field(default_factory=list)
    suspect_accounts: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    sources_seen: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def by_rule(self) -> dict[str, int]:
        return dict(Counter(f.rule_id for f in self.findings))

    def ordered(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.ts is None, f.ts.timestamp() if f.ts else 0.0,
                                                    SEVERITY_RANK.get(f.severity, 9)))

    def rules_hit(self) -> list[str]:
        return sorted({f.rule_id for f in self.findings})

    def signal_ids(self) -> list[str]:
        return sorted({f.signal for f in self.findings if f.signal})

    def to_dict(self) -> dict:
        return {
            "count": len(self.findings),
            "suspect_ips": self.suspect_ips,
            "suspect_accounts": self.suspect_accounts,
            "hosts": self.hosts,
            "counts": self.counts,
            "sources_seen": self.sources_seen,
            "notes": self.notes,
            "signals": self.signal_ids(),
            "findings": [f.to_dict() for f in self.ordered()],
        }


def _params(raw: str) -> dict[str, str]:
    """감사 로그 Parameters('k=v ; k=v')를 딕셔너리로."""
    out = {}
    for chunk in re.split(r"\s*;\s*", raw or ""):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _recipients(raw: str) -> int:
    if not raw:
        return 0
    m = re.search(r"(\d[\d,]*)\s*(?:recipients|명|수신자)", raw, re.IGNORECASE)
    if m:
        return int(m.group(1).replace(",", ""))
    m = re.search(r"Recipients\s*=\s*(\d+)", raw, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def _country(loc: str) -> str:
    if not loc:
        return ""
    parts = [p.strip() for p in loc.split(",") if p.strip()]
    return parts[-1].upper() if parts else ""


def detect(logs: list[ingest.ParsedLog], *, org_country: str = "KR",
           is_eml: dict | None = None) -> DetectionResult:
    res = DetectionResult()
    by_kind: dict[str, list[ingest.Record]] = defaultdict(list)
    for log in logs:
        by_kind[log.kind].extend(log.records)
        if log.records:
            res.sources_seen[log.kind] = res.sources_seen.get(log.kind, 0) + len(log.records)
        res.notes.extend(log.warnings)

    signin = by_kind[ingest.SIGNIN]
    audit = by_kind[ingest.AUDIT]
    trace = by_kind[ingest.TRACE]
    firewall = by_kind[ingest.FIREWALL]
    syslog = by_kind[ingest.SYSLOG]
    edr = by_kind[ingest.EDR]
    backup = by_kind[ingest.BACKUP]

    def add(rule_id: str, ts, summary: str, severity: str, source: str,
            signal: str = "", actor: str = "", detail: dict | None = None) -> None:
        res.findings.append(Finding(rule_id, ts, summary, severity, source, signal, "확인", actor, detail or {}))

    # ---------------------------------------------------------------- 로그인
    suspect_ips: set[str] = set()
    accounts: set[str] = set()

    def user_of(r: ingest.Record) -> str:
        return r.get("UserPrincipalName", "UserId", "user")

    successes = [r for r in signin if r.get("Status").lower() == "success"]
    home: dict[str, str] = {}
    for user in {user_of(r) for r in signin}:
        first = sorted((r for r in signin if user_of(r) == user and r.get("Status").lower() == "success" and r.ts),
                       key=lambda r: r.ts)  # type: ignore[arg-type,return-value]
        home[user] = org_country or (_country(first[0].get("Location")) if first else "")

    for r in successes:
        user, ctry = user_of(r), _country(r.get("Location"))
        ip = r.get("IPAddress")
        if home.get(user) and ctry and ctry != home[user]:
            suspect_ips.add(ip)
            accounts.add(user)
            add("LR_FOREIGN_LOGIN", r.ts,
                f"{user} {r.get('Location')} {ip} ({r.get('AppDisplayName')}) — 기준 국가 {home[user]}",
                "high", ingest.SIGNIN, "SIG_FOREIGN_LOGIN", user, {"ip": ip, "country": ctry})
        if "app password" in r.get("MfaDetail").lower() or r.get("ClientAppUsed").lower() in LEGACY_AUTH:
            suspect_ips.add(ip)
            accounts.add(user)
            add("LR_APP_PASSWORD_AUTH", r.ts,
                f"{user} {r.get('ClientAppUsed') or '레거시 인증'} {ip} — MFA 우회 가능 경로",
                "high", ingest.SIGNIN, "SIG_FOREIGN_LOGIN", user, {"ip": ip})
    # 세션 탈취: 같은 CorrelationId가 두 국가, 또는 같은 사용자 60분 내 두 국가 (v0.3 신규 구현)
    by_corr: dict[str, set[str]] = defaultdict(set)
    for r in successes:
        if r.get("CorrelationId"):
            by_corr[r.get("CorrelationId")].add(_country(r.get("Location")))
    for cid, countries in by_corr.items():
        countries.discard("")
        if len(countries) > 1:
            rows = sorted((r for r in successes if r.get("CorrelationId") == cid and r.ts), key=lambda r: r.ts)  # type: ignore[arg-type,return-value]
            first = rows[0]
            user = user_of(first)
            for r in rows:
                # 조직 기준 국가와 다른 로그인의 IP만 의심 IP로 둔다(정상 사내 IP 오탐 방지)
                if home.get(user) and _country(r.get("Location")) != home[user]:
                    suspect_ips.add(r.get("IPAddress"))
            accounts.add(user)
            add("LR_IMPOSSIBLE_TRAVEL", first.ts,
                f"세션 {cid}가 {'/'.join(sorted(countries))}에서 사용 — 같은 세션 토큰으로 두 국가 접근(AiTM 의심)",
                "critical", ingest.SIGNIN, "SIG_IMPOSSIBLE_TRAVEL", user_of(first),
                {"correlation_id": cid, "countries": sorted(countries), "basis": "동일 CorrelationId"})

    per_user: dict[str, list[ingest.Record]] = defaultdict(list)
    for r in successes:
        if r.ts:
            per_user[user_of(r)].append(r)
    for user, rows in per_user.items():
        rows.sort(key=lambda r: r.ts)  # type: ignore[arg-type,return-value]
        for prev, cur in zip(rows, rows[1:]):
            c1, c2 = _country(prev.get("Location")), _country(cur.get("Location"))
            if not c1 or not c2 or c1 == c2:
                continue
            gap = (cur.ts - prev.ts).total_seconds() / 60  # type: ignore[operator]
            if gap <= 60 and prev.get("CorrelationId") != cur.get("CorrelationId"):
                suspect_ips.add(cur.get("IPAddress"))
                if home.get(user) and c1 != home[user]:
                    suspect_ips.add(prev.get("IPAddress"))
                accounts.add(user)
                add("LR_IMPOSSIBLE_TRAVEL", cur.ts,
                    f"{user} {int(gap)}분 내 {c1}→{c2} 로그인 — 물리적 이동 불가",
                    "critical", ingest.SIGNIN, "SIG_IMPOSSIBLE_TRAVEL", user,
                    {"minutes": int(gap), "from": c1, "to": c2, "basis": "60분 규칙"})

    for r in signin:
        if r.get("Status").lower() != "success" and r.get("IPAddress") in suspect_ips:
            add("LR_SPRAY_SAME_IP", r.ts,
                f"의심 IP {r.get('IPAddress')}로 {user_of(r)} 로그인 시도({r.get('Status')}: {r.get('MfaDetail')})",
                "high", ingest.SIGNIN, "SIG_FOREIGN_LOGIN", user_of(r), {"ip": r.get("IPAddress")})

    # ---------------------------------------------------------------- 감사 로그
    for r in audit:
        op = r.get("Operation")
        low = op.lower()
        ip = r.get("ClientIP")
        prm = r.get("Parameters")
        pd = _params(prm)

        if low in ("new-inboxrule", "set-inboxrule"):
            target = pd.get("MoveToFolder", "") + " " + pd.get("CopyToFolder", "")
            hide = any(f in target.lower() for f in HIDE_FOLDERS) or "tru" in pd.get("DeleteMessage", "").lower()
            forward = pd.get("ForwardTo", "") + pd.get("ForwardAsAttachmentTo", "") + pd.get("RedirectTo", "")
            words = pd.get("SubjectOrBodyContainsWords", "")
            money = any(w.lower() in (words + " " + prm).lower() for w in MONEY_WORDS)
            if hide or forward:
                sev = "critical" if (money or forward) else "high"
                bits = []
                if target.strip():
                    bits.append(f"이동 폴더={target.strip()}")
                if forward.strip():
                    bits.append(f"외부 전달={forward.strip()}")
                if money:
                    bits.append(f"키워드={words}")
                add("LR_HIDING_RULE", r.ts,
                    f"숨김 규칙 '{pd.get('Name', '?')}' 생성({ip}): " + ", ".join(bits),
                    sev, ingest.AUDIT, "SIG_INBOX_RULE", r.get("UserId"),
                    {"parameters": pd, "ip": ip})
        elif low in ("mailitemsaccessed", "searchqueryinitiatedexchange", "searchqueryinitiatedsharepoint"):
            if ip in suspect_ips:
                add("LR_MAIL_ACCESS", r.ts,
                    f"{op} — {prm}",
                    "high", ingest.AUDIT, "SIG_UNKNOWN_SENT", r.get("UserId"), {"ip": ip})
        elif any(low.startswith(p) or p in low for p in PERSIST_OPS):
            if low.startswith("set-mailbox") and not ("forwarding" in low or "Forwarding" in prm):
                continue  # 오탐 방지: 전달 설정이 없는 Set-Mailbox는 지속성 아님
            add("LR_PERSISTENCE", r.ts,
                f"지속성 수단: {op} ({ip}) — {prm[:120]}",
                "critical", ingest.AUDIT, "SIG_OAUTH_CONSENT", r.get("UserId"), {"ip": ip})
        elif low in DELETE_OPS:
            if "보낸 편지함" in prm or "SentItems" in prm or "Sent Items" in prm:
                add("LR_COVER_TRACKS", r.ts, f"{op} — {prm}", "high", ingest.AUDIT, "SIG_UNKNOWN_SENT",
                    r.get("UserId"), {"ip": ip})

        if low == "send" or low.startswith("send"):
            subj = pd.get("Subject", "")
            rcpt = _recipients(prm)
            money = any(w.lower() in subj.lower() for w in MONEY_WORDS)
            if ip in suspect_ips:
                sev = "critical" if money or rcpt >= 50 else "high"
                add("LR_SUSPICIOUS_SEND", r.ts,
                    f"발송({ip}) 제목='{subj}' 수신자 {rcpt or '?'}명" + (" — 계좌·송금 키워드" if money else ""),
                    sev, ingest.AUDIT, "SIG_UNKNOWN_SENT", r.get("UserId"),
                    {"ip": ip, "subject": subj, "recipients": rcpt, "money": money})
            elif money:
                # 발송 IP가 의심 목록 밖이라도 우리 계정에서 계좌 변경 메일이 나간 기록은 남긴다.
                add("LR_ACCOUNT_CHANGE_MAIL", r.ts,
                    f"계좌 변경 키워드 발송 — '{subj}' 수신자 {rcpt or '?'}명 (발송 IP {ip})",
                    "medium", ingest.AUDIT, "SIG_VENDOR_ACCOUNT_CHANGE", r.get("UserId"),
                    {"ip": ip, "subject": subj})

    # ---------------------------------------------------------------- 메시지 추적
    for r in trace:
        frm_ip = r.get("FromIP")
        subj = r.get("Subject")
        rcpt = _recipients(r.get("RecipientAddress"))
        money = any(w.lower() in subj.lower() for w in MONEY_WORDS)
        if frm_ip in suspect_ips:
            sev = "critical" if money else ("high" if rcpt >= 50 else "medium")
            tag = "계좌·송금 사칭" if money else "대량/피싱 발송"
            add("LR_SUSPICIOUS_SEND", r.ts,
                f"[{tag}] '{subj}' → {r.get('RecipientAddress')} ({r.get('Status')})",
                sev, ingest.TRACE, "SIG_UNKNOWN_SENT", r.get("SenderAddress"),
                {"ip": frm_ip, "subject": subj, "recipients": rcpt, "money": money})
        elif money and "@" in (r.get("SenderAddress") or "") and r.get("Status", "").startswith("Delivered"):
            # 의심 IP 밖에서 나갔더라도 우리 계정에서 계좌 변경 메일이 나갔다면 별도 신호
            add("LR_ACCOUNT_CHANGE_MAIL", r.ts,
                f"계좌 변경 키워드 메일 발송 — '{subj}' → {r.get('RecipientAddress')} (발송 IP {frm_ip})",
                "medium", ingest.TRACE, "SIG_VENDOR_ACCOUNT_CHANGE", r.get("SenderAddress"),
                {"ip": frm_ip, "subject": subj})

    # ---------------------------------------------------------------- syslog (자체 메일 서버)
    fails: dict[str, list[datetime]] = defaultdict(list)
    for r in syslog:
        line = r.get("message", r.raw)
        low = line.lower()
        if "failed password" in low or "invalid user" in low or "authentication failure" in low:
            ip_m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
            if ip_m and r.ts:
                fails[ip_m.group(1)].append(r.ts)
        if "maximum authentication attempts exceeded" in low:
            add("SR_BRUTEFORCE", r.ts, f"무차별 대입 상한 초과 — {line[:140]}", "high", ingest.SYSLOG,
                "SIG_FOREIGN_LOGIN", r.get("host"))

    for ip, times in fails.items():
        times.sort()
        window: list[datetime] = []
        for t in times:
            window = [x for x in window if (t - x) <= timedelta(minutes=10)] + [t]
            if len(window) >= 5:
                sev = "critical" if len(window) >= 20 else "high"
                add("SR_BRUTEFORCE", t,
                    f"{ip}에서 10분 내 SSH 로그인 실패 {len(window)}회 — 무차별 대입",
                    sev, ingest.SYSLOG, "SIG_FOREIGN_LOGIN", hostname_from_syslog(logs),
                    {"ip": ip, "count": len(window)})
                break

    for r in syslog:
        line = r.get("message", r.raw)
        low = line.lower()
        if "accepted password for root" in low or re.search(r"accepted (publickey|password) for root", low):
            ip_m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
            ip = ip_m.group(1) if ip_m else ""
            private = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                                     "172.2", "172.30.", "172.31."))
            sev = "critical"
            where = "내부 IP" if private else "외부 IP"
            add("SR_ROOT_LOGIN", r.ts, f"root 원격 로그인 성공 ({where} {ip or '미상'}) — 관리자 권한 탈취 의심",
                sev, ingest.SYSLOG, "SIG_FOREIGN_LOGIN", r.get("host"), {"ip": ip})
        if "started" in low and any(k in low for k in ("agent", "service")) and ("/usr/share" in low or "rmtagent" in low or "remote" in low):
            add("SR_PERSIST_SERVICE", r.ts, f"의심 서비스 설치·시작 — {line[:160]}", "critical", ingest.SYSLOG,
                "SIG_INBOX_RULE", r.get("host"))
        if re.search(r"(truncate -s 0|rm -f).{0,40}(/var/log|\.bash_history|/root/\.)", low) or "history -c" in low:
            add("SR_LOG_TAMPER", r.ts, f"로그·흔적 삭제 — {line[:160]}", "critical", ingest.SYSLOG,
                "SIG_UNKNOWN_SENT", r.get("host"))
        if "fw-log" in low and "dpt=3389" in low.replace(" ", ""):
            add("SR_OUTBOUND_RDP", r.ts, f"내부 호스트에서 외부 3389 아웃바운드 — {line[:140]}", "high",
                ingest.SYSLOG, "SIG_UNKNOWN_SENT", r.get("host"))

    # ---------------------------------------------------------------- 방화벽
    for r in firewall:
        port = r.get("dst_port")
        dst = r.get("dst_ip")
        if port == "3389" and dst and not dst.startswith(("10.", "192.168.", "127.")):
            sessions = int(re.sub(r"\D", "", r.get("sessions") or "0") or 0)
            bytes_out = int(re.sub(r"\D", "", r.get("bytes_out") or "0") or 0)
            sev = "critical" if sessions >= 3 or bytes_out >= 1_000_000 else "high"
            suspect_ips.add(dst)
            add("FW_OUTBOUND_RDP", r.ts,
                f"{r.get('src_host') or r.get('src_ip')} → {dst}:3389 아웃바운드 허용 (세션 {sessions}, 송신 {bytes_out:,}B)",
                sev, ingest.FIREWALL, "SIG_UNKNOWN_SENT", r.get("src_host"), {"dst": dst, "bytes_out": bytes_out})

    # ---------------------------------------------------------------- EDR·파일 서버 (v0.5 랜섬웨어)
    SEC_OFF_WORDS = ("veeam", "backup", "defender", "antivirus", "백신", "windows defender", "mssql", "sql server")
    enc_by_host: dict[str, list[ingest.Record]] = defaultdict(list)
    for r in edr:
        ev = r.get("event_type").lower()
        host = r.get("host")
        detail, path, proc = r.get("detail"), r.get("path"), r.get("process")
        if ev in ("file_encrypted", "mass_file_rename", "encrypted"):
            enc_by_host[host].append(r)
        elif ev in ("ransom_note_written", "ransom_note"):
            add("RW_RANSOM_NOTE", r.ts, f"{host} 랜섬노트 생성 — {path or detail}", "critical",
                ingest.EDR, "SIG_RANSOMWARE", host, {"path": path, "host": host})
        elif ev in ("shadow_copy_delete", "vss_delete"):
            add("RW_SHADOW_DELETE", r.ts, f"{host} 볼륨 섀도 복사본 삭제 — {proc or detail} (복구 수단 제거)",
                "critical", ingest.EDR, "SIG_RANSOMWARE", host, {"process": proc})
        elif ev in ("service_stop", "security_disabled"):
            blob = f"{proc} {detail}".lower()
            if any(w in blob for w in SEC_OFF_WORDS):
                add("RW_SECURITY_DISABLED", r.ts, f"{host} 보안·백업 서비스 중지 — {proc or detail}",
                    "high", ingest.EDR, "SIG_RANSOMWARE", host, {"process": proc})
        elif ev in ("smb_lateral", "remote_share"):
            dst = r.get("dst_ip")
            if dst:
                suspect_ips.add(dst)
            add("RW_LATERAL", r.ts, f"{host} → {dst or r.get('path') or '원격 공유'} 접근 — 측면 이동·백업 공격 의심",
                "high", ingest.EDR, "SIG_RANSOMWARE", host, {"dst": dst})

    for host, rows in enc_by_host.items():
        files = 0
        for r in rows:
            m = re.search(r"(?:files|count)\s*=\s*(\d[\d,]*)", r.get("detail") or "")
            files += int(m.group(1).replace(",", "")) if m else 1
        ext = next((_ext_of(r.get("path")) for r in rows if _ext_of(r.get("path"))), "")
        ts = min((r.ts for r in rows if r.ts), default=None)
        add("RW_EXTENSION_MASS", ts,
            f"{host} 파일 {files:,}건이 {ext or '변조 확장자'}로 변경 — 대량 암호화(랜섬웨어)",
            "critical", ingest.EDR, "SIG_RANSOMWARE", host,
            {"files": files, "ext": ext, "host": host, "events": len(rows)})

    for r in backup:
        status = (r.get("status") or "").lower()
        detail = (r.get("detail") or "")
        job = r.get("job") or ""
        if status in ("failed", "fail", "error") or any(k in detail.lower() for k in ("offline", "deleted", "unreachable", "암호화")):
            add("RW_BACKUP_TARGETED", r.ts,
                f"백업 작업 '{job}' {status or '이상'} — {detail or '백업 대상 접근 불가'}",
                "critical", ingest.BACKUP, "SIG_RANSOMWARE", r.get("backup_host"),
                {"job": job, "status": status, "detail": detail})

    # ---------------------------------------------------------------- EML 판독 결과
    if is_eml:
        verdict = is_eml.get("verdict", "unknown")
        rule = {"ato": ("LR_HEADER_TRIAGE_ATO", "critical", "SIG_VENDOR_ACCOUNT_CHANGE"),
                "spoof": ("LR_HEADER_TRIAGE_SPOOF", "high", "SIG_VENDOR_ACCOUNT_CHANGE"),
                "lookalike": ("LR_HEADER_TRIAGE_LOOKALIKE", "high", "SIG_VENDOR_ACCOUNT_CHANGE"),
                "external": ("LR_HEADER_TRIAGE_EXTERNAL", "medium", "SIG_VENDOR_ACCOUNT_CHANGE"),
                "unknown": ("LR_HEADER_TRIAGE", "info", "SIG_VENDOR_ACCOUNT_CHANGE")}.get(verdict)
        if rule:
            basis = " / ".join(is_eml.get("basis") or [])
            add(rule[0], None, f"메일 원본 판독: {is_eml.get('subject', '')} — {basis}", rule[1], ingest.EML, rule[2],
                is_eml.get("from_addr", ""), {"verdict": verdict})
        ip = is_eml.get("originating_ip")
        if ip:
            suspect_ips.add(ip)

    # 정리
    seen, unique = set(), []
    for f in res.findings:
        # 같은 사건을 감사 로그와 메시지 추적이 함께 보고하면 한 줄로 합친다.
        key = (f.rule_id, f.ts) if f.rule_id in ("LR_SUSPICIOUS_SEND", "SR_BRUTEFORCE") else (f.rule_id, f.ts, f.summary)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    res.findings = unique
    res.suspect_ips = sorted(i for i in suspect_ips if i)
    res.suspect_accounts = sorted(a for a in accounts if a)
    res.hosts = sorted({r.get("host") for r in syslog if r.get("host")})
    res.counts = dict(Counter(f.rule_id for f in res.findings))

    for kind, label in ((ingest.SIGNIN, "로그인 로그"), (ingest.AUDIT, "감사 로그"), (ingest.TRACE, "메시지 추적")):
        if not by_kind[kind]:
            res.notes.append(f"{label}가 없습니다. 이 로그가 없으면 관련 신호는 '미확인'이며, 결과 없음이 피해 없음을 뜻하지 않습니다.")
    return res


def _ext_of(path: str) -> str:
    """변조 확장자만 뽑는다(.locked, .encrypted 등). 원본 확장자(.docx)는 무시."""
    if not path:
        return ""
    m = re.findall(r"(\.[A-Za-z0-9]{3,10})", path)
    if not m:
        return ""
    for ext in reversed(m):
        if ext.lower() not in (".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".csv", ".jpg", ".png",
                               ".zip", ".bak", ".mdf", ".ldf", ".eml", ".pst", ".hwp", ".hwpx", ".ppt", ".pptx"):
            return ext
    return ""


def hostname_from_syslog(logs: list[ingest.ParsedLog]) -> str:
    for log in logs:
        for r in log.records:
            if r.kind == ingest.SYSLOG and r.get("host"):
                return r.get("host")
    return ""
