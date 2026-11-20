"""로그 인제스트 — 붙여넣은 텍스트/파일을 형식별 레코드로 정규화한다.

지원 형식
- Microsoft 365 Entra 로그인 로그 (CreatedDateTime(UTC), UserPrincipalName, CorrelationId ...)
- Microsoft 365 통합 감사 로그 (CreationDate(UTC), Operation, ClientIP, Parameters ...)
- 메시지 추적 (Received(UTC), SenderAddress, RecipientAddress, FromIP ...)
- 방화벽 알림 CSV (timestamp_kst, rule, src_ip, dst_ip, dst_port ...)
- Linux secure 로그(syslog) — SSH 무차별 대입·root 로그인·서비스 설치·로그 삭제
- EML 원본 (헤더 판독은 eml.py)

모든 레코드는 UTC aware 시각을 갖고, 파일에 KST만 있으면 KST로 표기된 것으로 명시한다.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .timeutil import KST, parse_ts

SIGNIN = "signin"
AUDIT = "audit"
TRACE = "trace"
FIREWALL = "firewall"
SYSLOG = "syslog"
EDR = "edr"
BACKUP = "backup"
EML = "eml"
UNKNOWN = "unknown"

KIND_LABEL = {
    SIGNIN: "M365 로그인 로그",
    AUDIT: "M365 감사 로그",
    TRACE: "메시지 추적",
    FIREWALL: "방화벽 알림",
    SYSLOG: "Linux secure 로그",
    EDR: "EDR·파일 서버 이벤트",
    BACKUP: "백업 작업 로그",
    EML: "메일 원본(EML)",
    UNKNOWN: "알 수 없는 형식",
}


@dataclass
class Record:
    kind: str
    ts: datetime | None
    data: dict[str, str]
    raw: str = ""

    def get(self, *names: str, default: str = "") -> str:
        for n in names:
            if n in self.data and self.data[n] != "":
                return self.data[n]
        return default


@dataclass
class ParsedLog:
    kind: str
    records: list[Record] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records)


def sniff(text: str) -> str:
    """내용으로 로그 형식을 판별한다. 확장자에 기대지 않는다."""
    head = text[:4000]
    if not head.strip():
        return UNKNOWN
    low = head.lower()
    if "userprincipalname" in low and "correlationid" in low:
        return SIGNIN
    if "operation" in low and "clientip" in low and "objectid" in low:
        return AUDIT
    if "senderaddress" in low and "recipientaddress" in low:
        return TRACE
    if "dst_port" in low and "src_ip" in low:
        return FIREWALL
    if "backup_host" in low and ("job" in low or "status" in low):
        return BACKUP
    if "event_type" in low and "host" in low and ("path" in low or "user" in low):
        return EDR
    if "sshd[" in low or "pam_unix" in low or "fw-log" in low:
        return SYSLOG
    if ("received:" in low or low.startswith("from:")) and ("message-id" in low or "subject:" in low):
        return EML
    if head.lstrip().startswith("{") and '"' in head:
        return "json"
    return UNKNOWN


def _rows(text: str) -> list[dict[str, str]]:
    """CSV 파싱 — 구분자와 BOM을 견딘다."""
    sample = text.lstrip("\ufeff")
    try:
        dialect = csv.Sniffer().sniff(sample.splitlines()[0] + "\n" + (sample.splitlines()[1] if len(sample.splitlines()) > 1 else ""), delimiters=",;\t")
    except Exception:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(sample), dialect=dialect)
    out = []
    for row in reader:
        clean = {(k or "").strip(): (v or "").strip() for k, v in row.items() if k is not None}
        if any(clean.values()):
            out.append(clean)
    return out


def _first(row: dict[str, str], *keys: str) -> str:
    for k in keys:
        for actual in row:
            if actual.lower() == k.lower() and row[actual]:
                return row[actual]
    return ""


def parse(text: str, *, kind: str | None = None, default_year: int | None = None) -> ParsedLog:
    kind = kind or sniff(text)
    default_year = default_year or datetime.now(KST).year
    if kind == SIGNIN:
        recs = []
        for row in _rows(text):
            recs.append(Record(SIGNIN, parse_ts(_first(row, "CreatedDateTime(UTC)", "CreatedDateTime", "TimeGenerated"), default_year=default_year), row))
        return ParsedLog(SIGNIN, recs)

    if kind == AUDIT:
        recs = []
        for row in _rows(text):
            recs.append(Record(AUDIT, parse_ts(_first(row, "CreationDate(UTC)", "CreationDate", "CreationTime"), default_year=default_year), row))
        return ParsedLog(AUDIT, recs)

    if kind == TRACE:
        recs = []
        for row in _rows(text):
            recs.append(Record(TRACE, parse_ts(_first(row, "Received(UTC)", "Received", "Date"), default_year=default_year), row))
        return ParsedLog(TRACE, recs)

    if kind == EDR:
        recs = []
        for row in _rows(text):
            ts_raw = _first(row, "timestamp_kst", "timestamp", "time")
            assume_utc = not any(k.lower() in ("timestamp_kst", "time_kst") for k in row)
            recs.append(Record(EDR, parse_ts(ts_raw, assume_utc=assume_utc, default_year=default_year), row))
        return ParsedLog(EDR, recs)

    if kind == BACKUP:
        recs = []
        for row in _rows(text):
            ts_raw = _first(row, "timestamp_kst", "timestamp", "time")
            assume_utc = not any(k.lower() in ("timestamp_kst", "time_kst") for k in row)
            recs.append(Record(BACKUP, parse_ts(ts_raw, assume_utc=assume_utc, default_year=default_year), row))
        return ParsedLog(BACKUP, recs)

    if kind == FIREWALL:
        # 파일에 따라 KST/UTC 표기가 다르다. 컬럼 이름으로 판단한다.
        recs = []
        for row in _rows(text):
            ts_raw = _first(row, "timestamp_kst", "timestamp", "time", "Timestamp")
            assume_utc = not any(k.lower() in ("timestamp_kst", "time_kst") for k in row)
            recs.append(Record(FIREWALL, parse_ts(ts_raw, assume_utc=assume_utc, default_year=default_year), row))
        return ParsedLog(FIREWALL, recs)

    if kind == SYSLOG:
        recs, warnings = [], []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 3)
            if len(parts) < 4:
                warnings.append(f"형식을 해석하지 못한 줄: {line[:60]}")
                continue
            stamp = " ".join(parts[:3])
            try:
                ts = parse_ts(stamp, assume_utc=False, default_year=default_year)
            except Exception:
                ts = None
                warnings.append(f"시각을 읽지 못한 줄: {line[:60]}")
            recs.append(Record(SYSLOG, ts, {"host": parts[3].split(" ", 1)[0], "message": parts[3], "line": line}, raw=line))
        return ParsedLog(SYSLOG, recs, warnings)

    if kind == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ParsedLog(UNKNOWN, [], [f"JSON 파싱 실패: {exc}"])
        rows = data if isinstance(data, list) else data.get("value") or data.get("records") or []
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            kind2 = sniff(",".join(rows[0].keys()))
            if kind2 != UNKNOWN:
                header = ",".join(rows[0].keys())
                csv_text = header + "\n" + "\n".join(
                    ",".join('"' + str(r.get(k, "")).replace('"', '""') + '"' for k in rows[0].keys()) for r in rows
                )
                return parse(csv_text, kind=kind2, default_year=default_year)
        return ParsedLog(UNKNOWN, [], ["JSON에서 로그 레코드를 찾지 못했습니다."])

    return ParsedLog(UNKNOWN, [], ["지원하지 않는 형식입니다. CSV 헤더나 로그 첫 줄을 확인해 주세요."])


def parse_paths(paths: list[str | Path], *, default_year: int | None = None) -> list[ParsedLog]:
    out = []
    for p in paths:
        p = Path(p)
        out.append(parse(p.read_text(encoding="utf-8", errors="replace"), default_year=default_year))
    return out


HEADER_SIGNATURES = (
    (SIGNIN, ("CreatedDateTime", "UserPrincipalName")),
    (AUDIT, ("CreationDate", "Operation", "ClientIP")),
    (TRACE, ("Received(UTC)", "SenderAddress")),
    (FIREWALL, ("dst_port", "src_ip")),
    (BACKUP, ("backup_host", "job")),
    (EDR, ("event_type", "host")),
)


def parse_multi(text: str, *, default_year: int | None = None) -> list[ParsedLog]:
    """한 번에 여러 로그를 붙여넣은 경우(예: 로그인 로그 + 감사 로그) 각각 파싱한다.

    헤더 줄을 기준으로 블록을 나누고, 헤더 앞의 설명 문장은 버린다.
    블록을 찾지 못하면 단일 파싱으로 넘긴다.
    """
    lines = text.splitlines()

    def kind_of(line: str) -> str | None:
        for kind, sigs in HEADER_SIGNATURES:
            if sum(s.lower() in line.lower() for s in sigs) >= 2:
                return kind
        return None

    blocks: list[tuple[str, list[str]]] = []
    current_kind: str | None = None
    current: list[str] = []
    syslog_line = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s\d{2}:\d{2}:\d{2}")

    for line in lines:
        k = kind_of(line)
        is_syslog = bool(syslog_line.match(line))
        if k or (is_syslog and current_kind != SYSLOG):
            if current and current_kind:
                blocks.append((current_kind, current))
            current_kind, current = (k or SYSLOG), [line]
        elif current_kind is not None and line.strip():
            current.append(line)
    if current and current_kind:
        blocks.append((current_kind, current))

    out: list[ParsedLog] = []
    for kind, block in blocks:
        parsed = parse("\n".join(block), kind=kind, default_year=default_year)
        if parsed.records:
            out.append(parsed)
    if out:
        return out
    return [parse(text, default_year=default_year)]
