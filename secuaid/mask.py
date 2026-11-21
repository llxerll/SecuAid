"""민감정보 마스킹 — 모델·외부 API로 보내는 텍스트에서 개인정보를 토큰으로 치환한다.

플레이북 원칙: "민감정보를 밖으로 보내지 않는다. 원본 증거는 사용자 쪽에만 남긴다."
v0.2에는 마스킹이 아예 없었다(기획서 핵심 원칙 미구현).

- `Masker.mask(text)` → (마스킹된 텍스트, 매핑) : 같은 원본 값은 같은 토큰을 재사용한다.
- `Masker.unmask(text)` → 모델이 돌려준 문장의 토큰을 원래 값으로 복원한다.
- 매핑은 메모리에만 있고 디스크·로그에 쓰지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 순서가 중요하다: 더 구체적인 패턴(주민번호·카드·계좌)을 먼저 처리한다.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("주민등록번호", re.compile(r"\b\d{6}[-\s]?[1-4]\d{6}\b")),
    ("카드번호", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("여권번호", re.compile(r"\b[MSROD]\d{8}\b")),
    ("운전면허번호", re.compile(r"\b\d{2}-\d{2}-\d{6}-\d{2}\b")),
    ("전화번호", re.compile(r"\b0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}\b")),
    ("계좌번호", re.compile(r"\b\d{2,6}-\d{2,6}-\d{4,8}\b")),
    ("이메일", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("IP주소", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)

_TOKENS = {
    "주민등록번호": "주민번호",
    "카드번호": "카드번호",
    "여권번호": "여권번호",
    "운전면허번호": "면허번호",
    "계좌번호": "계좌번호",
    "전화번호": "전화번호",
    "이메일": "이메일",
    "IP주소": "IP",
}


@dataclass
class Masker:
    """가역 마스킹. 한 사건(session) 안에서 재사용한다."""

    keep_ip: bool = False
    _map: dict[str, str] = field(default_factory=dict)   # token -> 원본
    _reverse: dict[str, str] = field(default_factory=dict)  # 원본 -> token
    _compound: dict[str, str] = field(default_factory=dict)  # token@domain -> 원본
    _seq: dict[str, int] = field(default_factory=dict)

    def _token_for(self, kind: str, original: str) -> str:
        if original in self._reverse:
            return self._reverse[original]
        n = self._seq.get(kind, 0) + 1
        self._seq[kind] = n
        token = f"[{_TOKENS.get(kind, kind)}_{n}]"
        self._map[token] = original
        self._reverse[original] = token
        return token

    def mask(self, text: str) -> str:
        if not text:
            return text
        out = text
        for kind, pattern in PATTERNS:
            if kind == "IP주소" and self.keep_ip:
                continue
            # 이메일은 도메인을 남겨 사칭 판별 단서를 보존한다.
            if kind == "이메일":
                def repl_email(m: re.Match[str]) -> str:
                    addr = m.group(0)
                    token = self._token_for("이메일", addr)
                    domain = addr.split("@", 1)[1]
                    self._compound[f"{token}@{domain}"] = addr
                    return f"{token}@{domain}"
                out = pattern.sub(repl_email, out)
            else:
                out = pattern.sub(lambda m, k=kind: self._token_for(k, m.group(0)), out)
        return out

    def unmask(self, text: str) -> str:
        if not text:
            return text
        out = text
        # 이메일은 '토큰@도메인' 합성형을 먼저 되돌린 뒤, 남은 토큰을 치환한다.
        for compound in sorted(self._compound, key=len, reverse=True):
            out = out.replace(compound, self._compound[compound])
        for token in sorted(self._map, key=len, reverse=True):
            out = out.replace(token, self._map[token])
        return out

    @property
    def kinds(self) -> list[str]:
        return sorted({t.strip("[]").rsplit("_", 1)[0] for t in self._map})
