"""Liner Platform API 클라이언트 — 실제 서비스의 5개 API만 쓴다.

검증된 엔드포인트(2026-11-15 / 2026-11-20, platform.liner.com):
- Router API(대화·문장 작성): POST /api/v1/chat/completions, model=liner-mark-1.3 (OpenAI 호환, Bearer)
- Search API(검색 결과 JSON): POST /api/v1/tools/search/web, 헤더 x-api-key
- Search Agent API(근거+인용 답변): POST /api/v1/agents/search, 헤더 x-api-key, stream=false
- Quick Answer Agent API(즉답 가이드): POST /api/v1/agents/quick-answer, 헤더 x-api-key, stream=false
  → {answer, references[]} · 약 200자 답변 + 출처 3개 · 단발성 초동 가이드용
- Visualization API(차트 HTML): POST /api/v1/tools/visualization, 헤더 x-api-key, stream=false
  → chunks[].data.atlasArtifact.html (완전한 HTML 문서, iframe srcdoc 로 렌더)

기획서 v0.9에 적힌 "Liner Legal Search"는 존재하지 않는 API명이다. 법령·KISA 공지 근거는
Search API와 Search Agent API로 확보한다(Search Agent가 출처 링크 20~50건을 함께 준다).

키는 환경변수에서만 읽는다(.env). 코드·로그·응답에 키를 남기지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BASE = "https://platform.liner.com/api/v1"
DEFAULT_MODEL = "liner-mark-1.3"
LOCAL_ENV = Path(__file__).resolve().parent.parent / ".env"
_STATUS_CACHE: dict[tuple, tuple[float, dict]] = {}   # 인스턴스가 살아 있는 동안 /models 확인 결과 재사용


class LinerError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, code: str = "", retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.code = code
        self.retryable = retryable


class LinerUnavailable(LinerError):
    """키가 없거나 네트워크·크레딧 문제로 Liner를 쓸 수 없는 상태(오프라인 모드로 전환)."""


def load_env(path: Path | None = None) -> dict[str, str]:
    """의존성 없는 .env 로더. 이미 있는 환경변수를 우선한다."""
    path = path or LOCAL_ENV
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    for k in list(values):
        os.environ.setdefault(k, values[k])
    return values


@dataclass
class LinerClient:
    api_key: str = ""
    base_url: str = DEFAULT_BASE
    model: str = DEFAULT_MODEL
    timeout: int = 90
    retries: int = 2
    offline: bool = False
    calls: list[dict] = field(default_factory=list)

    @classmethod
    def from_env(cls, model: str | None = None, timeout: int | None = None) -> "LinerClient":
        load_env()
        key = os.environ.get("LINER_API_KEY", "").strip()
        return cls(
            api_key=key,
            base_url=os.environ.get("LINER_BASE_URL", DEFAULT_BASE).rstrip("/"),
            model=model or os.environ.get("LINER_MODEL", DEFAULT_MODEL),
            timeout=timeout or int(os.environ.get("LINER_TIMEOUT", "90")),
            offline=not bool(key) or os.environ.get("LINER_OFFLINE", "0") == "1",
        )

    # ------------------------------------------------------------------ 기반
    @property
    def available(self) -> bool:
        return bool(self.api_key) and not self.offline

    def _log_call(self, name: str, ok: bool, ms: int, detail: str = "") -> None:
        self.calls.append({"id": uuid.uuid4().hex[:10], "api": name, "ok": ok, "ms": ms, "detail": detail[:300]})

    def _post(self, path: str, payload: dict, *, auth: str = "bearer", api_name: str = "",
              timeout: int | None = None, retries: int | None = None) -> dict:
        if not self.available:
            raise LinerUnavailable("LINER_API_KEY가 없습니다. .env에 키를 설정하면 Liner API가 켜집니다.")
        url = f"{self.base_url}{path}"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if auth == "x-api-key":
            headers["x-api-key"] = self.api_key
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"

        last: LinerError | None = None
        max_retries = self.retries if retries is None else retries
        for attempt in range(max_retries + 1):
            started = time.time()
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                self._log_call(api_name or path, True, int((time.time() - started) * 1000))
                return json.loads(raw) if raw.strip().startswith("{") else {"raw": raw}
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")
                code, retryable = "", exc.code in (429, 500, 502, 503, 504)
                try:
                    parsed = json.loads(body)
                    err = parsed.get("error") or parsed
                    code = str(err.get("code") or err.get("type") or "")
                    msg = str(err.get("message") or body)[:300]
                except json.JSONDecodeError:
                    msg = body[:300]
                msg = msg.replace(self.api_key, "***") if self.api_key else msg
                hint = {
                    401: "API 키가 유효하지 않습니다(.env의 LINER_API_KEY 확인).",
                    402: "크레딧이 부족합니다(platform.liner.com에서 충전).",
                    403: "계정이 정지되어 호출이 차단되었습니다.",
                    429: "요청 한도 초과 — 잠시 후 재시도합니다.",
                }.get(exc.code, "")
                last = LinerError(f"{exc.code} {code} {msg} {hint}".strip(), status=exc.code, code=code,
                                  retryable=retryable)
                self._log_call(api_name or path, False, int((time.time() - started) * 1000), f"HTTP {exc.code} {code}")
                if not retryable or attempt >= max_retries:
                    raise last
                time.sleep(1.5 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError) as exc:
                self._log_call(api_name or path, False, int((time.time() - started) * 1000), str(exc)[:120])
                last = LinerError(f"네트워크 오류: {exc}", retryable=True)
                if attempt >= max_retries:
                    raise last
                time.sleep(1.5 * (attempt + 1))
        raise last or LinerError("알 수 없는 오류")

    # ------------------------------------------------------------------ 1) 대화·문장
    def chat(self, messages: list[dict], *, temperature: float = 0.2, max_tokens: int = 2000,
             json_mode: bool = False) -> str:
        """Liner Mark(Router API). OpenAI 호환 chat/completions.

        주의: response_format을 함께 보내면 400 invalid_request가 돌아온다(2026-11-15 확인).
        JSON이 필요하면 프롬프트로 요구하고 클라이언트에서 관대하게 파싱한다.
        """
        payload: dict[str, Any] = {"model": self.model, "messages": messages,
                                   "temperature": temperature, "max_tokens": max_tokens}
        data = self._post("/chat/completions", payload, auth="bearer", api_name="chat",
                          timeout=min(self.timeout, 25), retries=1)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError) as exc:
            raise LinerError(f"응답 형식이 예상과 다릅니다: {str(data)[:200]}") from exc

    def chat_json(self, system: str, user: str, *, retries: int = 1, max_tokens: int = 400) -> dict:
        """JSON만 받는다. 코드펜스·설명이 섞이면 한 번 더 교정 요청한다."""
        messages = [{"role": "system", "content": system + "\n반드시 설명·코드펜스 없이 JSON 객체 하나만 출력한다."},
                    {"role": "user", "content": user}]
        last_raw = ""
        for _ in range(retries + 1):
            raw = self.chat(messages, json_mode=True, max_tokens=max_tokens)
            last_raw = raw
            parsed = _parse_json_loose(raw)
            if parsed is not None:
                return parsed
            messages += [{"role": "assistant", "content": raw},
                         {"role": "user", "content": "위 응답은 JSON이 아닙니다. 설명·코드펜스 없이 JSON 객체만 다시 출력하세요."}]
        raise LinerError(f"JSON 파싱 실패: {last_raw[:200]}")

    # ------------------------------------------------------------------ 2) 검색
    def search_web(self, query: str, *, lang: str = "ko", country: str = "KR",
                   max_results: int = 8, date_range: str | None = None) -> list[dict]:
        payload: dict[str, Any] = {"query": query, "lang": lang, "country_code": country,
                                   "max_results": max(1, min(20, max_results)), "include_knowledge": False}
        if date_range:
            payload["date_range"] = date_range
        data = self._post("/tools/search/web", payload, auth="x-api-key", api_name="search_web",
                          timeout=min(self.timeout, 15), retries=1)
        return [{"title": r.get("title", ""), "url": r.get("url", ""), "hostname": r.get("hostname", ""),
                 "description": r.get("description", ""), "date": r.get("date") or ""}
                for r in data.get("results", [])]

    # ------------------------------------------------------------------ 3) 근거 답변
    def search_agent(self, question: str, *, lang: str = "ko", mode: str = "general",
                     history: list[dict] | None = None) -> dict:
        messages = list(history or []) + [{"role": "user", "content": question}]
        payload = {"messages": messages, "model": None, "lang": lang, "mode": mode, "stream": False}
        # 서버리스 한도(60초) 안에서 끝나도록 재시도 없이 50초까지만 기다린다.
        data = self._post("/agents/search", payload, auth="x-api-key", api_name="search_agent",
                          timeout=min(self.timeout, 50), retries=0)
        refs = []
        for r in data.get("references") or []:
            refs.append({"title": r.get("title", ""), "url": r.get("url", ""),
                         "hostname": r.get("hostname", ""), "date": r.get("date") or "",
                         "description": (r.get("description") or "")[:280]})
        return {"answer": data.get("answer", ""), "references": refs,
                "chunks": data.get("chunks") or []}

    # ------------------------------------------------------------------ 4) 즉답 가이드
    def quick_answer(self, question: str, *, history: list[dict] | None = None,
                     timeout: int | None = None) -> dict:
        """Quick Answer Agent — 약 200자 즉답 + 출처 3개. 초동 가이드·법령 한 줄 확인용.

        Search Agent(느리지만 긴 근거)와 달리 단일 패스라 지연이 짧다.
        stream=false 로 받아 JSON 한 번에 처리한다(모바일·서버리스에서 타임아웃이 짧다).
        """
        messages = list(history or []) + [{"role": "user", "content": question}]
        payload = {"messages": messages, "stream": False,
                   "request_id": "qa_" + hashlib.sha1(question.encode("utf-8")).hexdigest()[:12]}
        data = self._post("/agents/quick-answer", payload, auth="x-api-key",
                          api_name="quick_answer", timeout=timeout or min(self.timeout, 30), retries=0)
        refs = []
        for r in data.get("references") or []:
            refs.append({"title": r.get("title", ""), "url": r.get("url", ""),
                         "hostname": r.get("hostname", ""), "date": r.get("date") or "",
                         "description": (r.get("description") or "")[:240]})
        return {"answer": (data.get("answer") or "").strip(), "references": refs}

    # ------------------------------------------------------------------ 5) 시각화
    def visualize(self, query: str, *, is_search_context: bool = False, appearance: str = "dark",
                  max_results: int | None = None, date_range: str | None = None,
                  timeout: int | None = None) -> dict:
        """Visualization API — 자연어 질의를 HTML 차트로. html은 iframe srcdoc에 그대로 넣는다.

        평균 20~30초. 실패·오프라인은 상위에서 폴백 카드로 처리한다.
        """
        payload: dict[str, Any] = {"query": query, "appearance": appearance, "stream": False}
        if is_search_context:
            payload["is_search_context"] = True
            if max_results:
                payload["max_results"] = max(1, min(20, max_results))
            if date_range:
                payload["date_range"] = date_range
        data = self._post("/tools/visualization", payload, auth="x-api-key",
                          api_name="visualization", timeout=timeout or min(self.timeout, 55), retries=0)
        artifact: dict = {}
        for chunk in data.get("chunks") or []:
            if chunk.get("type") == "data-atlas":
                artifact = (chunk.get("data") or {}).get("atlasArtifact") or {}
                break
        if not artifact and isinstance(data.get("atlasArtifact"), dict):
            artifact = data["atlasArtifact"]
        refs = []
        for r in data.get("references") or []:
            refs.append({"title": r.get("title", ""), "url": r.get("url", ""),
                         "hostname": r.get("hostname", ""), "date": r.get("date") or ""})
        html = artifact.get("html") or ""
        return {"ok": bool(html), "html": html, "theme": artifact.get("theme", ""),
                "description": artifact.get("description", ""),
                "resource_id": artifact.get("resourceId", ""), "references": refs}

    # ------------------------------------------------------------------ 상태
    def status(self, *, probe: bool = False) -> dict:
        """연결 상태. 화면을 열 때마다 Liner를 부르지 않도록 결과를 5분 캐시한다(probe=True면 새로 측정)."""
        cache_key = (self.base_url, self.api_key[-6:] if self.api_key else "", self.offline)
        hit = _STATUS_CACHE.get(cache_key)
        if hit and not probe and time.time() - hit[0] < 300:
            return {**hit[1], "cached": True}
        ok, detail, ms = False, "키 없음", None
        if self.available:
            started = time.time()
            try:
                req = urllib.request.Request(f"{self.base_url}/models",
                                             headers={"Authorization": f"Bearer {self.api_key}"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    ok = resp.status == 200
                    detail = "정상" if ok else f"HTTP {resp.status}"
            except Exception as exc:  # noqa: BLE001 - 상태 표시용
                detail = str(exc)[:120]
            ms = int((time.time() - started) * 1000)
        result = {"available": self.available, "ok": ok, "detail": detail, "model": self.model,
                  "base_url": self.base_url, "offline": self.offline or not self.api_key, "latency_ms": ms}
        if self.available:
            _STATUS_CACHE[cache_key] = (time.time(), result)
        return result


def _parse_json_loose(raw: str) -> dict | None:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
