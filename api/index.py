"""Vercel Python 런타임 진입점 — Flask `app` 을 그대로 노출한다.

서버리스에서는 인스턴스가 바뀌면 메모리 세션이 사라진다. 그래서 화면이 사건 상태 토큰(state)을
들고 다니고, 서버는 요청에 실린 토큰으로 `Agent` 를 즉시 복원한다(app.py 참고).

로컬과 동일하게 `python app.py` 로도 실행된다.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app  # noqa: E402  (sys.path 설정 뒤에 import 해야 한다)

# Vercel 은 `app`(WSGI) 을 자동 인식한다. handler 는 다른 런타임 규약을 쓰는 경우의 별칭이다.
handler = app
