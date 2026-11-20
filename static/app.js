/* 실드메이트 72 (ShieldMate 72) — 화면 로직 (의존성 없음) · v0.7
   - 서버리스(Vercel) 대응: 사건 상태 토큰(state)을 브라우저가 보관하고 매 요청에 실어 보낸다.
   - 10대 사고 유형 선택기, 유형별 즉답 가이드(Quick Answer), 사건 보드 차트(Visualization).
   - 탭 워크스페이스: PC 는 대화 + 대응 보드(3탭), 모바일(≤900px)은 상단 탭으로 한 화면씩.
   - 증거 첨부(.csv/.eml): 브라우저에서 읽어(UTF-8→EUC-KR 재시도) 대화로 보낸다. */
const S = { sid: null, board: null, busy: false, replaying: false, stopReplay: false,
            state: null, cats: [], cat: null, viz: null };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STORE_KEY = "shieldmate72:v1";
const VIEW_KEY = "shieldmate72:view";

function persist() {
  try {
    if (S.state && S.sid) sessionStorage.setItem(STORE_KEY, JSON.stringify({ sid: S.sid, state: S.state }));
  } catch (e) { /* 저장 공간 부족 — 메모리 상태로 계속 동작한다 */ }
}

function restorePoint() {
  try {
    const raw = sessionStorage.getItem(STORE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw);
    return v && v.sid && v.state ? v : null;
  } catch (e) { return null; }
}

async function api(path, options = {}) {
  const opts = { headers: { "Content-Type": "application/json" }, ...options };
  let p = path;
  if (S.state) {
    if ((opts.method || "GET") === "GET") {
      p += (p.includes("?") ? "&" : "?") + "state=" + encodeURIComponent(S.state);
    } else {
      opts.body = JSON.stringify({ ...(opts.body ? JSON.parse(opts.body) : {}), state: S.state });
    }
  }
  const res = await fetch(p, opts);
  if (!res.ok) {
    const text = await res.text();
    const err = new Error(text || res.statusText);
    err.status = res.status;
    throw err;
  }
  const data = await res.json();
  if (data.state) { S.state = data.state; persist(); }
  return data;
}

async function fetchDoc(path) {
  // state 를 본문에 실어 받는다 — 서버리스에서 세션이 사라졌거나 토큰이 길어도 동작한다.
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state: S.state || "" }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res;
}

function filenameFrom(res, fallback) {
  // 서버가 보내는 filename*=UTF-8''…(한글 제목)을 우선 쓰고, 없으면 ASCII 이름.
  const cd = res.headers.get("Content-Disposition") || "";
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) { try { return decodeURIComponent(star[1].trim()); } catch (e) { /* 아래로 */ } }
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return plain ? plain[1].trim() : fallback;
}

async function downloadFile(path, filename) {
  try {
    const res = await fetchDoc(path);
    const buf = await res.arrayBuffer();          // 바이너리를 그대로 받아 Blob 으로
    const type = res.headers.get("Content-Type") || "application/octet-stream";
    const blob = new Blob([buf], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filenameFrom(res, filename);
    a.rel = "noopener";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 8000);
    if (blob.size < 512) say("system", "내려받은 파일이 비어 있습니다. 다시 시도해 주세요.");
  } catch (e) {
    say("system", "다운로드 실패: " + e.message);
  }
}

function setBusy(on, msg = "") {
  S.busy = on;
  $("send").disabled = on;
  $("runScenario").disabled = on;
  $("makeDocs").disabled = on;
  $("guideBtn").disabled = on;
  $("vizBtn").disabled = on;
  $("replay").textContent = S.replaying ? "■ 재생 정지" : "▶ 단계별 재생";
  $("typing").textContent = on ? msg || "처리 중…" : "";
}

/* ---------------------------------------------------------------- 탭 · 화면 전환 */
const BOARD_TAB_IDS = { "1": "tab-1", "2": "tab-2", "3": "tab-3" };
const isMobile = () => window.matchMedia("(max-width: 900px)").matches;

function setBoardTab(n, opts = {}) {
  const tab = BOARD_TAB_IDS[String(n)] ? String(n) : "1";
  document.body.dataset.boardTab = tab;
  document.querySelectorAll(".b-tab").forEach((b) => {
    const on = b.dataset.tab === tab;
    b.classList.toggle("is-on", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  Object.entries(BOARD_TAB_IDS).forEach(([k, id]) => { const el = $(id); if (el) el.hidden = k !== tab; });
  document.querySelectorAll(".m-tab").forEach((b) => b.classList.toggle("is-on", b.dataset.tab === tab));
  if (opts.remember !== false && !isMobile()) { try { sessionStorage.setItem(VIEW_KEY, tab); } catch (e) { /* noop */ } }
}

function setView(v, opts = {}) {
  const view = String(v || "1");
  if (view === "chat") {
    document.body.dataset.view = "chat";
    document.querySelectorAll(".m-tab").forEach((b) => b.classList.toggle("is-on", b.dataset.tab === "chat"));
    try { sessionStorage.setItem(VIEW_KEY, "chat"); } catch (e) { /* noop */ }
    return;
  }
  document.body.dataset.view = "board";
  setBoardTab(view, opts);
  try { sessionStorage.setItem(VIEW_KEY, view); } catch (e) { /* noop */ }
}

function restoreView() {
  let view = null;
  try { view = sessionStorage.getItem(VIEW_KEY); } catch (e) { view = null; }
  setView(view || (isMobile() ? "chat" : "1"), { remember: false });
}

function setBadge(id, value, title) {
  const el = $(id);
  if (!el) return;
  el.textContent = String(value);
  el.title = title || "";
  el.classList.toggle("hot", Number(value) > 0);
}

/* ---------------------------------------------------------------- 증거 첨부 */
function decodeBytes(bytes) {
  let text = new TextDecoder("utf-8").decode(bytes);
  if (text.indexOf("\uFFFD") === -1) return text;
  try {                                    // 오래된 메일 원본은 EUC-KR 인 경우가 많다
    const kr = new TextDecoder("euc-kr").decode(bytes);
    if (kr.indexOf("\uFFFD") === -1) return kr;
  } catch (e) { /* 브라우저가 euc-kr 을 지원하지 않으면 UTF-8 결과를 쓴다 */ }
  return text;
}

async function attachFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (S.busy) { say("system", "지금 처리 중입니다. 끝난 뒤 다시 첨부해 주세요."); return; }
  const loaded = [];
  for (const f of files) {
    try {
      if (f.size > 8 * 1024 * 1024) { say("system", `${f.name} 은(는) 8MB 를 넘어 건너뜁니다.`); continue; }
      const bytes = new Uint8Array(await f.arrayBuffer());
      loaded.push({ name: f.name, text: decodeBytes(bytes) });
    } catch (e) {
      say("system", `파일을 읽지 못했습니다: ${f.name}`);
    }
  }
  if (!loaded.length) return;
  $("attachInfo").textContent = loaded.map((x) => x.name).join(", ");
  const emls = loaded.filter((x) => /\.eml$/i.test(x.name));
  const logs = loaded.filter((x) => !/\.eml$/i.test(x.name));
  if (logs.length) {
    await sendText(logs.map((x) => x.text).join("\n\n"), {
      label: logs.map((x) => x.name).join(", "),
      attachment: logs.map((x) => `### ${x.name}\n${x.text}`).join("\n\n"),
      busy: "로그 판독 중…",
    });
  }
  for (const eml of emls) {
    await sendText(eml.text, { label: eml.name, attachment: eml.text, busy: "메일 원본 판독 중…" });
  }
}

function bindQuickChips() {
  const box = $("quickChips");
  if (!box) return;
  box.addEventListener("click", (e) => {
    const chip = e.target.closest(".quick");
    if (!chip || S.busy) return;
    $("input").value = chip.dataset.q || "";
    $("input").focus();
  });
}

function fmt(text) {
  const safe = esc(text);
  return safe.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
}

function say(role, text, attachment) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  if (role === "bot") div.innerHTML = fmt(text); else div.textContent = text;
  if (attachment) {
    const det = document.createElement("details");
    det.innerHTML = `<summary>원문 보기</summary><pre>${esc(attachment.slice(0, 4000))}${attachment.length > 4000 ? "\n…" : ""}</pre>`;
    div.appendChild(det);
  }
  $("chat").appendChild(div);
  $("chat").scrollTop = $("chat").scrollHeight;
  return div;
}

async function init() {
  try {
    const health = await api("/api/health");
    const liner = health.liner || {};
    $("modePill").textContent = liner.available ? `Liner ${liner.model}` : "규칙 기반(키 없음)";
    $("modePill").className = "pill" + (liner.available ? " live" : "");
    $("apiInfo").textContent = liner.available
      ? `${liner.base_url} · ${liner.detail}`
      : "LINER_API_KEY 미설정 — 규칙 기반 모드(판정·기한·문서는 동작)";
    S.cats = health.categories || [];
    renderCategoryChips();
    const sel = $("scenario");
    sel.innerHTML = "";
    (health.scenarios || []).forEach((s) => {
      const o = document.createElement("option");
      o.value = s.id;
      o.textContent = s.title || s.id;
      sel.appendChild(o);
    });
  } catch (e) {
    say("system", "서버 상태를 읽지 못했습니다: " + e.message);
  }

  restoreView();
  const saved = restorePoint();
  if (saved) {
    try {
      S.sid = saved.sid; S.state = saved.state;
      const data = await api(`/api/${S.sid}/board`);
      S.board = data.board;
      render(data.board);
      say("system", "이전에 보던 사건을 복원했습니다(서버가 바뀌어도 상태 토큰으로 이어집니다).");
      return;
    } catch (e) {
      S.sid = null; S.state = null;
      try { sessionStorage.removeItem(STORE_KEY); } catch (err) { /* noop */ }
    }
  }
  await newSession();
  say("system", "사고 유형을 고르거나 상황을 설명하세요. 로그(CSV)·메일 원본(.eml)을 붙여넣거나 아래에서 첨부해도 됩니다.");
}

async function newSession() {
  S.state = null;
  try { sessionStorage.removeItem(STORE_KEY); } catch (e) { /* noop */ }
  const data = await api("/api/session", { method: "POST", body: JSON.stringify({}) });
  S.sid = data.session;
  S.board = data.board;
  S.viz = null;
  $("vizFrame").srcdoc = "";
  render(data.board);
  return data;
}

function ensureSession() {
  if (!S.sid) return newSession();
}

async function retryOnce(fn) {
  try { return await fn(); }
  catch (e) {
    if (e.status === 404) {           // 서버가 상태를 잃었다 → 새 세션 뒤 한 번만 재시도
      await newSession();
      return await fn();
    }
    throw e;
  }
}

async function sendText(raw, opts = {}) {
  const text = String(raw || "").trim();
  if (!text || S.busy) return;
  if (opts.label) say("user", `📎 ${opts.label} 첨부`, opts.attachment || null);
  else say("user", text);
  await ensureSession();
  setBusy(true, opts.busy || "로그·메일 판독 중…");
  try {
    const data = await retryOnce(() => api(`/api/${S.sid}/message`, { method: "POST", body: JSON.stringify({ text }) }));
    S.board = data.board;
    render(data.board);
    if (data.board.reply) say("bot", data.board.reply);
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
}

async function send() {
  const text = $("input").value.trim();
  if (!text || S.busy) return;
  $("input").value = "";
  await sendText(text);
}

async function runScenario() {
  if (S.busy) return;
  const id = $("scenario").value;
  if (!id) return;
  setBusy(true, "시나리오 실행 중… (Liner 호출 시 최대 60초)");
  say("system", `시나리오 실행: ${id}`);
  try {
    await ensureSession();
    const t0 = Date.now();
    const data = await retryOnce(() => api(`/api/${S.sid}/scenario/${id}`, { method: "POST", body: JSON.stringify({}) }));
    S.board = data.board;
    render(data.board);
    say("bot", `시나리오 완료 — ${((Date.now() - t0) / 1000).toFixed(1)}초, 탐지 ${(S.board.findings || []).length}건, ` +
      `문서 ${(S.board.docs || []).length}종. 오른쪽 판정·기한을 확인하세요.`);
    await maybeAutoGuide();
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
}

async function replay() {
  if (S.replaying) { S.stopReplay = true; return; }
  if (S.busy) return;
  const id = $("scenario").value;
  if (!id) return;
  $("chat").innerHTML = "";
  await newSession();
  S.replaying = true; S.stopReplay = false;
  setBusy(true, "재생 준비 중…");
  $("replay").disabled = false;
  try {
    const data = await api(`/api/${S.sid}/replay/${id}`, { method: "POST", body: JSON.stringify({}) });
    S.board = data.board; render(data.board);
    say("system", `단계별 재생: ${$("scenario").selectedOptions[0].textContent} — 실제 사용자처럼 ${data.steps.length}번 입력합니다.`);
    for (let i = 0; i < data.steps.length; i++) {
      if (S.stopReplay) { say("system", "재생을 멈췄습니다. 이어서 직접 입력할 수 있습니다."); break; }
      const st = data.steps[i];
      await sleep(i ? 900 : 300);
      say("user", st.label, st.files && st.files.length ? st.text : null);
      $("typing").textContent = `단계 ${i + 1}/${data.steps.length} 처리 중…`;
      const before = (S.board.severity || {}).level;
      const res = await retryOnce(() => api(`/api/${S.sid}/message`, { method: "POST", body: JSON.stringify({ text: st.text }) }));
      S.board = res.board; render(res.board);
      if (res.board.reply) say("bot", res.board.reply);
      const after = (res.board.severity || {}).level;
      if (before && after && before !== after) flashSeverity(before, after, res.board.severity);
    }
    if (!S.stopReplay) say("system", "재생 완료 — [문서 초안 생성]으로 통지문·신고서를 만들 수 있습니다.");
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    S.replaying = false; S.stopReplay = false;
    setBusy(false);
  }
}

function flashSeverity(before, after, sev) {
  const div = say("system", `심각도 ${before} → ${after} ${sev.name || ""} — ${(sev.reasons || [])[0] || ""}`);
  div.classList.add("sevchange", "sev-" + after);
  const badge = $("sevBadge");
  badge.classList.remove("pulse"); void badge.offsetWidth; badge.classList.add("pulse");
}

async function makeDocs() {
  if (S.busy) return;
  await ensureSession();
  setBusy(true, "문서 초안 생성 중…");
  try {
    const data = await api(`/api/${S.sid}/docs`, { method: "POST", body: JSON.stringify({}) });
    S.board = data.board;
    render(data.board);
    say("bot", `문서 ${Object.keys(data.docs || {}).length}종을 만들었습니다. 발송은 사람이 합니다(초안까지만). 문서 탭에서 MD·DOCX·ZIP으로 내려받으세요.`);
    setView("3", { remember: false });
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
}

/* ---------------------------------------------------------------- 10대 유형 */
function renderCategoryChips() {
  const suggested = new Set(((S.board || {}).suggested_categories || []).map((x) => x.id));
  const active = ((S.board || {}).category || {}).id;
  $("catChips").innerHTML = (S.cats || []).map((c) => `
    <button class="cat-chip${active === c.id ? " active" : ""}${suggested.has(c.id) ? " suggested" : ""}"
      data-cat="${esc(c.id)}" title="${esc(c.name)} — ${esc(c.why_severity || "")}">
      <span class="n">${c.no}</span>${esc(c.short || c.name)}${c.deep ? '<span class="deep">심화</span>' : ""}
    </button>`).join("");
  $("catChips").querySelectorAll("button[data-cat]").forEach((btn) => {
    btn.onclick = () => applyCategory(btn.dataset.cat);
  });
}

async function applyCategory(id) {
  if (S.busy) return;
  const cat = (S.cats || []).find((c) => c.id === id);
  if (!cat) return;
  await ensureSession();
  const sel = $("scenario");
  if (cat.scenario && [...sel.options].some((o) => o.value === cat.scenario)) sel.value = cat.scenario;
  setBusy(true, `유형 ${cat.no}. ${cat.name} — 즉답 가이드 조회 중…`);
  try {
    const data = await retryOnce(() => api(`/api/${S.sid}/category/${id}`, { method: "POST", body: JSON.stringify({}) }));
    S.board = data.board;
    render(data.board);
    if (data.board.reply) say("bot", data.board.reply);
    if (cat.scenario) {
      say("system", `이 유형은 데모 시나리오(${cat.scenario})가 있습니다. [▶ 단계별 재생]을 누르면 판정 과정을 처음부터 볼 수 있습니다.`);
    }
  } catch (e) {
    say("system", "유형을 적용하지 못했습니다: " + e.message);
  } finally {
    setBusy(false);
  }
}

async function maybeAutoGuide() {
  const cat = (S.board || {}).category;
  if (!cat || (S.board || {}).guide) return;
  try { await guide(); } catch (e) { /* 가이드는 부가 기능 — 실패해도 화면은 유지 */ }
}

function renderGuide(b) {
  const cat = b.category;
  const g = b.guide;
  if (!cat) {
    $("guide").innerHTML = `<div class="g-src">위에서 10대 사고 유형을 고르면 공통 초동조치·법정 기한과 유형별 즉답 가이드가 바로 나옵니다.</div>`;
    $("guideBtn").disabled = true;
    return;
  }
  $("guideBtn").disabled = false;
  const head = `<div class="g-src">${cat.no}. ${esc(cat.name)} · <b>${esc(cat.base_severity)}</b> 기본 · 판단 ${esc(cat.level || "추정")}</div>`;
  if (!g) {
    $("guide").innerHTML = head + `<div class="g-src">${esc(cat.why_severity || "")} — [가이드 받기]를 누르면 Liner Quick Answer로 최신 안내를 받습니다.</div>`;
    return;
  }
  const label = g.status === "live" ? "Liner Quick Answer" : "규칙 기반 안내";
  const refs = (g.references || []).map((r) => `<a href="${esc(r.url)}" target="_blank" rel="noreferrer">${esc(r.title || r.hostname || r.url)}</a>`).join(" · ");
  $("guide").innerHTML = head + `
    <div class="g-answer${g.status === "live" ? "" : " g-offline"}">${esc(g.answer || "")}</div>
    <div class="g-src">출처: ${label}${g.status === "error" ? " (호출 실패 — 규칙 기반 안내로 대체)" : ""}</div>
    ${refs ? `<div class="g-src">${refs}</div>` : ""}`;
}

async function guide() {
  if (S.busy) return;
  await ensureSession();
  setBusy(true, "즉답 가이드 조회 중… (Quick Answer)");
  try {
    const data = await api(`/api/${S.sid}/guide`, { method: "POST", body: JSON.stringify({ force: true }) });
    S.board = data.board;
    render(data.board);
  } catch (e) {
    say("system", "가이드를 받지 못했습니다: " + e.message);
  } finally {
    setBusy(false);
  }
}

/* ---------------------------------------------------------------- 차트 */
function renderViz(b) {
  const v = b.viz || {};
  const htmlStart = `<div class="g-src">${esc(v.query || "")}</div>`;
  if (v.ok) {
    $("vizInfo").innerHTML = `<div class="g-src">${esc(v.description || "사건 대응 차트가 준비되었습니다.")}</div>`;
    $("vizBtn").textContent = "차트 다시 보기";
    return;
  }
  const reason = v.reason || (v.available ? "아직 차트를 만들지 않았습니다." : "Liner 키가 없어 차트 대신 요약 카드로 표시합니다.");
  $("vizInfo").innerHTML = htmlStart + `<div class="g-src">${esc(reason)}</div>` + vizFallback(b);
  $("vizBtn").textContent = "차트로 보기";
}

function vizFallback(b) {
  // 오프라인·실패 시 깨지지 않는 폴백: 지금 할 일을 시간 구간별로 접어 보여 준다.
  const buckets = { "0~10분": 0, "15분": 0, "조사": 0, "지금": 0 };
  (b.actions || []).forEach((a) => { if (buckets[a.kind] !== undefined) buckets[a.kind] += 1; });
  const cells = Object.entries(buckets).map(([k, n]) =>
    `<span class="cat-chip" style="cursor:default"><span class="n">${n}</span>${esc(k)}</span>`).join("");
  const due = (b.deadlines || {}).next_due;
  return `<div class="cat-chips" style="flex-wrap:wrap;margin-top:6px">${cells}</div>` +
    (due ? `<div class="g-src" style="margin-top:6px">다음 기한: ${esc(due.title)} → ${esc(due.due)} (${esc(due.remaining || "")})</div>` : "");
}

async function showViz() {
  if (S.busy) return;
  await ensureSession();
  if (S.viz) { openViz(); return; }
  setBusy(true, "차트 생성 중… (Visualization, 최대 30초)");
  try {
    const data = await api(`/api/${S.sid}/viz`, { method: "POST", body: JSON.stringify({}) });
    S.board = data.board || S.board;
    if (data.html) {
      S.viz = data.html;
      render(S.board);
      openViz();
    } else {
      render(S.board);
      say("system", "차트를 만들지 못했습니다 — " + ((data.viz || {}).reason || "요약 카드로 대체합니다."));
    }
  } catch (e) {
    say("system", "차트 요청 실패: " + e.message +
      " — 서버가 식어 있으면 첫 요청이 오래 걸릴 수 있습니다. 잠시 뒤 [차트로 보기]를 한 번 더 눌러 주세요.");
  } finally {
    setBusy(false);
  }
}

function openViz() {
  if (!S.viz) return;
  $("vizFrame").srcdoc = S.viz;
  const v = (S.board || {}).viz || {};
  $("vizTheme").textContent = v.theme || "chart";
  $("vizTitle").textContent = "사건 보드 차트 — " + (((S.board || {}).category || {}).name || "대응 타임라인");
  $("vizModal").classList.remove("hidden");
}

/* ---------------------------------------------------------------- 보드 */
function render(b) {
  if (!b) return;
  const c = b.case || {};
  $("caseTitle").textContent = c.title || "사건";
  $("caseMeta").textContent = `${c.id || ""} · 인지 ${c.aware_at || "미확인"} · 로그 ${(b.log_kinds || []).join(", ") || "없음"}`;

  const sev = b.severity || {};
  const badge = $("sevBadge");
  badge.textContent = `${sev.level || "—"} ${sev.name || ""} ${sev.evidence_level ? "(" + sev.evidence_level + ")" : ""}`;
  badge.className = "sev " + (sev.level ? "sev-" + sev.level : "sev-none");

  const mode = (b.api || {}).mode === "liner" ? "Liner 연동" : "규칙 기반";
  $("modePill").textContent = mode;
  $("modePill").className = "pill" + ((b.api || {}).mode === "liner" ? " live" : "");
  const calls = ((b.api || {}).calls || []).map((x) => `${x.api}:${x.ok ? "ok" : "fail"}/${x.ms}ms`).join(" · ");
  if (calls) $("apiInfo").textContent = calls;

  const hist = b.severity_history || [];
  $("sevTrail").innerHTML = hist.length > 1
    ? hist.map((h) => `<span class="trail sev-${esc(h.level)}" title="${esc(h.at + " · " + h.reason)}">${esc(h.level)}</span>`).join('<span class="arrow">→</span>')
    : "";

  renderCategoryChips();
  renderGuide(b);
  renderActions(b);
  renderDeadlines(b);
  renderTimeline(b);
  renderVerdict(b);
  renderFacts(b);
  renderDocs(b);
  renderSources(b);
  renderViz(b);

  $("dontdo").innerHTML = (b.dont_do || []).map((d) => `<li>${esc(d)}</li>`).join("");

  // 탭 배지 — 한눈에 남은 일·근거·문서 수를 보여 준다
  const nActions = (b.actions || []).length;
  const nDue = ((b.deadlines || {}).items || []).filter((x) => x.status === "해당").length;
  const nFindings = (b.findings || []).length;
  const nDocs = (b.docs || []).length;
  const nSources = (b.sources || []).length;
  setBadge("badgeTab1", nActions, `지금 할 일 ${nActions}개 · 해당 기한 ${nDue}개`);
  setBadge("badgeTab2", nFindings, `탐지 ${nFindings}건 · 근거 ${nSources}건`);
  setBadge("badgeTab3", nDocs, `문서 ${nDocs}종`);
  setBadge("mBadge1", nActions, `지금 할 일 ${nActions}개 · 해당 기한 ${nDue}개`);
  setBadge("mBadge2", nFindings, `탐지 ${nFindings}건`);
  setBadge("mBadge3", nDocs, `문서 ${nDocs}종`);
  $("phaseLabel").textContent = b.phase ? `${b.phase.window || ""} ${b.phase.elapsed_minutes != null ? "· 인지 후 " + elapsed(b.phase.elapsed_minutes) : ""}` : "";

  const warn = document.createElement("div");
  warn.className = "msg system";
  if (b.missing && b.missing.length && !document.querySelector(".nextq")) {
    warn.classList.add("nextq");
    warn.textContent = "확인 필요: " + b.missing[0];
    $("chat").appendChild(warn);
  }
}

function elapsed(min) {
  if (min < 60) return `${min}분`;
  const h = Math.floor(min / 60), m = min % 60;
  return h < 48 ? `${h}시간 ${m}분` : `${Math.floor(h / 24)}일 ${h % 24}시간`;
}

function renderActions(b) {
  const items = b.actions || [];
  $("actions").innerHTML = items.length
    ? items.map((a, i) => `<li>
        <span class="num">${i + 1}</span>
        <span>${esc(a.action)}${a.kind ? `<span class="tag">${esc(a.kind)}</span>` : ""}</span>
        <span class="who">${esc(a.who)}<br><span class="ref">플레이북 ${esc(a.ref)}</span></span>
      </li>`).join("")
    : `<li><span class="num">·</span><span>사건을 시작하면 지금 할 일이 나옵니다.</span><span></span></li>`;
}

function renderDeadlines(b) {
  const d = b.deadlines || {};
  const items = d.items || [];
  $("deadlines").innerHTML = items.map((x) => {
    const cls = x.status === "해당" ? "due" : "";
    const chipCls = (x.status || "").replace(/[()\s]/g, "");
    return `<div class="ddl ${cls}">
      <div class="ddl-top">
        <span class="ddl-title">${esc(x.title)}</span>
        <span class="chip ${chipCls}">${esc(x.status)}</span>
      </div>
      <div class="ddl-meta">${esc(x.to)} · 마감 ${esc(x.due || "미확인")} ${x.remaining ? "· " + esc(x.remaining) : ""}</div>
      <div class="ddl-why">${esc(x.why)}</div>
      ${x.legal_ref ? `<div class="ddl-meta">근거 ${esc(x.legal_ref)}</div>` : ""}
    </div>`;
  }).join("") || `<div class="hint">인지 시각과 사실관계가 들어오면 기한이 계산됩니다.</div>`;

  const ops = (d.operational || []).filter((o) => o.triggered);
  if (ops.length) {
    $("deadlines").insertAdjacentHTML("beforeend",
      `<div class="ddl"><div class="ddl-top"><span class="ddl-title">운영상 연락(법정 신고 아님)</span><span class="chip 검토">즉시</span></div>` +
      ops.map((o) => `<div class="ddl-why">· ${esc(o.title)} — ${esc(o.how)}</div>`).join("") + `</div>`);
  }
}

function renderTimeline(b) {
  const rows = (b.findings || []).slice(0, 40);
  $("timeline").innerHTML = rows.map((f) => `<div class="tl ${f.severity === "critical" ? "crit" : f.severity === "high" ? "high" : ""}">
      <div><div class="t">${f.ts ? esc(f.ts_kst) : "시각 미상"}</div><div class="u">${f.ts ? esc(f.ts.replace("T", " ").slice(0, 16)) + "Z" : "메일 원본 판독"}</div></div>
      <div><span class="r">${esc(f.rule_id)}</span> ${esc(f.summary)}</div>
    </div>`).join("") || `<div class="hint">로그를 붙여넣으면 시간순 사건이 여기에 쌓입니다.</div>`;
}

function renderVerdict(b) {
  const c = b.classification || {};
  const sev = b.severity || {};
  const cat = b.category;
  const basis = (c.basis || []).map((x) => `<div class="basis">· ${esc(x)}</div>`).join("");
  const missing = (c.missing || []).length ? `<div class="basis">모르는 것: ${esc((c.missing || []).join(", "))}</div>` : "";
  $("verdict").innerHTML = `
    <div class="line"><span class="big">${esc(c.label || "판별 전")}</span> <span class="badge ${esc(c.level || "미확인")}">${esc(c.level || "미확인")}</span></div>
    ${cat ? `<div class="ddl-meta">10대 유형 ${cat.no}. ${esc(cat.name)}</div>` : ""}
    ${basis}${missing}
    <div class="line" style="margin-top:8px">심각도 <b>${esc(sev.level || "-")}</b> ${esc(sev.name || "")} — ${esc((sev.reasons || [])[0] || "")}</div>
    <div class="ddl-meta">보고 주기 ${esc(sev.next_report || "-")}</div>`;
}

function renderFacts(b) {
  const facts = b.facts || [];
  $("facts").innerHTML = facts.map((f) => `<div class="fact">
      <span class="k">${esc(f.label)}</span>
      <span class="v">${esc(typeof f.value === "object" ? JSON.stringify(f.value) : f.value)}</span>
      <span class="badge ${esc(f.level)}">${esc(f.level)}</span>
    </div>`).join("") || `<div class="hint">아직 기록된 사실이 없습니다.</div>`;
}

function renderDocs(b) {
  const docs = b.docs || [];
  $("docs").innerHTML = docs.map((d) => `<div class="doc">
      <div class="doc-title">${esc(d.title)}</div>
      <div class="doc-tools">
        <button data-doc="${esc(d.id)}">미리보기</button>
        <button data-md="${esc(d.id)}">MD</button>
        <button data-docx="${esc(d.id)}">DOCX</button>
      </div>
    </div>`).join("") || `<div class="hint">[문서 초안 생성]을 누르면 통지문·신고서가 만들어지고, MD·DOCX·ZIP으로 내려받을 수 있습니다.</div>`;
  $("zipAll").classList.toggle("hidden", !docs.length);
  $("docs").querySelectorAll("button[data-doc]").forEach((btn) => {
    btn.onclick = () => previewDoc(btn.dataset.doc);
  });
  $("docs").querySelectorAll("button[data-md]").forEach((btn) => {
    btn.onclick = () => downloadFile(`/api/${S.sid}/download/${btn.dataset.md}`, `${btn.dataset.md}.md`);
  });
  $("docs").querySelectorAll("button[data-docx]").forEach((btn) => {
    btn.onclick = () => downloadFile(`/api/${S.sid}/download/${btn.dataset.docx}.docx`, `${btn.dataset.docx}.docx`);
  });
}

async function previewDoc(id) {
  try {
    const res = await fetchDoc(`/api/${S.sid}/download/${id}`);
    const text = await res.text();
    const meta = (S.board.docs || []).find((d) => d.id === id);
    $("modalTitle").textContent = meta ? meta.title : id;
    $("modalTitle").dataset.doc = id;
    $("modalBody").textContent = text;
    $("modal").classList.remove("hidden");
  } catch (e) {
    say("system", "문서를 열지 못했습니다: " + e.message);
  }
}

function renderSources(b) {
  const src = b.sources || [];
  const law = (b.law_checks || [])[0];
  let html = "";
  if (law) {
    html += `<div class="source"><b>법령 재확인</b> — ${esc(law.status)}${law.drift && law.drift.length ? " · 차이: " + esc(law.drift.join(" / ")) : " · 코드 규칙과 일치 확인"}</div>`;
  }
  html += src.slice(0, 12).map((s) => `<div class="source">
      <a href="${esc(s.url)}" target="_blank" rel="noreferrer">${esc(s.title || s.url)}</a>
      <div class="host">${esc(s.hostname || "")} ${s.date ? "· " + esc(s.date) : ""}</div>
    </div>`).join("");
  $("sources").innerHTML = html || `<div class="hint">Liner 검색 근거가 여기에 표시됩니다.</div>`;
}

document.querySelectorAll(".b-tab").forEach((b) => {
  b.onclick = () => setBoardTab(b.dataset.tab);
});
document.querySelectorAll(".m-tab").forEach((b) => {
  b.onclick = () => setView(b.dataset.tab === "chat" ? "chat" : b.dataset.tab);
});
$("fileInput").addEventListener("change", (e) => {
  const files = e.target.files;
  attachFiles(files);
  e.target.value = "";
});
bindQuickChips();
$("send").onclick = send;
$("input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send();
});
$("runScenario").onclick = runScenario;
$("replay").onclick = replay;
$("guideBtn").onclick = guide;
$("vizBtn").onclick = showViz;
$("modalCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("modalBody").textContent); $("modalCopy").textContent = "복사됨"; }
  catch { $("modalCopy").textContent = "복사 실패"; }
  setTimeout(() => ($("modalCopy").textContent = "복사"), 1200);
};
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    $("modal").classList.add("hidden");
    $("vizModal").classList.add("hidden");
  }
});
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("modal").classList.add("hidden"); });
$("vizModal").addEventListener("click", (e) => { if (e.target.id === "vizModal") $("vizModal").classList.add("hidden"); });
$("modalDownload").onclick = () => {
  const id = $("modalTitle").dataset.doc;
  if (id) downloadFile(`/api/${S.sid}/download/${id}`, `${id}.md`);
};
$("modalDocx").onclick = () => {
  const id = $("modalTitle").dataset.doc;
  if (id) downloadFile(`/api/${S.sid}/download/${id}.docx`, `${id}.docx`);
};
$("zipAll").onclick = (e) => {
  e.preventDefault();
  downloadFile(`/api/${S.sid}/download/zip`, `ShieldMate72_documents.zip`);
};
$("makeDocs").onclick = makeDocs;
$("newCase").onclick = async () => {
  $("chat").innerHTML = "";
  S.viz = null;
  $("vizFrame").srcdoc = "";
  await newSession();
  say("system", "새 사건을 시작했습니다.");
};
init();
