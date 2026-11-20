/* 실드메이트 72 (ShieldMate 72) — 화면 로직 (의존성 없음) · v0.8
   - 판정은 즉시, Liner 문장은 뒤따라: /message(defer) → /enrich(브리핑·가이드) · /law(법령 재확인, 병렬)
   - 상태 토큰(state)을 바꾸는 요청은 한 줄로 세운다(queue) — 동시 요청이 토큰을 갈라놓지 않게.
   - 72시간 시계: 인지 시각 기준 구간·다음 법정 기한 카운트다운을 1초마다 갱신.
   - 지금 할 일 체크리스트: 완료 시각이 신고서 '현재까지의 대응'에 들어간다. */
const S = {
  sid: null, state: null, board: null, busy: false, replaying: false, stopReplay: false,
  cats: [], viz: null, lawInFlight: false, liner: false, linerJobs: 0, queue: Promise.resolve(),
};
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const STORE_KEY = "shieldmate72:v2";
const isMobile = () => window.matchMedia("(max-width: 900px)").matches;

/* ---------------------------------------------------------------- 통신 */
function persist() {
  try { if (S.state && S.sid) sessionStorage.setItem(STORE_KEY, JSON.stringify({ sid: S.sid, state: S.state })); }
  catch (e) { /* 저장 공간 부족 — 메모리로 계속 */ }
}
function restorePoint() {
  try { const v = JSON.parse(sessionStorage.getItem(STORE_KEY) || "null"); return v && v.sid && v.state ? v : null; }
  catch (e) { return null; }
}

async function api(path, body) {
  // 상태 토큰은 항상 본문으로 보낸다(URL 길이 제한 회피). body 가 없으면 GET.
  const opts = body === undefined
    ? { method: "GET" }
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, state: S.state || undefined }) };
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = j.error || msg; } catch (e) { /* 텍스트 응답 */ }
    const err = new Error(msg); err.status = res.status; throw err;
  }
  const data = await res.json();
  if (data.state) { S.state = data.state; persist(); }
  return data;
}

function enqueue(fn) {
  const run = S.queue.then(fn, fn);
  S.queue = run.catch(() => {});
  return run;
}
const post = (path, body = {}) => enqueue(() => api(path, body));

async function withSession(fn) {
  if (!S.sid) await newSession();
  try { return await fn(); }
  catch (e) {
    if (e.status === 404) { await newSession(); return await fn(); }   // 서버가 상태를 잃음 → 새 세션 1회 재시도
    throw e;
  }
}

function linerJob(delta) {
  S.linerJobs = Math.max(0, S.linerJobs + delta);
  renderMode();
}

/* ---------------------------------------------------------------- 화면 상태 */
function setStage(stage) {
  document.body.dataset.stage = stage;
  if (stage === "case" && isMobile() && !document.body.dataset.viewSet) setView("chat");
}

function setView(v) {
  const view = String(v);
  document.body.dataset.viewSet = "1";
  if (view === "chat" || view === "side") document.body.dataset.view = view;
  else { document.body.dataset.view = "board"; setBoardTab(view); }
  document.querySelectorAll(".m-tab").forEach((b) => {
    const t = b.dataset.tab;
    b.classList.toggle("is-on", t === view || (document.body.dataset.view === "board" && t === document.body.dataset.boardTab && view !== "chat" && view !== "side"));
  });
  if (isMobile()) window.scrollTo({ top: 0 });
}

function setBoardTab(n) {
  const tab = ["1", "2", "3", "4"].includes(String(n)) ? String(n) : "1";
  document.body.dataset.boardTab = tab;
  document.querySelectorAll(".b-tab").forEach((b) => {
    const on = b.dataset.tab === tab;
    b.classList.toggle("is-on", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  ["1", "2", "3", "4"].forEach((k) => { $("tab-" + k).hidden = k !== tab; });
}

function setBusy(on, msg = "") {
  S.busy = on;
  ["send", "runScenario", "makeDocs", "startSend"].forEach((id) => { $(id).disabled = on; });
  $("replay").disabled = on && !S.replaying;
  $("stopReplay").classList.toggle("hidden", !S.replaying);
  $("typing").textContent = on ? msg || "처리 중…" : "";
}

/* ---------------------------------------------------------------- 대화 */
function fmt(text) {
  return esc(text).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
}

function say(role, text, opts = {}) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  if (role === "pending") {
    div.innerHTML = `<span class="spin" aria-hidden="true"></span><span>${esc(text)}</span>`;
  } else if (role === "bot" || role === "liner") {
    div.innerHTML = fmt(text);
  } else {
    div.textContent = text;
  }
  if (opts.src) {
    const s = document.createElement("span");
    s.className = "src"; s.textContent = opts.src;
    div.appendChild(s);
  }
  if (opts.attachment) {
    const det = document.createElement("details");
    det.innerHTML = `<summary>원문 보기</summary><pre>${esc(opts.attachment.slice(0, 4000))}${opts.attachment.length > 4000 ? "\n…" : ""}</pre>`;
    div.appendChild(det);
  }
  $("chat").appendChild(div);
  $("chat").scrollTop = $("chat").scrollHeight;
  return div;
}

function askNext(b) {
  const q = (b.missing || [])[0];
  const last = $("chat").lastElementChild;
  if (q && !(last && last.dataset.q === q)) {
    const d = say("system", "확인 필요 · " + q);
    d.dataset.q = q;
  }
}

/* ---------------------------------------------------------------- 시작 */
async function init() {
  setBoardTab("1");
  try {
    const health = await api("/api/health");
    S.liner = !!(health.liner || {}).available;
    S.cats = health.categories || [];
    renderCategoryGrid();
    const sel = $("scenario");
    sel.innerHTML = (health.scenarios || []).map((s) => `<option value="${esc(s.id)}">${esc(s.title || s.id)}</option>`).join("");
    renderMode(health.liner);
  } catch (e) {
    $("modeText").textContent = "서버 응답 없음";
  }

  const saved = restorePoint();
  if (saved) {
    try {
      S.sid = saved.sid; S.state = saved.state;
      const data = await api(`/api/${S.sid}/board`, {});
      if (hasCase(data.board)) {
        S.board = data.board;
        setStage("case");
        render(data.board);
        say("system", "이전에 보던 사건을 이어서 엽니다.");
        return;
      }
    } catch (e) { /* 새로 시작 */ }
  }
  await newSession();
}

function hasCase(b) {
  if (!b) return false;
  return !!((b.findings || []).length || b.category || (b.case || {}).aware_at !== "미확인" || (b.docs || []).length);
}

async function newSession() {
  S.state = null; S.viz = null;
  try { sessionStorage.removeItem(STORE_KEY); } catch (e) { /* noop */ }
  const data = await api("/api/session", {});
  S.sid = data.session; S.board = data.board;
  $("vizFrame").srcdoc = "";
  render(data.board);
  return data;
}

/* ---------------------------------------------------------------- 입력 처리 */
async function sendText(raw, opts = {}) {
  const text = String(raw || "").trim();
  if (!text || S.busy) return;
  setStage("case");
  if (opts.label) say("user", `📎 ${opts.label}`, { attachment: opts.attachment || null });
  else say("user", text);
  setBusy(true, opts.busy || "판독 중…");
  let data;
  try {
    data = await withSession(() => post(`/api/${S.sid}/message`, { text, defer: true }));
    applyBoard(data.board, { reply: true });
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
  if (data) await handlePending(data.board.pending, text);
}

function applyBoard(b, opts = {}) {
  const before = (S.board && S.board.severity || {}).level;
  S.board = b;
  render(b);
  if (opts.reply && b.reply) say("bot", b.reply);
  const after = (b.severity || {}).level;
  if (before && after && before !== after && hasCase(b)) flashSeverity(before, after, b.severity);
  askNext(b);
}

async function handlePending(pending, text = "") {
  const list = pending || [];
  if (list.includes("law")) startLaw();
  const fast = list.filter((t) => ["facts", "narrate", "guide"].includes(t));
  if (fast.length) await runEnrich(fast, text);
}

async function runEnrich(tasks, text = "") {
  const label = tasks.includes("guide") && !tasks.includes("narrate")
    ? "Liner Quick Answer로 유형별 가이드를 받는 중…" : "Liner Mark가 상황 브리핑을 쓰는 중…";
  const wait = say("pending", label);
  const t0 = performance.now();
  linerJob(+1);
  try {
    const data = await post(`/api/${S.sid}/enrich`, { tasks, text });
    wait.remove();
    S.board = data.board; render(data.board);
    if ((data.updated || []).length) say("system", "Liner가 사실을 보탰습니다 · " + data.updated.join(", "));
    if (data.brief) say("liner", data.brief, { src: `Liner Mark 브리핑 · ${((performance.now() - t0) / 1000).toFixed(1)}초` });
    if (tasks.includes("guide") && (data.board.guide || {}).status === "live") {
      say("liner", data.board.guide.answer, { src: "Liner Quick Answer · 유형별 즉답" });
    }
  } catch (e) {
    wait.remove();
    say("system", "Liner 보강을 건너뜁니다(판정·기한은 그대로 유효): " + e.message);
  } finally {
    linerJob(-1);
  }
}

function startLaw() {
  if (S.lawInFlight || ((S.board || {}).law_checks || []).length || !S.sid) return;
  S.lawInFlight = true;
  renderLawBadge();
  const wait = say("pending", "Liner Search Agent가 신고 기한의 법령 근거를 재확인하는 중… (판정은 이미 반영됨)");
  const t0 = performance.now();
  linerJob(+1);
  const sid = S.sid;
  api(`/api/${sid}/law`, {})                         // 상태를 바꾸지 않으므로 줄 밖에서 동시에 실행
    .then((r) => (sid === S.sid ? post(`/api/${sid}/law/merge`, { law_check: r.law_check }) : null))
    .then((data) => {
      wait.remove();
      if (!data) return;
      S.board = data.board; render(data.board);
      const law = (data.board.law_checks || [])[0] || {};
      const secs = ((performance.now() - t0) / 1000).toFixed(0);
      if (law.status === "live") {
        say("system", `법령 재확인 완료(${secs}초) · ` + ((law.drift || []).length ? "코드 규칙과 차이: " + law.drift.join(" / ") : "코드 규칙과 차이 없음") + " · 근거는 [근거·차트] 탭");
      } else {
        say("system", "법령 재확인을 하지 못해 규칙 기준을 유지합니다" + (law.error ? ` (${law.error.slice(0, 80)})` : ""));
      }
    })
    .catch((e) => { wait.remove(); say("system", "법령 재확인 실패 — 규칙 기준 유지: " + e.message); })
    .finally(() => { S.lawInFlight = false; linerJob(-1); renderLawBadge(); });
}

async function send() {
  const text = $("input").value.trim();
  if (!text || S.busy) return;
  $("input").value = "";
  await sendText(text);
}

/* ---------------------------------------------------------------- 증거 첨부 */
function decodeBytes(bytes) {
  const text = new TextDecoder("utf-8").decode(bytes);
  if (text.indexOf("�") === -1) return text;
  try { const kr = new TextDecoder("euc-kr").decode(bytes); if (kr.indexOf("�") === -1) return kr; }
  catch (e) { /* euc-kr 미지원 */ }
  return text;
}

async function attachFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (S.busy) { say("system", "지금 처리 중입니다. 끝난 뒤 다시 첨부해 주세요."); return; }
  const loaded = [];
  for (const f of files) {
    if (f.size > 8 * 1024 * 1024) { say("system", `${f.name} 은(는) 8MB를 넘어 건너뜁니다.`); continue; }
    try { loaded.push({ name: f.name, text: decodeBytes(new Uint8Array(await f.arrayBuffer())) }); }
    catch (e) { say("system", `파일을 읽지 못했습니다: ${f.name}`); }
  }
  if (!loaded.length) return;
  setStage("case");
  $("attachInfo").textContent = "첨부: " + loaded.map((x) => x.name).join(", ");
  const emls = loaded.filter((x) => /\.eml$/i.test(x.name));
  const logs = loaded.filter((x) => !/\.eml$/i.test(x.name));
  if (logs.length) {
    await sendText(logs.map((x) => x.text).join("\n\n"), {
      label: logs.map((x) => x.name).join(", ") + " 첨부",
      attachment: logs.map((x) => `### ${x.name}\n${x.text}`).join("\n\n"), busy: "로그 판독 중…",
    });
  }
  for (const eml of emls) await sendText(eml.text, { label: eml.name + " 첨부", attachment: eml.text, busy: "메일 원본 판독 중…" });
}

/* ---------------------------------------------------------------- 데모 */
function demoAwareAt() {
  // 데모는 '지금 15분 전에 알았다'로 시작한다 — 시나리오 원본의 고정 날짜로 돌리면 시연 날 기한이 이미 지나 있다.
  const k = new Date(Date.now() + 9 * 3600e3 - 15 * 60e3);   // KST
  const p = (n) => String(n).padStart(2, "0");
  return `${k.getUTCFullYear()}-${p(k.getUTCMonth() + 1)}-${p(k.getUTCDate())} ${p(k.getUTCHours())}:${p(k.getUTCMinutes())}`;
}

async function startDemo() {
  $("chat").innerHTML = "";
  S.lawInFlight = false;
  await newSession();
  setStage("case");
}

async function replay() {
  if (S.replaying) { S.stopReplay = true; return; }
  if (S.busy) return;
  const id = $("scenario").value;
  if (!id) return;
  await startDemo();
  S.replaying = true; S.stopReplay = false;
  setBusy(true, "재생 준비 중…");
  try {
    const data = await post(`/api/${S.sid}/replay/${id}`, { aware_at: demoAwareAt() });
    S.board = data.board; render(data.board);
    say("system", `단계별 재생 — ${$("scenario").selectedOptions[0].textContent} · 실제 사용자처럼 ${data.steps.length}번 입력합니다`);
    for (let i = 0; i < data.steps.length; i++) {
      if (S.stopReplay) { say("system", "재생을 멈췄습니다. 이어서 직접 입력할 수 있습니다."); break; }
      const st = data.steps[i];
      await sleep(i ? 700 : 250);
      say("user", st.label, { attachment: st.files && st.files.length ? st.text : null });
      $("typing").textContent = `단계 ${i + 1}/${data.steps.length} 판독 중…`;
      const res = await post(`/api/${S.sid}/message`, { text: st.text, defer: true });
      applyBoard(res.board, { reply: true });
      await handlePending(res.board.pending, st.text);
    }
    if (!S.stopReplay) say("system", "재생 완료 — [문서] 탭에서 통지문·신고서 초안을 만들 수 있습니다.");
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    S.replaying = false; S.stopReplay = false;
    setBusy(false);
  }
}

async function runScenario() {
  if (S.busy) return;
  const id = $("scenario").value;
  if (!id) return;
  await startDemo();
  setBusy(true, "시나리오 처리 중…");
  let data;
  try {
    const t0 = performance.now();
    data = await post(`/api/${S.sid}/scenario/${id}`, { defer: true, aware_at: demoAwareAt() });
    applyBoard(data.board, { reply: true });
    say("system", `규칙 엔진 처리 ${((performance.now() - t0) / 1000).toFixed(1)}초 · 탐지 ${(data.board.findings || []).length}건 · 문서 ${(data.board.docs || []).length}종`);
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
  if (data) await handlePending(data.board.pending);
}

/* ---------------------------------------------------------------- 10대 유형 */
function renderCategoryGrid() {
  const active = ((S.board || {}).category || {}).id;
  $("catChips").innerHTML = (S.cats || []).map((c) => `
    <button class="cat-chip${active === c.id ? " active" : ""}" type="button" data-cat="${esc(c.id)}" title="${esc(c.deadline_focus || "")}">
      <span class="top"><span class="n">${String(c.no).padStart(2, "0")}</span>${c.deep ? '<span class="deep">심화</span>' : ""}</span>
      <span class="name">${esc(c.name)}</span>
      <span class="base">기본 ${esc(c.base_severity || "")}</span>
    </button>`).join("");
  $("catChips").querySelectorAll("button[data-cat]").forEach((btn) => { btn.onclick = () => applyCategory(btn.dataset.cat); });
}

async function applyCategory(id) {
  if (S.busy) return;
  const cat = (S.cats || []).find((c) => c.id === id);
  if (!cat) return;
  if (cat.scenario && [...$("scenario").options].some((o) => o.value === cat.scenario)) $("scenario").value = cat.scenario;
  setStage("case");
  setBusy(true, `${cat.name} 접수 중…`);
  let data;
  try {
    data = await withSession(() => post(`/api/${S.sid}/category/${id}`, { defer: true }));
    applyBoard(data.board, { reply: true });
  } catch (e) {
    say("system", "유형을 적용하지 못했습니다: " + e.message);
  } finally {
    setBusy(false);
  }
  if (data) await handlePending(data.board.pending);
}

/* ---------------------------------------------------------------- 체크리스트 */
async function toggleAction(key, done) {
  const a = ((S.board || {}).actions || []).find((x) => x.key === key);
  if (!a) return;
  a.done = done; a.done_at = done ? "저장 중" : null;          // 먼저 화면에 반영
  renderActions(S.board); renderProgress(S.board);
  try {
    const data = await post(`/api/${S.sid}/action`, { key, done });
    S.board = data.board; renderActions(data.board); renderProgress(data.board);
  } catch (e) {
    a.done = !done; renderActions(S.board); renderProgress(S.board);
    say("system", "체크를 저장하지 못했습니다: " + e.message);
  }
}

/* ---------------------------------------------------------------- 문서 */
async function fetchDoc(path) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ state: S.state || "" }) });
  if (!res.ok) throw new Error(await res.text());
  return res;
}
function filenameFrom(res, fallback) {
  const cd = res.headers.get("Content-Disposition") || "";
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) { try { return decodeURIComponent(star[1].trim()); } catch (e) { /* 아래로 */ } }
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return plain ? plain[1].trim() : fallback;
}
async function downloadFile(path, filename) {
  try {
    const res = await fetchDoc(path);
    const blob = new Blob([await res.arrayBuffer()], { type: res.headers.get("Content-Type") || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filenameFrom(res, filename); a.rel = "noopener";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 8000);
  } catch (e) {
    say("system", "다운로드 실패: " + e.message);
  }
}

async function makeDocs() {
  if (S.busy) return;
  setBusy(true, "문서 초안 생성 중…");
  try {
    const data = await withSession(() => post(`/api/${S.sid}/docs`, { defer: true }));
    S.board = data.board; render(data.board);
    say("bot", `문서 ${Object.keys(data.docs || {}).length}종을 만들었습니다. 체크리스트에 완료 표시한 조치가 '현재까지의 대응'에 시각과 함께 들어갑니다. 발송·제출은 사람이 합니다.`);
    setView("3");
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
}

async function previewDoc(id) {
  try {
    const res = await fetchDoc(`/api/${S.sid}/download/${id}`);
    const meta = (S.board.docs || []).find((d) => d.id === id);
    $("modalTitle").textContent = meta ? meta.title : id;
    $("modalTitle").dataset.doc = id;
    $("modalBody").textContent = await res.text();
    $("modal").classList.remove("hidden");
    $("modalClose").focus();
  } catch (e) {
    say("system", "문서를 열지 못했습니다: " + e.message);
  }
}

/* ---------------------------------------------------------------- 가이드 · 차트 */
async function refreshGuide() {
  if (S.busy || !(S.board || {}).category) return;
  if (!S.liner) { say("system", "Liner 키가 없어 규칙 기반 안내만 표시합니다."); return; }
  await runEnrich(["guide"]);
}

async function showViz() {
  if (S.busy) return;
  if (S.viz) { openViz(); return; }
  $("vizBtn").textContent = "차트 생성 중…";
  setBusy(true, "Liner Visualization이 차트를 그리는 중… (20~30초)");
  linerJob(+1);
  try {
    const data = await withSession(() => post(`/api/${S.sid}/viz`, {}));
    S.board = data.board || S.board;
    render(S.board);
    if (data.html) { S.viz = data.html; openViz(); }
    else say("system", "차트를 만들지 못했습니다 — " + ((data.viz || {}).reason || "요약 카드로 대체합니다."));
  } catch (e) {
    say("system", "차트 요청 실패: " + e.message);
  } finally {
    linerJob(-1);
    setBusy(false);
    $("vizBtn").textContent = S.viz ? "차트 다시 보기" : "차트로 보기";
  }
}
function openViz() {
  if (!S.viz) return;
  $("vizFrame").srcdoc = S.viz;
  $("vizTheme").textContent = ((S.board || {}).viz || {}).theme || "Liner Visualization";
  $("vizTitle").textContent = "사건 보드 차트 — " + (((S.board || {}).category || {}).name || "대응 타임라인");
  $("vizModal").classList.remove("hidden");
}

/* ---------------------------------------------------------------- 렌더링 */
function render(b) {
  if (!b) return;
  const c = b.case || {};
  $("caseTitle").textContent = c.title || "사건";
  $("caseMeta").textContent = `${c.id || ""} · 인지 ${c.aware_at || "미확인"} · 로그 ${(b.log_kinds || []).length ? (b.log_kinds || []).length + "종" : "없음"}`;

  const sev = b.severity || {};
  $("sevBadge").textContent = sev.level ? `${sev.level} ${sev.name || ""}${sev.evidence_level ? " · " + sev.evidence_level : ""}` : "—";
  $("sevBadge").className = "sev case-only " + (sev.level ? "sev-" + sev.level : "sev-none");
  const hist = b.severity_history || [];
  $("sevTrail").innerHTML = hist.length > 1
    ? hist.slice(0, -1).map((h) => `<span class="trail" title="${esc(h.at + " · " + h.reason)}">${esc(h.level)}</span>`).join('<span class="arrow">→</span>') + '<span class="arrow">→</span>'
    : "";

  renderMode();
  renderCategoryGrid();
  renderActions(b);
  renderProgress(b);
  renderDeadlines(b);
  renderTimeline(b);
  renderVerdict(b);
  renderFacts(b);
  renderDocs(b);
  renderSources(b);
  renderGuide(b);
  renderViz(b);
  renderLawBadge();
  $("dontdo").innerHTML = (b.dont_do || []).map((d) => `<li>${esc(d)}</li>`).join("") || "<li>사건이 시작되면 금기 행동이 표시됩니다</li>";

  const nOpen = (b.actions || []).filter((a) => !a.done).length;
  setBadge("badgeTab1", nOpen); setBadge("mBadge1", nOpen);
  setBadge("badgeTab2", (b.findings || []).length);
  setBadge("badgeTab3", (b.docs || []).length); setBadge("mBadge3", (b.docs || []).length);
  setBadge("badgeTab4", (b.sources || []).length);
  $("phaseLabel").textContent = b.phase ? `${b.phase.window || ""}${b.phase.elapsed_minutes != null ? " · 인지 후 " + elapsed(b.phase.elapsed_minutes) : ""}` : "";
  tick();
}

function setBadge(id, n) {
  const el = $(id);
  el.textContent = String(n);
  el.classList.toggle("hot", id.endsWith("1") && Number(n) > 0);
}

function renderMode(liner) {
  const b = S.board || {};
  const live = S.liner || (b.api || {}).mode === "liner";
  const pill = $("modePill");
  pill.className = "pill" + (S.linerJobs ? " busy" : live ? " live" : "");
  const last = ((b.api || {}).calls || []).slice(-1)[0];
  if (S.linerJobs) $("modeText").textContent = `Liner 호출 중 · ${S.linerJobs}건`;
  else if (live) $("modeText").textContent = "Liner 연동" + (last ? ` · 최근 ${(last.ms / 1000).toFixed(1)}초` : liner && liner.latency_ms ? ` · ${liner.latency_ms}ms` : "");
  else $("modeText").textContent = "규칙 기반(키 없음)";
  pill.title = live ? "Liner API 연동 — 판정·기한은 규칙 엔진, 문장·근거는 Liner" : "LINER_API_KEY 미설정 — 판정·기한·문서는 규칙 엔진으로 동작";
}

function elapsed(min) {
  if (min < 60) return `${min}분`;
  const h = Math.floor(min / 60), m = min % 60;
  return h < 48 ? `${h}시간 ${m}분` : `${Math.floor(h / 24)}일 ${h % 24}시간`;
}

function renderActions(b) {
  const items = b.actions || [];
  if (!items.length) { $("actions").innerHTML = `<div class="empty">사건을 시작하면 우선순위대로 할 일이 나옵니다.</div>`; return; }
  const groups = [];
  items.forEach((a) => {
    const k = a.kind || "지금";
    let g = groups.find((x) => x.k === k);
    if (!g) { g = { k, items: [] }; groups.push(g); }
    g.items.push(a);
  });
  const label = { "0~10분": "0~10분 · 돈과 계정부터", "15분": "15분 안에 · 확산 막기", "조사": "조사 · 범위 확인", "지금": "지금" };
  $("actions").innerHTML = groups.map((g) => `
    <div class="group-head"><b class="${g.k === "0~10분" || g.k === "지금" ? "urgent" : ""}">${esc(label[g.k] || g.k)}</b>
      <span>${g.items.filter((a) => a.done).length} / ${g.items.length}</span></div>
    ${g.items.map((a) => `
      <label class="act${a.done ? " done" : ""}">
        <input type="checkbox" data-key="${esc(a.key)}" ${a.done ? "checked" : ""} />
        <span class="body">
          <span class="text">${esc(a.action)}</span>
          <span class="meta">${esc(a.who)} · 플레이북 ${esc(a.ref)}${a.done && a.done_at ? ` · <b>완료 ${esc(a.done_at)}</b>` : ""}</span>
        </span>
        <span class="win">${esc(a.kind || "")}</span>
      </label>`).join("")}`).join("");
  $("actions").querySelectorAll("input[data-key]").forEach((cb) => {
    cb.onchange = () => toggleAction(cb.dataset.key, cb.checked);
  });
}

function renderProgress(b) {
  const items = b.actions || [];
  const done = items.filter((a) => a.done).length;
  $("progressText").textContent = `${done} / ${items.length} 완료`;
  $("progressBar").style.width = items.length ? `${Math.round((done / items.length) * 100)}%` : "0";
  const nDocs = (b.docs || []).length;
  $("docsCount").textContent = nDocs ? `${nDocs}종 준비` : "아직 없음";
}

function renderDeadlines(b) {
  const d = b.deadlines || {};
  const items = d.items || [];
  let html = items.map((x) => `
    <div class="ddl">
      <div class="ddl-top"><span class="ddl-title">${esc(x.title)}</span><span class="chip ${esc((x.status || "").replace(/[()\s]/g, ""))}">${esc(x.status)}</span></div>
      <span class="ddl-due" ${x.due_iso && (x.status === "해당" || x.status === "검토") ? `data-due="${esc(x.due_iso)}"` : ""}>${esc(x.due || "마감 미확인")}${x.remaining ? " · " + esc(x.remaining) : ""}</span>
      <span class="ddl-meta">${esc(x.to)}${x.legal_ref ? " · " + esc(x.legal_ref) : ""}</span>
      <span class="ddl-why">${esc(x.why)}</span>
    </div>`).join("") || `<div class="empty">인지 시각과 사실관계가 들어오면 기한이 계산됩니다.</div>`;
  const ops = (d.operational || []).filter((o) => o.triggered);
  if (ops.length) html += `<div class="ops"><b>운영상 연락 · 법정 신고 아님</b>${ops.map((o) => `<span>· ${esc(o.title)} — ${esc(o.how)}</span>`).join("")}</div>`;
  $("deadlines").innerHTML = html;
}

function renderLawBadge() {
  const law = ((S.board || {}).law_checks || [])[0];
  let t = S.liner ? "규칙 엔진 계산" : "규칙 엔진 계산(키 없음)";
  if (S.lawInFlight) t = "Liner 법령 재확인 중…";
  else if (law && law.status === "live") t = (law.drift || []).length ? `Liner 근거 · 차이 ${law.drift.length}건` : "Liner 근거 재확인 · 차이 없음";
  else if (law && law.status === "error") t = "Liner 재확인 실패 · 규칙 기준";
  $("lawBadge").textContent = t;
  $("lawStatus").textContent = law ? (law.status === "live" ? "Search Agent · Search" : "규칙 기반") : "";
}

function renderTimeline(b) {
  const rows = (b.findings || []).slice(0, 60);
  $("timeline").innerHTML = rows.map((f) => `<div class="tl ${f.severity === "critical" ? "crit" : f.severity === "high" ? "high" : ""}">
      <div><div class="t">${f.ts ? esc(f.ts_kst) : "시각 미상"}</div><div class="u">${f.ts ? esc(f.ts.replace("T", " ").slice(0, 16)) + "Z" : "메일 원본 판독"}</div></div>
      <div><span class="r">${esc(f.rule_id)}</span>${esc(f.summary)}</div>
    </div>`).join("") || `<div class="empty">로그를 붙여넣으면 시간순 사건이 여기에 쌓입니다.</div>`;
}

function renderVerdict(b) {
  const c = b.classification || {};
  const sev = b.severity || {};
  const cat = b.category;
  $("verdictLevel").textContent = c.level || "미확인";
  $("verdictLevel").className = "lv " + (c.level || "미확인");
  $("verdict").innerHTML = `
    <span class="big">${esc(c.label || "판별 전")}</span>
    ${cat ? `<span class="meta">10대 유형 ${cat.no}. ${esc(cat.name)}</span>` : ""}
    ${(c.basis || []).length ? `<ul>${c.basis.slice(0, 5).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    ${(c.missing || []).length ? `<span class="meta">모르는 것 · ${esc(c.missing.join(", "))}</span>` : ""}
    <span class="sevline">심각도 <b>${esc(sev.level || "-")} ${esc(sev.name || "")}</b> — ${esc((sev.reasons || [])[0] || "")}</span>
    <span class="meta">경영진 보고 주기 ${esc(sev.next_report || "-")}</span>`;
}

function renderFacts(b) {
  $("facts").innerHTML = (b.facts || []).map((f) => `<div class="fact">
      <span class="k">${esc(f.label)}</span>
      <span class="v">${esc(typeof f.value === "object" ? JSON.stringify(f.value) : f.value)}</span>
      <span class="badge ${esc(f.level)}" title="${esc(f.source || "")}">${esc(f.level)}</span>
    </div>`).join("") || `<div class="empty">아직 기록된 사실이 없습니다.</div>`;
}

function renderDocs(b) {
  const docs = b.docs || [];
  $("docs").innerHTML = docs.map((d) => `<div class="doc">
      <span class="doc-title">${esc(d.title)}<span class="doc-kind">${d.kind === "report" ? "신고·보고" : "통지"}</span></span>
      <span class="doc-tools">
        <button type="button" data-doc="${esc(d.id)}">미리보기</button>
        <button type="button" data-md="${esc(d.id)}">MD</button>
        <button type="button" data-docx="${esc(d.id)}">DOCX</button>
      </span>
    </div>`).join("") || `<div class="empty">[문서 초안 생성]을 누르면 통지문·신고서가 만들어집니다. 모르는 칸은 〔미확인〕으로 남깁니다.</div>`;
  $("zipAll").classList.toggle("hidden", !docs.length);
  $("docs").querySelectorAll("button[data-doc]").forEach((x) => { x.onclick = () => previewDoc(x.dataset.doc); });
  $("docs").querySelectorAll("button[data-md]").forEach((x) => { x.onclick = () => downloadFile(`/api/${S.sid}/download/${x.dataset.md}`, `${x.dataset.md}.md`); });
  $("docs").querySelectorAll("button[data-docx]").forEach((x) => { x.onclick = () => downloadFile(`/api/${S.sid}/download/${x.dataset.docx}.docx`, `${x.dataset.docx}.docx`); });
}

function renderSources(b) {
  const law = (b.law_checks || [])[0];
  let html = "";
  if (law && law.status === "live") {
    html += `<div class="source law"><b>법령 재확인</b> — ${(law.drift || []).length ? "코드 규칙과 차이: " + esc(law.drift.join(" / ")) : "코드 규칙(24h·72h)과 차이 없음"}</div>`;
  }
  html += (b.sources || []).slice(0, 20).map((s) => `<div class="source">
      <a href="${esc(s.url)}" target="_blank" rel="noreferrer">${esc(s.title || s.url)}</a>
      <div class="host">${esc(s.hostname || "")}${s.date ? " · " + esc(s.date) : ""}</div>
    </div>`).join("");
  $("sources").innerHTML = html || `<div class="empty">Liner 검색 근거가 여기에 표시됩니다.</div>`;
}

function renderGuide(b) {
  const cat = b.category;
  const g = b.guide;
  $("guideBtn").disabled = !cat || !S.liner;
  if (!cat) { $("guide").innerHTML = `<span class="g-src">첫 화면에서 사고 유형을 고르면 유형별 즉답 가이드가 나옵니다.</span>`; return; }
  const head = `<span class="g-src">${cat.no}. ${esc(cat.name)} · 기본 ${esc(cat.base_severity)} · ${esc(cat.deadline_focus || "")}</span>`;
  if (!g) { $("guide").innerHTML = head; return; }
  const refs = (g.references || []).map((r) => `<a href="${esc(r.url)}" target="_blank" rel="noreferrer">${esc(r.title || r.hostname || r.url)}</a>`).join(" · ");
  $("guide").innerHTML = head + `<div class="g-answer">${esc(g.answer || "")}</div>
    <span class="g-src">출처: ${g.status === "live" ? "Liner Quick Answer" : "규칙 기반 안내"}${g.status === "error" ? " (호출 실패 — 규칙 기반 안내로 대체)" : ""}</span>
    ${refs ? `<span class="g-src">${refs}</span>` : ""}`;
}

function renderViz(b) {
  const v = b.viz || {};
  if (v.ok) { $("vizInfo").textContent = v.description || "사건 대응 차트가 준비되었습니다."; return; }
  const due = (b.deadlines || {}).next_due;
  $("vizInfo").textContent = (v.reason || (S.liner ? "Liner Visualization API로 이 사건의 0~72시간 대응을 한 장으로 그립니다." : "Liner 키가 없어 차트 대신 72시간 시계를 사용하세요.")) +
    (due ? ` 다음 기한: ${due.title} → ${due.due}` : "");
}

function flashSeverity(before, after, sev) {
  const div = say("system", `심각도 ${before} → ${after} ${sev.name || ""} — ${(sev.reasons || [])[0] || ""}`);
  div.className = "msg sevchange";
  const badge = $("sevBadge");
  badge.classList.remove("pulse"); void badge.offsetWidth; badge.classList.add("pulse");
}

/* ---------------------------------------------------------------- 72시간 시계 */
const SEG_HOURS = [0, 1 / 6, 1, 4, 24, 72];
const SEG_PCT = [0, 8, 18, 32, 58, 100];
function trackPct(h) {
  if (h <= 0) return 0;
  for (let i = 1; i < SEG_HOURS.length; i++) {
    if (h <= SEG_HOURS[i]) return SEG_PCT[i - 1] + ((h - SEG_HOURS[i - 1]) / (SEG_HOURS[i] - SEG_HOURS[i - 1])) * (SEG_PCT[i] - SEG_PCT[i - 1]);
  }
  return 100;
}
function hms(ms) {
  const t = Math.floor(Math.abs(ms) / 1000);
  const d = Math.floor(t / 86400), h = Math.floor((t % 86400) / 3600), m = Math.floor((t % 3600) / 60), s = t % 60;
  const p = (n) => String(n).padStart(2, "0");
  return (d ? `${d}일 ` : "") + `${p(h)}:${p(m)}:${p(s)}`;
}
function tick() {
  const b = S.board;
  if (!b) return;
  const now = Date.now();
  const aware = (b.case || {}).aware_iso ? Date.parse(b.case.aware_iso) : null;
  const items = ((b.deadlines || {}).items || []).filter((x) => x.due_iso && (x.status === "해당" || x.status === "검토"));
  const upcoming = items.map((x) => ({ ...x, t: Date.parse(x.due_iso) })).sort((a, c) => a.t - c.t);
  const overdue = upcoming.filter((x) => x.t <= now && x.status === "해당");
  const next = overdue.length ? overdue[overdue.length - 1] : upcoming.find((x) => x.t > now) || upcoming[upcoming.length - 1];
  const time = $("clockTime");
  if (next) {
    const diff = next.t - now;
    const review = next.status === "검토";
    $("clockLabel").textContent = `${diff < 0 ? "기한 경과 · " : review ? "해당 여부 검토 중인 기한 · " : "다음 법정 기한 · "}${next.title}`;
    time.textContent = (diff < 0 ? "+" : "") + hms(diff);
    time.className = "clock-time" + (diff < 0 && !review ? " over" : review || diff > 48 * 3600e3 ? " calm" : "");
    $("clockDue").textContent = `마감 ${next.due} · ${next.to}${next.status === "검토" ? " · 해당 여부 검토" : ""}`;
  } else {
    const anyNo = ((b.deadlines || {}).items || []).some((x) => x.status === "비해당");
    $("clockLabel").textContent = "다음 법정 기한";
    time.textContent = "--:--:--";
    time.className = "clock-time calm";
    $("clockDue").textContent = !aware ? "인지 시각을 알려 주면 기한이 계산됩니다"
      : anyNo ? "현재 사실로는 신고 대상이 아닙니다(판단은 담당자)" : "사실관계가 더 필요합니다 — 판단 보류";
  }
  document.querySelectorAll("#deadlines [data-due]").forEach((el) => {
    const t = Date.parse(el.dataset.due);
    el.classList.toggle("over", t < now);
  });
  const segs = document.querySelectorAll("#track .seg");
  const labels = document.querySelectorAll("#trackLabels span");
  if (aware) {
    const h = (now - aware) / 3600e3;
    $("nowMarker").style.left = `calc(${trackPct(h)}% - 1px)`;
    $("nowMarker").hidden = false;
    segs.forEach((s, i) => {
      s.classList.toggle("past", h >= SEG_HOURS[i + 1]);
      s.classList.toggle("current", h >= SEG_HOURS[i] && h < SEG_HOURS[i + 1]);
    });
    labels.forEach((s, i) => s.classList.toggle("current", h >= SEG_HOURS[i] && h < SEG_HOURS[i + 1]));
  } else {
    $("nowMarker").hidden = true;
    segs.forEach((s) => s.classList.remove("past", "current"));
    labels.forEach((s) => s.classList.remove("current"));
  }
}

/* ---------------------------------------------------------------- 이벤트 */
document.querySelectorAll(".b-tab").forEach((b) => { b.onclick = () => setView(b.dataset.tab); });
document.querySelectorAll(".m-tab").forEach((b) => { b.onclick = () => setView(b.dataset.tab); });
$("fileInput").addEventListener("change", (e) => { attachFiles(e.target.files); e.target.value = ""; });
$("quickChips").addEventListener("click", (e) => {
  const chip = e.target.closest(".quick");
  if (!chip || S.busy) return;
  $("input").value = chip.dataset.q || "";
  $("input").focus();
});
$("send").onclick = send;
$("input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send(); });
$("startForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = $("startInput").value.trim();
  if (!text) { $("startInput").focus(); return; }
  $("startInput").value = "";
  sendText(text);
});
$("startInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) $("startForm").requestSubmit(); });
$("runScenario").onclick = runScenario;
$("replay").onclick = replay;
$("stopReplay").onclick = () => { S.stopReplay = true; };
$("guideBtn").onclick = refreshGuide;
$("vizBtn").onclick = showViz;
$("makeDocs").onclick = makeDocs;
$("zipAll").onclick = () => downloadFile(`/api/${S.sid}/download/zip`, "ShieldMate72_documents.zip");
$("modalDownload").onclick = () => { const id = $("modalTitle").dataset.doc; if (id) downloadFile(`/api/${S.sid}/download/${id}`, `${id}.md`); };
$("modalDocx").onclick = () => { const id = $("modalTitle").dataset.doc; if (id) downloadFile(`/api/${S.sid}/download/${id}.docx`, `${id}.docx`); };
$("modalCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("modalBody").textContent); $("modalCopy").textContent = "복사됨"; }
  catch (e) { $("modalCopy").textContent = "복사 실패"; }
  setTimeout(() => ($("modalCopy").textContent = "복사"), 1200);
};
const closeModals = () => { $("modal").classList.add("hidden"); $("vizModal").classList.add("hidden"); };
$("modalClose").onclick = closeModals;
$("vizClose").onclick = closeModals;
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModals(); });
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModals(); });
$("vizModal").addEventListener("click", (e) => { if (e.target.id === "vizModal") closeModals(); });
$("newCase").onclick = async () => {
  if (S.busy && !S.replaying) return;
  S.stopReplay = true;
  $("chat").innerHTML = "";
  S.lawInFlight = false;
  await newSession();
  document.body.dataset.viewSet = "";
  setStage("start");
  window.scrollTo({ top: 0 });
};
setInterval(tick, 1000);
init();
