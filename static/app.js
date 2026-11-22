/* 시큐에이드 (SecuAid) — 화면 로직 (프레임워크 없음) · v0.14
   - 판정은 즉시, Liner 문장은 뒤따라: /message(defer) → /enrich(브리핑·가이드·답변) · /law(법령 재확인, 병렬)
   - 상태 토큰(state)을 바꾸는 요청은 한 줄로 세운다(queue) — 동시 요청이 토큰을 갈라놓지 않게.
   - 사건은 탭(sessionStorage)과 이 브라우저(localStorage, 최근 5건)에 보관, 사건 파일(.json)로 옮긴다.
   - 72시간 시계: 인지 시각 기준 구간·다음 법정 기한 카운트다운을 1초마다 갱신.
   - 지금 할 일 체크리스트: 완료 시각이 신고서 '현재까지의 대응'에 들어간다. */
const S = {
  sid: null, state: null, board: null, busy: false, replaying: false, stopReplay: false,
  cats: [], viz: null, lawInFlight: false, liner: false, linerJobs: 0, queue: Promise.resolve(),
  health: null,
};
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const STORE_KEY = "secuaid:v1";
const isMobile = () => window.matchMedia("(max-width: 900px)").matches;

/* ---------------------------------------------------------------- 통신 */
function persist(board) {
  try { if (S.state && S.sid) sessionStorage.setItem(STORE_KEY, JSON.stringify({ sid: S.sid, state: S.state })); }
  catch (e) { /* 저장 공간 부족 — 메모리로 계속 */ }
  const b = board || S.board;
  if (S.state && S.sid && b && hasCase(b)) saveRecent(b);
}

/* v0.12 — 진행 중인 사건: 이 브라우저(localStorage)에 최근 5건 자동 보관 · 창을 닫아도 이어 하기 */
const RECENT_KEY = "secuaid:cases";
const RECENT_MAX = 5;
function loadRecent() {
  try { const v = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); return Array.isArray(v) ? v.filter((x) => x && x.sid && x.state) : []; }
  catch (e) { return []; }
}
function writeRecent(list) {
  for (let n = list.length; n > 0; n--) {
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, n))); return; }
    catch (e) { /* 용량 초과 — 오래된 사건부터 덜어 낸다 */ }
  }
  try { localStorage.removeItem(RECENT_KEY); } catch (e) { /* noop */ }
}
function saveRecent(b) {
  const c = b.case || {};
  const acts = b.actions || [];
  const entry = {
    sid: S.sid, state: S.state, id: c.id || "", title: c.title || "사건", aware: c.aware_at || "",
    sev: (b.severity || {}).level || "", done: acts.filter((a) => a.done).length, total: acts.length,
    updated: new Date().toISOString(),
  };
  writeRecent([entry, ...loadRecent().filter((x) => x.sid !== S.sid && (!entry.id || x.id !== entry.id))].slice(0, RECENT_MAX));
}
function forgetRecent(sid) { writeRecent(loadRecent().filter((x) => x.sid !== sid)); }
function agoLabel(iso) {
  const m = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60000));
  if (!isFinite(m)) return "";
  if (m < 1) return "방금";
  if (m < 60) return `${m}분 전`;
  if (m < 1440) return `${Math.floor(m / 60)}시간 전`;
  return `${Math.floor(m / 1440)}일 전`;
}
function renderRecent() {
  const box = $("recentCases");
  const list = loadRecent();
  if (!list.length) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  box.classList.remove("hidden");
  box.innerHTML = `<div class="recent-head"><b>진행 중인 사건</b><span class="hint">이 브라우저에 자동 보관 · 이어서 하세요</span></div>
    ${list.map((x, i) => `<div class="recent-row">
      <button class="recent-open" type="button" data-i="${i}">
        <span class="sev sev-${esc(x.sev || "none")}">${esc(x.sev || "—")}</span>
        <span class="recent-txt"><b>${esc(x.title)}</b><span>${esc(x.id)} · 인지 ${esc(x.aware || "미확인")} · 할 일 ${x.done}/${x.total} · ${esc(agoLabel(x.updated))} 저장</span></span>
        <span class="recent-go">이어서 하기 →</span>
      </button>
      <button class="btn small recent-del" type="button" data-i="${i}" aria-label="${esc(x.title)} 지우기">지우기</button>
    </div>`).join("")}`;
  box.querySelectorAll(".recent-open").forEach((el) => { el.onclick = () => resumeCase(list[+el.dataset.i]); });
  box.querySelectorAll(".recent-del").forEach((el) => {
    el.onclick = () => {
      const x = list[+el.dataset.i];
      if (!confirm(`'${x.title}' 사건을 이 브라우저에서 지울까요? (내려받은 문서·사건 파일은 남습니다)`)) return;
      forgetRecent(x.sid); renderRecent();
    };
  });
}
async function resumeCase(x, note) {
  if (!x || S.busy) return;
  S.stopReplay = true;
  try {
    S.sid = x.sid; S.state = x.state; S.viz = null; S.evPicked = false; S.evPlatform = null; S.lawInFlight = false;
    const data = await api(`/api/${S.sid}/board`, {});
    if (!hasCase(data.board)) throw new Error("빈 사건");
    $("chat").innerHTML = "";
    S.board = data.board;
    setStage("case");
    render(data.board);
    persist(data.board);
    say("system", note || `'${data.board.case.title}' 사건을 이어서 엽니다. 체크한 일·타임라인·증거 표시가 그대로 있습니다.`);
    window.scrollTo({ top: 0 });
  } catch (e) {
    say("system", "사건을 열지 못했습니다: " + e.message);
    await newSession();
    setStage("start");
  }
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
  if (data.state) { S.state = data.state; persist(data.board); }
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
  const tab = ["1", "2", "3", "4", "5"].includes(String(n)) ? String(n) : "1";
  document.body.dataset.boardTab = tab;
  document.querySelectorAll(".b-tab").forEach((b) => {
    const on = b.dataset.tab === tab;
    b.classList.toggle("is-on", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  ["1", "2", "3", "4", "5"].forEach((k) => { $("tab-" + k).hidden = k !== tab; });
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


/* ---------------------------------------------------------------- 확인이 필요해요 · 지금 가장 먼저 */
function renderAsk(b) {
  const asks = b.asks || [];
  const card = $("askCard");
  if (!asks.length || document.body.dataset.stage !== "case") { card.classList.add("hidden"); return; }
  const a = asks[0];
  card.classList.remove("hidden");
  card.innerHTML = `<div class="ask-head"><b>확인이 필요해요</b><span>${asks.length > 1 ? `${asks.length}개 중 1` : "마지막 질문"}</span></div>
    <p class="ask-q">${esc(a.q)}</p>
    <div class="ask-opts">${(a.options || []).map((o, i) => `<button type="button" class="ask-opt${o.say === "@skip" ? " skip" : ""}" data-i="${i}">${esc(o.label)}</button>`).join("")}</div>`;
  card.querySelectorAll("button[data-i]").forEach((btn) => {
    btn.onclick = () => answerAsk(a, a.options[Number(btn.dataset.i)]);
  });
}

async function answerAsk(a, o) {
  if (S.busy) return;
  if (o.say === "@skip") {
    try { const d = await post(`/api/${S.sid}/ask/skip`, { id: a.id }); S.board = d.board; render(d.board); say("system", "모르는 것으로 두고 넘어갑니다(문서에는 〔미확인〕으로 남습니다)."); }
    catch (e) { say("system", "오류: " + e.message); }
    return;
  }
  if (o.say === "@aware") { openAwareForm(); return; }
  if (o.say === "@domain") { $("input").value = "회사 메일 도메인은 @"; $("input").focus(); return; }
  if (o.say === "@type") { $("input").placeholder = "예) 출근했더니 파일이 열리지 않아요 / 모르는 사람이 우리 메일로 로그인했대요"; $("input").focus(); return; }
  await sendText(o.say);
}

function renderNextCta(b) {
  const box = $("nextCta");
  const acts = b.actions || [];
  if (!acts.length || document.body.dataset.stage !== "case") { box.classList.add("hidden"); return; }
  box.classList.remove("hidden");
  const next = acts.find((x) => !x.done);
  if (!next) {
    const hasDocs = (b.docs || []).length;
    box.innerHTML = `<div class="cta-text"><span class="cta-label ok">초동 조치 완료</span><b>${hasDocs ? "신고서·통지문 초안이 준비돼 있습니다. 검토 후 제출하세요." : "이제 신고서·통지문 초안을 만드세요."}</b></div>
      <div class="cta-btns"><button class="btn dark" type="button" id="ctaDocs">${hasDocs ? "문서 보기" : "문서 초안 만들기"}</button></div>`;
    box.querySelector("#ctaDocs").onclick = () => (hasDocs ? setView("3") : makeDocs());
    return;
  }
  const left = acts.filter((x) => !x.done).length;
  box.innerHTML = `<div class="cta-text"><span class="cta-label">지금 가장 먼저 · ${esc(next.kind || "")}</span><b>${esc(next.action)}</b><span class="cta-who">${esc(next.who)} · 남은 일 ${left}개</span></div>
    <div class="cta-btns"><button class="btn" type="button" id="ctaHow">어떻게 하나요?</button><button class="btn accent" type="button" id="ctaDone">했어요</button><button class="btn" type="button" id="ctaAll">할 일 전체</button></div>`;
  box.querySelector("#ctaHow").onclick = () => openHowto(next.key);
  box.querySelector("#ctaDone").onclick = () => toggleAction(next.key, true);
  box.querySelector("#ctaAll").onclick = () => setView("1");
}

function openAwareForm() {
  $("awareForm").classList.remove("hidden");
  $("awareInput").focus();
}

async function submitAware(when) {
  if (!when) return;
  try {
    const d = await withSession(() => post(`/api/${S.sid}/aware`, { when }));
    S.board = d.board; render(d.board);
    $("awareForm").classList.add("hidden"); $("awareInput").value = "";
    say("system", `인지 시각을 ${d.board.case.aware_at}(으)로 고쳤습니다. 신고 기한이 다시 계산됐습니다.`);
  } catch (e) { say("system", e.message); }
}

/* ---------------------------------------------------------------- 시작 */
async function init() {
  setBoardTab("1");
  try {
    const health = await api("/api/health");
    S.liner = !!(health.liner || {}).available;
    S.health = health.liner || null;
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
  renderRecent();
}

function hasCase(b) {
  if (!b) return false;
  return !!((b.findings || []).length || b.category || (b.case || {}).aware_at !== "미확인" || (b.docs || []).length);
}

async function newSession() {
  S.state = null; S.viz = null; S.evPicked = false; S.evPlatform = null;
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
    if ((data.board.reply || "").includes("[증거 확보]")) setView("5");
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
}

async function handlePending(pending, text = "") {
  const list = pending || [];
  if (list.includes("law")) startLaw();
  const fast = list.filter((t) => ["facts", "narrate", "guide", "answer"].includes(t));
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
    if (data.answer && data.answer.answer) {
      const refs = (data.answer.references || []).map((r) => r.hostname || r.title).filter(Boolean).slice(0, 3).join(", ");
      say("liner", data.answer.answer, { src: `Liner Quick Answer · 질문에 대한 답${refs ? " · 출처 " + refs : ""}` });
    }
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
  S.optimistic = S.optimistic || {};
  S.optimistic[key] = done;                              // 저장이 끝날 때까지 다른 응답이 와도 체크 상태를 유지
  render(S.board);
  try {
    const data = await post(`/api/${S.sid}/action`, { key, done });
    delete S.optimistic[key];
    S.board = data.board; render(data.board);
  } catch (e) {
    delete S.optimistic[key];
    render(S.board);
    say("system", "체크를 저장하지 못했습니다: " + e.message);
  }
}

/* ---------------------------------------------------------------- Liner API 활용 창 (v0.13) */
function renderLinerModal() {
  const b = S.board || {};
  const live = S.liner || (b.api || {}).mode === "liner";
  const h = S.health || {};
  $("linerStatus").innerHTML = `<span class="pill ${live ? "live" : ""} light"><span class="dot"></span>${live ? "Liner 연동 중" : "Liner 키 없음 — 규칙 기반으로 동작"}</span>
    <span>기본 모델 <code>${esc((b.api || {}).model || "liner-mark-1.3")}</code></span>
    ${h.latency_ms ? `<span>연결 확인 ${esc(h.latency_ms)}ms</span>` : ""}`;
}
function openLiner() {
  renderLinerModal();
  $("linerModal").classList.remove("hidden");
  $("linerClose").focus();
}
function linerGo(where) {
  closeModals();
  if (where === "viz") { showViz(); setVizTab("liner"); return; }
  setView(where);
  if (where === "4") $("guide").scrollIntoView({ block: "center" });
  if (where === "side") $("deadlines").scrollIntoView({ block: "center" });
}

/* ---------------------------------------------------------------- 어떻게 하나요? (v0.12) */
function howtoHtml(h) {
  const li = (xs) => xs.map((x) => `<li>${esc(x)}</li>`).join("");
  return `<h4 class="howto-title">${esc(h.title)}</h4>
    ${h.contact ? `<div class="howto-sec contact"><b>어디에 연락</b><p>${esc(h.contact)}</p></div>` : ""}
    ${(h.prepare || []).length ? `<div class="howto-sec"><b>준비할 것</b><ul>${li(h.prepare)}</ul></div>` : ""}
    <div class="howto-sec"><b>순서</b><ol>${li(h.steps || [])}</ol></div>
    ${h.script ? `<div class="howto-sec script"><div class="script-head"><b>전화할 때 이렇게 말하세요</b><button class="btn small" type="button" id="howtoCopy">복사</button></div><p>${esc(h.script)}</p></div>` : ""}
    ${h.caution ? `<div class="howto-sec caution"><b>주의</b><p>${esc(h.caution)}</p></div>` : ""}`;
}
async function openHowto(key) {
  const b = S.board || {};
  const a = (b.actions || []).find((x) => x.key === key);
  if (!a) return;
  S.howtoKey = key;
  $("howtoTitle").textContent = "어떻게 하나요?";
  $("howtoDone").textContent = a.done ? "완료 취소" : "했어요";
  $("howtoModal").classList.remove("hidden");
  const head = `<p class="howto-action">${esc(a.action)}</p>`;
  const h = a.howto && (b.howto || {})[a.howto];
  if (h) {
    $("howtoBody").innerHTML = head + howtoHtml(h);
    $("howtoNote").textContent = "시큐에이드 내장 안내 · 기관·업체 사정에 따라 다를 수 있어요";
  } else {
    S.howtoCache = S.howtoCache || {};
    const cached = S.howtoCache[a.action];
    $("howtoBody").innerHTML = head + (cached || `<div class="howto-loading"><span class="spin" aria-hidden="true"></span>Liner Quick Answer가 이 사건 상황에 맞춰 방법을 찾는 중입니다… 보통 5~15초</div>`);
    $("howtoNote").textContent = "Liner Quick Answer · 출처를 확인하세요";
    if (!cached) {
      linerJob(+1);
      try {
        const r = await withSession(() => api(`/api/${S.sid}/howto`, { action: a.action }));
        const refs = (r.references || []).map((x) => `<li><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.title || x.url)}</a></li>`).join("");
        const html = r.answer
          ? `<div class="howto-sec liner"><b>방법 (Liner)</b><div class="liner-answer">${fmt(r.answer)}</div>${refs ? `<b>출처</b><ul class="refs">${refs}</ul>` : ""}</div>`
          : `<div class="howto-sec caution"><b>안내를 찾지 못했어요</b><p>${esc(r.error || "잠시 후 다시 눌러 보세요.")}</p><p>급하면 KISA 118(무료·24시간)에 이 할 일을 그대로 읽어 주고 상담받으세요.</p></div>`;
        if (r.answer) S.howtoCache[a.action] = html;
        if (S.howtoKey === key) $("howtoBody").innerHTML = head + html;
      } catch (e) {
        if (S.howtoKey === key) $("howtoBody").innerHTML = head + `<div class="howto-sec caution"><b>연결 실패</b><p>${esc(e.message)}</p></div>`;
      } finally { linerJob(-1); }
    }
  }
  const cp = $("howtoBody").querySelector("#howtoCopy");
  if (cp) cp.onclick = async () => {
    try { await navigator.clipboard.writeText(h.script); cp.textContent = "복사됨"; } catch (e) { cp.textContent = "복사 실패"; }
    setTimeout(() => (cp.textContent = "복사"), 1200);
  };
  $("howtoClose").focus();
}

/* ---------------------------------------------------------------- 저장·공유 (v0.12) */
const DEADLINE_ON = (x) => x.due_iso && (x.status === "해당" || x.status === "검토" || x.status === "판단 보류");
const DDL_NOTE = { "검토": "해당 여부 검토", "판단 보류": "대상이면 이 시각까지 — 확인 필요" };
function shareSummary(b) {
  const c = b.case || {}, sev = b.severity || {};
  const acts = b.actions || [];
  const done = acts.filter((a) => a.done);
  const todo = acts.filter((a) => !a.done).slice(0, 3);
  const ddl = ((b.deadlines || {}).items || []).filter(DEADLINE_ON);
  const cut = (t) => (t.length > 60 ? t.slice(0, 58) + "…" : t);
  const lines = [
    `[보안사고 보고] ${c.title || "사건"}`,
    `· 심각도 ${sev.level || "-"} ${sev.name || ""}${sev.evidence_level ? ` (${sev.evidence_level})` : ""}`,
    `· 인지 ${c.aware_at || "미확인"} · 사건번호 ${c.id || "-"}`,
    "",
    `■ 한 일 (${done.length}/${acts.length})`,
    ...(done.length ? done.slice(0, 5).map((a) => `- ${cut(a.action)}${a.done_at && a.done_at !== "저장 중" ? ` (${a.done_at})` : ""}`) : ["- 아직 없음"]),
    "",
    "■ 다음 할 일",
    ...(todo.length ? todo.map((a, i) => `${i + 1}. ${cut(a.action)} — ${a.who}`) : ["- 초동 조치 완료 · 신고서·통지문 검토"]),
  ];
  if (ddl.length) {
    lines.push("", "■ 신고 마감");
    ddl.forEach((x) => lines.push(`- ${x.title}: ${x.due}${x.remaining ? ` (${x.remaining})` : ""}${DDL_NOTE[x.status] ? " · " + DDL_NOTE[x.status] : ""}`));
  }
  lines.push("", "※ 시큐에이드 초안 · 최종 판단은 담당자 · 급하면 KISA 118");
  return lines.join("\n");
}
function icsDate(iso) { return new Date(iso).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, ""); }
function icsText(s) { return String(s || "").replace(/\\/g, "\\\\").replace(/([,;])/g, "\\$1").replace(/\n/g, "\\n"); }
function buildIcs(b) {
  const c = b.case || {};
  const items = ((b.deadlines || {}).items || []).filter(DEADLINE_ON);
  const stamp = icsDate(new Date().toISOString());
  const ev = items.map((x, i) => {
    const end = new Date(Date.parse(x.due_iso) + 30 * 60000).toISOString();
    return ["BEGIN:VEVENT", `UID:${c.id || "case"}-${x.rule_id || i}@secuaid`, `DTSTAMP:${stamp}`,
      `DTSTART:${icsDate(x.due_iso)}`, `DTEND:${icsDate(end)}`,
      `SUMMARY:${icsText(`[마감] ${x.title}${x.status !== "해당" ? `(${x.status})` : ""} — ${c.title || ""}`)}`,
      `DESCRIPTION:${icsText(`제출처: ${x.to}\n근거: ${x.legal_ref || "-"}\n${x.why || ""}\n사건번호 ${c.id || ""} · 시큐에이드 초안 기준(최종 판단은 담당자)`)}`,
      "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:-PT2H", `DESCRIPTION:${icsText(x.title + " 마감 2시간 전")}`, "END:VALARM",
      "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:-PT30M", `DESCRIPTION:${icsText(x.title + " 마감 30분 전")}`, "END:VALARM",
      "END:VEVENT"].join("\r\n");
  });
  return { n: items.length, text: ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//SecuAid//Incident deadlines//KO", "CALSCALE:GREGORIAN", ...ev, "END:VCALENDAR", ""].join("\r\n") };
}
function saveBlob(text, filename, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function openShare() {
  const b = S.board;
  if (!b || !hasCase(b)) return;
  $("shareText").textContent = shareSummary(b);
  const n = buildIcs(b).n;
  $("shareIcs").disabled = !n;
  $("shareIcsNote").textContent = n ? `마감 ${n}건` : "계산된 법정 마감이 아직 없습니다";
  $("shareNative").classList.toggle("hidden", !navigator.share);
  $("shareModal").classList.remove("hidden");
  $("shareClose").focus();
}
function caseFileName(b, ext) {
  const c = (b || {}).case || {};
  return `SecuAid_${c.id || "case"}_${new Date().toISOString().slice(0, 10)}.${ext}`;
}
function exportCase() {
  const b = S.board || {};
  const payload = { format: "secuaid-case", v: 1, exported: new Date().toISOString(), id: (b.case || {}).id, title: (b.case || {}).title, state: S.state };
  saveBlob(JSON.stringify(payload, null, 1), caseFileName(b, "json"), "application/json");
}
async function importCase(file) {
  if (!file) return;
  try {
    if (/\.(csv|eml|log|txt)$/i.test(file.name)) throw new Error("로그·메일 원본은 사건 파일이 아닙니다. 사건을 시작한 뒤 대화창의 [.csv · .eml 첨부]로 넣으세요");
    let j;
    try { j = JSON.parse(await file.text()); } catch (e) { throw new Error("시큐에이드 사건 파일(.json) 형식이 아닙니다"); }
    if (!j || j.format !== "secuaid-case" || !j.state) throw new Error("시큐에이드에서 [사건 파일 저장]으로 받은 .json이 아닙니다");
    const sid = "f" + Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, "0")).join("");
    closeModals();
    await resumeCase({ sid, state: j.state }, `사건 파일을 열었습니다 — '${j.title || "사건"}' (${(j.exported || "").slice(0, 10)} 저장본). 이 브라우저에도 보관됩니다.`);
  } catch (e) {
    alert("사건 파일을 열지 못했습니다: " + e.message);
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
    $("modalDownload").classList.remove("hidden"); $("modalDocx").classList.remove("hidden");
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

/* ---------------------------------------------------------------- 72시간 대응 차트
   기본은 앱이 사건 데이터로 직접 그리는 차트(즉시·결정적). Liner Visualization은 두 번째 탭에서 생성한다. */
function showViz() {
  if (!S.board) return;
  renderChart(S.board);
  setVizTab("native");
  $("vizModal").classList.remove("hidden");
  $("vizClose").focus();
}

function setVizTab(tab) {
  const native = tab === "native";
  $("vizTabNative").classList.toggle("is-on", native);
  $("vizTabLiner").classList.toggle("is-on", !native);
  $("vizTabNative").setAttribute("aria-selected", String(native));
  $("vizTabLiner").setAttribute("aria-selected", String(!native));
  $("chartNative").hidden = !native;
  $("linerPane").hidden = native;
  $("vizPrint").classList.toggle("hidden", !native);
  $("vizTheme").classList.toggle("hidden", !!(native || !S.viz));
  if (native) { $("vizWarn").classList.add("hidden"); $("vizUnsafe").classList.add("hidden"); }
  if (!native) {
    const has = !!S.viz;
    $("vizFrame").hidden = !has;
    $("vizIntro").classList.toggle("hidden", !!(has || S.vizLoading));
    $("vizGenerate").disabled = !S.liner;
    if (!S.liner) $("vizIntro").querySelector("p").textContent = "Liner 키가 없어 AI 시각화를 만들 수 없습니다. 왼쪽 '대응 차트'는 키 없이도 동작합니다.";
  }
}

async function generateLinerViz() {
  if (S.vizLoading) return;
  if (S.viz) { openViz(); return; }
  S.vizLoading = true;
  $("vizIntro").classList.add("hidden");
  $("vizLoading").classList.remove("hidden");
  const t0 = performance.now();
  const timer = setInterval(() => {
    $("vizLoadingText").textContent = `Liner Visualization이 이 사건의 차트를 그리는 중입니다… ${Math.round((performance.now() - t0) / 1000)}초 (보통 10~20초)`;
  }, 1000);
  linerJob(+1);
  try {
    const data = await withSession(() => post(`/api/${S.sid}/viz`, {}));
    S.board = data.board || S.board;
    render(S.board);
    if (data.html) { S.viz = data.html; openViz(); }
    else {
      $("vizIntro").classList.remove("hidden");
      $("vizIntro").querySelector("p").textContent = "차트를 만들지 못했습니다 — " + ((data.viz || {}).reason || "잠시 뒤 다시 시도해 주세요.");
    }
  } catch (e) {
    $("vizIntro").classList.remove("hidden");
    $("vizIntro").querySelector("p").textContent = "Liner 시각화 요청 실패: " + e.message;
  } finally {
    clearInterval(timer);
    S.vizLoading = false;
    $("vizLoading").classList.add("hidden");
    linerJob(-1);
  }
}

const PHASES = [
  { k: "pre", label: "인지 전", sub: "공격 경과" },
  { k: 0, label: "0~10분", sub: "돈과 계정부터" },
  { k: 1, label: "10~60분", sub: "확산 막기" },
  { k: 2, label: "1~4시간", sub: "범위 확인" },
  { k: 3, label: "4~24시간", sub: "침해사고 신고" },
  { k: 4, label: "24~72시간", sub: "개인정보 신고·통지" },
];
const KIND_PHASE = { "지금": 0, "0~10분": 0, "15분": 1, "조사": 2 };

function phaseOfHours(h) {
  if (h < 0) return "pre";
  for (let i = 0; i < 5; i++) if (h < SEG_HOURS[i + 1]) return i;
  return 4;
}
function kstShort(ms) {
  const k = new Date(ms + 9 * 3600e3);
  const p = (n) => String(n).padStart(2, "0");
  return `${k.getUTCMonth() + 1}/${k.getUTCDate()} ${p(k.getUTCHours())}:${p(k.getUTCMinutes())}`;
}

function renderChart(b) {
  const c = b.case || {};
  const aware = c.aware_iso ? Date.parse(c.aware_iso) : null;
  const now = Date.now();
  const hNow = aware ? (now - aware) / 3600e3 : null;
  const cur = hNow == null ? null : phaseOfHours(hNow);
  const cols = {};
  PHASES.forEach((p) => { cols[p.k] = { find: [], act: [], due: [], ops: [], docs: [] }; });

  (b.findings || []).forEach((f) => {
    if (!f.ts || !aware) { cols.pre.find.push(f); return; }
    cols[phaseOfHours((Date.parse(f.ts) - aware) / 3600e3)].find.push(f);
  });
  (b.events || []).forEach((e) => {
    const f = { ts: e.ts, ts_kst: e.ts ? kstShort(Date.parse(e.ts)) : "", summary: "[진술] " + e.what, severity: "info" };
    if (!e.ts || !aware) { cols.pre.find.push(f); return; }
    cols[phaseOfHours((Date.parse(e.ts) - aware) / 3600e3)].find.push(f);
  });
  (b.actions || []).forEach((a) => cols[KIND_PHASE[a.kind] ?? 0].act.push(a));
  ((b.deadlines || {}).items || []).forEach((d) => {
    if (d.status === "비해당") return;
    const hours = d.due_iso && aware ? (Date.parse(d.due_iso) - aware) / 3600e3 - 0.001 : (d.rule_id === "R_INTRUSION_REPORT" ? 23.9 : 71.9);
    cols[phaseOfHours(hours)].due.push(d);
  });
  ((b.deadlines || {}).operational || []).filter((o) => o.triggered).forEach((o) => cols[0].ops.push(o));
  cols[3].docs = b.docs || [];

  const sev = b.severity || {};
  const acts = b.actions || [];
  const done = acts.filter((a) => a.done).length;
  const next = (b.deadlines || {}).next_due;
  const head = `
    <div class="ch-summary">
      <div class="ch-title"><span class="sev sev-${esc(sev.level || "none")}">${esc(sev.level || "—")} ${esc(sev.name || "")}</span>
        <b>${esc(c.title || "사건")}</b></div>
      <div class="ch-kpis">
        <span><em>인지</em>${esc(c.aware_at || "미확인")}</span>
        <span><em>경과</em>${hNow == null ? "—" : elapsed(Math.max(0, Math.round(hNow * 60)))}</span>
        <span><em>초동 조치</em>${done} / ${acts.length}</span>
        <span><em>다음 기한</em>${next ? esc(next.title) + " · " + esc(next.due) : "판단 보류"}</span>
      </div>
    </div>`;

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const colHtml = PHASES.map((p) => {
    const col = cols[p.k];
    const isCur = cur === p.k;
    const isPast = cur != null && p.k !== "pre" && cur !== "pre" && p.k < cur;
    let range = "";
    if (aware && p.k !== "pre") range = `${kstShort(aware + SEG_HOURS[p.k] * 3600e3)} ~ ${kstShort(aware + SEG_HOURS[p.k + 1] * 3600e3)}`;
    else if (p.k === "pre" && aware) range = `~ ${kstShort(aware)}`;
    const blocks = [];
    if (col.find.length) {
      const top = col.find.slice().sort((x, y) => (severityOrder[x.severity] ?? 5) - (severityOrder[y.severity] ?? 5)).slice(0, 5)
        .sort((x, y) => String(x.ts).localeCompare(String(y.ts)));
      blocks.push(`<div class="ch-lane"><div class="ch-lane-h">탐지 ${col.find.length}건</div>${top.map((f) => `
        <div class="ch-find ${f.severity === "critical" ? "crit" : ""}"><span class="t">${f.ts ? esc(String(f.ts_kst || "").replace(/^\d{4}-/, "").replace(" KST", "")) : "시각 미상"}</span>${esc(f.summary)}</div>`).join("")}
        ${col.find.length > top.length ? `<div class="ch-more">외 ${col.find.length - top.length}건 · 타임라인 탭</div>` : ""}</div>`);
    }
    if (col.act.length) {
      blocks.push(`<div class="ch-lane"><div class="ch-lane-h">할 일 ${col.act.filter((a) => a.done).length}/${col.act.length}</div>${col.act.map((a) => `
        <div class="ch-act ${a.done ? "done" : ""}"><span class="box" aria-hidden="true">${a.done ? "✓" : ""}</span><span>${esc(a.action)}<small>${esc(a.who)}${a.done && a.done_at ? " · 완료 " + esc(a.done_at) : ""}</small></span></div>`).join("")}</div>`);
    }
    if (col.ops.length) {
      blocks.push(`<div class="ch-lane"><div class="ch-lane-h">즉시 연락</div>${col.ops.map((o) => `<div class="ch-op">${esc(o.title)}</div>`).join("")}</div>`);
    }
    if (col.due.length) {
      blocks.push(col.due.map((d) => {
        const over = d.due_iso && Date.parse(d.due_iso) < now;
        return `<div class="ch-due ${esc(d.status)}${over ? " over" : ""}"><div class="ch-due-top"><b>${esc(d.title)}</b><span class="chip ${esc(d.status.replace(/[()\s]/g, ""))}">${esc(d.status)}</span></div>
          <span class="mono">${esc(d.due || "마감 미확인")}${over ? " · 경과" : ""}</span><small>${esc(d.to)}</small></div>`;
      }).join(""));
    }
    if (p.k === 3) {
      blocks.push(col.docs.length
        ? `<div class="ch-lane"><div class="ch-lane-h">문서 초안 ${col.docs.length}종</div><div class="ch-op">신고서·통지문 준비됨 — 발송은 담당자</div></div>`
        : `<div class="ch-lane muted"><div class="ch-lane-h">문서 초안</div><div class="ch-op">아직 생성 전 — [문서] 탭</div></div>`);
    }
    return `<section class="ch-col${isCur ? " cur" : ""}${isPast ? " past" : ""}${p.k === "pre" ? " pre" : ""}">
      <header><div><b>${p.label}</b>${isCur ? '<span class="now-tag">지금</span>' : ""}</div><span>${p.sub}</span>${range ? `<span class="mono">${range}</span>` : ""}</header>
      ${blocks.join("") || '<div class="ch-empty">해당 없음</div>'}</section>`;
  }).join("");
  $("chartNative").innerHTML = head + `<div class="ch-scroll"><div class="ch-grid">${colHtml}</div></div>
    <p class="ch-foot">규칙 엔진 결과로 그린 차트입니다(같은 입력이면 같은 결과). 시각은 KST, 구간은 인지 시각 기준입니다.</p>`;
}

/* 차트는 Liner가 만든 외부 HTML이다. 기본은 격리(sandbox="allow-scripts", 고유 출처 없음)로 띄워
   이 화면의 상태 토큰·세션 저장소에 닿지 못하게 한다. 격리 상태에서 흔히 깨지는 저장소·쿠키 접근은
   메모리 대체물로 바꾸고, 그려졌는지 여부를 부모에게 알려 준다. 실패할 때만 사용자가 직접 격리를 해제한다. */
const VIZ_SHIM = `<script>(function(){
function M(){var d={};return{getItem:function(k){return Object.prototype.hasOwnProperty.call(d,k)?d[k]:null},setItem:function(k,v){d[k]=String(v)},removeItem:function(k){delete d[k]},clear:function(){d={}},key:function(i){return Object.keys(d)[i]||null},get length(){return Object.keys(d).length}}}
["localStorage","sessionStorage"].forEach(function(n){try{window[n].getItem("_")}catch(e){try{Object.defineProperty(window,n,{value:M(),configurable:true})}catch(_){}}});
try{document.cookie}catch(e){try{Object.defineProperty(document,"cookie",{get:function(){return""},set:function(){},configurable:true})}catch(_){}}
var errs=[];window.addEventListener("error",function(ev){errs.push(String(ev.message||"error").slice(0,120))});
window.addEventListener("load",function(){setTimeout(function(){var b=document.body;
parent.postMessage({type:"secuaid-viz",errors:errs.slice(0,3),text:b?b.innerText.trim().length:0,
nodes:b?b.querySelectorAll("svg,canvas,table,img").length:0},"*")},1500)});
})();<\/script>`;

function vizDoc(html) {
  const m = /<head[^>]*>/i.exec(html);
  return m ? html.slice(0, m.index + m[0].length) + VIZ_SHIM + html.slice(m.index + m[0].length) : VIZ_SHIM + html;
}

function setVizIsolation(isolated) {
  $("vizFrame").setAttribute("sandbox", isolated ? "allow-scripts" : "allow-scripts allow-same-origin");
  $("vizWarn").classList.add("hidden");
  $("vizUnsafe").classList.add("hidden");
}

window.addEventListener("message", (e) => {
  if (e.source !== $("vizFrame").contentWindow || !e.data || e.data.type !== "secuaid-viz") return;
  const broken = (e.data.errors || []).length > 0 || (!e.data.text && !e.data.nodes);
  if (broken && $("vizFrame").getAttribute("sandbox") === "allow-scripts") {
    $("vizWarn").textContent = "격리 상태에서 차트가 제대로 그려지지 않았습니다" + ((e.data.errors || [])[0] ? ` (${e.data.errors[0]})` : "");
    $("vizWarn").classList.remove("hidden");
    $("vizUnsafe").classList.remove("hidden");
  }
});

function openViz() {
  if (!S.viz) return;
  setVizIsolation(true);
  $("vizFrame").srcdoc = vizDoc(S.viz);
  $("vizTheme").textContent = "Liner " + (((S.board || {}).viz || {}).theme || "Visualization");
  setVizTab("liner");
  $("vizModal").classList.remove("hidden");
}

/* ---------------------------------------------------------------- 렌더링 */
function render(b) {
  if (!b) return;
  if (S.optimistic) {
    (b.actions || []).forEach((a) => {
      if (a.key in S.optimistic) { a.done = S.optimistic[a.key]; a.done_at = a.done ? (a.done_at || "저장 중") : null; }
    });
  }
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
  renderAsk(b);
  renderNextCta(b);
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
  setBadge("badgeTab2", (b.findings || []).length + (b.events || []).length);
  setBadge("badgeTab3", (b.docs || []).length); setBadge("mBadge3", (b.docs || []).length);
  setBadge("badgeTab4", (b.sources || []).length);
  const ev = b.evidence || {};
  setBadge("badgeTab5", ev.have || 0);
  renderEvidence(b);
  $("phaseLabel").textContent = b.phase ? `${b.phase.window || ""}${b.phase.elapsed_minutes != null ? " · 인지 후 " + elapsed(b.phase.elapsed_minutes) : ""}` : "";
  tick();
  if (!$("vizModal").classList.contains("hidden") && !$("chartNative").hidden) renderChart(b);
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
  pill.className = "pill pill-btn" + (S.linerJobs ? " busy" : live ? " live" : "");
  const last = ((b.api || {}).calls || []).slice(-1)[0];
  if (S.linerJobs) $("modeText").textContent = `Liner 호출 중 · ${S.linerJobs}건`;
  else if (live) $("modeText").textContent = "Liner 연동" + (last ? ` · 최근 ${(last.ms / 1000).toFixed(1)}초` : liner && liner.latency_ms ? ` · ${liner.latency_ms}ms` : "");
  else $("modeText").textContent = "규칙 기반(키 없음)";
  pill.title = (live ? "Liner API 연동 — 판정·기한은 규칙 엔진, 문장·근거는 Liner" : "LINER_API_KEY 미설정 — 판정·기한·문서는 규칙 엔진으로 동작") + " · 눌러서 Liner API 활용 보기";
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
        <button class="how-btn" type="button" data-how="${esc(a.key)}" title="준비물 · 순서 · 전화할 때 할 말">어떻게?</button>
        <span class="win">${esc(a.kind || "")}</span>
      </label>`).join("")}`).join("");
  $("actions").querySelectorAll("input[data-key]").forEach((cb) => {
    cb.onchange = () => toggleAction(cb.dataset.key, cb.checked);
  });
  $("actions").querySelectorAll("button[data-how]").forEach((bt) => {
    bt.onclick = (e) => { e.preventDefault(); e.stopPropagation(); openHowto(bt.dataset.how); };
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
  const rows = (b.findings || []).map((f) => ({ ts: f.ts, kst: f.ts_kst, kind: "log", f }))
    .concat((b.events || []).map((e) => ({ ts: e.ts, kind: "event", e })));
  rows.sort((x, y) => String(x.ts || "9999").localeCompare(String(y.ts || "9999")));
  $("timeline").innerHTML = rows.slice(0, 80).map((r) => {
    if (r.kind === "event") {
      const e = r.e;
      const when = e.ts ? kstShort(Date.parse(e.ts)) : "시각 미상";
      return `<div class="tl ev">
        <div><div class="t">${esc(when)}</div><div class="u">${esc(e.source || "진술")}</div></div>
        <div class="tl-ev"><span class="r">진술 · ${esc(e.level || "추정")}</span>${esc(e.what)}
          <button class="link-btn" type="button" data-del="${esc(e.id)}" aria-label="이 기록 삭제">삭제</button></div>
      </div>`;
    }
    const f = r.f;
    return `<div class="tl ${f.severity === "critical" ? "crit" : f.severity === "high" ? "high" : ""}">
      <div><div class="t">${f.ts ? esc(f.ts_kst) : "시각 미상"}</div><div class="u">${f.ts ? esc(f.ts.replace("T", " ").slice(0, 16)) + "Z" : "메일 원본 판독"}</div></div>
      <div><span class="r">${esc(f.rule_id)}</span>${esc(f.summary)}</div>
    </div>`;
  }).join("") || `<div class="empty">로그가 없어도 괜찮습니다. 위 '기억나는 일 추가'에 본 것과 시각을 적거나, 대화창에 "오늘 아침 8시 반에 발견했어요"처럼 말하면 여기에 쌓입니다.</div>`;
  $("timeline").querySelectorAll("button[data-del]").forEach((btn) => {
    btn.onclick = async () => {
      try { const d = await post(`/api/${S.sid}/event/delete`, { id: btn.dataset.del }); S.board = d.board; render(d.board); }
      catch (e) { say("system", "삭제하지 못했습니다: " + e.message); }
    };
  });
}

/* ---------------------------------------------------------------- 증거 확보 도우미 */
function renderEvidence(b) {
  const ev = b.evidence;
  if (!ev) return;
  $("evCount").textContent = `확보 ${ev.have} · 못 구함 ${ev.cannot}`;
  $("evCaveat").textContent = ev.caveat || "";
  $("evAlways").innerHTML = (ev.always || []).map(evItemHtml).join("");
  const plats = ev.platforms || [];
  // 사용자가 직접 고르기 전에는 사건에 맞는 추천 환경(맨 앞)을 따라간다
  if (!S.evPicked || !plats.some((p) => p.id === S.evPlatform)) S.evPlatform = (plats[0] || {}).id;
  $("evPlatforms").innerHTML = plats.map((p) => `<button type="button" role="tab" class="ev-pf${p.id === S.evPlatform ? " is-on" : ""}${p.recommended ? " rec" : ""}" data-pf="${esc(p.id)}">${esc(p.name.split("(")[0])}${p.recommended ? '<span class="rec-dot" title="이 사건에 맞는 환경"></span>' : ""}</button>`).join("");
  const p = plats.find((x) => x.id === S.evPlatform);
  $("evPlatform").innerHTML = p ? `
    <div class="ev-pf-head"><div><b>${esc(p.name)}</b><span class="hint">할 수 있는 사람: ${esc(p.who)}</span></div>
      <div class="ev-pf-tools">
        <button class="btn small" type="button" data-req="${esc(p.id)}">업체에 보낼 요청 메일 초안</button>
        <button class="btn small" type="button" data-search="${esc(p.id)}" ${S.liner ? "" : "disabled"}>공식 안내 찾기 (Liner)</button>
      </div></div>
    <div class="ev-items">${p.items.map(evItemHtml).join("")}</div>
    <div id="evSearch" class="ev-search"></div>` : "";
  $("evPlatforms").querySelectorAll("button[data-pf]").forEach((x) => { x.onclick = () => { S.evPlatform = x.dataset.pf; S.evPicked = true; renderEvidence(S.board); }; });
  document.querySelectorAll("#tab-5 button[data-ev]").forEach((x) => { x.onclick = () => setEvidence(x.dataset.ev, x.dataset.st); });
  const rq = document.querySelector("#tab-5 button[data-req]"); if (rq) rq.onclick = () => showRequestLetter(rq.dataset.req);
  const sr = document.querySelector("#tab-5 button[data-search]"); if (sr) sr.onclick = () => searchOfficial(sr.dataset.search);
}

function evItemHtml(i) {
  const st = i.status || "";
  return `<details class="ev-item ${st}"${st ? "" : " open"}>
    <summary><span class="ev-title">${esc(i.title)}</span>
      <span class="ev-state">${st === "have" ? "확보함" : st === "cannot" ? "못 구함" : ""}</span></summary>
    <p class="ev-why">${esc(i.why)}</p>
    ${(i.how || []).length ? `<ol class="ev-how">${i.how.map((h) => `<li>${esc(h)}</li>`).join("")}</ol>` : ""}
    ${i.retention ? `<p class="ev-ret">보관 기간: ${esc(i.retention)}</p>` : ""}
    ${i.fallback ? `<p class="ev-fb">못 구하면: ${esc(i.fallback)}</p>` : ""}
    <div class="ev-btns">
      <button class="btn small${st === "have" ? " dark" : ""}" type="button" data-ev="${esc(i.id)}" data-st="${st === "have" ? "" : "have"}">확보함</button>
      <button class="btn small${st === "cannot" ? " dark" : ""}" type="button" data-ev="${esc(i.id)}" data-st="${st === "cannot" ? "" : "cannot"}">못 구함</button>
    </div>
  </details>`;
}

async function setEvidence(item, status) {
  try { const d = await post(`/api/${S.sid}/evidence`, { item, status }); S.board = d.board; render(d.board); }
  catch (e) { say("system", "저장하지 못했습니다: " + e.message); }
}

async function showRequestLetter(platform) {
  try {
    const d = await api(`/api/${S.sid}/evidence/request`, { platform });
    const l = d.letter;
    $("modalTitle").textContent = "업체에 보낼 로그 보존·제공 요청 (초안)";
    $("modalTitle").dataset.doc = "";
    $("modalBody").textContent = `받는 곳: ${l.to}\n제목: ${l.subject}\n\n${l.body}\n※ ${l.note}`;
    $("modalDownload").classList.add("hidden"); $("modalDocx").classList.add("hidden");
    $("modal").classList.remove("hidden");
  } catch (e) { say("system", "초안을 만들지 못했습니다: " + e.message); }
}

async function searchOfficial(platform) {
  const box = document.querySelector("#evSearch");
  box.innerHTML = `<div class="hint"><span class="spin" aria-hidden="true"></span> Liner Search로 공식 안내를 찾는 중…</div>`;
  linerJob(+1);
  try {
    const d = await api(`/api/${S.sid}/evidence/search`, { platform });
    box.innerHTML = (d.results || []).length
      ? `<div class="lbl">Liner Search · ${esc(d.query)}</div>` + d.results.map((r) => `<div class="source"><a href="${esc(r.url)}" target="_blank" rel="noreferrer">${esc(r.title || r.url)}</a><div class="host">${esc(r.hostname || "")}</div></div>`).join("")
      : `<div class="hint">${esc(d.error || "찾은 안내가 없습니다. 업체 고객센터에 요청 메일을 보내세요.")}</div>`;
  } catch (e) { box.innerHTML = `<div class="hint">검색 실패: ${esc(e.message)}</div>`; }
  finally { linerJob(-1); }
}

async function addEvent(e) {
  e.preventDefault();
  const what = $("evWhat").value.trim();
  if (!what) { $("evWhat").focus(); return; }
  try {
    const d = await withSession(() => post(`/api/${S.sid}/event`, { when: $("evWhen").value.trim(), what, discovery: $("evDiscovery").checked }));
    $("evWhat").value = ""; $("evWhen").value = ""; $("evDiscovery").checked = false;
    setStage("case");
    S.board = d.board; render(d.board);
  } catch (err) { say("system", "기록하지 못했습니다: " + err.message); }
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
    ${(c.missing || []).length ? `<span class="meta">모르는 것 · ${esc(c.missing.join(", "))}</span>
      <button class="btn small ev-open" type="button" onclick="setView('5')">로그를 못 구하겠다면 → 증거 확보 도우미</button>` : ""}
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
  const pend = docs.length ? (b.docs_pending || []) : [];
  if (pend.length) {
    $("docs").insertAdjacentHTML("beforeend", `<div class="docs-pending"><b>이 사건에 해당하는 문서만 만듭니다 — 아직 없는 문서</b>
      <ul>${pend.map((p) => `<li><span>${esc(p.title)}</span> — ${esc(p.why)}</li>`).join("")}</ul>
      <span class="hint">사실이 확인되면 [문서 초안 생성]을 다시 누르세요.</span></div>`);
  }
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
  const done = (b.actions || []).filter((a) => a.done).length;
  $("vizInfo").textContent = `인지 전 공격 경과부터 0~10분 · 10~60분 · 1~4시간 · 4~24시간 · 24~72시간까지, 할 일(${done}/${(b.actions || []).length} 완료)과 법정 기한을 한 장에 정리합니다. Liner AI 시각화는 차트 창의 두 번째 탭에서 만들 수 있습니다.`;
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
    // 신고 대상이 아직 '판단 보류'여도 시계는 멈추지 않는다 — 대상이라면 가장 이른 마감까지를 센다.
    const pending = ((b.deadlines || {}).items || []).filter((x) => x.due_iso && x.status === "판단 보류")
      .map((x) => ({ ...x, t: Date.parse(x.due_iso) })).sort((a, c) => a.t - c.t);
    const soon = pending.find((x) => x.t > now) || pending[pending.length - 1];
    const anyNo = ((b.deadlines || {}).items || []).some((x) => x.status === "비해당");
    if (soon) {
      const diff = soon.t - now;
      $("clockLabel").textContent = `신고 대상이라면 마감까지 · ${soon.title}`;
      time.textContent = (diff < 0 ? "+" : "") + hms(diff);
      time.className = "clock-time calm";
      $("clockDue").textContent = `마감 ${soon.due} · 해당 여부는 '확인이 필요해요' 질문에 답하면 정해집니다`;
    } else if (aware) {
      $("clockLabel").textContent = anyNo ? "신고 대상 아님(현재 판단) · 인지 후 경과" : "인지 후 경과";
      time.textContent = hms(now - aware);
      time.className = "clock-time calm";
      $("clockDue").textContent = anyNo ? "현재 사실로는 법정 신고 대상이 아닙니다(최종 판단은 담당자)" : "사실관계가 더 필요합니다 — 판단 보류";
    } else {
      $("clockLabel").textContent = "다음 법정 기한";
      time.textContent = "--:--:--";
      time.className = "clock-time calm";
      $("clockDue").textContent = "사건을 시작하면 바로 시계가 돕니다";
    }
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
$("zipAll").onclick = () => downloadFile(`/api/${S.sid}/download/zip`, "SecuAid_documents.zip");
$("modalDownload").onclick = () => { const id = $("modalTitle").dataset.doc; if (id) downloadFile(`/api/${S.sid}/download/${id}`, `${id}.md`); };
$("modalDocx").onclick = () => { const id = $("modalTitle").dataset.doc; if (id) downloadFile(`/api/${S.sid}/download/${id}.docx`, `${id}.docx`); };
$("modalCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("modalBody").textContent); $("modalCopy").textContent = "복사됨"; }
  catch (e) { $("modalCopy").textContent = "복사 실패"; }
  setTimeout(() => ($("modalCopy").textContent = "복사"), 1200);
};
const closeModals = () => { ["modal", "vizModal", "helpModal", "howtoModal", "shareModal", "linerModal", "archModal"].forEach((id) => $(id).classList.add("hidden")); };
$("modalClose").onclick = closeModals;
$("vizClose").onclick = closeModals;
$("chartBtn").onclick = showViz;
$("eventForm").addEventListener("submit", addEvent);
$("awareEdit").onclick = () => $("awareForm").classList.toggle("hidden");
$("awareForm").addEventListener("submit", (e) => { e.preventDefault(); submitAware($("awareInput").value.trim()); });
$("awareForm").querySelectorAll("button[data-when]").forEach((b) => { b.onclick = () => submitAware(b.dataset.when); });
const openHelp = () => { $("helpModal").classList.remove("hidden"); $("helpClose").focus(); };
$("helpBtn").onclick = openHelp;
$("howtoMore").onclick = openHelp;
$("helpClose").onclick = () => $("helpModal").classList.add("hidden");
$("helpModal").addEventListener("click", (e) => { if (e.target.id === "helpModal") $("helpModal").classList.add("hidden"); });
$("vizTabNative").onclick = () => setVizTab("native");
$("vizTabLiner").onclick = () => { setVizTab("liner"); if (S.viz) openViz(); };
$("vizGenerate").onclick = generateLinerViz;
$("vizPrint").onclick = () => { document.body.classList.add("print-chart"); window.print(); setTimeout(() => document.body.classList.remove("print-chart"), 500); };
$("vizUnsafe").onclick = () => {
  if (!S.viz) return;
  setVizIsolation(false);
  $("vizFrame").srcdoc = vizDoc(S.viz);
};
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
  renderRecent();
  window.scrollTo({ top: 0 });
};
$("modePill").onclick = openLiner;
const openArch = () => { closeModals(); $("archModal").classList.remove("hidden"); $("archClose").focus(); };
$("archOpen").onclick = openArch;
$("archFromHelp").onclick = openArch;
$("archClose").onclick = closeModals;
$("archModal").addEventListener("click", (e) => { if (e.target.id === "archModal") closeModals(); });
$("linerClose").onclick = closeModals;
$("linerModal").addEventListener("click", (e) => { if (e.target.id === "linerModal") closeModals(); });
document.querySelectorAll("#linerModal .api-go").forEach((bt) => { bt.onclick = () => linerGo(bt.dataset.go); });
$("howtoClose").onclick = closeModals;
$("howtoDone").onclick = () => {
  const a = ((S.board || {}).actions || []).find((x) => x.key === S.howtoKey);
  closeModals();
  if (a) toggleAction(a.key, !a.done);
};
$("howtoModal").addEventListener("click", (e) => { if (e.target.id === "howtoModal") closeModals(); });
$("shareBtn").onclick = openShare;
$("shareClose").onclick = closeModals;
$("shareModal").addEventListener("click", (e) => { if (e.target.id === "shareModal") closeModals(); });
$("shareCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("shareText").textContent); $("shareCopy").textContent = "복사됨 — 카톡에 붙여넣기"; }
  catch (e) { $("shareCopy").textContent = "복사 실패 — 글을 길게 눌러 복사"; }
  setTimeout(() => ($("shareCopy").textContent = "요약 복사"), 1800);
};
$("shareNative").onclick = async () => { try { await navigator.share({ title: "보안사고 보고", text: $("shareText").textContent }); } catch (e) { /* 취소 */ } };
$("shareIcs").onclick = () => { const b = S.board; if (b) saveBlob(buildIcs(b).text, caseFileName(b, "ics"), "text/calendar;charset=utf-8"); };
$("shareSave").onclick = exportCase;
$("shareForget").onclick = () => {
  if (!confirm("이 사건을 이 브라우저에서 지울까요? 화면은 첫 화면으로 돌아갑니다. (내려받은 파일은 남습니다)")) return;
  forgetRecent(S.sid);
  closeModals();
  $("newCase").click();
};
$("caseFileInput").addEventListener("change", (e) => { importCase(e.target.files[0]); e.target.value = ""; });
document.querySelector(".brand").addEventListener("click", (e) => {
  // 로고 = 첫 화면. 지금 사건은 '진행 중인 사건'에 남아 있어 언제든 이어 한다(모바일에서는 [새 사건] 버튼 대신).
  if (document.body.dataset.stage !== "case") return;
  e.preventDefault();
  $("newCase").click();
});
window.addEventListener("beforeunload", (e) => {
  // 체크 저장이 Liner 응답 뒤에 줄 서 있는 동안 창을 닫으면 그 체크가 사라진다 — 한 번 묻는다.
  if (S.optimistic && Object.keys(S.optimistic).length) { e.preventDefault(); e.returnValue = ""; }
});
setInterval(tick, 1000);
init();
