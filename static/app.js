/* 인시던트 노트 — 화면 로직 (의존성 없음) */
const S = { sid: null, board: null, busy: false, replaying: false, stopReplay: false };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

function setBusy(on, msg = "") {
  S.busy = on;
  $("send").disabled = on;
  $("runScenario").disabled = on;
  $("makeDocs").disabled = on;
  $("replay").textContent = S.replaying ? "■ 재생 정지" : "▶ 단계별 재생";
  $("typing").textContent = on ? msg || "처리 중…" : "";
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
      : "LINER_API_KEY 미설정 — .env에 키를 넣으면 해석·근거 검색이 켜집니다";
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
  await newSession();
  say("system", "사건을 시작하려면 상황을 설명하거나, 데모 시나리오를 선택해 [시나리오 실행]을 누르세요.");
}

async function newSession() {
  const data = await api("/api/session", { method: "POST", body: JSON.stringify({}) });
  S.sid = data.session;
  S.board = data.board;
  render(data.board);
  return data;
}

function ensureSession() {
  if (!S.sid) return newSession();
}

async function send() {
  const text = $("input").value.trim();
  if (!text || S.busy) return;
  $("input").value = "";
  say("user", text);
  await ensureSession();
  setBusy(true, "로그·메일 판독 중…");
  try {
    const data = await api(`/api/${S.sid}/message`, { method: "POST", body: JSON.stringify({ text }) });
    S.board = data.board;
    render(data.board);
    if (data.board.reply) say("bot", data.board.reply);
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
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
    const data = await api(`/api/${S.sid}/scenario/${id}`, { method: "POST", body: JSON.stringify({}) });
    S.board = data.board;
    render(data.board);
    const steps = (S.board.facts || []).length;
    say("bot", `시나리오 완료 — ${((Date.now() - t0) / 1000).toFixed(1)}초, 탐지 ${(S.board.findings || []).length}건, ` +
      `문서 ${(S.board.docs || []).length}종. 오른쪽 판정·기한을 확인하세요.`);
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
      const res = await api(`/api/${S.sid}/message`, { method: "POST", body: JSON.stringify({ text: st.text }) });
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
    say("bot", `문서 ${Object.keys(data.docs || {}).length}종을 만들었습니다. 발송은 사람이 합니다(초안까지만).`);
  } catch (e) {
    say("system", "오류: " + e.message);
  } finally {
    setBusy(false);
  }
}

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

  renderActions(b);
  renderDeadlines(b);
  renderTimeline(b);
  renderVerdict(b);
  renderFacts(b);
  renderDocs(b);
  renderSources(b);

  $("dontdo").innerHTML = (b.dont_do || []).map((d) => `<li>${esc(d)}</li>`).join("");
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
  const basis = (c.basis || []).map((x) => `<div class="basis">· ${esc(x)}</div>`).join("");
  const missing = (c.missing || []).length ? `<div class="basis">모르는 것: ${esc((c.missing || []).join(", "))}</div>` : "";
  $("verdict").innerHTML = `
    <div class="line"><span class="big">${esc(c.label || "판별 전")}</span> <span class="badge ${esc(c.level || "미확인")}">${esc(c.level || "미확인")}</span></div>
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
      <span>${esc(d.title)}</span>
      <span>
        <button data-doc="${esc(d.id)}">미리보기</button>
        <a class="btn small" href="/api/${S.sid}/doc/${esc(d.id)}">MD</a>
        <a class="btn small" href="/api/${S.sid}/doc/${esc(d.id)}.docx">DOCX</a>
      </span>
    </div>`).join("") || `<div class="hint">[문서 초안 생성]을 누르면 6종 통지문 + 신고서 초안이 만들어집니다.</div>`;
  $("zipAll").classList.toggle("hidden", !docs.length);
  $("zipAll").href = `/api/${S.sid}/docs.zip`;
  $("docs").querySelectorAll("button[data-doc]").forEach((btn) => {
    btn.onclick = () => previewDoc(btn.dataset.doc);
  });
}

async function previewDoc(id) {
  try {
    const res = await fetch(`/api/${S.sid}/doc/${id}`);
    const text = await res.text();
    const meta = (S.board.docs || []).find((d) => d.id === id);
    $("modalTitle").textContent = meta ? meta.title : id;
    $("modalDocx").href = `/api/${S.sid}/doc/${id}.docx`;
    $("modalBody").textContent = text;
    $("modalDownload").href = `/api/${S.sid}/doc/${id}`;
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

$("send").onclick = send;
$("input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send();
});
$("runScenario").onclick = runScenario;
$("replay").onclick = replay;
$("modalCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("modalBody").textContent); $("modalCopy").textContent = "복사됨"; }
  catch { $("modalCopy").textContent = "복사 실패"; }
  setTimeout(() => ($("modalCopy").textContent = "복사"), 1200);
};
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("modal").classList.add("hidden"); });
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("modal").classList.add("hidden"); });
$("makeDocs").onclick = makeDocs;
$("newCase").onclick = async () => {
  $("chat").innerHTML = "";
  await newSession();
  say("system", "새 사건을 시작했습니다.");
};
init();
