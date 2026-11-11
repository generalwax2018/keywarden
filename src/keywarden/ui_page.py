"""The page keywarden ui serves. One file, no external requests: no fonts, scripts, or images from anywhere else."""

from __future__ import annotations

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Keywarden</title>
<style nonce="__NONCE__">
/* Layout: a header band, then a fixed-width control column on the left and results on the right; one column on narrow screens. */
:root {
  --bg: #1c1d18; --band: #20211c; --panel: #26281f; --panel-2: #2d2f26; --line: #3a3c32; --line-soft: #303228;
  --ink: #efece2; --muted: #b0ad9f; --faint: #8c8a7d;
  --accent: #ffe582; --accent-ink: #26240f; --accent-soft: #3d3a20;
  --fail: #f2836f; --warn: #f0c36a; --pass: #b5dd9c; --acpt: #9fc2f5;
  --font: "IBM Plex Sans", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: "IBM Plex Mono", "Cascadia Mono", "SFMono-Regular", Consolas, "DejaVu Sans Mono", monospace;
  color-scheme: dark;
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    --bg: #f6f5ef; --band: #efede4; --panel: #ffffff; --panel-2: #f3f1e8; --line: #d9d6c8; --line-soft: #e6e3d6;
    --ink: #1f2018; --muted: #5d5b4f; --faint: #77756a;
    --accent: #f5d34a; --accent-ink: #26240f; --accent-soft: #fbefb8;
    --fail: #c2412d; --warn: #9a6a06; --pass: #3f7a2a; --acpt: #2f62b5;
    color-scheme: light;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; }
body { background: var(--bg); color: var(--ink); font: 16px/1.55 var(--font); }
button, input, textarea, select { font: inherit; color: inherit; }
.mono { font-family: var(--mono); }
.gutter { padding-left: max(20px, env(safe-area-inset-left, 0px)); padding-right: max(20px, env(safe-area-inset-right, 0px)); }
.inner { max-width: 1440px; margin: 0 auto; }

header.band { background: var(--band); border-bottom: 1px solid var(--line); padding-block: 32px 36px; }
.head-row { display: flex; gap: 20px; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; }
.brand { display: flex; gap: 18px; align-items: center; }
.tile { width: 64px; height: 64px; border-radius: 14px; background: var(--accent); color: var(--accent-ink); display: grid; place-items: center; flex: none; }
.eyebrow { font: 500 14px/1 var(--mono); letter-spacing: .14em; color: var(--accent); text-transform: uppercase; }
h1 { margin: 6px 0 0; font-size: clamp(24px, 3vw, 32px); line-height: 1.15; font-weight: 600; text-wrap: balance; }
.intro { color: var(--muted); max-width: 74ch; margin: 22px 0 0; font-size: 17px; }
.release { margin-top: 28px; border: 1px solid var(--line); border-radius: 18px; padding: 22px 26px; display: grid; gap: 12px; }
.release .eyebrow { font-size: 13px; }
.release p { margin: 0; color: var(--muted); }
pre.snippet { margin: 0; background: var(--bg); border-radius: 12px; padding: 14px 18px; font: 14px/1.6 var(--mono); overflow-x: auto; color: var(--ink); }

.btn { border: 1px solid var(--line); background: var(--panel); border-radius: 14px; padding: 12px 18px; display: inline-flex; gap: 10px; align-items: center; cursor: pointer; font-weight: 500; }
.btn:hover { border-color: var(--faint); }
.btn:disabled { opacity: .55; cursor: progress; }
.btn.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); justify-content: center; }
.btn.small { padding: 8px 12px; border-radius: 10px; font-size: 14px; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

main { padding-block: 40px 60px; }
.layout { display: grid; grid-template-columns: minmax(300px, 400px) minmax(0, 1fr); gap: 28px; align-items: start; }
@media (max-width: 960px) { .layout { grid-template-columns: minmax(0, 1fr); } }
.side { display: grid; gap: 22px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 22px; display: grid; gap: 14px; min-width: 0; }
.panel h2 { margin: 0; font-size: 20px; font-weight: 600; }
.panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
.tag { font: 13px var(--mono); color: var(--faint); letter-spacing: .04em; }
.help { margin: 0; color: var(--muted); font-size: 15px; }
textarea, input[type=text], input[type=number] { width: 100%; background: var(--bg); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; font: 14px/1.5 var(--mono); }
textarea { min-height: 150px; resize: vertical; }
.row { display: flex; gap: 10px; flex-wrap: wrap; }
.row > .btn.primary { flex: 1 1 180px; }
.pushset { display: grid; gap: 4px; font: 13px/1.5 var(--mono); color: var(--faint); min-width: 0; }
.pushset div { overflow-wrap: anywhere; }
.lab-note { color: var(--muted); font-size: 15px; margin: 0; }

fieldset { border: 1px solid var(--line); border-radius: 18px; padding: 18px 22px 22px; margin: 0; display: grid; gap: 14px; background: var(--panel); min-width: 0; }
legend { padding: 0 8px; font-weight: 600; font-size: 18px; }
.check { display: grid; grid-template-columns: auto 1fr; gap: 2px 12px; align-items: start; cursor: pointer; }
.check input { width: 20px; height: 20px; margin-top: 3px; accent-color: var(--accent); }
.check small { grid-column: 2; color: var(--muted); font-size: 15px; }
.field { display: grid; gap: 6px; }
.field label { font-size: 15px; }
.field small { color: var(--faint); font-size: 13px; }
.targets { display: grid; gap: 8px; }
.target { display: grid; grid-template-columns: auto 1fr; gap: 2px 12px; align-items: start; border: 1px solid var(--line-soft); border-radius: 12px; padding: 10px 12px; cursor: pointer; }
.target:has(input:checked) { border-color: var(--accent); background: var(--panel-2); }
.target input { margin-top: 4px; accent-color: var(--accent); }
.target small { grid-column: 2; color: var(--muted); font-size: 14px; }
.target .sub { grid-column: 2; margin-top: 6px; }
details.panel summary { cursor: pointer; font-weight: 600; font-size: 18px; list-style: none; display: flex; gap: 10px; align-items: center; }
details.panel summary::before { content: "\25B6"; font-size: 12px; transition: transform .15s; }
details.panel[open] summary::before { transform: rotate(90deg); }
details.panel summary::-webkit-details-marker { display: none; }

.topline { display: flex; gap: 14px; flex-wrap: wrap; align-items: stretch; justify-content: space-between; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat { border: 1px solid var(--line); border-radius: 14px; padding: 12px 18px 10px; min-width: 128px; background: var(--panel); }
.stat span { display: block; color: var(--muted); font-size: 15px; }
.stat b { display: block; font: 500 28px/1.3 var(--font); font-variant-numeric: tabular-nums; }
.stat b.bad { color: var(--fail); } .stat b.warnc { color: var(--warn); }
.exports { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.views { display: flex; gap: 6px; margin-top: 22px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.views button { background: none; border: 0; border-bottom: 2px solid transparent; padding: 10px 14px; cursor: pointer; color: var(--muted); font-weight: 500; }
.views button[aria-selected=true] { color: var(--ink); border-bottom-color: var(--accent); }
.filters { display: flex; gap: 8px; margin: 18px 0; flex-wrap: wrap; }
.filters button { background: none; border: 0; border-radius: 12px; padding: 10px 16px; cursor: pointer; color: var(--ink); font-size: 17px; }
.filters button[aria-pressed=true] { background: var(--panel-2); }

.hosts { display: grid; gap: 16px; }
.host { border: 1px solid var(--line); border-radius: 18px; background: var(--panel); overflow: hidden; }
.host-head { width: 100%; display: grid; grid-template-columns: auto 1fr auto auto; gap: 4px 16px; align-items: center; padding: 18px 22px; background: none; border: 0; text-align: left; cursor: pointer; }
.host-head .name { font-size: 22px; font-weight: 600; }
.host-head .role { color: var(--faint); font-size: 16px; margin-left: 10px; font-weight: 400; }
.host-head .meta { grid-column: 2; font: 15px var(--mono); color: var(--muted); overflow-wrap: anywhere; }
.host-head .count { font: 15px var(--mono); }
.chev { transition: transform .15s; color: var(--muted); }
.host[data-open=true] .chev { transform: rotate(180deg); }
.findings { border-top: 1px solid var(--line); }
.finding { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 6px 14px; padding: 16px 22px; border-top: 1px solid var(--line-soft); }
.finding:first-child { border-top: 0; }
.finding .title { display: flex; gap: 10px; flex-wrap: wrap; align-items: baseline; font-size: 17px; }
.finding .detail { grid-column: 2; font: 14px/1.7 var(--mono); color: var(--muted); overflow-wrap: anywhere; }
.badge { font: 13px var(--mono); padding: 2px 8px; border-radius: 8px; background: var(--accent-soft); color: var(--accent); }
.badge.acpt { background: transparent; border: 1px solid var(--acpt); color: var(--acpt); }
.badge.code { background: transparent; color: var(--faint); padding: 0; }
.ico { width: 22px; height: 22px; margin-top: 2px; }
.sev-fail { color: var(--fail); } .sev-warn { color: var(--warn); } .sev-pass { color: var(--pass); } .sev-accepted { color: var(--acpt); }
.passes summary { cursor: pointer; padding: 14px 22px; color: var(--muted); border-top: 1px solid var(--line-soft); }

.empty { border: 1px dashed var(--line); border-radius: 18px; padding: 40px 28px; color: var(--muted); display: grid; gap: 10px; }
.empty b { color: var(--ink); font-size: 18px; }
.error { border: 1px solid var(--fail); color: var(--ink); background: color-mix(in srgb, var(--fail) 12%, transparent); border-radius: 12px; padding: 12px 16px; }
.notes { color: var(--muted); font-size: 15px; margin-top: 18px; display: grid; gap: 6px; }

.table-tools { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; margin: 18px 0 12px; color: var(--muted); }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 14px; background: var(--panel); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line-soft); white-space: nowrap; }
th button { background: none; border: 0; padding: 0; cursor: pointer; color: var(--muted); font-weight: 500; }
td.fp, td.mono { font-family: var(--mono); font-size: 13px; }
tr:last-child td { border-bottom: 0; }
.pill { font: 12.5px var(--mono); padding: 2px 8px; border-radius: 8px; border: 1px solid var(--line); }
.pill.bad { color: var(--fail); border-color: color-mix(in srgb, var(--fail) 50%, transparent); }
.pill.ok { color: var(--pass); border-color: color-mix(in srgb, var(--pass) 50%, transparent); }
.pill.warnp { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 50%, transparent); }

.find-form { display: grid; gap: 12px; margin-top: 18px; max-width: 860px; }
.hits { display: grid; gap: 10px; margin-top: 18px; }
.hit { border: 1px solid var(--line); border-radius: 14px; background: var(--panel); padding: 14px 18px; display: grid; gap: 4px; }
.hit .where { font-weight: 600; }
.hit .mono { color: var(--muted); font-size: 13.5px; overflow-wrap: anywhere; }
.spin { display: inline-block; width: 14px; height: 14px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: s 0.8s linear infinite; }
@keyframes s { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin, .chev, details.panel summary::before { animation: none; transition: none; } }
footer { color: var(--faint); font-size: 14px; padding-bottom: 40px; }
</style>
</head>
<body>
<header class="band gutter">
  <div class="inner">
    <div class="head-row">
      <div class="brand">
        <div class="tile" aria-hidden="true"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8 20 3"/><path d="M16 7l3 3"/><path d="M18.5 4.5l2 2"/></svg></div>
        <div>
          <div class="eyebrow">Keywarden</div>
          <h1>Free SSH posture check. No key store.</h1>
        </div>
      </div>
      <button class="btn" id="drop" type="button" title="Forget the pushed fingerprints in this tab">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>
        Drop push set
      </button>
    </div>
    <p class="intro">You already push public keys. Keywarden checks root login, root keys, passwords, certificates, trusted CAs, and algorithms sshd will still accept, then shows who each key lets in, as what, and when it was last used. Running a check wipes the key text. This tab keeps fingerprints only, and the exported findings do not contain key bodies.</p>
    <div class="release">
      <div class="eyebrow">Open source · MIT · __VERSION__</div>
      <p>Runs on your machine and talks only to the hosts you check. The same checks are on the command line.</p>
      <pre class="snippet">pip install "git+https://github.com/generalwax2018/keywarden.git@v__VERSION__"
keywarden check --inventory hosts.ini --allow team.pub</pre>
    </div>
  </div>
</header>

<main class="gutter">
  <div class="inner layout">
    <aside class="side">
      <section class="panel" aria-labelledby="push-title">
        <div class="panel-head"><h2 id="push-title">Push public keys</h2><span class="tag">session only</span></div>
        <p class="help">One public key per line. Options are read for cert-authority and from=, then dropped. The text is wiped when you run the check.</p>
        <textarea id="allow" aria-label="Public keys you push" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA... ops@example"></textarea>
        <div class="row">
          <button class="btn primary" id="run" type="button">Run checks</button>
          <button class="btn" id="lab" type="button">Fill lab keys</button>
        </div>
        <p class="lab-note" id="push-note" hidden></p>
        <div class="pushset" id="pushset"></div>
      </section>

      <section class="panel" aria-labelledby="target-title">
        <h2 id="target-title">What to check</h2>
        <div class="targets" role="radiogroup" aria-labelledby="target-title">
          <label class="target"><input type="radio" name="target" value="lab" id="t-lab" checked><span>Lab hosts</span><small>Six made-up hosts, to try the checks.</small></label>
          <label class="target"><input type="radio" name="target" value="local" id="t-local"><span>This machine</span><small>Run Keywarden as root, or with passwordless sudo, to see every account.</small></label>
          <label class="target"><input type="radio" name="target" value="host" id="t-host"><span>One host</span><small>SSH in batch mode. Your known_hosts and SSH agent are used.</small>
            <input class="sub" type="text" id="host" placeholder="deploy@app-web-03.example" autocomplete="off" spellcheck="false"></label>
          <label class="target"><input type="radio" name="target" value="inventory" id="t-inv"><span>Ansible inventory</span><small>A path to an INI inventory on this machine. One SSH per host.</small>
            <input class="sub" type="text" id="inventory" placeholder="~/ansible/hosts.ini" autocomplete="off" spellcheck="false"></label>
        </div>
        <label class="check"><input type="checkbox" id="accept-new"><span>Trust host keys I have not seen</span><small>Off by default. A missing or changed host key fails that host.</small></label>
      </section>

      <fieldset>
        <legend>Checks</legend>
        <label class="check"><input type="checkbox" id="flag-outside" checked><span>Flag keys outside the push</span><small>Anything authorized that you did not just push is a miss.</small></label>
        <label class="check"><input type="checkbox" id="flag-weak" checked><span>Flag weak algorithms</span><small>DSA, and RSA under 3072 bits.</small></label>
        <div class="field"><label for="stale">Stale after (days)</label><input type="number" id="stale" min="1" max="3650" value="90"><small>A key with no login in this many days is stale, if the host's logs go back that far.</small></div>
        <div class="field"><label for="accounts">Extra accounts</label><input type="text" id="accounts" placeholder="postgres, svc-backup" autocomplete="off" spellcheck="false"><small>Read these too, even without a key file.</small></div>
        <div class="field"><label for="waivers">Waivers file</label><input type="text" id="waivers" placeholder="~/keywarden.toml" autocomplete="off" spellcheck="false"><small>Accepted risks with a reason, an owner, and an end date.</small></div>
        <div class="field"><label for="prior">Earlier report, for drift</label><input type="file" id="prior" accept=".json,application/json"><small>A JSON report from an earlier single-host run. Read in this tab only.</small></div>
      </fieldset>

      <details class="panel" id="paste-panel">
        <summary>Check a host you paste</summary>
        <p class="help">Run the collector on the host and paste what it prints. Do not save that output: it contains public keys. Only fingerprints come back here.</p>
        <div class="row"><button class="btn small" id="copy-collector" type="button">Copy the collector script</button></div>
        <textarea id="observation" aria-label="Collector output" spellcheck="false" autocomplete="off" placeholder="KEYWARDEN 3&#10;HOST ..."></textarea>
        <button class="btn primary" id="run-paste" type="button">Check this paste</button>
      </details>
    </aside>

    <section aria-label="Results" id="results">
      <div class="topline">
        <div class="stats" id="stats"></div>
        <div class="exports">
          <button class="btn" id="export-json" type="button" disabled>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg>
            Export findings
          </button>
          <button class="btn" id="export-csv" type="button" disabled>Export CSV</button>
        </div>
      </div>
      <div class="views" role="tablist" aria-label="Views">
        <button role="tab" aria-selected="true" data-view="findings" type="button">Findings</button>
        <button role="tab" aria-selected="false" data-view="review" type="button">Access review</button>
        <button role="tab" aria-selected="false" data-view="find" type="button">Find a key</button>
      </div>
      <div id="message"></div>
      <div id="view-findings"></div>
      <div id="view-review" hidden></div>
      <div id="view-find" hidden>
        <div class="find-form">
          <p class="help">Offboarding someone, or a laptop was stolen: find every host and account that still accepts the key. Uses the hosts chosen under What to check.</p>
          <div class="field"><label for="find-fp">Fingerprint</label><input type="text" id="find-fp" placeholder="SHA256:..." autocomplete="off" spellcheck="false"></div>
          <div class="field"><label for="find-key">Or paste a public key</label><textarea id="find-key" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA... alice@laptop"></textarea></div>
          <div class="row"><button class="btn primary" id="find" type="button">Find this key</button></div>
        </div>
        <div class="hits" id="hits"></div>
      </div>
      <div class="notes" id="notes"></div>
    </section>
  </div>
</main>
<footer class="gutter"><div class="inner">Keywarden __VERSION__ · served from this machine only · nothing is kept when the server stops</div></footer>

<script nonce="__NONCE__">
"use strict";
const TOKEN = "__TOKEN__";
history.replaceState(null, "", "/");

const $ = (id) => document.getElementById(id);
const state = { push: [], lab: false, report: null, csv: "", filter: "work", view: "findings", sort: { key: "host", dir: 1 }, onlyRoot: false, onlyStale: false, prior: null, busy: false };

// Build elements with text nodes only. Values from hosts never reach innerHTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const ICONS = {
  fail: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M12 8v5M12 16v.5"/>',
  warn: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M12 8v5M12 16v.5"/>',
  pass: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/>',
  accepted: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12h6"/>',
  chevron: '<path d="M6 9l6 6 6-6"/>',
};
function icon(name, cls) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8"); svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true"); svg.setAttribute("class", cls || "ico");
  svg.innerHTML = ICONS[name];
  return svg;
}

async function api(path, body) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Keywarden-Token": TOKEN }, body: JSON.stringify(body || {}), cache: "no-store" });
  const data = await response.json().catch(() => ({ error: "The server sent something unreadable." }));
  if (!response.ok) throw new Error(data.error || "The check failed.");
  return data;
}
function showError(text) { const box = $("message"); box.replaceChildren(text ? h("div", { class: "error", role: "alert" }, text) : ""); }

function selectedTarget() { return document.querySelector('input[name="target"]:checked').value; }
function baseBody(target) {
  return {
    target,
    host: $("host").value.trim(),
    inventoryPath: $("inventory").value.trim(),
    acceptNew: $("accept-new").checked,
    accounts: $("accounts").value.split(/[\s,]+/).filter(Boolean),
  };
}

function setBusy(busy, label) {
  state.busy = busy;
  for (const id of ["run", "run-paste", "find", "lab"]) $(id).disabled = busy;
  $("run").replaceChildren(busy ? h("span", { class: "spin", "aria-hidden": "true" }) : "", busy ? (label || " Checking…") : "Run checks");
}

async function runCheck(target) {
  if (state.busy) return;
  showError("");
  const allowText = $("allow").value;
  const body = Object.assign(baseBody(target), {
    allowText,
    allowFingerprints: allowText.trim() ? [] : state.push,
    flagOutside: $("flag-outside").checked,
    flagWeak: $("flag-weak").checked,
    staleDays: parseInt($("stale").value, 10) || 90,
    waiversPath: $("waivers").value.trim(),
    prior: state.prior,
  });
  if (target === "paste") body.observation = $("observation").value;
  // The key text leaves the page now. It is not kept here, sent again, or saved.
  $("allow").value = "";
  if (target === "paste") $("observation").value = "";
  setBusy(true, target === "inventory" ? " Checking each host…" : " Checking…");
  try {
    const data = await api("/api/check", body);
    state.report = data.report; state.csv = data.csv;
    state.push = (data.report.push || []).map((k) => ({ fingerprint: k.fingerprint, type: k.type, bits: k.bits, comment: k.comment }));
    state.lab = data.lab;
    $("export-json").disabled = false; $("export-csv").disabled = false;
    renderPush(); renderAll(data.notes || []);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

function renderPush() {
  const note = $("push-note");
  const labPush = state.lab && state.push.length && state.push.every((k) => /@latch$|^ci-bot$/.test(k.comment));
  note.hidden = !state.push.length;
  note.textContent = labPush ? "Comparing against the lab push (ops, deploy, ci). Not your keys." : (state.push.length ? `Comparing against ${state.push.length} pushed key${state.push.length === 1 ? "" : "s"}. Only fingerprints are held in this tab.` : "");
  $("pushset").replaceChildren(...state.push.map((k) => h("div", {}, `${k.type} ${k.fingerprint.slice(7, 19)}… ${k.comment || ""}`)));
}

function stats() {
  const hosts = state.report ? state.report.hosts : [];
  const keys = hosts.flatMap((host) => host.keys || []);
  const failed = hosts.reduce((n, host) => n + host.findings.filter((f) => f.severity === "fail").length, 0);
  const tiles = [
    ["Hosts", hosts.length, ""],
    ["Failing hosts", hosts.filter((host) => host.posture === "fail").length, "bad"],
    ["Failed checks", failed, "bad"],
    ["Keys to root", keys.filter((k) => k.reach === "root" || k.reach === "root-nopasswd").length, "bad"],
    ["Stale keys", keys.filter((k) => k.usage === "stale").length, "warnc"],
  ];
  $("stats").replaceChildren(...tiles.map(([label, value, cls]) => h("div", { class: "stat" }, h("span", {}, label), h("b", { class: value ? cls : "" }, state.report ? value : "–"))));
}

const ORDER = { fail: 0, warn: 1, accepted: 2, pass: 3 };
function when(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  return isNaN(date) ? iso : date.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function findingRow(item) {
  const sev = item.severity;
  return h("div", { class: "finding" },
    h("span", { class: "sev-" + sev }, icon(sev)),
    h("div", { class: "title" },
      h("span", {}, item.title),
      item.drift ? h("span", { class: "badge" }, item.drift === "new-keys" ? "New keys" : item.drift.charAt(0).toUpperCase() + item.drift.slice(1)) : "",
      sev === "accepted" ? h("span", { class: "badge acpt" }, "Accepted") : "",
      h("span", { class: "badge code" }, item.code)),
    h("div", { class: "detail" }, item.detail));
}

function hostCard(host, open) {
  const fails = host.findings.filter((f) => f.severity === "fail").length;
  const warns = host.findings.filter((f) => f.severity === "warn").length;
  const sorted = [...host.findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const shown = sorted.filter((f) => f.severity !== "pass");
  const passes = sorted.filter((f) => f.severity === "pass");
  const card = h("article", { class: "host", "data-open": open ? "true" : "false" });
  const list = h("div", { class: "findings", hidden: !open },
    shown.map(findingRow),
    passes.length ? h("details", { class: "passes" }, h("summary", {}, `${passes.length} passing check${passes.length === 1 ? "" : "s"}`), passes.map(findingRow)) : "");
  const sev = host.posture === "fail" ? "fail" : host.posture === "warn" ? "warn" : "pass";
  const count = fails ? `${fails} failed` : warns ? `${warns} to review` : "clear";
  const head = h("button", { class: "host-head", type: "button", "aria-expanded": open ? "true" : "false", onclick: () => {
      const now = card.dataset.open !== "true";
      card.dataset.open = String(now); list.hidden = !now; head.setAttribute("aria-expanded", String(now));
    } },
    h("span", { class: "sev-" + sev }, icon(sev === "pass" ? "pass" : "fail")),
    h("span", {}, h("span", { class: "name" }, host.name), host.roleLabel ? h("span", { class: "role" }, host.roleLabel) : ""),
    h("span", { class: "count sev-" + sev }, count),
    icon("chevron", "ico chev"),
    h("span", { class: "meta" }, [host.address, host.observedAt ? "observed " + when(host.observedAt) : "", host.authLog && host.authLog !== "unknown" ? "logs: " + host.authLog : ""].filter(Boolean).join(" · ")));
  card.append(head, list);
  return card;
}

function renderFindings() {
  const view = $("view-findings");
  if (!state.report) {
    view.replaceChildren(h("div", { class: "empty" }, h("b", {}, "No hosts checked yet."), h("span", {}, "Paste the public keys you push and choose what to check, or press Fill lab keys and Run checks to try six made-up hosts.")));
    return;
  }
  const hosts = state.report.hosts;
  const needs = hosts.filter((host) => host.posture !== "pass");
  const clear = hosts.filter((host) => host.posture === "pass");
  const pick = state.filter === "work" ? needs : state.filter === "clear" ? clear : hosts;
  const filters = h("div", { class: "filters", role: "group", "aria-label": "Filter hosts" },
    [["work", `Needs work (${needs.length})`], ["all", "All"], ["clear", `Clear (${clear.length})`]].map(([key, label]) =>
      h("button", { type: "button", "aria-pressed": state.filter === key ? "true" : "false", onclick: () => { state.filter = key; renderFindings(); } }, label)));
  const rank = (host) => (host.posture === "fail" ? 0 : host.posture === "warn" ? 1 : 2);
  const ordered = [...pick].sort((a, b) => rank(a) - rank(b));
  const list = ordered.length
    ? h("div", { class: "hosts" }, ordered.map((host, index) => hostCard(host, index === 0 && host.posture !== "pass")))
    : h("div", { class: "empty" }, h("b", {}, state.filter === "work" ? "Every host is clear." : "No host is fully clear yet."));
  view.replaceChildren(filters, list);
}

const COLUMNS = [["host", "Host"], ["account", "Account"], ["fingerprint", "Fingerprint"], ["reach", "Reach"], ["usage", "Usage"], ["lastUsed", "Last used"], ["from", "From"], ["inAllow", "In push"], ["comment", "Comment"]];
function cell(row, key) {
  if (key === "from") return (row.options.from || []).join(", ") || "any";
  if (key === "inAllow") return row.inAllow == null ? "–" : row.inAllow ? "yes" : "no";
  if (key === "lastUsed") return row.lastUsed ? row.lastUsed.slice(0, 10) : "–";
  return row[key] == null || row[key] === "" ? "–" : String(row[key]);
}
function renderReview() {
  const view = $("view-review");
  if (!state.report) { view.replaceChildren(h("div", { class: "empty" }, h("b", {}, "Run a check to see every authorized key."))); return; }
  let rows = state.report.hosts.flatMap((host) => host.keys || []);
  if (state.onlyRoot) rows = rows.filter((r) => r.reach === "root" || r.reach === "root-nopasswd");
  if (state.onlyStale) rows = rows.filter((r) => r.usage === "stale");
  const { key, dir } = state.sort;
  rows = [...rows].sort((a, b) => cell(a, key).localeCompare(cell(b, key), undefined, { numeric: true }) * dir);
  const tools = h("div", { class: "table-tools" },
    h("label", { class: "check" }, h("input", { type: "checkbox", id: "only-root", checked: state.onlyRoot, onchange: (e) => { state.onlyRoot = e.target.checked; renderReview(); } }), h("span", {}, "Only keys that reach root")),
    h("label", { class: "check" }, h("input", { type: "checkbox", id: "only-stale", checked: state.onlyStale, onchange: (e) => { state.onlyStale = e.target.checked; renderReview(); } }), h("span", {}, "Only stale keys")),
    h("span", {}, `${rows.length} key${rows.length === 1 ? "" : "s"}`));
  const pillFor = (k, v) => {
    if (k === "reach") return h("span", { class: "pill " + (v === "root" || v === "root-nopasswd" ? "bad" : v === "root-password" ? "warnp" : "") }, v);
    if (k === "usage") return h("span", { class: "pill " + (v === "stale" ? "bad" : v === "fresh" ? "ok" : "warnp") }, v);
    return v;
  };
  const table = h("table", {},
    h("thead", {}, h("tr", {}, COLUMNS.map(([k, label]) => h("th", { scope: "col", "aria-sort": key === k ? (dir > 0 ? "ascending" : "descending") : "none" },
      h("button", { type: "button", onclick: () => { state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 }; renderReview(); } }, label + (key === k ? (dir > 0 ? " ↑" : " ↓") : "")))))),
    h("tbody", {}, rows.map((row) => h("tr", {}, COLUMNS.map(([k]) => h("td", { class: k === "fingerprint" ? "fp" : (k === "from" || k === "lastUsed" ? "mono" : "") }, pillFor(k, cell(row, k))))))));
  view.replaceChildren(tools, h("div", { class: "table-wrap" }, table));
}

function renderAll(notes) {
  stats(); renderFindings(); renderReview();
  const lines = [...(notes || [])];
  if (state.report && state.lab) lines.push("The six lab hosts are a fixed observation, the way the collector reports sshd -T, sudo rights, logins, and fingerprints back. app-web-03 and ci-runner regressed against the previous run. A paste is checked the same way and is not kept as a key store.");
  $("notes").replaceChildren(...lines.map((line) => h("p", { class: "lab-note" }, line)));
}

function showView(name) {
  state.view = name;
  for (const tab of document.querySelectorAll('[role="tab"]')) tab.setAttribute("aria-selected", String(tab.dataset.view === name));
  for (const v of ["findings", "review", "find"]) $("view-" + v).hidden = v !== name;
}

async function findKey() {
  if (state.busy) return;
  showError("");
  const body = Object.assign(baseBody(selectedTarget()), { fingerprints: [$("find-fp").value.trim()].filter(Boolean), keyText: $("find-key").value });
  $("find-key").value = "";
  setBusy(true);
  $("find").replaceChildren(h("span", { class: "spin", "aria-hidden": "true" }), " Looking…");
  try {
    const data = await api("/api/where", body);
    const hits = data.found.map((hit) => h("div", { class: "hit" },
      h("div", { class: "where" }, `${hit.host} · ${hit.account}`),
      h("div", {}, `${hit.how}. Reach: ${hit.reach}${hit.reachVia ? " (" + hit.reachVia + ")" : ""}. From: ${hit.from.length ? hit.from.join(", ") : "any address"}. Last used: ${hit.lastUsed ? when(hit.lastUsed) : "no login in the logs"}.`),
      h("div", { class: "mono" }, hit.fingerprint)));
    const blind = data.notChecked.map((line) => h("p", { class: "lab-note" }, line));
    $("hits").replaceChildren(hits.length ? h("p", { class: "help" }, `Found in ${hits.length} place${hits.length === 1 ? "" : "s"}.`) : h("div", { class: "empty" }, h("b", {}, "Not found on any host that could be read.")), ...hits, ...blind);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
    $("find").replaceChildren("Find this key");
  }
}

function download(name, type, text) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = h("a", { href: url, download: name });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");

$("run").addEventListener("click", () => runCheck(selectedTarget()));
$("run-paste").addEventListener("click", () => runCheck("paste"));
$("find").addEventListener("click", findKey);
$("lab").addEventListener("click", async () => {
  try {
    const data = await api("/api/lab-keys");
    $("allow").value = data.keys.join("\n");
    $("t-lab").checked = true;
  } catch (error) { showError(error.message); }
});
$("drop").addEventListener("click", () => {
  state.push = []; state.lab = false; $("allow").value = ""; renderPush();
  showError(""); $("message").append(h("p", { class: "lab-note" }, "Push set dropped. Paste keys again before the next run."));
});
$("export-json").addEventListener("click", () => state.report && download(`keywarden-${stamp()}.json`, "application/json", JSON.stringify(state.report, null, 2)));
$("export-csv").addEventListener("click", () => state.csv && download(`keywarden-access-review-${stamp()}.csv`, "text/csv", state.csv));
$("copy-collector").addEventListener("click", async (event) => {
  try {
    const data = await api("/api/collector");
    await navigator.clipboard.writeText("sh -s -- root <<'KEYWARDEN'\n" + data.script + "\nKEYWARDEN\n");
    event.target.textContent = "Copied. Run it on the host, then paste the output below.";
  } catch (error) { event.target.textContent = "Copy failed. Use: keywarden check --observation - on the command line."; }
});
$("prior").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  state.prior = null;
  if (!file) return;
  try { state.prior = JSON.parse(await file.text()); showError(""); }
  catch { showError("That file is not a Keywarden JSON report."); event.target.value = ""; }
});
for (const tab of document.querySelectorAll('[role="tab"]')) tab.addEventListener("click", () => showView(tab.dataset.view));
for (const id of ["host", "inventory"]) $(id).addEventListener("focus", () => { $(id === "host" ? "t-host" : "t-inv").checked = true; });
renderPush(); renderAll([]);
</script>
</body>
</html>
"""


def render_page(nonce: str, token: str, version: str) -> str:
    return PAGE.replace("__NONCE__", nonce).replace("__TOKEN__", token).replace("__VERSION__", version)
