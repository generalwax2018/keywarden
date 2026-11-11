"""The page keywarden ui serves. One file, no external requests: no fonts, scripts, or images from anywhere else."""

from __future__ import annotations

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>Keywarden</title>
<style nonce="__NONCE__">
/* Layout: a translucent toolbar, a source-list sidebar of grouped settings, and a content pane of summary tiles and inset grouped lists. Follows the system light or dark appearance. */
:root {
  --window: #f5f5f7; --sidebar: #ececef; --surface: #ffffff; --surface-2: #f2f2f4; --fill: rgba(118,118,128,.12); --fill-strong: rgba(118,118,128,.2);
  --separator: rgba(60,60,67,.14); --separator-strong: rgba(60,60,67,.24);
  --label: #1d1d1f; --secondary: #6e6e73; --tertiary: #8e8e93;
  --blue: #0071e3; --blue-hover: #0077ed; --blue-soft: rgba(0,113,227,.1);
  --red: #ff3b30; --orange: #ff9500; --green: #34c759; --indigo: #5856d6;
  --red-text: #d70015; --orange-text: #c93400; --green-text: #248a3d; --indigo-text: #3634a3;
  --shadow: 0 1px 2px rgba(0,0,0,.04), 0 4px 16px rgba(0,0,0,.04);
  --toolbar: rgba(245,245,247,.78);
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI Variable Text", "Segoe UI", system-ui, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, "Cascadia Mono", Consolas, monospace;
  --radius: 12px;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --window: #1e1e1e; --sidebar: #252527; --surface: #2c2c2e; --surface-2: #3a3a3c; --fill: rgba(118,118,128,.24); --fill-strong: rgba(118,118,128,.36);
    --separator: rgba(84,84,88,.55); --separator-strong: rgba(84,84,88,.8);
    --label: #f5f5f7; --secondary: #a1a1a6; --tertiary: #8e8e93;
    --blue: #0a84ff; --blue-hover: #409cff; --blue-soft: rgba(10,132,255,.18);
    --red: #ff453a; --orange: #ff9f0a; --green: #30d158; --indigo: #5e5ce6;
    --red-text: #ff6961; --orange-text: #ffb340; --green-text: #4cd964; --indigo-text: #a5a4ff;
    --shadow: 0 1px 2px rgba(0,0,0,.3);
    --toolbar: rgba(30,30,30,.78);
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { margin: 0; }
body { background: var(--window); color: var(--label); font: 14px/1.45 var(--font); -webkit-font-smoothing: antialiased; letter-spacing: -.005em; }
button, input, textarea { font: inherit; color: inherit; }
.mono { font-family: var(--mono); }
:focus-visible { outline: 3px solid color-mix(in srgb, var(--blue) 55%, transparent); outline-offset: 1px; border-radius: 8px; }

/* Toolbar */
.toolbar { position: sticky; top: env(safe-area-inset-top, 0px); z-index: 20; background: var(--toolbar); backdrop-filter: saturate(180%) blur(20px); -webkit-backdrop-filter: saturate(180%) blur(20px); border-bottom: 1px solid var(--separator); }
body::before { content: ""; position: fixed; inset: 0 0 auto; height: env(safe-area-inset-top, 0px); z-index: 21; background: var(--window); }
.toolbar-inner { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 16px; padding: 10px max(20px, env(safe-area-inset-right, 0px)) 10px max(20px, env(safe-area-inset-left, 0px)); }
.app { display: flex; align-items: center; gap: 10px; min-width: 0; }
.app-icon { width: 30px; height: 30px; border-radius: 7px; background: linear-gradient(160deg, #3a8dff 0%, #0058d1 100%); display: grid; place-items: center; color: #fff; box-shadow: inset 0 0 0 .5px rgba(0,0,0,.15), 0 1px 2px rgba(0,0,0,.15); flex: none; }
.app-name { font-weight: 600; font-size: 15px; }
.app-version { color: var(--tertiary); font-size: 12px; }
.toolbar-end { display: flex; justify-content: flex-end; gap: 8px; }
@media (max-width: 900px) { .toolbar-inner { grid-template-columns: 1fr auto; } .toolbar .segmented-wrap { grid-column: 1 / -1; grid-row: 2; justify-self: start; } }

/* Controls */
.segmented { display: inline-flex; background: var(--fill); border-radius: 9px; padding: 2px; gap: 2px; }
.segmented button { border: 0; background: transparent; border-radius: 7px; padding: 5px 14px; font-size: 13px; font-weight: 500; color: var(--label); cursor: pointer; white-space: nowrap; }
.segmented button[aria-selected=true], .segmented button[aria-pressed=true] { background: var(--surface); box-shadow: 0 1px 3px rgba(0,0,0,.12), 0 0 0 .5px rgba(0,0,0,.04); }
@media (prefers-color-scheme: dark) { .segmented button[aria-selected=true], .segmented button[aria-pressed=true] { background: #636366; } }
.btn { border: 0; border-radius: 8px; padding: 6px 12px; background: var(--fill); font-size: 13px; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; white-space: nowrap; }
.btn:hover:not(:disabled) { background: var(--fill-strong); }
.btn:disabled { opacity: .45; cursor: default; }
.btn.primary { background: var(--blue); color: #fff; justify-content: center; padding: 8px 14px; font-size: 14px; }
.btn.primary:hover:not(:disabled) { background: var(--blue-hover); }
.btn.plain { background: transparent; color: var(--blue); padding: 6px 4px; }
.btn svg { flex: none; }

/* Layout */
.layout { display: grid; grid-template-columns: 340px minmax(0, 1fr); min-height: calc(100vh - 51px); }
@media (max-width: 900px) { .layout { grid-template-columns: minmax(0, 1fr); } }
.sidebar { background: var(--sidebar); border-right: 1px solid var(--separator); padding: 20px max(16px, env(safe-area-inset-left, 0px)) 32px 16px; display: grid; gap: 22px; align-content: start; }
@media (max-width: 900px) { .sidebar { border-right: 0; border-bottom: 1px solid var(--separator); padding-right: max(16px, env(safe-area-inset-right, 0px)); } }
.content { padding: 24px max(28px, env(safe-area-inset-right, 0px)) 48px 28px; min-width: 0; display: grid; gap: 20px; align-content: start; }
@media (max-width: 900px) { .content { padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); } }

/* Sidebar groups */
.group { display: grid; gap: 7px; min-width: 0; }
.group-title { font-size: 11px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--secondary); padding: 0 12px; display: flex; justify-content: space-between; gap: 8px; }
.group-title span + span { text-transform: none; letter-spacing: 0; font-weight: 500; color: var(--tertiary); }
.card { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.card.pad { padding: 12px; display: grid; gap: 10px; }
.foot { font-size: 12px; color: var(--secondary); padding: 0 12px; margin: 0; }
textarea, input[type=text], input[type=number] { width: 100%; background: var(--surface-2); border: 1px solid transparent; border-radius: 8px; padding: 8px 10px; font-size: 13px; }
textarea { font: 12px/1.5 var(--mono); min-height: 112px; resize: vertical; }
textarea:focus, input[type=text]:focus, input[type=number]:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-soft); background: var(--surface); }
.actions { display: grid; grid-template-columns: 1fr auto; gap: 8px; }
.pushset { display: grid; gap: 2px; font: 11.5px/1.5 var(--mono); color: var(--secondary); min-width: 0; }
.pushset div { overflow-wrap: anywhere; }
.lab-note { margin: 0; color: var(--secondary); font-size: 12.5px; }

.list { display: grid; }
.list > * + * { border-top: 1px solid var(--separator); }
.option { display: grid; grid-template-columns: 1fr auto; gap: 2px 12px; align-items: center; padding: 10px 12px; cursor: pointer; }
.option .text { display: grid; gap: 1px; min-width: 0; }
.option small { color: var(--secondary); font-size: 12px; }
.option .sub { grid-column: 1 / -1; margin-top: 6px; }
.option input[type=radio] { appearance: none; -webkit-appearance: none; width: 16px; height: 16px; margin: 0; border-radius: 50%; border: 1.5px solid var(--separator-strong); background: var(--surface); }
.option input[type=radio]:checked { border: 5px solid var(--blue); }
.option input[type=checkbox] { appearance: none; -webkit-appearance: none; width: 34px; height: 20px; border-radius: 10px; background: var(--fill-strong); position: relative; margin: 0; cursor: pointer; transition: background .2s; flex: none; }
.option input[type=checkbox]::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.25); transition: transform .2s; }
.option input[type=checkbox]:checked { background: var(--green); }
.option input[type=checkbox]:checked::after { transform: translateX(14px); }
.field { display: grid; gap: 4px; padding: 10px 12px; }
.field label { font-size: 13px; }
.field small { color: var(--secondary); font-size: 12px; }
.field.inline { grid-template-columns: 1fr 72px; align-items: center; }
.field.inline small { grid-column: 1 / -1; }
input[type=file] { font-size: 12px; color: var(--secondary); }
input[type=file]::file-selector-button { border: 0; border-radius: 6px; background: var(--fill); padding: 4px 10px; margin-right: 8px; cursor: pointer; color: var(--label); }
details.card summary { cursor: pointer; padding: 10px 12px; list-style: none; display: flex; align-items: center; justify-content: space-between; font-size: 13px; }
details.card summary::after { content: ""; width: 7px; height: 7px; border-right: 1.5px solid var(--tertiary); border-bottom: 1.5px solid var(--tertiary); transform: rotate(-45deg); transition: transform .15s; }
details.card[open] summary::after { transform: rotate(45deg); }
details.card summary::-webkit-details-marker { display: none; }
details.card .inside { padding: 0 12px 12px; display: grid; gap: 10px; }
.help { margin: 0; color: var(--secondary); font-size: 12.5px; }

/* Summary */
.heading { display: flex; justify-content: space-between; align-items: end; gap: 16px; flex-wrap: wrap; }
.heading h1 { margin: 0; font-size: 26px; font-weight: 700; letter-spacing: -.02em; }
.heading p { margin: 2px 0 0; color: var(--secondary); font-size: 13px; }
.stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; }
@media (max-width: 1100px) { .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 520px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.stat { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); padding: 12px 14px; display: grid; gap: 2px; }
.stat span { color: var(--secondary); font-size: 12px; font-weight: 500; display: flex; align-items: center; gap: 6px; }
.stat span::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--tertiary); }
.stat.c-red span::before { background: var(--red); } .stat.c-orange span::before { background: var(--orange); } .stat.c-blue span::before { background: var(--blue); }
.stat b { font-size: 28px; font-weight: 600; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
.filters { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }

/* Hosts */
.hosts { display: grid; gap: 12px; }
.host { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.host-head { width: 100%; display: grid; grid-template-columns: auto minmax(0, 1fr) auto auto; gap: 1px 12px; align-items: center; padding: 12px 16px; background: none; border: 0; text-align: left; cursor: pointer; }
.host-head:hover { background: color-mix(in srgb, var(--fill) 40%, transparent); }
.host-head .name { font-size: 15px; font-weight: 600; }
.host-head .role { color: var(--secondary); font-weight: 400; margin-left: 8px; font-size: 13px; }
.host-head .meta { grid-column: 2; color: var(--secondary); font-size: 12px; overflow-wrap: anywhere; }
.count { font-size: 12px; font-weight: 600; padding: 2px 9px; border-radius: 999px; white-space: nowrap; }
.count.sev-fail { background: color-mix(in srgb, var(--red) 14%, transparent); color: var(--red-text); }
.count.sev-warn { background: color-mix(in srgb, var(--orange) 16%, transparent); color: var(--orange-text); }
.count.sev-pass { background: color-mix(in srgb, var(--green) 16%, transparent); color: var(--green-text); }
.chev { width: 14px; height: 14px; color: var(--tertiary); transition: transform .2s; }
.host[data-open=true] .chev { transform: rotate(180deg); }
.findings { border-top: 1px solid var(--separator); }
.finding { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 3px 12px; padding: 11px 16px 12px; }
.finding + .finding, .passes { border-top: 1px solid var(--separator); }
.finding .title { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; font-size: 14px; font-weight: 500; }
.finding .detail { grid-column: 2; color: var(--secondary); font-size: 12.5px; line-height: 1.5; overflow-wrap: anywhere; }
.badge { font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 999px; background: color-mix(in srgb, var(--orange) 16%, transparent); color: var(--orange-text); }
.badge.acpt { background: color-mix(in srgb, var(--indigo) 14%, transparent); color: var(--indigo-text); }
.badge.code { background: transparent; color: var(--tertiary); font: 11px var(--mono); padding: 0; }
.ico { width: 18px; height: 18px; flex: none; margin-top: 1px; }
.sev-fail { color: var(--red); } .sev-warn { color: var(--orange); } .sev-pass { color: var(--green); } .sev-accepted { color: var(--indigo); }
.passes summary { cursor: pointer; padding: 10px 16px; color: var(--blue); font-size: 13px; list-style: none; }
.passes summary::-webkit-details-marker { display: none; }
.passes[open] summary { border-bottom: 1px solid var(--separator); }

/* States */
.empty { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); padding: 48px 24px; text-align: center; display: grid; gap: 6px; justify-items: center; color: var(--secondary); }
.empty b { color: var(--label); font-size: 17px; font-weight: 600; }
.empty .glyph { width: 44px; height: 44px; border-radius: 11px; background: var(--blue-soft); color: var(--blue); display: grid; place-items: center; margin-bottom: 6px; }
.empty .btn { margin-top: 10px; }
.error { background: color-mix(in srgb, var(--red) 10%, var(--surface)); color: var(--label); border-radius: 10px; padding: 10px 14px; font-size: 13px; box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--red) 35%, transparent); }
.info { color: var(--secondary); font-size: 13px; margin: 0; }
.notes { display: grid; gap: 4px; }
.notes .lab-note { font-size: 12px; color: var(--tertiary); }

/* Table */
.table-tools { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; color: var(--secondary); font-size: 13px; }
.table-tools .option { padding: 0; grid-template-columns: auto auto; }
.table-wrap { overflow-x: auto; background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 8px 14px; white-space: nowrap; }
thead th { font-size: 12px; font-weight: 500; color: var(--secondary); border-bottom: 1px solid var(--separator); background: var(--surface); position: sticky; top: 0; }
tbody tr:nth-child(even) td { background: color-mix(in srgb, var(--fill) 35%, transparent); }
th button { background: none; border: 0; padding: 0; cursor: pointer; color: inherit; font-weight: inherit; }
td.fp, td.mono { font-family: var(--mono); font-size: 12px; }
.pill { font-size: 11.5px; font-weight: 600; padding: 1px 8px; border-radius: 999px; background: var(--fill); color: var(--secondary); }
.pill.bad { background: color-mix(in srgb, var(--red) 14%, transparent); color: var(--red-text); }
.pill.ok { background: color-mix(in srgb, var(--green) 16%, transparent); color: var(--green-text); }
.pill.warnp { background: color-mix(in srgb, var(--orange) 16%, transparent); color: var(--orange-text); }

/* Find a key */
.find-form { display: grid; gap: 10px; max-width: 760px; }
.hits { display: grid; gap: 10px; }
.hit { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); padding: 12px 16px; display: grid; gap: 3px; }
.hit .where { font-weight: 600; }
.hit .mono { color: var(--tertiary); font-size: 12px; overflow-wrap: anywhere; }
.spin { display: inline-block; width: 13px; height: 13px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: s .8s linear infinite; }
@keyframes s { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin, .chev, .option input::after, details.card summary::after { animation: none; transition: none; } }
.legal { color: var(--tertiary); font-size: 11.5px; padding: 0 12px; margin: 0; }
</style>
</head>
<body>
<header class="toolbar">
  <div class="toolbar-inner">
    <div class="app">
      <div class="app-icon" aria-hidden="true"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8 20 3"/><path d="M16 7l3 3"/><path d="M18.5 4.5l2 2"/></svg></div>
      <span class="app-name">Keywarden</span><span class="app-version">__VERSION__</span>
    </div>
    <div class="segmented-wrap">
      <div class="segmented" role="tablist" aria-label="Views">
        <button role="tab" aria-selected="true" data-view="findings" type="button">Findings</button>
        <button role="tab" aria-selected="false" data-view="review" type="button">Access Review</button>
        <button role="tab" aria-selected="false" data-view="find" type="button">Find a Key</button>
      </div>
    </div>
    <div class="toolbar-end">
      <button class="btn" id="export-json" type="button" disabled title="Download the findings as JSON. Key bodies are not included.">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg>Export
      </button>
      <button class="btn" id="export-csv" type="button" disabled title="Download the access review table as CSV">CSV</button>
    </div>
  </div>
</header>

<div class="layout">
  <aside class="sidebar" aria-label="Check settings">
    <section class="group" aria-labelledby="push-title">
      <div class="group-title"><span id="push-title">Public keys you push</span><span>Session only</span></div>
      <div class="card pad">
        <textarea id="allow" aria-label="Public keys you push" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA… ops@example"></textarea>
        <div class="actions">
          <button class="btn primary" id="run" type="button">Run Checks</button>
          <button class="btn" id="lab" type="button">Use Lab Keys</button>
        </div>
        <p class="lab-note" id="push-note" hidden></p>
        <div class="pushset" id="pushset"></div>
      </div>
      <p class="foot">One key per line. The text is fingerprinted and cleared when you run. Only fingerprints stay in this window.</p>
      <p class="foot"><button class="btn plain" id="drop" type="button">Clear Keys</button></p>
    </section>

    <section class="group" aria-labelledby="target-title">
      <div class="group-title"><span id="target-title">Check</span></div>
      <div class="card list" role="radiogroup" aria-labelledby="target-title">
        <label class="option"><span class="text"><span>Lab hosts</span><small>Six example hosts</small></span><input type="radio" name="target" value="lab" id="t-lab" checked></label>
        <label class="option"><span class="text"><span>This machine</span><small>Run as root or with passwordless sudo</small></span><input type="radio" name="target" value="local" id="t-local"></label>
        <label class="option"><span class="text"><span>One host</span><small>SSH in batch mode</small></span><input type="radio" name="target" value="host" id="t-host">
          <input class="sub" type="text" id="host" aria-label="Host" placeholder="deploy@app-web-03.example" autocomplete="off" spellcheck="false"></label>
        <label class="option"><span class="text"><span>Ansible inventory</span><small>INI file on this machine</small></span><input type="radio" name="target" value="inventory" id="t-inv">
          <input class="sub" type="text" id="inventory" aria-label="Inventory path" placeholder="~/ansible/hosts.ini" autocomplete="off" spellcheck="false"></label>
        <label class="option"><span class="text"><span>Trust new host keys</span><small>Off: an unknown host key fails the host</small></span><input type="checkbox" id="accept-new"></label>
      </div>
    </section>

    <section class="group" aria-labelledby="checks-title">
      <div class="group-title"><span id="checks-title">Checks</span></div>
      <div class="card list">
        <label class="option"><span class="text"><span>Flag keys outside the push</span><small>Anything authorized you did not push</small></span><input type="checkbox" id="flag-outside" checked></label>
        <label class="option"><span class="text"><span>Flag weak algorithms</span><small>DSA, and RSA under 3072 bits</small></span><input type="checkbox" id="flag-weak" checked></label>
        <div class="field inline"><label for="stale">Stale after (days)</label><input type="number" id="stale" min="1" max="3650" value="90"><small>Counted only when the host's logs go back that far</small></div>
        <div class="field"><label for="accounts">Extra accounts</label><input type="text" id="accounts" placeholder="postgres, svc-backup" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="waivers">Waivers file</label><input type="text" id="waivers" placeholder="~/keywarden.toml" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="prior">Earlier report</label><input type="file" id="prior" accept=".json,application/json"><small>Marks what regressed since then. Read in this window only.</small></div>
      </div>
    </section>

    <section class="group">
      <div class="group-title"><span>Offline</span></div>
      <details class="card" id="paste-panel">
        <summary>Check pasted collector output</summary>
        <div class="inside">
          <p class="help">Run the collector on the host and paste what it prints. Don't save that output; it contains public keys.</p>
          <button class="btn" id="copy-collector" type="button">Copy Collector Script</button>
          <textarea id="observation" aria-label="Collector output" spellcheck="false" autocomplete="off" placeholder="KEYWARDEN 3&#10;HOST …"></textarea>
          <button class="btn primary" id="run-paste" type="button">Check Paste</button>
        </div>
      </details>
    </section>
    <p class="legal">Runs on this machine and talks only to the hosts you check. Open source, MIT.</p>
  </aside>

  <main class="content" id="results" aria-label="Results">
    <div class="heading">
      <div><h1 id="page-title">Findings</h1><p id="page-sub">No hosts checked yet</p></div>
      <div id="filters"></div>
    </div>
    <div id="message"></div>
    <div class="stats" id="stats"></div>
    <div id="view-findings"></div>
    <div id="view-review" hidden></div>
    <div id="view-find" hidden>
      <div class="find-form">
        <p class="info">Find every host and account that still accepts a key, for offboarding or a lost laptop. Uses the hosts selected under Check.</p>
        <div class="card list">
          <div class="field"><label for="find-fp">Fingerprint</label><input type="text" id="find-fp" placeholder="SHA256:…" autocomplete="off" spellcheck="false"></div>
          <div class="field"><label for="find-key">Or paste a public key</label><textarea id="find-key" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA… alice@laptop"></textarea></div>
        </div>
        <div><button class="btn primary" id="find" type="button">Find Key</button></div>
      </div>
      <div class="hits" id="hits"></div>
    </div>
    <div class="notes" id="notes"></div>
  </main>
</div>

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
// Static icon markup only; nothing from a host goes in here.
const ICONS = {
  fail: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7" stroke="#fff" stroke-width="2" stroke-linecap="round"/>',
  warn: '<path d="M12 2.8 22 20.5H2z" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 9.5v5" stroke="#fff" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17.6" r="1.2" fill="#fff"/>',
  pass: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M7.5 12.3l3 3 6-6.3" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  accepted: '<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M8 12h8" stroke="#fff" stroke-width="2" stroke-linecap="round"/>',
  chevron: '<path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  shield: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
};
function icon(name, cls) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none");
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
function showError(text) { $("message").replaceChildren(text ? h("div", { class: "error", role: "alert" }, text) : ""); }
function showInfo(text) { $("message").replaceChildren(h("p", { class: "info", role: "status" }, text)); }

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
  $("run").replaceChildren(busy ? h("span", { class: "spin", "aria-hidden": "true" }) : "", busy ? (label || " Checking…") : "Run Checks");
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
  setBusy(true, target === "inventory" ? " Checking hosts…" : " Checking…");
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
  note.textContent = labPush ? "Comparing against the lab keys (ops, deploy, ci), not yours." : (state.push.length ? `Comparing against ${state.push.length} key${state.push.length === 1 ? "" : "s"}. Fingerprints only.` : "");
  $("pushset").replaceChildren(...state.push.map((k) => h("div", {}, `${k.fingerprint.slice(0, 19)}…  ${k.comment || k.type}`)));
}

function stats() {
  const hosts = state.report ? state.report.hosts : [];
  const keys = hosts.flatMap((host) => host.keys || []);
  const failed = hosts.reduce((n, host) => n + host.findings.filter((f) => f.severity === "fail").length, 0);
  const tiles = [
    ["Hosts", hosts.length, "c-blue"],
    ["Failing hosts", hosts.filter((host) => host.posture === "fail").length, "c-red"],
    ["Failed checks", failed, "c-red"],
    ["Keys to root", keys.filter((k) => k.reach === "root" || k.reach === "root-nopasswd").length, "c-orange"],
    ["Stale keys", keys.filter((k) => k.usage === "stale").length, "c-orange"],
  ];
  $("stats").hidden = !state.report;
  $("stats").replaceChildren(...tiles.map(([label, value, cls]) => h("div", { class: "stat " + cls }, h("span", {}, label), h("b", {}, value))));
}

const ORDER = { fail: 0, warn: 1, accepted: 2, pass: 3 };
function when(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  return isNaN(date) ? iso : date.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit" });
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
    passes.length ? h("details", { class: "passes" }, h("summary", {}, `Show ${passes.length} passing check${passes.length === 1 ? "" : "s"}`), passes.map(findingRow)) : "");
  const sev = host.posture === "fail" ? "fail" : host.posture === "warn" ? "warn" : "pass";
  const count = fails ? `${fails} failed` : warns ? `${warns} to review` : "Passed";
  const head = h("button", { class: "host-head", type: "button", "aria-expanded": open ? "true" : "false", onclick: () => {
      const now = card.dataset.open !== "true";
      card.dataset.open = String(now); list.hidden = !now; head.setAttribute("aria-expanded", String(now));
    } },
    h("span", { class: "sev-" + sev }, icon(sev, "ico")),
    h("span", {}, h("span", { class: "name" }, host.name), host.roleLabel ? h("span", { class: "role" }, host.roleLabel) : ""),
    h("span", { class: "count sev-" + sev }, count),
    icon("chevron", "chev"),
    h("span", { class: "meta" }, [host.address, host.observedAt ? "Checked " + when(host.observedAt) : "", host.authLog && host.authLog !== "unknown" ? "Logs: " + host.authLog : ""].filter(Boolean).join("  ·  ")));
  card.append(head, list);
  return card;
}

function emptyState() {
  return h("div", { class: "empty" },
    h("div", { class: "glyph" }, icon("shield", "ico")),
    h("b", {}, "Check who can get in"),
    h("span", {}, "Paste the public keys you push, choose what to check, and run. Keys are fingerprinted and never stored."),
    h("button", { class: "btn", type: "button", onclick: () => { $("lab").click(); setTimeout(() => runCheck("lab"), 150); } }, "Try the Lab Hosts"));
}

function renderFilters() {
  const box = $("filters");
  if (!state.report || state.view !== "findings") { box.replaceChildren(); return; }
  const hosts = state.report.hosts;
  const needs = hosts.filter((host) => host.posture !== "pass").length;
  const clear = hosts.length - needs;
  box.replaceChildren(h("div", { class: "segmented", role: "group", "aria-label": "Filter hosts" },
    [["work", `Needs Work (${needs})`], ["all", `All (${hosts.length})`], ["clear", `Passed (${clear})`]].map(([key, label]) =>
      h("button", { type: "button", "aria-pressed": state.filter === key ? "true" : "false", onclick: () => { state.filter = key; renderFindings(); renderFilters(); } }, label))));
}

function renderFindings() {
  const view = $("view-findings");
  if (!state.report) { view.replaceChildren(emptyState()); return; }
  const hosts = state.report.hosts;
  const pick = state.filter === "work" ? hosts.filter((x) => x.posture !== "pass") : state.filter === "clear" ? hosts.filter((x) => x.posture === "pass") : hosts;
  const rank = (host) => (host.posture === "fail" ? 0 : host.posture === "warn" ? 1 : 2);
  const ordered = [...pick].sort((a, b) => rank(a) - rank(b));
  view.replaceChildren(ordered.length
    ? h("div", { class: "hosts" }, ordered.map((host, index) => hostCard(host, index === 0 && host.posture !== "pass")))
    : h("div", { class: "empty" }, h("b", {}, state.filter === "work" ? "Every host passed" : "No host passed every check yet")));
}

const COLUMNS = [["host", "Host"], ["account", "Account"], ["fingerprint", "Fingerprint"], ["reach", "Reach"], ["usage", "Usage"], ["lastUsed", "Last Used"], ["from", "From"], ["inAllow", "In Push"], ["comment", "Comment"]];
function cell(row, key) {
  if (key === "from") return (row.options.from || []).join(", ") || "Any";
  if (key === "inAllow") return row.inAllow == null ? "–" : row.inAllow ? "Yes" : "No";
  if (key === "lastUsed") return row.lastUsed ? row.lastUsed.slice(0, 10) : "–";
  return row[key] == null || row[key] === "" ? "–" : String(row[key]);
}
function renderReview() {
  const view = $("view-review");
  if (!state.report) { view.replaceChildren(emptyState()); return; }
  let rows = state.report.hosts.flatMap((host) => host.keys || []);
  if (state.onlyRoot) rows = rows.filter((r) => r.reach === "root" || r.reach === "root-nopasswd");
  if (state.onlyStale) rows = rows.filter((r) => r.usage === "stale");
  const { key, dir } = state.sort;
  rows = [...rows].sort((a, b) => cell(a, key).localeCompare(cell(b, key), undefined, { numeric: true }) * dir);
  const toggle = (id, label, value, set) => h("label", { class: "option" }, h("span", {}, label), h("input", { type: "checkbox", id, checked: value, onchange: (e) => { set(e.target.checked); renderReview(); } }));
  const tools = h("div", { class: "table-tools" },
    toggle("only-root", "Only keys that reach root", state.onlyRoot, (v) => { state.onlyRoot = v; }),
    toggle("only-stale", "Only stale keys", state.onlyStale, (v) => { state.onlyStale = v; }),
    h("span", {}, `${rows.length} key${rows.length === 1 ? "" : "s"}`));
  const pillFor = (k, v) => {
    if (k === "reach") return h("span", { class: "pill " + (v === "root" || v === "root-nopasswd" ? "bad" : v === "root-password" ? "warnp" : "") }, v);
    if (k === "usage") return h("span", { class: "pill " + (v === "stale" ? "bad" : v === "fresh" ? "ok" : "warnp") }, v);
    return v;
  };
  const table = h("table", {},
    h("thead", {}, h("tr", {}, COLUMNS.map(([k, label]) => h("th", { scope: "col", "aria-sort": key === k ? (dir > 0 ? "ascending" : "descending") : "none" },
      h("button", { type: "button", onclick: () => { state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 }; renderReview(); } }, label + (key === k ? (dir > 0 ? " ▲" : " ▼") : "")))))),
    h("tbody", {}, rows.map((row) => h("tr", {}, COLUMNS.map(([k]) => h("td", { class: k === "fingerprint" ? "fp" : (k === "from" || k === "lastUsed" ? "mono" : "") }, pillFor(k, cell(row, k))))))));
  view.replaceChildren(h("div", { class: "hosts" }, tools, h("div", { class: "table-wrap" }, table)));
}

const TITLES = { findings: "Findings", review: "Access Review", find: "Find a Key" };
function renderHeading() {
  $("page-title").textContent = TITLES[state.view];
  const r = state.report;
  $("page-sub").textContent = r ? `${r.hosts.length} host${r.hosts.length === 1 ? "" : "s"} checked ${when(r.generatedAt)}${state.lab ? " · lab data" : ""}` : "No hosts checked yet";
}

function renderAll(notes) {
  stats(); renderFindings(); renderReview(); renderFilters(); renderHeading();
  const lines = [...(notes || [])];
  if (state.report && state.lab) lines.push("Lab hosts are a fixed example observation: what the collector reports back for sshd, sudo rights, logins, and fingerprints. app-web-03 and ci-runner regressed against the previous run.");
  $("notes").replaceChildren(...lines.map((line) => h("p", { class: "lab-note" }, line)));
}

function showView(name) {
  state.view = name;
  for (const tab of document.querySelectorAll('[role="tab"]')) tab.setAttribute("aria-selected", String(tab.dataset.view === name));
  for (const v of ["findings", "review", "find"]) $("view-" + v).hidden = v !== name;
  $("stats").hidden = !state.report || name === "find";
  renderFilters(); renderHeading();
}

async function findKey() {
  if (state.busy) return;
  showError("");
  const body = Object.assign(baseBody(selectedTarget()), { fingerprints: [$("find-fp").value.trim()].filter(Boolean), keyText: $("find-key").value });
  $("find-key").value = "";
  setBusy(true);
  $("find").replaceChildren(h("span", { class: "spin", "aria-hidden": "true" }), " Searching…");
  try {
    const data = await api("/api/where", body);
    const hits = data.found.map((hit) => h("div", { class: "hit" },
      h("div", { class: "where" }, `${hit.host}  ·  ${hit.account}`),
      h("div", {}, `${hit.how}. Reach: ${hit.reach}${hit.reachVia ? " (" + hit.reachVia + ")" : ""}. From: ${hit.from.length ? hit.from.join(", ") : "any address"}. Last used: ${hit.lastUsed ? when(hit.lastUsed) : "no login in the logs"}.`),
      h("div", { class: "mono" }, hit.fingerprint)));
    const blind = data.notChecked.map((line) => h("p", { class: "lab-note" }, line));
    $("hits").replaceChildren(hits.length ? h("p", { class: "info" }, `Found in ${hits.length} place${hits.length === 1 ? "" : "s"}.`) : h("div", { class: "empty" }, h("b", {}, "Not found on any host that could be read")), ...hits, ...blind);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
    $("find").replaceChildren("Find Key");
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
  showInfo("Keys cleared. Paste keys again before the next run.");
});
$("export-json").addEventListener("click", () => state.report && download(`keywarden-${stamp()}.json`, "application/json", JSON.stringify(state.report, null, 2)));
$("export-csv").addEventListener("click", () => state.csv && download(`keywarden-access-review-${stamp()}.csv`, "text/csv", state.csv));
$("copy-collector").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    const data = await api("/api/collector");
    await navigator.clipboard.writeText("sh -s -- root <<'KEYWARDEN'\n" + data.script + "\nKEYWARDEN\n");
    button.textContent = "Copied";
  } catch (error) { button.textContent = "Copy failed"; }
  setTimeout(() => { button.textContent = "Copy Collector Script"; }, 2000);
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
