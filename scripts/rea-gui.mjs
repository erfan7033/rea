#!/usr/bin/env node

/**
 * REA Workbench: a local browser GUI over the extraction pipeline.
 *
 * Binds to 127.0.0.1 only. No external dependencies. The browser talks to a
 * short-lived local HTTP server; decompilation runs through the same
 * `rea-dotnet` CLI used from the terminal.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const decompileScript = join(repoRoot, "scripts", "rea-dotnet-decompile.mjs");
const TOKEN = randomBytes(16).toString("hex");
const MAX_BODY = 1_000_000;
const MAX_LOG_CHARS = 2_000_000;

const parseArgs = (argv) => {
  const options = { port: 0, open: true };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--port") options.port = Number(argv[++index]);
    else if (value === "--no-open") options.open = false;
    else if (value === "--open") options.open = true;
    else if (value === "--help" || value === "-h") options.help = true;
    else throw new Error(`Unknown option: ${value}`);
  }
  return options;
};

const usage = () => `Usage: rea-gui [options]

Options:
  --port <number>   Port to listen on (default: random)
  --no-open         Do not open the browser automatically
  --help            Show this help
`;

const exists = async (path) => {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
};

const json = (response, status, value) => {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(value));
};

const text = (response, status, value, type = "text/plain; charset=utf-8") => {
  response.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store",
  });
  response.end(value);
};

const readBody = (request) =>
  new Promise((settle, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY) {
        reject(new Error("Request body is too large"));
        request.destroy();
      }
    });
    request.on("end", () => settle(body));
    request.on("error", reject);
  });

const stripAnsi = (value) => value.replace(/\u001b\[[0-9;]*m/gu, "");

const authorized = (request, url) =>
  request.headers["x-rea-token"] === TOKEN ||
  url.searchParams.get("token") === TOKEN;

const openPath = (path) => {
  if (process.platform === "win32") {
    const command = /^https?:/u.test(path)
      ? ["cmd", ["/c", "start", "", path]]
      : ["explorer", [path]];
    return spawn(command[0], command[1], {
      stdio: "ignore",
      detached: true,
      windowsHide: true,
    }).unref();
  }
  const command =
    process.platform === "darwin" ? ["open", [path]] : ["xdg-open", [path]];
  return spawn(command[0], command[1], {
    stdio: "ignore",
    detached: true,
  }).unref();
};

const pickFolder = () =>
  new Promise((settle) => {
    const command =
      process.platform === "win32"
        ? [
            "powershell.exe",
            [
              "-NoProfile",
              "-Command",
              "Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; if($d.ShowDialog() -eq 'OK'){ Write-Output $d.SelectedPath }",
            ],
          ]
        : process.platform === "darwin"
          ? ["osascript", ["-e", "POSIX path of (choose folder)"]]
          : ["zenity", ["--file-selection", "--directory"]];
    const child = spawn(command[0], command[1], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", () =>
      settle({ ok: false, error: "No native folder picker is available." }),
    );
    child.on("close", (code) => {
      const path = stdout.trim().split("\n")[0];
      if (code === 0 && path.length > 0) settle({ ok: true, path });
      else
        settle({
          ok: false,
          error: stderr.trim() || "Folder selection was cancelled.",
        });
    });
  });

const runs = new Map();

const reaGoalScript = join(repoRoot, "scripts", "rea-goal.mjs");

const startProcess = (args, { target, output, kind }) => {
  const id = randomBytes(8).toString("hex");
  const child = spawn(process.execPath, args, {
    cwd: repoRoot,
    env: process.env,
  });
  const run = {
    id,
    kind,
    child,
    output,
    target,
    logs: [],
    chars: 0,
    listeners: new Set(),
    done: false,
    code: null,
    error: null,
  };
  const push = (value) => {
    const clean = stripAnsi(value);
    run.chars += clean.length;
    while (run.chars > MAX_LOG_CHARS && run.logs.length > 1) {
      run.chars -= run.logs.shift().length;
    }
    run.logs.push(clean);
    for (const listener of run.listeners) listener(clean);
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", push);
  child.stderr.on("data", push);
  child.on("error", (cause) => {
    run.error = cause.message;
    push(`Error: ${cause.message}\n`);
  });
  child.on("close", (code) => {
    run.done = true;
    run.code = code;
    for (const listener of run.listeners) listener(null);
  });
  runs.set(id, run);
  return run;
};

const startRun = (body) => {
  const target = resolve(String(body.path ?? ""));
  const output = resolve(String(body.output ?? ""));
  const args = [decompileScript, target, output];
  if (body.repo === true) args.push("--repo");
  if (body.force === true) args.push("--force");
  if (body.noMembers === true) args.push("--no-members");
  if (body.allIl2cpp === true) args.push("--all-il2cpp");
  if (body.noIl2cppCode === true) args.push("--no-il2cpp-code");
  if (body.allBundles === true) args.push("--all-bundles");
  if (body.includeFramework === true) args.push("--include-framework");
  if (body.noPdb === true) args.push("--no-pdb");
  if (body.noReferenceRewrite === true) args.push("--no-reference-rewrite");
  if (body.noHashScan === true) args.push("--no-hash-scan");
  if (body.noLicenseScan === true) args.push("--no-license-scan");
  if (body.gitInit === true) args.push("--git-init");
  if (body.build === true) args.push("--build");
  args.push("--quiet");
  return startProcess(args, { target, output, kind: "extract" });
};

const startAgent = (body) => {
  const output = resolve(String(body.output ?? ""));
  const runDirectory = join(output, `agent-run-${String(Date.now())}`);
  const model = String(body.model ?? "qwen2.5-coder:7b");
  const baseUrl = String(body.baseUrl ?? "http://127.0.0.1:11434/v1");
  const goal = String(
    body.goal ??
      "Make this recovered repository build. Fix one project at a time, record commands, and report unknowns.",
  );
  const args = [
    reaGoalScript,
    "--goal",
    goal,
    "--target",
    output,
    "--out",
    runDirectory,
    "--local-model",
    model,
    "--base-url",
    baseUrl,
    "--auto",
  ];
  return startProcess(args, {
    target: output,
    output: runDirectory,
    kind: "agent",
  });
};

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REA Workbench</title>
<style>
:root { color-scheme: dark; --bg:#0e1116; --panel:#171c23; --line:#2a323d; --text:#e6edf3; --muted:#8b98a8; --accent:#4cc2ff; --ok:#3fb950; --bad:#f85149; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
header { padding:18px 24px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; }
header h1 { font-size:18px; margin:0; font-weight:650; }
header .badge { color:var(--muted); font-size:12px; border:1px solid var(--line); padding:2px 8px; border-radius:999px; }
main { display:grid; grid-template-columns:minmax(360px, 460px) 1fr; gap:18px; padding:18px 24px 40px; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
h2 { font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:0 0 12px; }
label { display:block; font-size:12px; color:var(--muted); margin:10px 0 5px; }
input[type=text] { width:100%; background:#0b0f14; border:1px solid var(--line); border-radius:8px; color:var(--text); padding:9px 10px; font:13px ui-monospace,SFMono-Regular,Consolas,monospace; }
.row { display:flex; gap:8px; }
.row input { flex:1; }
button { background:#222b36; color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px 12px; cursor:pointer; font-weight:600; }
button:hover { border-color:#3d4a5a; }
button.primary { background:var(--accent); color:#04121a; border-color:var(--accent); }
button:disabled { opacity:.45; cursor:not-allowed; }
.checks { display:grid; grid-template-columns:1fr 1fr; gap:6px 10px; margin-top:12px; }
.checks label { display:flex; gap:6px; align-items:center; margin:0; color:var(--text); font-size:12px; }
.actions { display:flex; gap:8px; margin-top:16px; flex-wrap:wrap; }
.status { margin-top:14px; font-size:12px; color:var(--muted); min-height:18px; }
.status.ok { color:var(--ok); } .status.bad { color:var(--bad); }
pre { margin:0; padding:12px; background:#080b0f; border:1px solid var(--line); border-radius:10px; overflow:auto; max-height:45vh; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; }
#detect { margin-top:14px; font-size:13px; }
.kv { display:grid; grid-template-columns:140px 1fr; gap:4px 10px; font-size:13px; }
.kv div:nth-child(odd) { color:var(--muted); }
.tabs { display:flex; gap:6px; margin-bottom:10px; }
.tabs button { font-size:12px; padding:6px 10px; }
.tabs button.active { border-color:var(--accent); color:var(--accent); }
table { width:100%; border-collapse:collapse; font-size:12px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; }
a { color:var(--accent); }
footer { color:var(--muted); font-size:12px; padding:0 24px 30px; }
@media (max-width: 900px) { main { grid-template-columns:1fr; } }
</style>
</head>
<body>
<header><h1>REA Workbench</h1><span class="badge">local only</span><span class="badge" id="platform"></span></header>
<main>
  <section class="panel">
    <h2>Input</h2>
    <label for="target">Product folder, .exe, .dll, or .app</label>
    <div class="row"><input id="target" type="text" placeholder="C:\\Path\\To\\Product or /path/to/product" autocomplete="off"><button id="browse">Browse</button></div>
    <label for="output">Output folder</label>
    <input id="output" type="text" placeholder="C:\\Path\\To\\Product-rea-out" autocomplete="off">
    <div class="checks">
      <label><input id="repo" type="checkbox" checked> Build repo scaffold</label>
      <label><input id="force" type="checkbox"> Allow non-empty output</label>
      <label><input id="noMembers" type="checkbox"> Skip member summaries</label>
      <label><input id="allIl2cpp" type="checkbox"> All IL2CPP assemblies</label>
      <label><input id="noIl2cppCode" type="checkbox"> IL2CPP dump only</label>
      <label><input id="allBundles" type="checkbox"> All bundle entries</label>
      <label><input id="includeFramework" type="checkbox"> Include framework assemblies</label>
      <label><input id="noPdb" type="checkbox"> Ignore sidecar PDBs</label>
      <label><input id="noReferenceRewrite" type="checkbox"> Keep ILSpy references</label>
      <label><input id="noHashScan" type="checkbox"> Skip hash scan</label>
      <label><input id="noLicenseScan" type="checkbox"> Skip license scan</label>
      <label><input id="gitInit" type="checkbox"> git init output</label>
      <label><input id="build" type="checkbox"> Attempt build</label>
    </div>
    <div class="actions">
      <button id="scan">Scan</button>
      <button id="run" class="primary">Decompile</button>
      <button id="cancel" disabled>Cancel</button>
      <button id="open" disabled>Open output</button>
    </div>
    <div class="status" id="status"></div>
    <div id="detect"></div>
    <details style="margin-top:16px">
      <summary style="cursor:pointer;color:var(--muted);font-size:13px">AI rewrite with a local model</summary>
      <label for="agentModel">Model (Ollama)</label>
      <input id="agentModel" type="text" value="qwen2.5-coder:7b">
      <label for="agentBase">Base URL</label>
      <input id="agentBase" type="text" value="http://127.0.0.1:11434/v1">
      <label for="agentGoal">Goal</label>
      <input id="agentGoal" type="text" value="Make this recovered repository build. Fix one project at a time and report unknowns.">
      <div class="actions"><button id="agentRun">Run agent</button></div>
      <div class="status">Requires Ollama running and the model pulled. Agent output goes to an <code>agent-run-*</code> folder.</div>
    </details>
  </section>
  <section class="panel">
    <div class="tabs"><button id="tab-log" class="active">Log</button><button id="tab-result">Result</button><button id="tab-report">Report</button></div>
    <pre id="log" hidden></pre>
    <div id="result" hidden></div>
    <pre id="report" hidden></pre>
  </section>
</main>
<footer>Static analysis only. Targets are never executed. The browser UI is bound to 127.0.0.1 and requires this session's token.</footer>
<script>
const token = new URLSearchParams(location.search).get("token") || "";
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const setStatus = (value, kind) => { const el = $("status"); el.textContent = value; el.className = "status " + (kind || ""); };
const api = async (path, body) => {
  const response = await fetch(path, { method: "POST", headers: { "content-type": "application/json", "x-rea-token": token }, body: JSON.stringify(body) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
};
const showTab = (name) => {
  for (const id of ["log","result","report"]) $(id).hidden = id !== name;
  for (const id of ["tab-log","tab-result","tab-report"]) $(id).className = id === "tab-"+name ? "active" : "";
};
$("tab-log").onclick = () => showTab("log");
$("tab-result").onclick = () => showTab("result");
$("tab-report").onclick = () => showTab("report");
$("platform").textContent = navigator.platform || "";
const defaultOutput = () => {
  const target = $("target").value.trim().replace(/[\\\\/]+$/, "");
  if (!target) return "";
  return target + "-rea-out";
};
$("target").addEventListener("change", () => { if (!$("output").value.trim()) $("output").value = defaultOutput(); });
$("browse").onclick = async () => {
  setStatus("Opening folder picker...");
  try { const r = await api("/api/browse", {}); if (r.path) { $("target").value = r.path; $("output").value = defaultOutput(); setStatus(""); } else setStatus(r.error || "Cancelled", "bad"); }
  catch (e) { setStatus(e.message, "bad"); }
};
const options = () => ({
  path: $("target").value.trim(),
  output: $("output").value.trim(),
  repo: $("repo").checked,
  force: $("force").checked,
  noMembers: $("noMembers").checked,
  allIl2cpp: $("allIl2cpp").checked,
  noIl2cppCode: $("noIl2cppCode").checked,
  allBundles: $("allBundles").checked,
  includeFramework: $("includeFramework").checked,
  noPdb: $("noPdb").checked,
  noReferenceRewrite: $("noReferenceRewrite").checked,
  noHashScan: $("noHashScan").checked,
  noLicenseScan: $("noLicenseScan").checked,
  gitInit: $("gitInit").checked,
  build: $("build").checked,
});
$("scan").onclick = async () => {
  const path = $("target").value.trim();
  if (!path) { setStatus("Choose a target first.", "bad"); return; }
  $("scan").disabled = true; setStatus("Scanning...");
  try {
    const r = await api("/api/scan", { path });
    const c = r.counts;
    const kind = r.il2cpp ? "Unity IL2CPP" : c.single_file > 0 ? "Single-file .NET" : c.managed > 0 ? "Managed .NET" : c.native > 0 ? "Native" : "Unknown";
    $("detect").innerHTML = '<div class="kv">' +
      '<div>Detected</div><div><strong>' + esc(kind) + '</strong></div>' +
      '<div>Candidates</div><div>' + esc(r.candidates) + '</div>' +
      '<div>Managed</div><div>' + esc(c.managed) + '</div>' +
      '<div>Single-file</div><div>' + esc(c.single_file) + '</div>' +
      '<div>Native</div><div>' + esc(c.native) + '</div>' +
      (r.il2cpp ? '<div>Metadata</div><div>' + esc(r.il2cpp.metadata || "missing") + '</div><div>GameAssembly</div><div>' + esc(r.il2cpp.binary || "missing") + '</div>' : '') +
      '</div>';
    if (!$("output").value.trim()) $("output").value = defaultOutput();
    setStatus("Scan complete.", "ok");
  } catch (e) { setStatus(e.message, "bad"); }
  finally { $("scan").disabled = false; }
};
let source = null;
const streamRun = (id, onDone) => {
  source = new EventSource("/api/stream/" + id + "?token=" + encodeURIComponent(token));
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "log") { $("log").textContent += payload.text; $("log").scrollTop = $("log").scrollHeight; }
    if (payload.type === "done") {
      source.close();
      $("run").disabled = false; $("scan").disabled = false; $("agentRun").disabled = false; $("cancel").disabled = true;
      onDone(payload);
    }
  };
  source.onerror = () => { source.close(); $("run").disabled = false; $("scan").disabled = false; $("agentRun").disabled = false; $("cancel").disabled = true; setStatus("Log stream closed.", "bad"); };
};
$("agentRun").onclick = async () => {
  const output = $("output").value.trim();
  if (!output) { setStatus("Run an extraction first so an output folder exists.", "bad"); return; }
  $("log").textContent = ""; showTab("log");
  $("run").disabled = true; $("scan").disabled = true; $("agentRun").disabled = true; $("cancel").disabled = false;
  setStatus("Starting local agent...");
  try {
    const r = await api("/api/agent", { output, model: $("agentModel").value.trim(), baseUrl: $("agentBase").value.trim(), goal: $("agentGoal").value.trim() });
    streamRun(r.id, (payload) => {
      setStatus(payload.code === 0 ? "Agent finished." : "Agent finished with errors (code " + payload.code + ").", payload.code === 0 ? "ok" : "bad");
      if (payload.kind === "agent") { $("open").disabled = false; } else loadResult(output);
    });
  } catch (e) { $("run").disabled = false; $("scan").disabled = false; $("agentRun").disabled = false; $("cancel").disabled = true; setStatus(e.message, "bad"); }
};
$("run").onclick = async () => {
  const body = options();
  if (!body.path) { setStatus("Choose a target first.", "bad"); return; }
  if (!body.output) { body.output = defaultOutput(); $("output").value = body.output; }
  $("log").textContent = ""; $("result").innerHTML = ""; $("report").textContent = ""; showTab("log");
  $("run").disabled = true; $("scan").disabled = true; $("cancel").disabled = false;
  setStatus("Starting extraction...");
  try {
    const r = await api("/api/run", body);
    streamRun(r.id, (payload) => {
      $("open").disabled = false;
      setStatus(payload.code === 0 ? "Extraction complete." : "Extraction finished with errors (code " + payload.code + ").", payload.code === 0 ? "ok" : "bad");
      loadResult(body.output);
    });
  } catch (e) { $("run").disabled = false; $("scan").disabled = false; $("cancel").disabled = true; setStatus(e.message, "bad"); }
};
$("cancel").onclick = async () => { try { await api("/api/cancel", {}); setStatus("Cancellation requested."); } catch (e) { setStatus(e.message, "bad"); } };
$("open").onclick = async () => { try { await api("/api/open", { path: $("output").value.trim() }); } catch (e) { setStatus(e.message, "bad"); } };
async function loadResult(out) {
  try {
    const r = await api("/api/result", { path: out });
    const m = r.manifest;
    const rows = (m.assemblies || []).map(a => '<tr><td>'+esc(a.name)+'</td><td>'+esc(a.runtime_family||'unknown')+'</td><td>'+esc(a.decompiled_files)+'</td><td>'+esc(a.status)+'</td></tr>').join("");
    const bundles = (m.bundles || []).map(b => '<tr><td>'+esc(b.path)+'</td><td>'+esc(b.entries)+'</td><td>'+esc(b.status)+'</td></tr>').join("");
    $("result").innerHTML = '<div class="kv">' +
      '<div>Output</div><div>'+esc(m.output)+'</div>' +
      '<div>Managed</div><div>'+esc(m.counts.managed)+'</div>' +
      '<div>Bundles</div><div>'+esc(m.counts.bundles)+'</div>' +
      '<div>IL2CPP</div><div>'+esc(m.counts.il2cpp)+'</div>' +
      '<div>Native</div><div>'+esc(m.counts.native)+'</div>' +
      '<div>C# files</div><div>'+esc(m.counts.source_files)+'</div>' +
      (m.repo ? '<div>Repository</div><div>'+esc(m.repo.projects)+' projects · '+esc(m.repo.solution?.file || "no solution")+'</div>' : '') +
      (m.references ? '<div>References</div><div>'+esc(m.references.rewritten.length)+' rewritten · '+esc(m.references.references.length)+' vendored · '+esc(m.references.unresolved.length)+' unresolved</div>' : '') +
      (m.hash_scan ? '<div>Hashes</div><div>'+esc(m.hash_scan.total_candidates)+' candidates in '+esc(m.hash_scan.assemblies_scanned)+' assemblies</div>' : '') +
      (m.license_scan ? '<div>License</div><div>'+esc(m.license_scan.present)+' present · '+esc(m.license_scan.suspicious)+' suspicious</div>' : '') +
      (m.build ? '<div>Build</div><div>'+ (m.build.ok ? 'all projects built' : esc(m.build.failed)+' of '+esc(m.build.projects)+' failed') +'</div>' : '') +
      '</div>' +
      (rows ? '<h2 style="margin-top:16px">Assemblies</h2><table><thead><tr><th>Name</th><th>Runtime</th><th>.cs</th><th>Status</th></tr></thead><tbody>'+rows+'</tbody></table>' : '') +
      (bundles ? '<h2 style="margin-top:16px">Bundles</h2><table><thead><tr><th>Bundle</th><th>Entries</th><th>Status</th></tr></thead><tbody>'+bundles+'</tbody></table>' : '');
    $("report").textContent = r.report || "";
    showTab("result");
  } catch (e) { setStatus(e.message, "bad"); }
}
</script>
</body>
</html>`;

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  try {
    if (
      request.method === "GET" &&
      (url.pathname === "/" || url.pathname === "/index.html")
    ) {
      return text(response, 200, html, "text/html; charset=utf-8");
    }
    if (request.method === "GET" && url.pathname === "/api/health") {
      return json(response, 200, { ok: true });
    }
    if (url.pathname.startsWith("/api/") && !authorized(request, url)) {
      return json(response, 403, {
        error: "Missing or invalid session token.",
      });
    }
    if (request.method === "POST" && url.pathname === "/api/scan") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const target = resolve(String(body.path ?? ""));
      if (!(await exists(target)))
        return json(response, 400, {
          error: `Target does not exist: ${target}`,
        });
      const child = spawn(
        process.execPath,
        [decompileScript, "--detect", target],
        {
          cwd: repoRoot,
          env: process.env,
        },
      );
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("close", (code) => {
        if (code !== 0)
          return json(response, 500, {
            error: stderr.trim() || `Scan exited ${String(code)}`,
          });
        try {
          return json(response, 200, JSON.parse(stdout));
        } catch {
          return json(response, 500, { error: "Scan returned invalid JSON." });
        }
      });
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/run") {
      const body = JSON.parse((await readBody(request)) || "{}");
      if (typeof body.path !== "string" || body.path.trim().length === 0)
        return json(response, 400, { error: "Target path is required." });
      if (!(await exists(resolve(body.path))))
        return json(response, 400, { error: "Target does not exist." });
      if (typeof body.output !== "string" || body.output.trim().length === 0)
        return json(response, 400, { error: "Output path is required." });
      if ([...runs.values()].some((run) => !run.done))
        return json(response, 409, {
          error: "An extraction is already running.",
        });
      const run = startRun(body);
      return json(response, 200, { id: run.id });
    }
    if (request.method === "POST" && url.pathname === "/api/agent") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const output = resolve(String(body.output ?? ""));
      if (!(await exists(output)))
        return json(response, 400, {
          error: "Run an extraction first; the output folder does not exist.",
        });
      if ([...runs.values()].some((run) => !run.done))
        return json(response, 409, { error: "A run is already active." });
      const run = startAgent(body);
      return json(response, 200, { id: run.id });
    }
    if (request.method === "GET" && url.pathname.startsWith("/api/stream/")) {
      const id = url.pathname.slice("/api/stream/".length);
      const run = runs.get(id);
      if (run === undefined)
        return json(response, 404, { error: "Unknown run." });
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        connection: "keep-alive",
      });
      const send = (payload) =>
        response.write(`data: ${JSON.stringify(payload)}\n\n`);
      for (const log of run.logs) send({ type: "log", text: log });
      const listener = (chunk) => {
        if (chunk === null) {
          send({ type: "done", code: run.code ?? 1, kind: run.kind });
          response.end();
        } else send({ type: "log", text: chunk });
      };
      run.listeners.add(listener);
      if (run.done) listener(null);
      request.on("close", () => run.listeners.delete(listener));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/cancel") {
      for (const run of runs.values()) if (!run.done) run.child.kill("SIGTERM");
      return json(response, 200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/api/result") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const output = resolve(String(body.path ?? ""));
      const manifestPath = join(output, "manifest.json");
      let manifest;
      let report = "";
      try {
        manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        report = await readFile(join(output, "REPORT.md"), "utf8");
      } catch (cause) {
        return json(response, 404, {
          error: `No result in ${output}: ${cause.message}`,
        });
      }
      return json(response, 200, { manifest, report });
    }
    if (request.method === "POST" && url.pathname === "/api/open") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const path = resolve(String(body.path ?? ""));
      if (!(await exists(path)))
        return json(response, 404, { error: `Path does not exist: ${path}` });
      openPath(path);
      return json(response, 200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/api/browse") {
      const result = await pickFolder();
      return json(response, result.ok ? 200 : 400, result);
    }
    return json(response, 404, { error: "Not found." });
  } catch (cause) {
    return json(response, 500, {
      error: cause instanceof Error ? cause.message : String(cause),
    });
  }
});

const options = parseArgs(process.argv.slice(2));
if (options.help) {
  process.stdout.write(usage());
  process.exit(0);
}
server.on("error", (cause) => {
  process.stderr.write(`REA Workbench failed to listen: ${cause.message}\n`);
  process.exit(1);
});
server.listen(options.port, "127.0.0.1", () => {
  const address = server.address();
  const port =
    typeof address === "object" && address !== null
      ? address.port
      : options.port;
  const url = `http://127.0.0.1:${String(port)}/?token=${TOKEN}`;
  process.stdout.write(`REA Workbench: ${url}\n`);
  if (options.open) openPath(url);
});
