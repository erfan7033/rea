#!/usr/bin/env node

/**
 * REA Workbench: a local browser GUI over the .NET extraction pipeline.
 *
 * Guided wizard covering every step: pick a target, scan it, configure the
 * extraction, run it with live logs, review the manifest, inspect each
 * assembly, browse recovered files, build the recovered projects, and hand
 * off to an agent. Each step carries a plain-English how-to.
 *
 * Binds to 127.0.0.1 only. No external dependencies. The browser talks to a
 * short-lived local HTTP server; decompilation runs through the same
 * `rea-dotnet` CLI used from the terminal. Targets are never executed.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { access, readdir, readFile, stat } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const decompileScript = join(repoRoot, "scripts", "rea-dotnet-decompile.mjs");
const reaGoalScript = join(repoRoot, "scripts", "rea-goal.mjs");
const TOKEN = randomBytes(16).toString("hex");
const MAX_BODY = 1_000_000;
const MAX_LOG_CHARS = 2_000_000;
const MAX_TREE_ENTRIES = 2000;
const MAX_FILE_BYTES = 256 * 1024;

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

Guided local web UI for the .NET extraction pipeline (rea-dotnet):
pick a target, scan it, configure, run, review, inspect assemblies,
browse files, build, and hand off to an agent.

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

const stripAnsi = (value) => value.replace(/\u001B\[[0-9;]*m/gu, "");

const authorized = (request, url) =>
  request.headers["x-rea-token"] === TOKEN ||
  url.searchParams.get("token") === TOKEN;

/** Resolve a UI-supplied relative path strictly inside the output folder. */
const insideOutput = (output, rel) => {
  const candidate = resolve(output, String(rel ?? ""));
  if (candidate === output || candidate.startsWith(output + sep))
    return candidate;
  return null;
};

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
      const picked = stdout.trim().split("\n")[0];
      if (code === 0 && picked.length > 0) settle({ ok: true, path: picked });
      else
        settle({
          ok: false,
          error: stderr.trim() || "Folder selection was cancelled.",
        });
    });
  });

const runs = new Map();

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
  if (body.noSingleFile === true) args.push("--no-single-file");
  if (body.noIl2cpp === true) args.push("--no-il2cpp");
  if (body.allIl2cpp === true) args.push("--all-il2cpp");
  if (body.noIl2cppCode === true) args.push("--no-il2cpp-code");
  if (body.allBundles === true) args.push("--all-bundles");
  if (body.includeFramework === true) args.push("--include-framework");
  if (body.noPdb === true) args.push("--no-pdb");
  if (body.noReferenceRewrite === true) args.push("--no-reference-rewrite");
  if (body.noHashScan === true) args.push("--no-hash-scan");
  if (body.noLicenseScan === true) args.push("--no-license-scan");
  if (body.noSymbols === true) args.push("--no-symbols");
  if (body.noResources === true) args.push("--no-resources");
  if (body.noDeployment === true) args.push("--no-deployment");
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

/**
 * Sequential `dotnet build` over the recovered solution (or every recovered
 * project when there is no solution). Runs inside one child process so the
 * log stream stays ordered; prints ### markers the UI reads for verdicts.
 */
const buildRunnerCode = [
  "const { spawn } = require('node:child_process');",
  "const { readdir } = require('node:fs/promises');",
  "const { join } = require('node:path');",
  "const run = (cmd, args) => new Promise((settle) => {",
  "  const c = spawn(cmd, args);",
  "  c.stdout.on('data', (d) => process.stdout.write(d));",
  "  c.stderr.on('data', (d) => process.stderr.write(d));",
  "  c.on('error', () => settle(null));",
  "  c.on('close', (code) => settle(code));",
  "});",
  "const collect = async (dir, out) => {",
  "  let entries;",
  "  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }",
  "  for (const e of entries) {",
  "    const p = join(dir, e.name);",
  "    if (e.isDirectory()) { if (e.name !== 'bin' && e.name !== 'obj') await collect(p, out); }",
  "    else if (e.isFile() && e.name.endsWith('.csproj')) out.push(p);",
  "  }",
  "};",
  "(async () => {",
  "  const root = process.argv[1];",
  "  const top = await readdir(root, { withFileTypes: true }).catch(() => []);",
  "  const sln = top.filter((e) => e.isFile() && /^Recovered\\.slnx?$/.test(e.name)).map((e) => join(root, e.name));",
  "  const targets = [];",
  "  if (sln.length > 0) targets.push(sln[0]);",
  "  else { await collect(join(root, 'decompiled'), targets); targets.sort(); }",
  "  if (targets.length === 0) { console.log('### REA-BUILD none: no projects found'); process.exitCode = 2; return; }",
  "  let failed = 0;",
  "  for (const t of targets) {",
  "    console.log('### REA-BUILD target: ' + t);",
  "    const code = await run('dotnet', ['build', t, '--nologo', '-v:q']);",
  "    console.log('### REA-BUILD result: ' + t + ' exit=' + String(code));",
  "    if (code !== 0) failed += 1;",
  "  }",
  "  console.log('### REA-BUILD done: ' + String(targets.length - failed) + ' ok, ' + String(failed) + ' failed');",
  "  process.exitCode = failed === 0 ? 0 : 1;",
  "})();",
].join("\n");

const runOnce = (command, args, timeoutMs = 30000) =>
  new Promise((settle) => {
    const child = spawn(command, args, { env: process.env });
    let output = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle({ code: null, output, error: "timed out" });
    }, timeoutMs);
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr?.on("data", (chunk) => {
      output += chunk;
    });
    child.on("error", (cause) => {
      clearTimeout(timer);
      settle({ code: null, output, error: cause.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      settle({ code, output, error: null });
    });
  });

const startBuild = async (body) => {
  const output = resolve(String(body.output ?? ""));
  const preflight = await runOnce("dotnet", ["--version"]);
  if (preflight.code !== 0)
    return {
      ok: false,
      error: `The dotnet SDK was not found (${preflight.error ?? "dotnet --version failed"}). Install it, then retry.`,
    };
  const run = startProcess([ "-e", buildRunnerCode, output ], {
    target: output,
    output,
    kind: "build",
  });
  return { ok: true, run };
};

const readOptionalText = async (path) => {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size > MAX_FILE_BYTES) return null;
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
};

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REA Workbench — .NET Recovery Wizard</title>
<style>
:root { color-scheme: dark; --bg:#0e1116; --panel:#171c23; --line:#2a323d; --text:#e6edf3; --muted:#8b98a8; --accent:#4cc2ff; --ok:#3fb950; --bad:#f85149; --warn:#d29922; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:10px; }
header h1 { font-size:17px; margin:0; font-weight:650; }
header .badge { color:var(--muted); font-size:12px; border:1px solid var(--line); padding:2px 8px; border-radius:999px; }
#layout { display:grid; grid-template-columns:250px 1fr; gap:18px; padding:18px 24px 40px; max-width:1400px; margin:0 auto; }
#steps { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:12px; align-self:start; position:sticky; top:18px; }
#steps ol { list-style:none; margin:0; padding:0; }
#steps li button { width:100%; text-align:left; background:none; border:1px solid transparent; border-radius:8px; padding:9px 10px; color:var(--text); cursor:pointer; display:flex; gap:9px; align-items:baseline; }
#steps li button:hover { border-color:var(--line); }
#steps li button.current { border-color:var(--accent); }
#steps li .n { color:var(--muted); font-size:12px; min-width:16px; }
#steps li.done .n { color:var(--ok); }
#steps li .t { font-size:13px; font-weight:600; }
#steps li .d { display:block; font-size:11px; color:var(--muted); font-weight:400; }
main .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px; margin-bottom:18px; }
h2 { font-size:15px; margin:0 0 4px; }
.sub { color:var(--muted); font-size:13px; margin:0 0 14px; }
.howto { border-left:3px solid var(--accent); background:#0b0f14; padding:10px 12px; border-radius:0 8px 8px 0; margin:0 0 14px; font-size:13px; }
.howto strong { display:block; margin-bottom:4px; }
.howto ol, .howto ul { margin:6px 0 0; padding-left:20px; }
.howto code, p code, li code, td code { background:#0b0f14; border:1px solid var(--line); border-radius:5px; padding:0 5px; font-size:12px; }
label.f { display:block; font-size:12px; color:var(--muted); margin:10px 0 5px; }
input[type=text] { width:100%; background:#0b0f14; border:1px solid var(--line); border-radius:8px; color:var(--text); padding:9px 10px; font:13px ui-monospace,SFMono-Regular,Consolas,monospace; }
.row { display:flex; gap:8px; } .row input { flex:1; }
button { background:#222b36; color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px 12px; cursor:pointer; font-weight:600; }
button:hover { border-color:#3d4a5a; }
button.primary { background:var(--accent); color:#04121a; border-color:var(--accent); }
button:disabled { opacity:.45; cursor:not-allowed; }
.checks { display:grid; grid-template-columns:1fr 1fr; gap:8px 12px; margin-top:6px; }
.checks label { display:block; margin:0; font-size:12px; }
.checks label span { display:block; color:var(--muted); font-size:11px; font-weight:400; }
.checks h3 { grid-column:1 / -1; font-size:12px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); margin:10px 0 0; }
.actions { display:flex; gap:8px; margin-top:16px; flex-wrap:wrap; }
.status { margin-top:14px; font-size:12px; color:var(--muted); min-height:18px; }
.status.ok { color:var(--ok); } .status.bad { color:var(--bad); }
.bar { height:8px; background:#0b0f14; border:1px solid var(--line); border-radius:99px; overflow:hidden; margin-top:12px; display:none; }
.bar > div { height:100%; width:0; background:var(--accent); }
pre.log { margin:12px 0 0; padding:12px; background:#080b0f; border:1px solid var(--line); border-radius:10px; overflow:auto; max-height:45vh; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; }
pre.doc { margin:0; padding:12px; background:#080b0f; border:1px solid var(--line); border-radius:10px; overflow:auto; max-height:50vh; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; }
.kv { display:grid; grid-template-columns:190px 1fr; gap:4px 10px; font-size:13px; }
.kv div:nth-child(odd) { color:var(--muted); }
table { width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.tabs { display:flex; gap:6px; margin:12px 0 4px; flex-wrap:wrap; }
.tabs button { font-size:12px; padding:6px 10px; }
.tabs button.active { border-color:var(--accent); color:var(--accent); }
a { color:var(--accent); }
.tree { font:12px ui-monospace,SFMono-Regular,Consolas,monospace; }
.tree button { background:none; border:none; padding:3px 4px; font-weight:400; color:var(--text); cursor:pointer; display:block; text-align:left; width:100%; }
.tree button:hover { color:var(--accent); }
.crumb { margin:8px 0; font-size:12px; color:var(--muted); }
.crumb button { background:none; border:none; color:var(--accent); cursor:pointer; padding:0 2px; font-size:12px; }
.warn { color:var(--warn); } .ok { color:var(--ok); } .bad { color:var(--bad); }
footer { color:var(--muted); font-size:12px; padding:0 24px 30px; max-width:1400px; margin:0 auto; }
@media (max-width: 900px) { #layout { grid-template-columns:1fr; } #steps { position:static; } }
</style>
</head>
<body>
<header><h1>REA Workbench</h1><span class="badge">.NET recovery wizard</span><span class="badge">local only</span><span class="badge" id="platform"></span></header>
<div id="layout">
<nav id="steps"><ol id="stepList"></ol></nav>
<main>
<section class="panel" data-step="1">
<h2>1 · Pick your target</h2>
<p class="sub">Point the workbench at the product you own: an installed folder, a single <code>.dll</code>/<code>.exe</code>, or a Unity game folder.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Find the installed product: on Windows this is usually under <code>Program Files</code>; on macOS right-click the <code>.app</code> and choose Show Package Contents.</li><li>Paste the folder or file path below, or press <strong>Browse</strong> for a folder picker.</li><li>Press <strong>Scan target</strong>. Nothing is executed; the scan only reads file headers.</li><li>The output folder defaults to <code>&lt;target&gt;-rea-out</code>. Extraction never writes into your product.</li></ol></div>
<label class="f" for="target">Product folder, .exe, .dll, or .app</label>
<div class="row"><input id="target" type="text" placeholder="C:\\Path\\To\\Product or /path/to/product" autocomplete="off"><button id="browse">Browse</button></div>
<label class="f" for="output">Output folder (created for you)</label>
<input id="output" type="text" placeholder="C:\\Path\\To\\Product-rea-out" autocomplete="off">
<div class="actions"><button id="scan" class="primary">Scan target</button></div>
<div class="status" id="status1"></div>
<div id="detect"></div>
</section>
<section class="panel" data-step="2" hidden>
<h2>2 · Configure the extraction</h2>
<p class="sub">Everything is on by default. Untick only what you do not need — each option explains itself.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Leave <strong>Build repo scaffold</strong> on: it creates the solution, build scripts, and agent instructions.</li><li>Tick <strong>Attempt build</strong> if the <code>dotnet</code> SDK is installed and you want compile proof now.</li><li>For Unity games, keep IL2CPP on; for store apps with one big <code>.exe</code>, keep single-file bundles on.</li><li>Press <strong>Continue</strong> (or jump straight to step 3).</li></ol></div>
<div class="checks">
<h3>Repository</h3>
<label><input id="repo" type="checkbox" checked> Build repo scaffold<span>Solution, build scripts, agent task, dependency and limitation notes.</span></label>
<label><input id="gitInit" type="checkbox"> git init output<span>Start version control in the output folder.</span></label>
<label><input id="build" type="checkbox"> Attempt build<span>Runs dotnet build on every recovered project; needs the .NET SDK.</span></label>
<label><input id="force" type="checkbox"> Allow non-empty output<span>Reuse an output folder instead of requiring an empty one.</span></label>
<h3>Scope</h3>
<label><input id="noSingleFile" type="checkbox"> Skip single-file bundles<span>Ignore .NET single-file executables.</span></label>
<label><input id="noIl2cpp" type="checkbox"> Skip Unity IL2CPP<span>Ignore global-metadata.dat / GameAssembly pairs.</span></label>
<label><input id="allIl2cpp" type="checkbox"> All IL2CPP assemblies<span>Include framework/Unity dummy DLLs, not just app assemblies.</span></label>
<label><input id="noIl2cppCode" type="checkbox"> IL2CPP dump only<span>Run Il2CppDumper but skip decompiling dummy DLLs.</span></label>
<label><input id="allBundles" type="checkbox"> All bundle entries<span>Decompile every bundled assembly, including framework ones.</span></label>
<label><input id="includeFramework" type="checkbox"> Include framework assemblies<span>Also decompile System.* / UnityEngine.* instead of skipping them.</span></label>
<h3>Evidence (reconstruction inputs)</h3>
<label><input id="noMembers" type="checkbox"> Skip member summaries<span>Skip per-assembly REA type/method counts.</span></label>
<label><input id="noPdb" type="checkbox"> Ignore sidecar PDBs<span>ILSpy will not use .pdb files for local variable names.</span></label>
<label><input id="noSymbols" type="checkbox"> Skip PDB symbol recovery<span>Skip original file paths, SourceLink maps, and embedded-source extraction.</span></label>
<label><input id="noResources" type="checkbox"> Skip managed resources<span>Skip enumerating and extracting embedded resources.</span></label>
<label><input id="noDeployment" type="checkbox"> Skip deployment manifests<span>Skip .deps.json / runtimeconfig parsing and adjacent-file collection.</span></label>
<label><input id="noReferenceRewrite" type="checkbox"> Keep ILSpy references<span>Do not rewrite project references to recovered projects.</span></label>
<label><input id="noHashScan" type="checkbox"> Skip hash scan<span>Skip hash-shaped string and obfuscated-name classification.</span></label>
<label><input id="noLicenseScan" type="checkbox"> Skip license scan<span>Skip license-dongle evidence detection.</span></label>
</div>
<div class="actions"><button id="toRun" class="primary">Continue to run</button></div>
</section>
<section class="panel" data-step="3" hidden>
<h2>3 · Run the extraction</h2>
<p class="sub">Reads your product, decompiles it with ILSpy, and records evidence. Static analysis only — nothing is executed.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Press <strong>Start extraction</strong> and watch the log. Each assembly reports its own line.</li><li>Large products take minutes; single-file bundles and IL2CPP dumps are the slow parts.</li><li>You can <strong>Cancel</strong> any time; partial output stays on disk and is marked honestly.</li><li>When it finishes, press <strong>Review results</strong>.</li></ol></div>
<div class="actions"><button id="run" class="primary">Start extraction</button><button id="cancel" disabled>Cancel</button><button id="open" disabled>Open output folder</button></div>
<div class="bar" id="bar"><div id="fill"></div></div>
<div class="status" id="status3"></div>
<pre class="log" id="log" hidden></pre>
<div class="actions"><button id="toReview" disabled>Review results</button></div>
</section>
<section class="panel" data-step="4" hidden>
<h2>4 · Review the recovery</h2>
<p class="sub">Everything the extractor observed, with unknowns marked as unknowns.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Check the counts: managed assemblies decompiled, PDBs found, embedded sources, resources, NuGet packages.</li><li>Read the <strong>License</strong> row: <em>present</em> means a dongle check was observed in static evidence.</li><li>Open the <strong>Report</strong> tab for the full narrative, including limitations.</li><li>Pick an assembly in step 5 for the per-assembly detail.</li></ol></div>
<div class="tabs"><button id="tab-summary" class="active">Summary</button><button id="tab-report">Report</button></div>
<div id="result"></div>
<pre class="doc" id="report" hidden></pre>
</section>
<section class="panel" data-step="5" hidden>
<h2>5 · Inspect one assembly</h2>
<p class="sub">Symbols, embedded sources, resources, hashes, and license evidence per assembly.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Choose an assembly. Start with your product's own code, not <code>System.*</code>.</li><li><strong>Symbols &amp; sources</strong> shows original file paths; embedded sources are byte-identical producer copies — open them in step 6.</li><li><strong>Hashes &amp; names</strong> flags obfuscation: many hash-like names means a renamed binary.</li></ol></div>
<label class="f" for="assembly">Assembly</label>
<input id="assembly" type="text" list="assemblyList" placeholder="Start typing an assembly name" autocomplete="off">
<datalist id="assemblyList"></datalist>
<div class="tabs" id="asmTabs"><button data-atab="overview" class="active">Overview</button><button data-atab="protection">Protection</button><button data-atab="symbols">Symbols &amp; sources</button><button data-atab="resources">Resources</button><button data-atab="hashes">Hashes &amp; names</button><button data-atab="license">License</button></div>
<div id="assemblyDetail"><p class="sub">Run an extraction first, then pick an assembly.</p></div>
</section>
<section class="panel" data-step="6" hidden>
<h2>6 · Browse recovered files</h2>
<p class="sub">Walk the output tree and preview files. Binary resources are labelled, never dumped as text.</p>
<div class="howto"><strong>How to do this step</strong><ol><li><code>decompiled/</code> is ILSpy's reconstruction. <code>sources/</code> holds byte-identical embedded sources — prefer these on conflicts.</li><li><code>resources/</code> and <code>config/</code> hold extracted resources and adjacent files. <code>evidence/</code> holds the authoritative bundles.</li><li>Click a file to preview it (first 256 KiB).</li></ol></div>
<div class="tabs" id="roots"></div>
<div class="crumb" id="crumb"></div>
<div class="tree" id="tree"></div>
<pre class="doc" id="preview" hidden></pre>
</section>
<section class="panel" data-step="7" hidden>
<h2>7 · Build and verify</h2>
<p class="sub">Compile proof that the recovered projects stand up, then work the verification checklist.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Press <strong>Build now</strong> (needs the <code>dotnet</code> SDK). The solution builds when present, else every project in turn.</li><li>Fix failures top-down: target frameworks first, then references, then namespaces. <code>AGENT_TASK.md</code> (step 8) is the playbook.</li><li>Work through <strong>TESTING.md</strong> below: build, diff <code>sources/</code> against <code>decompiled/</code>, compare public APIs, and only then run anything — isolated, after explicit approval.</li></ol></div>
<div class="actions"><button id="buildNow" class="primary">Build now</button></div>
<div class="status" id="status7"></div>
<pre class="log" id="buildLog" hidden></pre>
<div id="buildExtras"></div>
</section>
<section class="panel" data-step="8" hidden>
<h2>8 · Next steps and handoff</h2>
<p class="sub">What remains is reconstruction work — an agent does it best with the playbook below.</p>
<div class="howto"><strong>How to do this step</strong><ol><li>Read <strong>LIMITATIONS.md</strong> first so you know what is proven and what is not.</li><li>Give <strong>AGENT_TASK.md</strong> to your agent together with the output folder.</li><li>Or run it headlessly: copy the <code>rea-goal</code> command below into a terminal (add <code>--dry-run</code> to preview).</li><li>IL2CPP games and obfuscated binaries need native decompilation next — see the limitations.</li></ol></div>
<div class="tabs"><button id="tab-agent" class="active">Agent task</button><button id="tab-limits">Limitations</button><button id="tab-goal">rea-goal command</button><button id="tab-local">Local-model agent</button></div>
<div id="nextBody"></div>
<div id="agentBox" hidden>
<label class="f" for="agentModel">Model (Ollama)</label>
<input id="agentModel" type="text" value="qwen2.5-coder:7b">
<label class="f" for="agentBase">Base URL</label>
<input id="agentBase" type="text" value="http://127.0.0.1:11434/v1">
<label class="f" for="agentGoal">Goal</label>
<input id="agentGoal" type="text" value="Make this recovered repository build. Fix one project at a time and report unknowns.">
<div class="actions"><button id="agentRun">Run agent</button></div>
<div class="status">Requires Ollama running and the model pulled. Agent output goes to an <code>agent-run-*</code> folder.</div>
</div>
</section>
</main>
</div>
<footer>Static analysis only. Targets are never executed and nothing is uploaded. The page is bound to 127.0.0.1 and requires this session's token.</footer>
<script>
const token = new URLSearchParams(location.search).get("token") || "";
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const STEPS = [
  ["Pick target", "Product path and scan"],
  ["Configure", "Extraction options"],
  ["Run", "Live extraction log"],
  ["Review", "Manifest dashboard"],
  ["Assembly", "Per-assembly detail"],
  ["Files", "Recovered file browser"],
  ["Build", "Compile and verify"],
  ["Next steps", "Agent handoff"],
];
const doneSteps = {};
const go = (n) => {
  document.querySelectorAll("main section.panel").forEach((s) => { s.hidden = Number(s.dataset.step) !== n; });
  document.querySelectorAll("#stepList li").forEach((li, i) => {
    const btn = li.querySelector("button");
    btn.className = (i + 1 === n) ? "current" : "";
  });
  window.scrollTo(0, 0);
};
const markDone = (n) => {
  doneSteps[n] = true;
  const li = document.querySelectorAll("#stepList li")[n - 1];
  if (li) li.classList.add("done");
};
$("stepList").innerHTML = STEPS.map((s, i) => '<li><button data-go="' + (i + 1) + '"><span class="n">' + (i + 1) + '</span><span><span class="t">' + esc(s[0]) + '</span><span class="d">' + esc(s[1]) + '</span></span></button></li>').join("");
document.querySelectorAll("#stepList button").forEach((b) => { b.onclick = () => go(Number(b.dataset.go)); });
$("platform").textContent = navigator.platform || "";
const setStatus = (id, value, kind) => { const el = $(id); el.textContent = value; el.className = "status " + (kind || ""); };
const api = async (path, body) => {
  const response = await fetch(path, { method: "POST", headers: { "content-type": "application/json", "x-rea-token": token }, body: JSON.stringify(body) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
};
const defaultOutput = () => {
  const target = $("target").value.trim().replace(/[\\\\/]+$/, "");
  if (!target) return "";
  return target + "-rea-out";
};
$("target").addEventListener("change", () => { if (!$("output").value.trim()) $("output").value = defaultOutput(); });
let manifest = null;
let outputPath = "";
$("browse").onclick = async () => {
  setStatus("status1", "Opening folder picker...");
  try { const r = await api("/api/browse", {}); if (r.path) { $("target").value = r.path; $("output").value = defaultOutput(); setStatus("status1", ""); } else setStatus("status1", r.error || "Cancelled", "bad"); }
  catch (e) { setStatus("status1", e.message, "bad"); }
};
$("scan").onclick = async () => {
  const path = $("target").value.trim();
  if (!path) { setStatus("status1", "Choose a target first.", "bad"); return; }
  $("scan").disabled = true; setStatus("status1", "Scanning (headers only, nothing is executed)...");
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
    setStatus("status1", "Scan complete. Continue to step 2.", "ok");
    markDone(1);
  } catch (e) { setStatus("status1", e.message, "bad"); }
  finally { $("scan").disabled = false; }
};
$("toRun").onclick = () => go(3);
const options = () => ({
  path: $("target").value.trim(),
  output: $("output").value.trim(),
  repo: $("repo").checked,
  force: $("force").checked,
  noMembers: $("noMembers").checked,
  noSingleFile: $("noSingleFile").checked,
  noIl2cpp: $("noIl2cpp").checked,
  allIl2cpp: $("allIl2cpp").checked,
  noIl2cppCode: $("noIl2cppCode").checked,
  allBundles: $("allBundles").checked,
  includeFramework: $("includeFramework").checked,
  noPdb: $("noPdb").checked,
  noReferenceRewrite: $("noReferenceRewrite").checked,
  noHashScan: $("noHashScan").checked,
  noLicenseScan: $("noLicenseScan").checked,
  noSymbols: $("noSymbols").checked,
  noResources: $("noResources").checked,
  noDeployment: $("noDeployment").checked,
  gitInit: $("gitInit").checked,
  build: $("build").checked,
});
let source = null;
let activeKind = "";
const stopStreamButtons = () => { $("run").disabled = false; $("cancel").disabled = true; $("buildNow").disabled = false; $("agentRun").disabled = false; };
const streamRun = (id, onDone) => {
  if (source) source.close();
  source = new EventSource("/api/stream/" + id + "?token=" + encodeURIComponent(token));
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "log") {
      const box = activeKind === "build" ? $("buildLog") : $("log");
      box.hidden = false;
      box.textContent += payload.text;
      box.scrollTop = box.scrollHeight;
      const m = payload.text.match(/\\[(\\d+)\\/(\\d+)\\]/);
      if (m && activeKind === "extract") {
        $("bar").style.display = "block";
        $("fill").style.width = Math.round((Number(m[1]) / Math.max(1, Number(m[2]))) * 100) + "%";
      }
      const b = payload.text.match(/### REA-BUILD done: (.*)/);
      if (b && activeKind === "build") setStatus("status7", b[1], "ok");
    }
    if (payload.type === "done") {
      source.close(); source = null;
      stopStreamButtons();
      onDone(payload);
    }
  };
  source.onerror = () => { if (source) source.close(); source = null; stopStreamButtons(); };
};
$("agentRun").onclick = async () => {
  if (!outputPath) { setStatus("status7", "Run an extraction first so an output folder exists.", "bad"); return; }
  $("buildLog").hidden = true; $("buildLog").textContent = "";
  $("run").disabled = true; $("buildNow").disabled = true; $("agentRun").disabled = true;
  setStatus("status7", "Starting local agent...");
  activeKind = "agent";
  try {
    const r = await api("/api/agent", { output: outputPath, model: $("agentModel").value.trim(), baseUrl: $("agentBase").value.trim(), goal: $("agentGoal").value.trim() });
    streamRun(r.id, (payload) => {
      setStatus("status7", payload.code === 0 ? "Agent finished." : "Agent finished with errors (code " + payload.code + ").", payload.code === 0 ? "ok" : "bad");
    });
  } catch (e) { stopStreamButtons(); setStatus("status7", e.message, "bad"); }
};
$("run").onclick = async () => {
  const body = options();
  if (!body.path) { setStatus("status3", "Go back to step 1 and choose a target.", "bad"); return; }
  if (!body.output) { body.output = defaultOutput(); $("output").value = body.output; }
  outputPath = body.output;
  $("log").textContent = ""; $("log").hidden = false; $("result").innerHTML = ""; $("report").textContent = "";
  $("bar").style.display = "block"; $("fill").style.width = "0";
  $("run").disabled = true; $("cancel").disabled = false; $("toReview").disabled = true;
  setStatus("status3", "Starting extraction...");
  activeKind = "extract";
  try {
    const r = await api("/api/run", body);
    streamRun(r.id, (payload) => {
      $("open").disabled = false;
      setStatus("status3", payload.code === 0 ? "Extraction complete." : "Extraction finished with errors (code " + payload.code + ").", payload.code === 0 ? "ok" : "bad");
      markDone(3);
      loadResult(body.output).then(() => { $("toReview").disabled = false; });
    });
  } catch (e) { $("run").disabled = false; $("cancel").disabled = true; setStatus("status3", e.message, "bad"); }
};
$("cancel").onclick = async () => { try { await api("/api/cancel", {}); setStatus("status3", "Cancellation requested."); } catch (e) { setStatus("status3", e.message, "bad"); } };
$("open").onclick = async () => { try { await api("/api/open", { path: outputPath || $("output").value.trim() }); } catch (e) { setStatus("status3", e.message, "bad"); } };
$("toReview").onclick = () => go(4);
$("tab-summary").onclick = () => { $("result").hidden = false; $("report").hidden = true; $("tab-summary").className = "active"; $("tab-report").className = ""; };
$("tab-report").onclick = () => { $("result").hidden = true; $("report").hidden = false; $("tab-summary").className = ""; $("tab-report").className = "active"; };
const kvRow = (k, v) => '<div>' + esc(k) + '</div><div>' + v + '</div>';
async function loadResult(out) {
  outputPath = out;
  const r = await api("/api/result", { path: out });
  manifest = r.manifest;
  const m = manifest;
  const rows = (m.assemblies || []).map((a) => '<tr><td><code>' + esc(a.name) + '</code></td><td>' + esc(a.runtime_family || "unknown") + '</td><td>' + esc(a.decompiled_files) + '</td><td>' + (a.symbols && a.symbols.kind ? esc(a.symbols.kind) + ' PDB' : 'no PDB') + '</td><td>' + esc(a.status) + '</td></tr>').join("");
  const bundles = (m.bundles || []).map((b) => '<tr><td><code>' + esc(b.path) + '</code></td><td>' + esc(b.entries) + '</td><td>' + esc(b.status) + '</td></tr>').join("");
  const frameworks = ((m.deployment && m.deployment.summary && m.deployment.summary.frameworks) || []).map((f) => esc(f.name || "?") + " " + esc(f.version || "")).join(", ");
  const packages = ((m.deployment && m.deployment.summary && m.deployment.summary.packages) || []).map((p) => '<code>' + esc(p.name) + '</code> ' + esc(p.version || "")).join(", ");
  $("result").innerHTML = '<div class="kv">' +
    kvRow("Output", "<code>" + esc(m.output) + "</code>") +
    kvRow("Schema", "<code>" + esc(m.schema) + "</code>") +
    kvRow("Managed", esc(m.counts.managed) + " assemblies, " + esc(m.counts.source_files) + " C# files") +
    kvRow("Bundles", esc(m.counts.bundles) + " · IL2CPP " + esc(m.counts.il2cpp) + " · native " + esc(m.counts.native) + " · skipped " + esc(m.counts.skipped)) +
    (m.repo ? kvRow("Repository", esc(m.repo.projects) + " projects · " + esc((m.repo.solution && m.repo.solution.file) || "no solution")) : "") +
    (m.references ? kvRow("References", esc(m.references.rewritten.length) + " rewritten · " + esc(m.references.references.length) + " vendored · " + esc(m.references.unresolved.length) + " unresolved") : "") +
    (m.symbols ? kvRow("Symbols", esc(m.symbols.assemblies_with_pdb) + " PDBs · " + esc(m.symbols.embedded_sources) + " embedded sources in sources/") : "") +
    (m.resources ? kvRow("Resources", esc(m.resources.entries) + " entries observed") : "") +
    (m.deployment ? kvRow("Deployment", esc((m.deployment.manifests || []).length) + " manifests · " + (frameworks || "no frameworks") + " · " + esc(m.deployment.summary ? m.deployment.summary.package_count : 0) + " NuGet packages") : "") +
    ((m.adjacent || []).length ? kvRow("Adjacent", esc(m.adjacent.length) + " files (" + esc(m.adjacent.filter((f) => f.output).length) + " copied to config/)") : "") +
    (m.hash_scan ? kvRow("Hashes", esc(m.hash_scan.total_candidates) + " candidates in " + esc(m.hash_scan.assemblies_scanned) + " assemblies") : "") +
    (m.license_scan ? kvRow("License", esc(m.license_scan.present) + " present · " + esc(m.license_scan.suspicious) + " suspicious") : "") +
    (m.protection ? kvRow("Protection", esc(m.protection.obfuscation_likely) + " likely · " + esc(m.protection.obfuscation_suspicious) + " suspicious · " + Object.entries(m.protection.runtime_kinds || {}).map((kv) => esc(kv[0]) + " ×" + esc(kv[1])).join(", ")) : "") +
    (m.protection ? kvRow("Signing", esc(m.protection.strong_named) + " strong-named · " + esc(m.protection.authenticode_signed) + " Authenticode-signed") : "") +
    (m.build ? kvRow("Build", m.build.ok ? '<span class="ok">all projects built</span>' : '<span class="bad">' + esc(m.build.failed) + " of " + esc(m.build.projects) + " failed</span>") : "") +
    '</div>' +
    (packages ? '<h2 style="margin-top:14px;font-size:13px">NuGet packages</h2><p class="sub">' + packages + '</p>' : '') +
    (rows ? '<h2 style="margin-top:14px;font-size:13px">Assemblies</h2><table><thead><tr><th>Name</th><th>Runtime</th><th>.cs</th><th>PDB</th><th>Status</th></tr></thead><tbody>' + rows + '</tbody></table>' : '') +
    (bundles ? '<h2 style="margin-top:14px;font-size:13px">Bundles</h2><table><thead><tr><th>Bundle</th><th>Entries</th><th>Status</th></tr></thead><tbody>' + bundles + '</tbody></table>' : '');
  $("report").textContent = r.report || "";
  const names = (m.assemblies || []).map((a) => a.name);
  $("assemblyList").innerHTML = names.map((n) => "<option value=\\"" + esc(n) + "\\">").join("");
  $("buildExtras").innerHTML = (r.extras.buildResults ? "<h2 style=\\"margin-top:14px;font-size:13px\\">BUILD_RESULTS.md</h2><pre class=\\"doc\\">" + esc(r.extras.buildResults) + "</pre>" : "") +
    (r.extras.testing ? "<h2 style=\\"margin-top:14px;font-size:13px\\">TESTING.md — verification checklist</h2><pre class=\\"doc\\">" + esc(r.extras.testing) + "</pre>" : "");
  $("nextBody").innerHTML = (r.extras.agentTask ? "<pre class=\\"doc\\">" + esc(r.extras.agentTask) + "</pre>" : "<p class=\\"sub\\">No AGENT_TASK.md yet — tick \\"Build repo scaffold\\" in step 2 and re-run.</p>");
  markDone(4);
}
const findAssembly = (name) => ((manifest && manifest.assemblies) || []).find((a) => a.name === name);
const showAssembly = () => {
  const name = $("assembly").value.trim();
  const a = findAssembly(name);
  if (!a) { $("assemblyDetail").innerHTML = '<p class="sub">Pick an assembly from the list.</p>'; return; }
  const tab = document.querySelector("#asmTabs button.active").dataset.atab;
  let body = "";
  if (tab === "overview") {
    body = '<div class="kv">' +
      kvRow("Version", esc(a.version || "unknown")) +
      kvRow("Runtime", esc(a.runtime_family || "unknown") + " · " + esc(a.runtime_version || "unknown")) +
      kvRow("Metadata", esc(a.metadata_version || "unknown") + " · " + esc(a.managed_architecture || "unknown")) +
      kvRow("Types / methods", esc((a.member_summary && a.member_summary.counts && a.member_summary.counts.types) ?? "?") + " / " + esc((a.member_summary && a.member_summary.counts && a.member_summary.counts.methods) ?? "?")) +
      kvRow("Decompiled", esc(a.decompiled_files) + " .cs files in <code>" + esc(a.decompiled_dir || "") + "</code>") +
      kvRow("References", ((a.references || []).map((r) => "<code>" + esc(r.name) + "</code>").join(", ")) || "none") +
      kvRow("Status", esc(a.status) + (((a.errors || []).length) ? " · " + esc(a.errors.join("; ")) : "")) +
      '</div>';
  } else if (tab === "protection") {
    const p = a.protection;
    if (!p) body = '<p class="sub">Protection analysis did not run for this assembly.</p>';
    else {
      const ob = p.obfuscation;
      const obRows = ob.status === "none"
        ? '<p class="sub">No obfuscator signals. Renamed-symbol ratios and watermark scans were clean.</p>'
        : '<table><thead><tr><th>Tool</th><th>Signal</th><th>Detail</th><th>Confidence</th></tr></thead><tbody>' + (ob.indicators || []).map((f) => "<tr><td>" + esc(f.tool || "unknown tool") + (f.vendor ? "<br>" + esc(f.vendor) : "") + "</td><td><code>" + esc(f.signal) + "</code></td><td><code>" + esc(f.detail) + "</code>" + (f.note ? "<br>" + esc(f.note) : "") + "</td><td>" + esc(f.confidence) + "</td></tr>").join("") + "</tbody></table>";
      const sign = p.signing;
      body = '<div class="kv">' +
        kvRow("Obfuscation", esc(ob.status)) +
        kvRow("Runtime kind", "<code>" + esc(p.runtime_kind.kind) + "</code>" + (((p.runtime_kind.notes) || []).length ? "<br>" + esc(p.runtime_kind.notes.join(" ")) : "")) +
        kvRow("Strong-named", sign.strong_named ? "yes" + (sign.public_key_token ? " · token <code>" + esc(sign.public_key_token) + "</code>" : "") : "no") +
        kvRow("Authenticode", sign.authenticode.present ? "present (" + esc(sign.authenticode.count) + " entries" + (sign.authenticode.signers.length ? ": " + esc(sign.authenticode.signers.join("; ")) : "") + ")" : "no certificate table (presence only; chains are never verified)") +
        '</div><h2 style="margin-top:12px;font-size:13px">Obfuscator indicators</h2>' + obRows +
        '<p class="sub">Detection is static identity only — it never defeats or removes protection.</p>';
    }
  } else if (tab === "symbols") {
    const s = a.symbols;
    if (!s) body = '<p class="sub">Symbol recovery was disabled or not run.</p>';
    else if (!s.kind) body = '<p class="sub">No PDB found (embedded or sidecar).' + (s.error ? " " + esc(s.error) : "") + '</p>';
    else {
      const docs = (s.documents || []).map((d) => "<tr><td><code>" + esc(d.path || "?") + "</code></td><td>" + esc(d.language || "?") + "</td><td>" + esc(d.hash_algorithm || "?") + "</td></tr>").join("");
      const srcs = (s.embedded_sources || []).map((e) => "<tr><td><code>" + esc(e.path || "?") + "</code></td><td><code>" + esc(e.output || "") + "</code></td><td>" + esc(e.bytes) + "</td></tr>").join("");
      body = '<div class="kv">' + kvRow("PDB", esc(s.kind)) + kvRow("Documents", esc((s.documents || []).length)) + kvRow("Embedded sources", esc((s.embedded_sources || []).length)) + kvRow("SourceLink", s.source_link ? "present (recorded, never fetched)" : "absent") + '</div>' +
        (docs ? '<h2 style="margin-top:12px;font-size:13px">Original file paths</h2><table><thead><tr><th>Path</th><th>Language</th><th>Hash</th></tr></thead><tbody>' + docs + '</tbody></table>' : "") +
        (srcs ? '<h2 style="margin-top:12px;font-size:13px">Byte-identical embedded sources (open in step 6, sources/)</h2><table><thead><tr><th>Original path</th><th>Recovered as</th><th>Bytes</th></tr></thead><tbody>' + srcs + '</tbody></table>' : "");
    }
  } else if (tab === "resources") {
    const r = a.resources;
    if (!r) body = '<p class="sub">Resource recovery was disabled or not run.</p>';
    else if (r.status === "none") body = '<p class="sub">No managed resources in this assembly.</p>';
    else if (r.status === "unknown") body = '<p class="sub">Enumeration failed: ' + esc(r.error || "?") + '</p>';
    else body = '<table><thead><tr><th>Entry</th><th>Status</th><th>Recovered as</th></tr></thead><tbody>' + (r.entries || []).map((e) => "<tr><td><code>" + esc(e.name) + "</code></td><td>" + esc(e.status) + "</td><td><code>" + esc(e.output || "—") + "</code></td></tr>").join("") + "</tbody></table>";
  } else if (tab === "hashes") {
    const h = a.hash_scan;
    if (!h) body = '<p class="sub">Hash scanning was disabled or not run.</p>';
    else {
      const algos = Object.entries((h.hash_strings || {}).by_algorithm || {}).map((kv) => "<code>" + esc(kv[0]) + "</code> ×" + esc(kv[1])).join(", ") || "none";
      const samples = ((h.hash_strings || {}).samples || []).map((s) => "<code>" + esc(s.value) + "</code> (" + esc(s.candidates.join(", ")) + ")").join("<br>") || "none";
      body = '<div class="kv">' + kvRow("Literals examined", esc((h.hash_strings || {}).literals_examined ?? "?")) + kvRow("Algorithms", algos) + kvRow("Hash-like names", esc(((h.member_names || {}).hash_like) ?? "?") + " · minified " + esc(((h.member_names || {}).minified) ?? "?")) + kvRow("Samples", samples) + '</div>';
    }
  } else {
    const l = a.license_scan;
    if (!l) body = '<p class="sub">License scanning was disabled or not run.</p>';
    else if (l.status === "none") body = '<p class="sub">No dongle signals in this assembly.</p>';
    else if (l.status === "unknown") body = '<p class="sub">Scan failed: ' + esc(l.error || "?") + '</p>';
    else body = '<table><thead><tr><th>Signal</th><th>Detail</th><th>Vendor</th></tr></thead><tbody>' + (l.findings || []).map((f) => "<tr><td><code>" + esc(f.signal) + "</code></td><td><code>" + esc(f.detail) + "</code>" + (f.purpose ? "<br>" + esc(f.purpose) : "") + "</td><td>" + esc(f.vendor || "—") + "</td></tr>").join("") + "</tbody></table><p class=\\"sub\\">Detection and explanation only — this workflow never provides bypass guidance.</p>";
  }
  $("assemblyDetail").innerHTML = body;
};
$("assembly").addEventListener("change", showAssembly);
document.querySelectorAll("#asmTabs button").forEach((b) => { b.onclick = () => { document.querySelectorAll("#asmTabs button").forEach((x) => { x.className = ""; }); b.className = "active"; showAssembly(); }; });
let treeRel = "";
const ROOTS = [["decompiled", "decompiled/"], ["sources", "sources/"], ["resources", "resources/"], ["config", "config/"], ["evidence", "evidence/"], ["", "output root"]];
$("roots").innerHTML = ROOTS.map((r, i) => '<button data-root="' + esc(r[0]) + '"' + (i === 0 ? ' class="active"' : "") + '>' + esc(r[1]) + "</button>").join("");
document.querySelectorAll("#roots button").forEach((b) => { b.onclick = () => { document.querySelectorAll("#roots button").forEach((x) => { x.className = ""; }); b.className = "active"; browseDir(b.dataset.root); }; });
async function browseDir(rel) {
  if (!outputPath) { $("tree").innerHTML = '<p class="sub">Run an extraction first.</p>'; return; }
  treeRel = rel;
  const parts = rel ? rel.split("/") : [];
  $("crumb").innerHTML = '<button data-crumb="">output</button>' + parts.map((p, i) => ' / <button data-crumb="' + esc(parts.slice(0, i + 1).join("/")) + '">' + esc(p) + "</button>").join("");
  document.querySelectorAll("#crumb button").forEach((b) => { b.onclick = () => browseDir(b.dataset.crumb); });
  const r = await api("/api/tree", { path: outputPath, rel });
  $("tree").innerHTML = r.entries.map((e) => '<button data-' + (e.type === "dir" ? "dir" : "file") + '="' + esc(e.rel) + '">' + (e.type === "dir" ? "📁 " : "📄 ") + esc(e.name) + (e.type === "file" ? ' <span style="color:var(--muted)">' + esc(e.size) + " B</span>" : "") + "</button>").join("") || '<p class="sub">Empty folder.</p>';
  document.querySelectorAll("#tree button[data-dir]").forEach((b) => { b.onclick = () => browseDir(b.dataset.dir); });
  document.querySelectorAll("#tree button[data-file]").forEach((b) => { b.onclick = () => previewFile(b.dataset.file); });
}
async function previewFile(rel) {
  const r = await api("/api/file", { path: outputPath, file: rel });
  $("preview").hidden = false;
  $("preview").textContent = r.binary ? "[binary file, " + r.size + " bytes — open it from the output folder]" : (r.text || "");
  $("preview").scrollIntoView({ block: "nearest" });
}
$("buildNow").onclick = async () => {
  if (!outputPath) { setStatus("status7", "Run an extraction first so an output folder exists.", "bad"); return; }
  $("buildLog").textContent = ""; $("buildLog").hidden = false;
  $("buildNow").disabled = true; $("run").disabled = true;
  setStatus("status7", "Building recovered projects...");
  activeKind = "build";
  try {
    const r = await api("/api/build", { output: outputPath });
    streamRun(r.id, (payload) => {
      setStatus("status7", payload.code === 0 ? "Build finished: all projects built." : "Build finished with failures (code " + payload.code + "). See the log.", payload.code === 0 ? "ok" : "bad");
      markDone(7);
    });
  } catch (e) { $("buildNow").disabled = false; $("run").disabled = false; setStatus("status7", e.message, "bad"); }
};
$("tab-agent").onclick = () => { $("nextBody").hidden = false; $("agentBox").hidden = true; $("tab-agent").className = "active"; $("tab-limits").className = ""; $("tab-goal").className = ""; $("tab-local").className = ""; };
$("tab-limits").onclick = async () => {
  $("nextBody").hidden = false; $("agentBox").hidden = true; $("tab-agent").className = ""; $("tab-limits").className = "active"; $("tab-goal").className = ""; $("tab-local").className = "";
  try { const r = await api("/api/file", { path: outputPath, file: "LIMITATIONS.md" }); $("nextBody").innerHTML = '<pre class="doc">' + esc(r.text || "") + "</pre>"; }
  catch (e) { $("nextBody").innerHTML = "<p class=\\"sub\\">" + esc(e.message) + "</p>"; }
};
$("tab-goal").onclick = () => {
  $("nextBody").hidden = false; $("agentBox").hidden = true; $("tab-agent").className = ""; $("tab-limits").className = ""; $("tab-goal").className = "active"; $("tab-local").className = "";
  $("nextBody").innerHTML = "<p class=\\"sub\\">Headless agent run over this output (add <code>--dry-run</code> to preview):</p><pre class=\\"doc\\">node scripts/rea-goal.mjs --goal \\"Make this recovered repository build\\" --target \\"" + esc(outputPath) + "\\"</pre>";
};
$("tab-local").onclick = () => { $("nextBody").hidden = true; $("agentBox").hidden = false; $("tab-agent").className = ""; $("tab-limits").className = ""; $("tab-goal").className = ""; $("tab-local").className = "active"; };
go(1);
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
      if (!authorized(request, url))
        return json(response, 403, {
          error: "Missing or invalid session token.",
        });
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
    if (request.method === "POST" && url.pathname === "/api/build") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const output = resolve(String(body.output ?? ""));
      if (!(await exists(output)))
        return json(response, 404, {
          error: `Output folder does not exist: ${output}`,
        });
      if ([...runs.values()].some((run) => !run.done))
        return json(response, 409, { error: "A run is already active." });
      const started = await startBuild({ output });
      if (!started.ok) return json(response, 400, { error: started.error });
      return json(response, 200, { id: started.run.id });
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
      const extras = {
        buildResults: await readOptionalText(join(output, "BUILD_RESULTS.md")),
        agentTask: await readOptionalText(join(output, "AGENT_TASK.md")),
        limitations: await readOptionalText(join(output, "LIMITATIONS.md")),
        testing: await readOptionalText(join(output, "TESTING.md")),
      };
      return json(response, 200, { manifest, report, extras });
    }
    if (request.method === "POST" && url.pathname === "/api/tree") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const output = resolve(String(body.path ?? ""));
      const directory = insideOutput(output, body.rel ?? "");
      if (directory === null)
        return json(response, 400, { error: "Path escapes the output folder." });
      let entries;
      try {
        const info = await stat(directory);
        if (!info.isDirectory())
          return json(response, 400, { error: "Not a folder." });
        entries = await readdir(directory, { withFileTypes: true });
      } catch (cause) {
        return json(response, 404, {
          error: `Cannot list folder: ${cause.message}`,
        });
      }
      const listed = [];
      for (const entry of entries
        .sort((left, right) => left.name.localeCompare(right.name))
        .slice(0, MAX_TREE_ENTRIES)) {
        const full = join(directory, entry.name);
        let size = null;
        if (entry.isFile()) {
          try {
            size = (await stat(full)).size;
          } catch {
            size = null;
          }
        }
        listed.push({
          name: entry.name,
          type: entry.isDirectory() ? "dir" : "file",
          size,
          rel: directory === output
            ? entry.name
            : `${String(body.rel ?? "").replace(/\/+$/u, "")}/${entry.name}`,
        });
      }
      return json(response, 200, {
        entries: listed,
        truncated: entries.length >= MAX_TREE_ENTRIES,
      });
    }
    if (request.method === "POST" && url.pathname === "/api/file") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const output = resolve(String(body.path ?? ""));
      const file = insideOutput(output, body.file ?? "");
      if (file === null)
        return json(response, 400, { error: "Path escapes the output folder." });
      let info;
      try {
        info = await stat(file);
      } catch {
        return json(response, 404, { error: "File does not exist." });
      }
      if (!info.isFile())
        return json(response, 400, { error: "Not a file." });
      if (info.size > MAX_FILE_BYTES)
        return json(response, 400, {
          error: `File is ${String(info.size)} bytes; open it from the output folder instead.`,
        });
      const bytes = await readFile(file);
      if (bytes.includes(0))
        return json(response, 200, { binary: true, size: info.size });
      return json(response, 200, { text: bytes.toString("utf8") });
    }
    if (request.method === "POST" && url.pathname === "/api/open") {
      const body = JSON.parse((await readBody(request)) || "{}");
      const target = resolve(String(body.path ?? ""));
      if (!(await exists(target)))
        return json(response, 404, { error: `Path does not exist: ${target}` });
      openPath(target);
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
