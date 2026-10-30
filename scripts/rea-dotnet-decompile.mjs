#!/usr/bin/env node

/**
 * Full .NET / Unity extraction workflow.
 *
 * Composes the standalone REA CLI (static evidence) with ILSpy (C# reconstruction)
 * and, when present, Il2CppDumper (IL2CPP dummy assemblies). No target code is
 * executed and no network access is required.
 *
 * Usage:
 *   rea-dotnet <target> <output-directory> [options]
 *   node scripts/rea-dotnet-decompile.mjs <target> <output-directory> [options]
 *
 * Supported targets:
 *   - Managed PE assemblies (.dll/.exe)                  -> REA evidence + ILSpy
 *   - .NET single-file bundles (PE or Mach-O)            -> ILSpy bundle entries
 *   - Unity IL2CPP products (global-metadata.dat + GameAssembly) -> REA metadata
 *     evidence + Il2CppDumper dummy assemblies + ILSpy structure. Method bodies
 *     are native code and are NOT recovered as C#.
 */

import { spawn } from "node:child_process";
import {
  chmod,
  cp,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createHash } from "node:crypto";
import {
  countSourceFiles,
  exists,
  findProjectFiles,
  isFrameworkAssembly,
  isManagedExtension,
  matchDongleSignals,
  rewriteProjectReferences,
  safeName,
  scanDecompiledDirectory,
  sha256File,
} from "./lib/dotnet-extraction.mjs";
import {
  collectAdjacentFiles,
  collectDeployment,
  deploymentSummary,
  recoverSymbols,
  sourceOutputName,
} from "./lib/dotnet-deconstruction.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const reaEntry = join(repoRoot, "scripts", "rea.mjs");
const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_INPUT_FILES = 5000;

const parseArgs = (argv) => {
  const positional = [];
  const options = {
    force: false,
    members: true,
    singleFile: true,
    il2cpp: true,
    il2cppScope: "app",
    bundleScope: "app",
    includeFramework: false,
    usePdb: true,
    rewriteReferences: true,
    hashScan: true,
    licenseScan: true,
    symbols: true,
    resources: true,
    deployment: true,
    detect: false,
    repo: false,
    gitInit: false,
    build: false,
    json: false,
    quiet: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--force") options.force = true;
    else if (value === "--no-members") options.members = false;
    else if (value === "--no-single-file") options.singleFile = false;
    else if (value === "--no-il2cpp") options.il2cpp = false;
    else if (value === "--all-il2cpp") options.il2cppScope = "all";
    else if (value === "--no-il2cpp-code") options.il2cppScope = "none";
    else if (value === "--all-bundles") options.bundleScope = "all";
    else if (value === "--include-framework") options.includeFramework = true;
    else if (value === "--no-pdb") options.usePdb = false;
    else if (value === "--no-reference-rewrite")
      options.rewriteReferences = false;
    else if (value === "--no-hash-scan") options.hashScan = false;
    else if (value === "--no-license-scan") options.licenseScan = false;
    else if (value === "--no-symbols") options.symbols = false;
    else if (value === "--no-resources") options.resources = false;
    else if (value === "--no-deployment") options.deployment = false;
    else if (value === "--detect") options.detect = true;
    else if (value === "--repo") options.repo = true;
    else if (value === "--git-init") options.gitInit = true;
    else if (value === "--build") options.build = true;
    else if (value === "--json") options.json = true;
    else if (value === "--quiet") options.quiet = true;
    else if (value === "--ilspy") options.ilspy = argv[++index];
    else if (value === "--il2cpp-dumper") options.il2cppDumper = argv[++index];
    else if (value === "--help" || value === "-h") options.help = true;
    else if (value.startsWith("-")) throw new Error(`Unknown option: ${value}`);
    else positional.push(value);
  }
  return { positional, options };
};

const usage = () => `Usage: rea-dotnet <target> <output-directory> [options]
       rea-dotnet --detect <target>
       node scripts/rea-dotnet-decompile.mjs <target> <output-directory> [options]

Supports managed PE assemblies, .NET single-file bundles, and Unity IL2CPP products.

Options:
  --force                 Allow writing into a non-empty output directory
  --ilspy <path>          Explicit ilspycmd executable
  --il2cpp-dumper <path>  Explicit Il2CppDumper.dll path
  --no-members            Skip per-assembly REA member summaries
  --no-single-file        Do not inspect .NET single-file bundles
  --no-il2cpp             Do not inspect Unity IL2CPP products
  --all-il2cpp            Decompile every dummy DLL (default: app assemblies only)
  --no-il2cpp-code        Run Il2CppDumper but do not decompile dummy assemblies
  --all-bundles           Decompile every bundle entry (default: app entries only)
  --include-framework     Also decompile framework assemblies found in a folder
  --no-pdb                Do not use a sidecar PDB for local variable names
  --no-reference-rewrite  Keep ILSpy's original reference paths
  --no-hash-scan          Skip hash and obfuscated-name scanning
  --no-license-scan       Skip license-dongle check detection
  --no-symbols            Skip PDB symbol recovery and embedded-source extraction
  --no-resources          Skip managed-resource enumeration and recovery
  --no-deployment         Skip deployment-manifest and adjacent-file collection
  --detect                Report the detected layout as JSON without writing anything
  --repo                  Add README, build scripts, solution, and agent handoff
  --git-init              Initialize a git repository in the output directory
  --build                 Attempt to build every recovered project and record results
  --json                  Print the final manifest as JSON on stdout
  --quiet                 Suppress per-artifact progress output
`;

const run = (command, args, { cwd, env, timeout = DEFAULT_TIMEOUT_MS } = {}) =>
  new Promise((settle) => {
    const child = spawn(command, args, {
      cwd,
      env: env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeout);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (cause) => {
      clearTimeout(timer);
      settle({
        code: null,
        stdout,
        stderr: `${stderr}${cause.message}`,
        timedOut,
      });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      settle({ code, stdout, stderr, timedOut });
    });
  });

const isManagedCandidate = (path) => isManagedExtension(path);

const shouldSkipDirectory = (name) =>
  name === ".git" ||
  name === "node_modules" ||
  name === ".cache" ||
  name === "obj" ||
  name === "bin";

const detectFormat = async (path) => {
  let handle;
  try {
    handle = await open(path, "r");
    const buffer = Buffer.alloc(4);
    await handle.read(buffer, 0, 4, 0);
    const magic = buffer.readUInt32BE(0);
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) return "pe";
    if (
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46
    )
      return "elf";
    if (
      magic === 0xfeedface ||
      magic === 0xfeedfacf ||
      magic === 0xcefaedfe ||
      magic === 0xcffaedfe ||
      magic === 0xcafebabe ||
      magic === 0xbebafeca ||
      magic === 0xcafebabf ||
      magic === 0xbfbafeca
    )
      return "macho";
    if (magic === 0xfab11baf) return "il2cpp-metadata";
    return "unknown";
  } catch {
    return "unknown";
  } finally {
    await handle?.close();
  }
};

const collectCandidates = async (inputPath, includeExecutables = true) => {
  const info = await stat(inputPath);
  if (info.isFile()) return [inputPath];
  if (!info.isDirectory())
    throw new Error(`Not a file or directory: ${inputPath}`);

  const files = [];
  const walk = async (directory) => {
    if (files.length >= MAX_INPUT_FILES) return;
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      if (files.length >= MAX_INPUT_FILES) return;
      const entryPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!shouldSkipDirectory(entry.name)) await walk(entryPath);
      } else if (entry.isFile()) {
        if (isManagedCandidate(entry.name)) {
          files.push(entryPath);
        } else if (includeExecutables && extname(entry.name) === "") {
          try {
            const entryInfo = await stat(entryPath);
            if ((entryInfo.mode & 0o111) !== 0) files.push(entryPath);
          } catch {
            // Ignore unreadable entries.
          }
        }
      }
    }
  };
  await walk(inputPath);
  return files;
};

const findIlspy = async (explicitPath) => {
  const executable = process.platform === "win32" ? "ilspycmd.exe" : "ilspycmd";
  const candidates = [
    explicitPath,
    process.env.REA_ILSPY_CMD_PATH,
    join(homedir(), ".local", "bin", executable),
    join(homedir(), ".dotnet", "tools", executable),
    process.env.DOTNET_CLI_HOME === undefined
      ? undefined
      : join(process.env.DOTNET_CLI_HOME, ".dotnet", "tools", executable),
    process.env.USERPROFILE === undefined
      ? undefined
      : join(process.env.USERPROFILE, ".dotnet", "tools", executable),
    "/opt/homebrew/bin/ilspycmd",
  ].filter((value) => typeof value === "string" && value.length > 0);
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return undefined;
};

const findIl2CppDumper = async (explicitPath) => {
  const candidates = [
    explicitPath,
    process.env.IL2CPP_DUMPER_PATH,
    join(homedir(), "Tools", "Il2CppDumper", "Il2CppDumper.dll"),
    join(homedir(), ".local", "bin", "Il2CppDumper.dll"),
    process.env.USERPROFILE === undefined
      ? undefined
      : join(
          process.env.USERPROFILE,
          "Tools",
          "Il2CppDumper",
          "Il2CppDumper.dll",
        ),
  ].filter((value) => typeof value === "string" && value.length > 0);
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return undefined;
};

const toolEnv = async (ilspyPath) => {
  const env = { ...process.env };
  if (env.DOTNET_ROOT === undefined) {
    const homebrewRoot = "/opt/homebrew/opt/dotnet/libexec";
    if (await exists(homebrewRoot)) env.DOTNET_ROOT = homebrewRoot;
  }
  if (ilspyPath !== undefined) {
    env.REA_ILSPY_CMD_PATH = ilspyPath;
    const directory = dirname(ilspyPath);
    const separator = process.platform === "win32" ? ";" : ":";
    env.PATH = `${directory}${separator}${env.PATH ?? ""}`;
  }
  return env;
};

const toolVersion = async (command, args, env) => {
  const result = await run(command, args, { env, timeout: 30_000 });
  if (result.code !== 0) return undefined;
  return result.stdout.trim().split("\n")[0] || undefined;
};

const parseJson = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

const inspectAssembly = async (path, env) => {
  const artifact = await run(
    process.execPath,
    [reaEntry, "inspect-managed-artifact", path, "--format", "json"],
    {
      env,
    },
  );
  if (artifact.code !== 0) {
    const payload = parseJson(artifact.stdout);
    return {
      managed: false,
      reason:
        payload?.message ??
        artifact.stderr.trim().split("\n")[0] ??
        `inspect-managed-artifact exited ${String(artifact.code)}`,
    };
  }
  const payload = parseJson(artifact.stdout);
  const result = payload?.normalized_result;
  if (result === undefined) {
    return {
      managed: false,
      reason: "REA returned no normalized artifact result",
    };
  }
  return { managed: true, artifact: result, payload };
};

const summarizeMembers = async (path, env, bundlePath) => {
  const result = await run(
    process.execPath,
    [
      reaEntry,
      "inspect-managed-members",
      path,
      "--detail",
      "summary",
      "--evidence-bundle",
      bundlePath,
      "--format",
      "json",
    ],
    { env },
  );
  if (result.code !== 0) {
    return {
      ok: false,
      error:
        result.stderr.trim().split("\n")[0] ?? `exited ${String(result.code)}`,
    };
  }
  const payload = parseJson(result.stdout);
  const view = payload?.normalized_result;
  if (view === undefined)
    return { ok: false, error: "REA returned no normalized summary result" };
  const summary = view.summary ?? {};
  const rows = summary.metadata?.table_row_counts ?? {};
  return {
    ok: true,
    coverage: view.coverage,
    counts: {
      types: rows.TypeDef ?? null,
      methods: rows.MethodDef ?? null,
      fields: rows.Field ?? null,
      member_refs: rows.MemberRef ?? null,
      method_rows: summary.method_rows?.total ?? null,
    },
  };
};

const inspectNativeBoundaries = async (path, env) => {
  const result = await run(
    process.execPath,
    [reaEntry, "inspect-managed-native-boundaries", path, "--format", "json"],
    { env },
  );
  if (result.code !== 0) {
    return {
      ok: false,
      error:
        result.stderr.trim().split("\n")[0] ?? `exited ${String(result.code)}`,
    };
  }
  const payload = parseJson(result.stdout);
  const normalized = payload?.normalized_result;
  if (normalized === undefined) {
    return { ok: false, error: "REA returned no normalized boundary result" };
  }
  return {
    ok: true,
    moduleRefs: (normalized.module_refs ?? []).map((row) => row.name),
    pinvokeImports: (normalized.pinvoke_imports ?? []).map(
      (row) => row.import_name,
    ),
  };
};

const ilspyProjectArgs = ({ output, referencePath, usePdb, bundleEntry }) => {
  const args = ["--disable-updatecheck", "--ignore-decompilation-errors"];
  if (bundleEntry !== undefined) args.push("--bundle-entry", bundleEntry);
  args.push("-p", "-o", output);
  if (referencePath !== undefined) args.push("-r", referencePath);
  if (usePdb) args.push("-usepdb");
  return args;
};

const MAX_RESOURCE_ENTRIES = 200;
const MAX_RESOURCE_BYTES = 8 * 1024 * 1024;
const MAX_ADJACENT_BYTES = 4 * 1024 * 1024;
const MAX_FIND_FILES = 5000;

const sha256Bytes = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Depth-bounded search for a file by exact base name under a directory. */
const findFileByName = async (root, leaf) => {
  const wanted = leaf.toLowerCase();
  const stack = [root];
  let visited = 0;
  while (stack.length > 0 && visited < MAX_FIND_FILES) {
    const current = stack.pop();
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      visited += 1;
      if (visited > MAX_FIND_FILES) break;
      const entryPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "bin" && entry.name !== "obj") stack.push(entryPath);
      } else if (
        entry.isFile() &&
        entry.name.toLowerCase() === wanted
      ) {
        return entryPath;
      }
    }
  }
  return undefined;
};

const resourceOutputName = (name, index) => {
  const leaf = String(name).split("/").pop() || "resource";
  return `${String(index).padStart(3, "0")}-${safeName(leaf)}`;
};

const listManagedResources = async (ilspyPath, path, env) => {
  const result = await run(
    ilspyPath,
    ["--disable-updatecheck", "--list-resources", path],
    { env, timeout: 120_000 },
  );
  if (result.code !== 0) {
    return {
      ok: false,
      error:
        result.stderr.trim().split("\n")[0] ??
        `ilspycmd --list-resources exited ${String(result.code)}`,
    };
  }
  const entries = result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .slice(0, MAX_RESOURCE_ENTRIES);
  return { ok: true, entries };
};

/**
 * Recover managed resources. ILSpy project output already materializes most
 * resources (config JSON, .resx from .resources, XAML from BAML); entries
 * already present are recorded, not duplicated. Missing entries are extracted
 * with `ilspycmd --resource` into resources/<stem>/.
 */
const recoverAssemblyResources = async ({
  ilspyPath,
  assemblyPath,
  assemblyOutput,
  outputPath,
  resourcesDirectory,
  stem,
  env,
}) => {
  const listed = await listManagedResources(ilspyPath, assemblyPath, env);
  if (!listed.ok) return { status: "unknown", entries: [], error: listed.error };
  if (listed.entries.length === 0)
    return { status: "none", entries: [], error: null };
  await mkdir(resourcesDirectory, { recursive: true });
  const entries = [];
  for (const [index, name] of listed.entries.entries()) {
    const leaf = String(name).split("/").pop();
    const container = String(name).split("/")[0];
    const materialized =
      leaf.length > 0
        ? await findFileByName(assemblyOutput, leaf)
        : undefined;
    // A .resources container usually materializes as a sibling .resx, and a
    // nested entry's value lives inside that same .resx.
    const containerResx =
      materialized === undefined &&
      container.endsWith(".resources")
        ? await findFileByName(
            assemblyOutput,
            `${container.slice(0, -".resources".length)}.resx`,
          )
        : undefined;
    const found = materialized ?? containerResx;
    if (found !== undefined) {
      entries.push({
        name,
        status: "recovered-via-project",
        output: relative(outputPath, found),
      });
      continue;
    }
    const outputName = resourceOutputName(name, index);
    const targetPath = join(resourcesDirectory, outputName);
    const extracted = await run(
      ilspyPath,
      [
        "--disable-updatecheck",
        "-o",
        resourcesDirectory,
        "--resource",
        name,
        assemblyPath,
      ],
      { env, timeout: 120_000 },
    );
    // ilspycmd writes the resource leaf into the output directory; move it to
    // the indexed name so nested entries cannot collide or escape.
    const written = join(resourcesDirectory, leaf);
    if (extracted.code === 0 && (await exists(written))) {
      let info;
      try {
        info = await stat(written);
      } catch {
        info = null;
      }
      if (info !== null && info.isFile() && info.size <= MAX_RESOURCE_BYTES) {
        const bytes = await readFile(written);
        await writeFile(targetPath, bytes);
        if (written !== targetPath) await rm(written, { force: true });
        entries.push({
          name,
          status: "extracted",
          output: relative(outputPath, targetPath),
          bytes: bytes.length,
          sha256: sha256Bytes(bytes),
        });
        continue;
      }
      await rm(written, { force: true }).catch(() => {});
      entries.push({
        name,
        status: "skipped",
        output: null,
        error: `resource exceeds ${String(MAX_RESOURCE_BYTES)} byte extraction bound`,
      });
      continue;
    }
    entries.push({
      name,
      status: "failed",
      output: null,
      error:
        extracted.stderr.trim().split("\n")[0] ??
        `ilspycmd --resource exited ${String(extracted.code)}`,
    });
  }
  const recovered = entries.filter(
    (entry) =>
      entry.status === "recovered-via-project" || entry.status === "extracted",
  ).length;
  return {
    status: recovered === entries.length ? "ok" : recovered > 0 ? "partial" : "failed",
    entries,
    error: null,
  };
};

/**
 * Recover PDB symbol evidence and embedded sources for one assembly. The
 * evidence record stays small (documents, hashes, SourceLink); raw source
 * bytes live under sources/<stem>/ with one file per PDB document row.
 */
const recoverAssemblySymbols = async ({
  assemblyPath,
  evidenceDirectory,
  sourcesDirectory,
  stem,
  outputPath,
}) => {
  const symbols = await recoverSymbols(assemblyPath);
  const record = {
    kind: symbols.kind,
    documents: (symbols.documents ?? []).map((document) => ({
      path: document.path,
      language: document.language,
      hash_algorithm: document.hash_algorithm,
      hash: document.hash,
    })),
    source_link: symbols.source_link,
    embedded_sources: [],
    error: symbols.error ?? null,
  };
  if (
    symbols.kind !== null &&
    symbols.embedded_sources !== undefined &&
    symbols.embedded_sources.length > 0
  ) {
    const assemblySources = join(sourcesDirectory, stem);
    await mkdir(assemblySources, { recursive: true });
    const used = new Set();
    for (const source of symbols.embedded_sources) {
      const document = symbols.documents.find(
        (entry) => entry.path === source.path,
      );
      const row = document?.row ?? 0;
      let fileName = sourceOutputName(source.path, row);
      let candidate = fileName;
      let counter = 1;
      while (used.has(candidate)) {
        counter += 1;
        candidate = `${fileName}-${String(counter)}`;
      }
      used.add(candidate);
      const output = join(assemblySources, candidate);
      await writeFile(output, source.bytes);
      record.embedded_sources.push({
        path: source.path,
        output: relative(outputPath, output),
        bytes: source.bytes.length,
        sha256: sha256Bytes(source.bytes),
      });
    }
  }
  await writeFile(
    join(evidenceDirectory, `${stem}.symbols.json`),
    `${JSON.stringify(record, null, 2)}\n`,
  );
  return record;
};

const listBundleEntries = async (ilspyPath, path, env) => {
  const result = await run(ilspyPath, ["--disable-updatecheck", path], {
    env,
    timeout: 120_000,
  });
  const output = `${result.stdout}\n${result.stderr}`;
  if (!output.includes("single-file bundle")) return undefined;
  const entries = [];
  let inList = false;
  for (const line of output.split("\n")) {
    if (line.includes("Managed entries:")) {
      inList = true;
      continue;
    }
    if (!inList) continue;
    const match = line.match(/^\s{2,}(\S+\.dll)\s*(?:\(entry point\))?\s*$/u);
    if (match)
      entries.push({
        name: match[1],
        entryPoint: line.includes("(entry point)"),
      });
    else if (line.trim().length === 0) inList = false;
  }
  return entries.length > 0 ? entries : undefined;
};

const decompileBundle = async (
  ilspyPath,
  path,
  outputRoot,
  entries,
  scope,
  env,
  { referencePath, usePdb } = {},
) => {
  const selected =
    scope === "all"
      ? entries
      : entries.filter((entry) => !isFrameworkAssembly(entry.name));
  const results = [];
  for (const entry of selected) {
    const entryDirectory = join(
      outputRoot,
      safeName(basename(entry.name, ".dll")),
    );
    await mkdir(entryDirectory, { recursive: true });
    const result = await run(
      ilspyPath,
      [
        ...ilspyProjectArgs({
          output: entryDirectory,
          referencePath,
          usePdb,
          bundleEntry: entry.name,
        }),
        path,
      ],
      { env },
    );
    const sources = await countSourceFiles(entryDirectory);
    const entryErrors = result.stderr
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    results.push({
      entry: entry.name,
      entry_point: entry.entryPoint,
      output: relative(dirname(outputRoot), entryDirectory),
      exit: result.code,
      source_files: sources,
      status:
        result.code === 0 && sources > 0 && entryErrors.length === 0
          ? "ok"
          : sources > 0
            ? "partial"
            : "failed",
      error:
        result.code === 0
          ? (entryErrors[0] ?? null)
          : (result.stderr.trim().split("\n")[0] ??
            `ilspycmd exited ${String(result.code)}`),
    });
  }
  return results;
};

const findIl2CppPair = async (inputPath) => {
  const metadataName = "global-metadata.dat";
  const binaryNames = new Set([
    "GameAssembly.dylib",
    "GameAssembly.dll",
    "libil2cpp.so",
  ]);
  const inputInfo = await stat(inputPath);
  if (inputInfo.isFile()) {
    if (basename(inputPath) === metadataName) {
      const directory = dirname(inputPath);
      for (const candidate of [
        join(directory, "..", "..", "..", "Frameworks", "GameAssembly.dylib"),
        join(directory, "..", "..", "..", "GameAssembly.dylib"),
      ]) {
        if (await exists(candidate))
          return { metadata: inputPath, binary: candidate };
      }
      return { metadata: inputPath, binary: undefined };
    }
    if (binaryNames.has(basename(inputPath)))
      return { metadata: undefined, binary: inputPath };
    return undefined;
  }
  if (!inputInfo.isDirectory()) return undefined;

  let metadata;
  let binary;
  const walk = async (directory) => {
    if (metadata !== undefined && binary !== undefined) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (metadata !== undefined && binary !== undefined) return;
      const entryPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && entry.name !== ".git")
          await walk(entryPath);
      } else if (entry.isFile()) {
        if (entry.name === metadataName) metadata = entryPath;
        else if (binaryNames.has(entry.name)) binary = entryPath;
      }
    }
  };
  await walk(inputPath);
  if (metadata === undefined && binary === undefined) return undefined;
  return { metadata, binary };
};

const runIl2CppDumper = async (
  dumperPath,
  metadata,
  binary,
  outputRoot,
  env,
) => {
  const toolDirectory = join(outputRoot, "tools", "Il2CppDumper");
  await rm(toolDirectory, { recursive: true, force: true });
  await mkdir(dirname(toolDirectory), { recursive: true });
  await cp(dirname(dumperPath), toolDirectory, {
    recursive: true,
    filter: (source) => {
      const name = basename(source);
      return (
        ![
          "DummyDll",
          "dump.cs",
          "il2cpp.h",
          "script.json",
          "stringliteral.json",
        ].includes(name) && !name.endsWith(".zip")
      );
    },
  });
  const copiedDumper = join(toolDirectory, basename(dumperPath));
  const configPath = join(toolDirectory, "config.json");
  if (await exists(configPath)) {
    const config = parseJson(await readFile(configPath, "utf8")) ?? {};
    config.RequireAnyKey = false;
    await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`);
  }
  const outputDirectory = join(outputRoot, "il2cpp");
  await mkdir(outputDirectory, { recursive: true });
  const result = await run(
    "dotnet",
    [copiedDumper, binary, metadata, outputDirectory],
    { env: { ...env, DOTNET_ROLL_FORWARD: "Major" }, timeout: 30 * 60 * 1000 },
  );
  if (result.code !== 0) {
    return {
      ok: false,
      error:
        result.stderr.trim().split("\n")[0] ??
        `Il2CppDumper exited ${String(result.code)}`,
      outputDirectory,
    };
  }
  const dummyDirectory = join(outputDirectory, "DummyDll");
  const available = await exists(dummyDirectory);
  return {
    ok: true,
    outputDirectory,
    dummyDirectory: available ? dummyDirectory : undefined,
  };
};

const verifyIl2CppEvidence = async (metadata, binary, env, bundlePath) => {
  const args = [
    reaEntry,
    "inspect-il2cpp-metadata",
    metadata,
    "--detail",
    "summary",
    "--evidence_output",
    bundlePath,
    "--format",
    "json",
  ];
  if (binary !== undefined) args.push("--binary", binary);
  const result = await run(process.execPath, args, { env });
  if (result.code !== 0) {
    return {
      ok: false,
      error:
        result.stderr.trim().split("\n")[0] ?? `exited ${String(result.code)}`,
    };
  }
  const payload = parseJson(result.stdout);
  const evidence = payload?.summary;
  const inner = evidence?.normalized_result?.summary;
  if (evidence === undefined || inner === undefined) {
    return { ok: false, error: "REA returned no IL2CPP summary" };
  }
  return {
    ok: true,
    evidence: {
      evidence_id: evidence.evidence_id,
      metadata_version: inner.metadata_version ?? null,
      counts: inner.counts ?? {},
      limitations: inner.limitations ?? [],
    },
  };
};

const runBuild = async (outputPath, env) => {
  const projects = await findProjectFiles(join(outputPath, "decompiled"));
  const results = [];
  for (const project of projects) {
    const result = await run("dotnet", ["build", project, "--nologo", "-v:q"], {
      env,
      timeout: 10 * 60 * 1000,
    });
    results.push({
      project: relative(outputPath, project),
      ok: result.code === 0,
      exit: result.code,
      error:
        result.code === 0
          ? null
          : result.stderr.trim().split("\n").slice(-3).join(" ") ||
            `dotnet build exited ${String(result.code)}`,
    });
  }
  const failed = results.filter((result) => !result.ok);
  const rows = results
    .map(
      (result) =>
        `| \`${result.project}\` | ${result.ok ? "ok" : "failed"} | ${result.exit ?? "?"} | ${result.error === null ? "" : result.error.replaceAll("|", "\\|")} |`,
    )
    .join("\n");
  await writeFile(
    join(outputPath, "BUILD_RESULTS.md"),
    `# Build results

| Project | Status | Exit | Error |
|---|---|---|---|
${rows || "| - | none | - | - |"}

${failed.length === 0 ? "All recovered projects built." : `${String(failed.length)} project(s) failed. The recovered source is a starting point, not a guaranteed build.`}
`,
  );
  return {
    ok: results.length > 0 && failed.length === 0,
    projects: results.length,
    failed: failed.length,
    results,
  };
};

const createSolution = async (outputPath, projects, env) => {
  if (projects.length === 0) return null;
  const created = await run(
    "dotnet",
    ["new", "sln", "--name", "Recovered", "--output", outputPath],
    { env },
  );
  if (created.code !== 0) {
    return {
      ok: false,
      error: created.stderr.trim().split("\n")[0] ?? "dotnet new sln failed",
    };
  }
  const solutionName = (await readdir(outputPath)).find((name) =>
    /^Recovered\.slnx?$/u.test(name),
  );
  if (solutionName === undefined)
    return { ok: false, error: "solution file was not created" };
  const solutionPath = join(outputPath, solutionName);
  const added = await run("dotnet", ["sln", solutionPath, "add", ...projects], {
    env,
    timeout: 5 * 60 * 1000,
  });
  return {
    ok: added.code === 0,
    file: solutionName,
    projects: projects.length,
    error:
      added.code === 0
        ? null
        : (added.stderr.trim().split("\n")[0] ?? "dotnet sln add failed"),
  };
};

const writeRepoScaffold = async (outputPath, manifest, options, env) => {
  const projects = await findProjectFiles(join(outputPath, "decompiled"));
  const referenceRewrite =
    options.rewriteReferences && projects.length > 0
      ? await rewriteProjectReferences({ outputPath, projects })
      : { references: [], rewritten: [], unresolved: [] };
  manifest.references = referenceRewrite;
  const solution = await createSolution(outputPath, projects, env);
  const assemblyRows = manifest.assemblies
    .map(
      (entry) =>
        `| ${entry.name} | ${entry.runtime_family ?? "unknown"} | ${entry.member_summary?.counts?.types ?? "?"} | ${entry.member_summary?.counts?.methods ?? "?"} | ${entry.decompiled_files} | ${entry.status} |`,
    )
    .join("\n");
  const bundleRows = manifest.bundles
    .map(
      (bundle) =>
        `| ${bundle.path} | ${bundle.entries} | ${bundle.decompiled.reduce((sum, item) => sum + item.source_files, 0)} | ${bundle.status} |`,
    )
    .join("\n");
  const references = manifest.assemblies.flatMap((entry) =>
    (entry.references ?? []).map((reference) =>
      `- ${entry.name} -> ${reference.name} ${reference.version ?? ""}`.trimEnd(),
    ),
  );
  const readme = `# Recovered .NET repository

Generated by REA from:

\`${manifest.input}\`

## What is here

- \`decompiled/\` — reconstructed C# and project files
- \`evidence/\` — REA evidence bundles (metadata, hashes, coverage)
- \`sources/\` — byte-identical embedded sources recovered from PDBs
- \`resources/\` — managed resources missing from project output
- \`config/\` — small adjacent files (configs, sidecar PDBs when small)
- \`deployment.json\` — deployment manifests and NuGet/framework summary
- \`il2cpp/\` — IL2CPP dummy assemblies and \`dump.cs\` when present
- \`manifest.json\` — machine-readable extraction record
- \`REPORT.md\` — extraction report and limitations
- \`manifest.json\` \`hash_scan\` — hash-shaped literals and obfuscated-name counts
- \`manifest.json\` \`license_scan\` — license-dongle check evidence per assembly
- \`AGENT_TASK.md\` — reconstruction instructions for an AI agent
- \`dependencies.md\` — observed assembly references
- \`LIMITATIONS.md\` — what this extraction cannot prove
- \`TESTING.md\` — how to verify reconstructed behavior
- \`BUILD_RESULTS.md\` — build attempt results when \`--build\` is used
${manifest.il2cpp === null ? "" : "- \`NATIVE_ANALYSIS.md\` — IL2CPP native handoff\n"}

## Inventory

| Assembly | Runtime | Types | Methods | .cs files | Status |
|---|---|---|---:|---|---:|---|
${assemblyRows || "| - | - | - | - | 0 | none |"}

${bundleRows.length === 0 ? "" : `## Single-file bundles\n\n| Bundle | Entries | .cs files | Status |\n|---|---:|---:|---|\n${bundleRows}\n`}
${manifest.il2cpp === null ? "" : `## IL2CPP\n\n- Metadata version: ${manifest.il2cpp.metadata_evidence?.metadata_version ?? "unknown"}\n- Dummy DLLs: ${manifest.il2cpp.dumper?.dummy_dlls ?? 0}\n- Method bodies are native code and are not present in the reconstructed C#.\n`}
## Build

Windows:

\`\`\`powershell
.\\build.ps1
\`\`\`

macOS/Linux:

\`\`\`bash
./build.sh
\`\`\`

The generated projects are a starting point. Missing references, compiler-generated code, and original resources commonly require manual reconstruction.

## Evidence policy

Decompiled C# is reconstructed, not original source. \`manifest.json\` and \`evidence/\` are the authoritative record of what was observed.
`;
  const agentTask = `# Reconstruction task

You are working on a decompiled .NET product. The extraction is already complete.

## Inputs

- \`manifest.json\`
- \`REPORT.md\`
- \`decompiled/\`
- \`evidence/\`
- \`sources/\` (embedded sources recovered from PDBs)
- \`deployment.json\` (frameworks, packages, assets)
- \`resources/\` (recovered managed resources)
${manifest.il2cpp === null ? "" : "- \`il2cpp/\` (dummy assemblies and native RVA map)\n"}
## Goal

Make the recovered projects build and, where tests or documented behavior exist, behave correctly.

## Rules

1. Never execute untrusted target code or decompiled code.
2. Never fabricate behavior. Mark unknown behavior explicitly.
3. Keep the REA evidence and manifest unchanged.
4. Fix one project or feature at a time; record every command and result.
5. Prefer minimal edits over rewriting whole files.
6. Do not add binary blobs or credentials to the repository.
7. If a dependency is proprietary or missing, stop and report it.

## Suggested order

1. Run the build script and collect errors.
2. Fix project files, target frameworks, and assembly references.
3. Resolve missing namespaces and API differences.
4. Reconstruct embedded resources only from evidence.
5. Add focused tests for verified behavior.
6. Report remaining unknowns and unverified paths.

${manifest.il2cpp === null ? "" : "IL2CPP note: dummy assemblies have empty method bodies. Method behavior requires native analysis of GameAssembly; do not invent C# bodies.\n"}
## Inventory

${assemblyRows || "- No managed assemblies were recovered."}
`;
  const rewriteLines = [
    ...referenceRewrite.rewritten.map(
      (project) => `- Rewrote references in \`${project}\``,
    ),
    ...referenceRewrite.references.map(
      (copied) =>
        `- Copied \`${copied.source}\` to \`${copied.output}\` (sha256 ${copied.sha256.slice(0, 12)})`,
    ),
    ...referenceRewrite.unresolved.map(
      (missing) =>
        `- Unresolved: \`${missing.project}\` references \`${missing.reference}\` at \`${missing.hint}\` (target missing)`,
    ),
  ];
  const dependencies = `# Observed assembly references

${references.length === 0 ? "- None recorded." : references.join("\n")}

## License-dongle checks

${
  options.licenseScan
    ? manifest.assemblies
        .map((entry) => {
          if (
            entry.license_scan === null ||
            entry.license_scan.status === "none"
          )
            return `- ${entry.name}: no dongle signals`;
          if (entry.license_scan.status === "unknown")
            return `- ${entry.name}: scan failed (${entry.license_scan.error ?? "unknown error"})`;
          return `- ${entry.name} (${entry.license_scan.status}): ${entry.license_scan.findings.map((finding) => `\`${finding.detail}\` [${finding.signal}]`).join(", ")}`;
        })
        .join("\n") || "- No assemblies scanned."
    : "- Disabled with --no-license-scan."
}

Findings describe license checks observed in static evidence. This repository provides no bypass, defeat, or circumvention guidance.

## Reference rewrite

${options.rewriteReferences ? (rewriteLines.length === 0 ? "- No project references needed rewriting." : rewriteLines.join("\n")) : "- Disabled with --no-reference-rewrite; ILSpy project references are unchanged."}
`;
  const limitations = `# Limitations

This repository is decompiled output, not the original source. Treat it as evidence-backed reconstruction.

## Not recovered as C#

- IL2CPP method bodies. IL2CPP compiles IL to native code; dummy assemblies carry names, fields, and RVA addresses, not C# bodies.
- Native or mixed-mode implementation code.
- Original comments and source layout. Local variable names come from PDBs only when the producer shipped them; decompiled names are otherwise ILSpy inference.
- Obfuscated or protected logic in its original form.

## Recovered byte-identical artifacts

- \`sources/\` files are producer-embedded PDB copies, not decompiled output. They are the closest thing to original source in this repository.
- \`resources/\` and \`config/\` files are extracted or copied bytes, recorded with sha256 in \`manifest.json\`.
- \`deployment.json\` records the shipped target frameworks, NuGet packages, and runtime/native assets from \`.deps.json\` and \`.runtimeconfig.json\`.

## Not guaranteed

- That the recovered projects build without changes.
- That decompiled behavior matches the original.
- That resources, XAML/BAML, shaders, or Unity assets are complete.
- That missing third-party dependencies can be redistributed.

## Required external verification

- Build every project and fix references manually or with an agent.
- Test behavior against documented behavior or a controlled oracle.
- Use a native decompiler (Ghidra, IDA, Hopper) for native code.
- Use an asset extractor for Unity assets; AssetRipper's free build is GUI-only.
`;
  const testing = `# Verification

Decompilation is not proof of behavior equivalence.

## Minimum checks

1. Build each project.
2. Run static checks and unit tests that you write from observed behavior.
3. Compare public API signatures against \`manifest.json\` and the original assemblies.
4. Diff \`sources/\` against \`decompiled/\` where both cover a file; embedded sources win on conflicts.
5. Confirm \`deployment.json\` frameworks and packages match the projects you build against.
6. Exercise entry points in an isolated environment only after explicit approval.

## Evidence boundaries

- \`manifest.json\` and \`evidence/\` describe what REA observed.
- Decompiled C# is inference, not original source. \`sources/\` files are byte-identical PDB copies and outrank decompiled text.
- SourceLink mappings are recorded evidence only; never fetch them without explicit approval.
- IL2CPP dummy assemblies contain empty method bodies; do not treat them as implemented logic.
- Unresolved calls, reflection, dependency injection, and dynamic loading remain unknown unless separately verified.
`;
  const nativeAnalysis =
    manifest.il2cpp === null
      ? ""
      : `# IL2CPP native analysis

- Metadata: \`${manifest.il2cpp.metadata ?? "missing"}\`
- GameAssembly: \`${manifest.il2cpp.binary ?? "missing"}\`
- Metadata version: ${manifest.il2cpp.metadata_evidence?.metadata_version ?? "unknown"}
- Dummy assemblies: \`il2cpp/DummyDll/\`
- Signatures and RVAs: \`il2cpp/dump.cs\`
- RVA/name map for Ghidra/IDA: \`il2cpp/script.json\`

Il2CppDumper writes Ghidra/IDA helper scripts in its own installation directory (\`ghidra.py\`, \`ghidra_with_struct.py\`, \`ida.py\`). Use them with the native binary to recover pseudo-code and cross-references.

The reconstructed C# bodies are empty. Native pseudo-code is not original C# and must be labeled as inference.
`;
  const gitignore = `bin/
obj/
.vs/
*.user
*.suo
*.cache
`;
  const buildPs1 = `$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$projects = Get-ChildItem -Path $root -Recurse -Filter *.csproj |
  Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' }
if (-not $projects) { Write-Host "No projects found."; exit 0 }
$failed = @()
foreach ($project in $projects) {
  Write-Host "Building $($project.FullName)"
  dotnet build $project.FullName --nologo
  if ($LASTEXITCODE -ne 0) { $failed += $project.FullName }
}
if ($failed.Count -gt 0) {
  Write-Host "Failed projects:"
  $failed | ForEach-Object { Write-Host "  $_" }
  exit 1
}
Write-Host "All projects built."
`;
  const buildSh = `#!/usr/bin/env bash
set -u
root="$(cd "$(dirname "$0")" && pwd)"
failed=0
while IFS= read -r -d '' project; do
  echo "Building $project"
  dotnet build "$project" --nologo || failed=1
done < <(find "$root" -name '*.csproj' -not -path '*/bin/*' -not -path '*/obj/*' -print0)
if [ "$failed" -ne 0 ]; then
  echo "One or more projects failed to build."
  exit 1
fi
echo "All projects built."
`;
  await writeFile(join(outputPath, "README.md"), readme);
  await writeFile(join(outputPath, "AGENT_TASK.md"), agentTask);
  await writeFile(join(outputPath, "dependencies.md"), dependencies);
  await writeFile(join(outputPath, "LIMITATIONS.md"), limitations);
  await writeFile(join(outputPath, "TESTING.md"), testing);
  if (nativeAnalysis.length > 0)
    await writeFile(join(outputPath, "NATIVE_ANALYSIS.md"), nativeAnalysis);
  await writeFile(join(outputPath, ".gitignore"), gitignore);
  await writeFile(join(outputPath, "build.ps1"), buildPs1);
  await writeFile(join(outputPath, "build.sh"), buildSh);
  try {
    await chmod(join(outputPath, "build.sh"), 0o755);
  } catch {
    // Windows does not use POSIX execute bits.
  }
  let git = null;
  if (options.gitInit) {
    const initialized = await run("git", ["init"], {
      cwd: outputPath,
      env,
      timeout: 60_000,
    });
    git = {
      ok: initialized.code === 0,
      error: initialized.code === 0 ? null : initialized.stderr.trim(),
    };
  }
  return {
    projects: projects.length,
    solution,
    build_scripts: ["build.ps1", "build.sh"],
    agent_task: "AGENT_TASK.md",
    reference_rewrite: {
      rewritten: referenceRewrite.rewritten,
      copied: referenceRewrite.references.length,
      unresolved: referenceRewrite.unresolved.length,
    },
    git,
  };
};

const detectInput = async (inputPath, env, ilspyPath, options) => {
  const pair = options.il2cpp ? await findIl2CppPair(inputPath) : undefined;
  const candidates = await collectCandidates(inputPath, pair === undefined);
  const counts = { managed: 0, native: 0, single_file: 0, unknown: 0 };
  const samples = [];
  const limit = Math.min(candidates.length, 50);
  for (let index = 0; index < limit; index += 1) {
    const candidate = candidates[index];
    const inspection = await inspectAssembly(candidate, env);
    if (inspection.managed) {
      counts.managed += 1;
      samples.push({
        path: candidate,
        kind: "managed",
        name: inspection.artifact.assembly?.name ?? basename(candidate),
        runtime_version: inspection.artifact.pe?.cli?.runtime_version ?? null,
      });
      continue;
    }
    const format = await detectFormat(candidate);
    if (
      options.singleFile &&
      (format === "pe" || format === "macho") &&
      (extname(candidate) === "" || extname(candidate).toLowerCase() === ".exe")
    ) {
      const entries = await listBundleEntries(ilspyPath, candidate, env);
      if (entries !== undefined) {
        counts.single_file += 1;
        samples.push({
          path: candidate,
          kind: "single-file",
          entries: entries.length,
        });
        continue;
      }
    }
    if (format === "pe" || format === "macho" || format === "elf") {
      counts.native += 1;
      samples.push({ path: candidate, kind: "native", format });
    } else {
      counts.unknown += 1;
      samples.push({ path: candidate, kind: "unknown", format });
    }
  }
  return {
    input: inputPath,
    il2cpp: pair ?? null,
    candidates: candidates.length,
    scanned: limit,
    counts,
    samples,
  };
};

const main = async () => {
  const { positional, options } = parseArgs(process.argv.slice(2));
  const progress = (message) => {
    if (options.quiet || options.json) process.stderr.write(message);
    else process.stdout.write(message);
  };
  const required = options.detect ? 1 : 2;
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }
  if (positional.length < required) {
    process.stdout.write(usage());
    return 2;
  }

  const inputPath = resolve(positional[0]);
  if (options.detect) {
    if (!(await exists(inputPath)))
      throw new Error(`Input does not exist: ${inputPath}`);
    const ilspy = await findIlspy(options.ilspy);
    if (ilspy === undefined) {
      throw new Error(
        "ilspycmd was not found. Install it with `dotnet tool install -g ilspycmd` or pass --ilspy <path>.",
      );
    }
    const env = await toolEnv(ilspy);
    const detection = await detectInput(inputPath, env, ilspy, options);
    process.stdout.write(`${JSON.stringify(detection, null, 2)}\n`);
    return 0;
  }
  const outputPath = resolve(positional[1]);
  if (!(await exists(inputPath)))
    throw new Error(`Input does not exist: ${inputPath}`);
  const inputInfo = await stat(inputPath);
  const inputIsDirectory = inputInfo.isDirectory();
  if ((await exists(outputPath)) && !options.force) {
    const existing = await readdir(outputPath);
    if (existing.length > 0) {
      throw new Error(
        `Output directory is not empty: ${outputPath} (use --force to continue)`,
      );
    }
  }
  await mkdir(outputPath, { recursive: true });

  if (!(await exists(join(repoRoot, "dist", "cli.js")))) {
    throw new Error(
      `REA build output is missing; run \`npm run build:cached\` in ${repoRoot}.`,
    );
  }

  const ilspyPath = await findIlspy(options.ilspy);
  if (ilspyPath === undefined) {
    throw new Error(
      "ilspycmd was not found. Install it with `dotnet tool install -g ilspycmd` or pass --ilspy <path>.",
    );
  }
  const env = await toolEnv(ilspyPath);

  const [reaVersion, nodeVersion, dotnetVersion, ilspyVersion] =
    await Promise.all([
      toolVersion(process.execPath, [reaEntry, "--version"], env),
      toolVersion(process.execPath, ["--version"], env),
      toolVersion("dotnet", ["--version"], env),
      toolVersion(ilspyPath, ["--version"], env),
    ]);

  const evidenceDirectory = join(outputPath, "evidence");
  const decompiledDirectory = join(outputPath, "decompiled");
  const sourcesDirectory = join(outputPath, "sources");
  const resourcesDirectory = join(outputPath, "resources");
  const configDirectory = join(outputPath, "config");
  await mkdir(evidenceDirectory, { recursive: true });
  await mkdir(decompiledDirectory, { recursive: true });

  const il2cppRecord = options.il2cpp
    ? await (async () => {
        const pair = await findIl2CppPair(inputPath);
        if (pair === undefined) return null;
        const label = safeName(
          basename(
            pair.metadata ? dirname(pair.metadata) : dirname(pair.binary),
          ),
        );
        const bundlePath = join(evidenceDirectory, `${label}-il2cpp.bundle`);
        const evidence = pair.metadata
          ? await verifyIl2CppEvidence(
              pair.metadata,
              pair.binary,
              env,
              bundlePath,
            )
          : {
              ok: false,
              error:
                "global-metadata.dat was not found next to the IL2CPP binary",
            };
        const record = {
          metadata: pair.metadata ?? null,
          binary: pair.binary ?? null,
          evidence_bundle: evidence.ok
            ? relative(outputPath, bundlePath)
            : null,
          metadata_evidence: evidence.ok ? evidence.evidence : null,
          metadata_error: evidence.ok ? null : evidence.error,
          dumper: null,
          decompiled: [],
          limitations: [
            "IL2CPP converts IL to native code; dummy assemblies recover structure and names, not method bodies.",
            "Method bodies require native decompilation of GameAssembly and are not produced as C#.",
          ],
        };
        if (pair.metadata === undefined || pair.binary === undefined) {
          return record;
        }
        const dumperPath = await findIl2CppDumper(options.il2cppDumper);
        if (dumperPath === undefined) {
          record.dumper = {
            ok: false,
            error: "Il2CppDumper.dll was not found",
          };
          return record;
        }
        const dumped = await runIl2CppDumper(
          dumperPath,
          pair.metadata,
          pair.binary,
          outputPath,
          env,
        );
        record.dumper = dumped.ok
          ? {
              ok: true,
              output: relative(outputPath, dumped.outputDirectory),
              dummy_dlls: dumped.dummyDirectory
                ? (await readdir(dumped.dummyDirectory)).filter((name) =>
                    name.endsWith(".dll"),
                  ).length
                : 0,
            }
          : {
              ok: false,
              error: dumped.error,
              output: relative(outputPath, dumped.outputDirectory),
            };
        if (
          dumped.ok &&
          dumped.dummyDirectory !== undefined &&
          options.il2cppScope !== "none"
        ) {
          const assemblies = (await readdir(dumped.dummyDirectory))
            .filter((name) => name.endsWith(".dll"))
            .sort();
          const selected =
            options.il2cppScope === "all"
              ? assemblies
              : assemblies.filter((name) => !isFrameworkAssembly(name));
          for (const assembly of selected) {
            const assemblyPath = join(dumped.dummyDirectory, assembly);
            const assemblyOutput = join(
              decompiledDirectory,
              "il2cpp",
              safeName(basename(assembly, ".dll")),
            );
            await mkdir(assemblyOutput, { recursive: true });
            const result = await run(
              ilspyPath,
              [
                ...ilspyProjectArgs({
                  output: assemblyOutput,
                  referencePath: dumped.dummyDirectory,
                  usePdb: false,
                }),
                assemblyPath,
              ],
              { env },
            );
            const sources = await countSourceFiles(assemblyOutput);
            const dummyErrors = result.stderr
              .split("\n")
              .map((line) => line.trim())
              .filter((line) => line.length > 0);
            record.decompiled.push({
              assembly,
              output: relative(outputPath, assemblyOutput),
              exit: result.code,
              source_files: sources,
              status:
                result.code === 0 && sources > 0 && dummyErrors.length === 0
                  ? "ok"
                  : sources > 0
                    ? "partial"
                    : "failed",
              error:
                result.code === 0
                  ? (dummyErrors[0] ?? null)
                  : (result.stderr.trim().split("\n")[0] ??
                    `ilspycmd exited ${String(result.code)}`),
            });
          }
        }
        return record;
      })()
    : null;

  const candidates = await collectCandidates(inputPath, il2cppRecord === null);
  if (candidates.length >= MAX_INPUT_FILES) {
    process.stderr.write(
      `Input scan reached the ${String(MAX_INPUT_FILES)} file limit; results are partial.\n`,
    );
  }

  const assemblies = [];
  const bundles = [];
  const native = [];
  const skipped = [];
  const seenDigests = new Set();

  for (const [index, candidate] of candidates.entries()) {
    const inspection = await inspectAssembly(candidate, env);
    if (!inspection.managed) {
      const format = await detectFormat(candidate);
      const mayBeBundle =
        options.singleFile &&
        (format === "pe" || format === "macho") &&
        (extname(candidate) === "" ||
          extname(candidate).toLowerCase() === ".exe");
      if (mayBeBundle) {
        const entries = await listBundleEntries(ilspyPath, candidate, env);
        if (entries !== undefined) {
          const stem = `${String(index).padStart(3, "0")}-${safeName(basename(candidate, extname(candidate)))}`;
          const bundleOutput = join(decompiledDirectory, stem);
          await mkdir(bundleOutput, { recursive: true });
          const results = await decompileBundle(
            ilspyPath,
            candidate,
            bundleOutput,
            entries,
            options.bundleScope,
            env,
            {
              referencePath: dirname(candidate),
              usePdb: options.usePdb,
            },
          );
          bundles.push({
            path: candidate,
            format,
            entries: entries.length,
            decompiled: results,
            status: results.some(
              (result) => result.status === "ok" || result.status === "partial",
            )
              ? "ok"
              : "failed",
          });
          progress(
            `[${String(index + 1)}/${String(candidates.length)}] ${basename(candidate)} -> single-file bundle (${String(results.length)} entries)\n`,
          );
          continue;
        }
      }
      if (format === "pe" || format === "macho" || format === "elf") {
        native.push({
          path: candidate,
          format,
          reason: "Native binary; use `rea decompile` with a native provider.",
        });
      } else {
        skipped.push({ path: candidate, reason: inspection.reason });
      }
      continue;
    }

    let digest;
    try {
      digest = await sha256File(candidate);
    } catch (cause) {
      skipped.push({
        path: candidate,
        reason: `Cannot hash: ${cause.message}`,
      });
      continue;
    }
    if (seenDigests.has(digest)) {
      skipped.push({
        path: candidate,
        reason: `Duplicate content (sha256 ${digest})`,
      });
      continue;
    }
    seenDigests.add(digest);

    const artifact = inspection.artifact;
    const assemblyName = artifact.assembly?.name ?? basename(candidate);
    if (
      !options.includeFramework &&
      inputIsDirectory &&
      isFrameworkAssembly(assemblyName)
    ) {
      skipped.push({
        path: candidate,
        reason: `Framework assembly (${assemblyName}); use --include-framework to decompile it`,
      });
      continue;
    }
    const stem = `${String(index).padStart(3, "0")}-${safeName(basename(candidate, extname(candidate)))}`;
    const bundlePath = join(evidenceDirectory, `${stem}.bundle`);
    const assemblyOutput = join(decompiledDirectory, stem);

    const entry = {
      path: candidate,
      sha256: digest,
      name: artifact.assembly?.name ?? basename(candidate),
      version: artifact.assembly?.version ?? null,
      runtime_version: artifact.pe?.cli?.runtime_version ?? null,
      runtime_family: artifact.classification?.runtime_family ?? null,
      metadata_version: artifact.metadata?.version ?? null,
      managed_architecture:
        artifact.classification?.managed_architecture ?? null,
      references: (artifact.references ?? []).map((reference) => ({
        name: reference.name,
        version: reference.version ?? null,
      })),
      evidence_bundle: relative(outputPath, bundlePath),
      decompiled_dir: relative(outputPath, assemblyOutput),
      member_summary: null,
      ilspy_exit: null,
      decompiled_files: 0,
      symbols: null,
      resources: null,
      status: "pending",
      errors: [],
    };

    if (options.members) {
      const members = await summarizeMembers(candidate, env, bundlePath);
      if (members.ok)
        entry.member_summary = {
          coverage: members.coverage,
          counts: members.counts,
        };
      else entry.errors.push(`member summary: ${members.error}`);
    }

    await mkdir(assemblyOutput, { recursive: true });
    const pdbPath = `${candidate.slice(0, candidate.lastIndexOf("."))}.pdb`;
    const decompile = await run(
      ilspyPath,
      [
        ...ilspyProjectArgs({
          output: assemblyOutput,
          referencePath: dirname(candidate),
          usePdb: options.usePdb && (await exists(pdbPath)),
        }),
        candidate,
      ],
      { env },
    );
    entry.ilspy_exit = decompile.code;
    const sources = await countSourceFiles(assemblyOutput);
    entry.decompiled_files = sources;
    const ilspyErrors = decompile.stderr
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (ilspyErrors.length > 0) entry.errors.push(...ilspyErrors.slice(0, 5));
    if (decompile.code !== 0) {
      entry.errors.push(
        `ilspycmd exited ${String(decompile.code)}: ${decompile.stderr.trim().split("\n")[0] ?? ""}`,
      );
      entry.status = sources > 0 ? "partial" : "failed";
    } else {
      entry.status =
        sources === 0 ? "empty" : ilspyErrors.length > 0 ? "partial" : "ok";
    }

    if (options.hashScan && sources > 0) {
      try {
        entry.hash_scan = await scanDecompiledDirectory(assemblyOutput);
      } catch (cause) {
        entry.hash_scan = null;
        entry.errors.push(
          `hash scan: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
    } else {
      entry.hash_scan = null;
    }

    if (options.licenseScan) {
      const boundaries = await inspectNativeBoundaries(candidate, env);
      if (!boundaries.ok) {
        entry.license_scan = {
          status: "unknown",
          findings: [],
          error: boundaries.error,
        };
        entry.errors.push(`license scan: ${boundaries.error}`);
      } else {
        const keywordHits = (entry.hash_scan?.keyword_hits ?? []).map(
          (hit) => ({ keyword: hit.keyword }),
        );
        const verdict = matchDongleSignals({
          assemblyReferences: (entry.references ?? []).map(
            (reference) => reference.name,
          ),
          moduleRefs: boundaries.moduleRefs,
          pinvokeImports: boundaries.pinvokeImports,
          keywordHits,
        });
        entry.license_scan = {
          status: verdict.status,
          findings: verdict.findings,
          error: null,
        };
      }
    } else {
      entry.license_scan = null;
    }

    if (options.symbols) {
      try {
        entry.symbols = await recoverAssemblySymbols({
          assemblyPath: candidate,
          evidenceDirectory,
          sourcesDirectory,
          stem,
          outputPath,
        });
      } catch (cause) {
        entry.symbols = null;
        entry.errors.push(
          `symbols: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
    } else {
      entry.symbols = null;
    }

    if (options.resources && entry.decompiled_files > 0) {
      try {
        entry.resources = await recoverAssemblyResources({
          ilspyPath,
          assemblyPath: candidate,
          assemblyOutput,
          outputPath,
          resourcesDirectory: join(resourcesDirectory, stem),
          stem,
          env,
        });
      } catch (cause) {
        entry.resources = { status: "unknown", entries: [], error: String(cause?.message ?? cause) };
        entry.errors.push(
          `resources: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
    } else {
      entry.resources = null;
    }
    assemblies.push(entry);

    progress(
      `[${String(index + 1)}/${String(candidates.length)}] ${entry.name} -> ${entry.status} (${String(entry.decompiled_files)} .cs)\n`,
    );
  }

  const managed = assemblies.filter(
    (entry) => entry.status === "ok" || entry.status === "partial",
  );
  if (options.build) options.repo = true;
  const hashAlgorithms = {};
  let hashCandidates = 0;
  let hashAssemblies = 0;
  let licensePresent = 0;
  let licenseSuspicious = 0;
  for (const assembly of assemblies) {
    const byAlgorithm = assembly.hash_scan?.hash_strings.by_algorithm ?? {};
    if (Object.keys(byAlgorithm).length > 0) hashAssemblies += 1;
    for (const [algorithm, count] of Object.entries(byAlgorithm)) {
      hashAlgorithms[algorithm] = (hashAlgorithms[algorithm] ?? 0) + count;
      hashCandidates += count;
    }
    if (assembly.license_scan?.status === "present") licensePresent += 1;
    else if (assembly.license_scan?.status === "suspicious")
      licenseSuspicious += 1;
  }
  // Deployment manifests and adjacent files describe the product as shipped:
  // target frameworks, NuGet/native assets, configs, and sidecar PDBs.
  // Collected once per run, never executed, never fetched from the network.
  let deployment = null;
  let adjacent = [];
  if (options.deployment) {
    const deploymentRoot = inputIsDirectory ? inputPath : dirname(inputPath);
    try {
      const manifests = await collectDeployment(deploymentRoot);
      const summary = deploymentSummary(manifests);
      deployment = {
        manifests: manifests.map((manifest) => ({
          path: manifest.path,
          kind: manifest.kind,
          parsed: manifest.parsed,
        })),
        summary,
      };
      await writeFile(
        join(outputPath, "deployment.json"),
        `${JSON.stringify(deployment, null, 2)}\n`,
      );
    } catch (cause) {
      deployment = {
        manifests: [],
        summary: null,
        error: cause instanceof Error ? cause.message : String(cause),
      };
    }
    try {
      const listed = await collectAdjacentFiles(deploymentRoot);
      for (const file of listed) {
        const record = {
          path: file.path,
          kind: file.kind,
          bytes: file.bytes,
          output: null,
          sha256: null,
        };
        if (file.bytes !== null && file.bytes <= MAX_ADJACENT_BYTES) {
          try {
            const bytes = await readFile(file.path);
            const outputName = `${safeName(basename(file.path))}`;
            await mkdir(configDirectory, { recursive: true });
            const output = join(configDirectory, outputName);
            if (!(await exists(output))) await writeFile(output, bytes);
            record.output = relative(outputPath, output);
            record.sha256 = sha256Bytes(bytes);
          } catch {
            // Record presence without content; the error stays on the file.
          }
        }
        adjacent.push(record);
      }
    } catch {
      adjacent = [];
    }
  }
  const manifest = {
    schema: "rea.dotnet-decompile/5",
    generated_at: new Date().toISOString(),
    input: inputPath,
    output: outputPath,
    tools: {
      rea: reaVersion ?? null,
      node: nodeVersion ?? null,
      dotnet: dotnetVersion ?? null,
      ilspy: ilspyVersion ?? null,
      ilspy_path: ilspyPath,
      il2cpp_dumper:
        options.il2cppDumper ?? (await findIl2CppDumper(undefined)) ?? null,
    },
    counts: {
      candidates: candidates.length,
      managed: assemblies.length,
      decompiled: managed.length,
      failed: assemblies.length - managed.length,
      bundles: bundles.length,
      il2cpp: il2cppRecord === null ? 0 : 1,
      native: native.length,
      skipped: skipped.length,
      source_files:
        assemblies.reduce((total, entry) => total + entry.decompiled_files, 0) +
        bundles.reduce(
          (total, bundle) =>
            total +
            bundle.decompiled.reduce(
              (sum, entry) => sum + entry.source_files,
              0,
            ),
          0,
        ) +
        (il2cppRecord?.decompiled.reduce(
          (sum, entry) => sum + entry.source_files,
          0,
        ) ?? 0),
    },
    assemblies,
    bundles,
    il2cpp: il2cppRecord,
    native,
    skipped,
    references: { references: [], rewritten: [], unresolved: [] },
    hash_scan: options.hashScan
      ? {
          assemblies_scanned: hashAssemblies,
          total_candidates: hashCandidates,
          by_algorithm: hashAlgorithms,
        }
      : null,
    license_scan: options.licenseScan
      ? { present: licensePresent, suspicious: licenseSuspicious }
      : null,
    symbols: options.symbols
      ? {
          assemblies_with_pdb:
            assemblies.filter((entry) => entry.symbols?.kind !== null && entry.symbols?.kind !== undefined).length,
          embedded_sources: assemblies.reduce(
            (total, entry) => total + (entry.symbols?.embedded_sources?.length ?? 0),
            0,
          ),
        }
      : null,
    resources: options.resources
      ? {
          entries: assemblies.reduce(
            (total, entry) => total + (entry.resources?.entries?.length ?? 0),
            0,
          ),
        }
      : null,
    deployment,
    adjacent,
    repo: null,
    build: null,
  };
  if (options.repo) {
    manifest.repo = await writeRepoScaffold(outputPath, manifest, options, env);
  }
  if (options.build) {
    manifest.build = await runBuild(outputPath, env);
    if (manifest.repo !== null) manifest.repo.build = manifest.build;
  }
  await writeFile(
    join(outputPath, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );

  const managedRows = assemblies
    .map(
      (entry) =>
        `| ${entry.name} | ${entry.runtime_family ?? "unknown"} | ${entry.member_summary?.counts?.types ?? "?"} | ${entry.member_summary?.counts?.methods ?? "?"} | ${entry.decompiled_files} | ${entry.status} |`,
    )
    .join("\n");
  const bundleRows = bundles
    .map(
      (bundle) =>
        `| \`${bundle.path}\` | ${bundle.format} | ${bundle.entries} | ${bundle.decompiled.reduce((sum, entry) => sum + entry.source_files, 0)} | ${bundle.status} |`,
    )
    .join("\n");
  const il2cppSection =
    il2cppRecord === null
      ? "- No IL2CPP metadata found."
      : `- Metadata: \`${il2cppRecord.metadata ?? "missing"}\`
- Native binary: \`${il2cppRecord.binary ?? "missing"}\`
- Metadata version: ${il2cppRecord.metadata_evidence?.metadata_version ?? "unknown"}
- Types / methods / fields: ${il2cppRecord.metadata_evidence?.counts?.types ?? "?"} / ${il2cppRecord.metadata_evidence?.counts?.methods ?? "?"} / ${il2cppRecord.metadata_evidence?.counts?.fields ?? "?"}
- Method addresses: ${il2cppRecord.metadata_evidence?.counts?.method_address_states?.code ?? "?"} with code, ${il2cppRecord.metadata_evidence?.counts?.method_address_states?.no_body ?? "?"} without body
- Il2CppDumper: ${il2cppRecord.dumper?.ok ? `ok (${il2cppRecord.dumper.dummy_dlls} dummy DLLs)` : (il2cppRecord.dumper?.error ?? "not run")}
- Decompiled dummy assemblies: ${il2cppRecord.decompiled.length}
- **Method bodies are native code and are not recovered as C#.**`;
  const nativeLines = native
    .map((entry) => `- \`${entry.path}\`: ${entry.format}; ${entry.reason}`)
    .join("\n");
  const skippedLines = skipped
    .map((entry) => `- \`${entry.path}\`: ${entry.reason}`)
    .join("\n");
  const repoSection =
    manifest.repo === null
      ? ""
      : `## Recovered repository

- Projects: ${manifest.repo.projects}
- Solution: ${manifest.repo.solution?.file ?? "not created"}
- Build: \`build.ps1\` (Windows), \`build.sh\` (macOS/Linux)
- Agent handoff: \`AGENT_TASK.md\`
${manifest.build === null ? "" : `- Build attempt: ${manifest.build.ok ? "all projects built" : `${String(manifest.build.failed)} of ${String(manifest.build.projects)} failed`} (see \`BUILD_RESULTS.md\`)\n`}
`;
  const hashRows = assemblies
    .filter((entry) => entry.hash_scan !== null)
    .map((entry) => {
      const strings = entry.hash_scan.hash_strings;
      const algorithms = Object.entries(strings.by_algorithm)
        .map(([algorithm, count]) => `${algorithm} x${String(count)}`)
        .join(", ");
      const names = entry.hash_scan.member_names;
      return `- \`${entry.name}\`: ${strings.distinct_values} distinct literals, ${algorithms || "no hash shapes"}; names: ${String(names.hash_like)} hash-like, ${String(names.minified)} minified`;
    })
    .join("\n");
  const hashSection =
    manifest.hash_scan === null
      ? "- Hash scanning was disabled with --no-hash-scan."
      : `- Assemblies with hash-shaped literals: ${manifest.hash_scan.assemblies_scanned}\n- Total candidates: ${manifest.hash_scan.total_candidates}\n\n${hashRows || "- No hash-shaped literals found."}\n\nUnprefixed hex digests are ambiguous by shape (MD5 and NTLM share one); the manifest lists every plausible algorithm with confidence.`;
  const licenseRows = assemblies
    .filter((entry) => entry.license_scan !== null)
    .map((entry) => {
      if (entry.license_scan.status === "none")
        return `- \`${entry.name}\`: no dongle signals`;
      if (entry.license_scan.status === "unknown")
        return `- \`${entry.name}\`: scan failed (${entry.license_scan.error ?? "unknown error"})`;
      return `- \`${entry.name}\` (${entry.license_scan.status}):\n${entry.license_scan.findings
        .map(
          (finding) =>
            `  - [${finding.signal}] ${finding.vendor !== undefined ? `${finding.vendor} ${finding.product ?? ""} — `.trim() : ""}\`${finding.detail}\`${finding.purpose !== undefined ? ` (${finding.purpose})` : ""}`,
        )
        .join("\n")}`;
    })
    .join("\n");
  const licenseSection =
    manifest.license_scan === null
      ? "- License-dongle scanning was disabled with --no-license-scan."
      : `- Assemblies with dongle evidence: ${manifest.license_scan.present}; keyword-only: ${manifest.license_scan.suspicious}\n\n${licenseRows || "- No assemblies scanned."}\n\nFindings describe license checks observed in static evidence (assembly references, P/Invoke imports, string keywords). This workflow does not provide bypass, defeat, or circumvention guidance.`;
  const symbolRows = assemblies
    .filter((entry) => entry.symbols !== null && entry.symbols !== undefined)
    .map((entry) => {
      const symbols = entry.symbols;
      if (symbols.kind === null || symbols.kind === undefined)
        return `- \`${entry.name}\`: no PDB (embedded or sidecar)${symbols.error === null || symbols.error === undefined ? "" : ` (${symbols.error})`}`;
      const sources = symbols.embedded_sources.length;
      return `- \`${entry.name}\` (${symbols.kind} PDB): ${String(symbols.documents.length)} documents, ${String(sources)} embedded sources${symbols.source_link === null ? "" : ", SourceLink present"}`;
    })
    .join("\n");
  const symbolSection =
    manifest.symbols === null
      ? "- Symbol recovery was disabled with --no-symbols."
      : `- Assemblies with a PDB: ${manifest.symbols.assemblies_with_pdb}\n- Embedded sources recovered: ${manifest.symbols.embedded_sources}\n\n${symbolRows || "- No assemblies scanned."}\n\nPDB documents record original paths, languages, and source hashes. Embedded sources are byte-identical producer copies under \`sources/\`; \`evidence/*.symbols.json\` is the authoritative record.`;
  const resourceRows = assemblies
    .filter((entry) => entry.resources !== null && entry.resources !== undefined)
    .map((entry) => {
      const resources = entry.resources;
      if (resources.status === "none") return `- \`${entry.name}\`: no managed resources`;
      if (resources.status === "unknown")
        return `- \`${entry.name}\`: enumeration failed (${resources.error ?? "unknown error"})`;
      return `- \`${entry.name}\` (${resources.status}): ${String(resources.entries.length)} entries`;
    })
    .join("\n");
  const resourceSection =
    manifest.resources === null
      ? "- Resource recovery was disabled with --no-resources."
      : `- Resource entries observed: ${manifest.resources.entries}\n\n${resourceRows || "- No assemblies scanned."}\n\nEntries already materialized by ILSpy project output (config JSON, .resx, XAML) are recorded, not duplicated; missing entries are extracted under \`resources/\`.`;
  const deploymentSection =
    manifest.deployment === null
      ? "- Deployment collection was disabled with --no-deployment."
      : manifest.deployment.error !== undefined && manifest.deployment.error !== null
        ? `- Deployment collection failed: ${manifest.deployment.error}`
        : `- Manifests: ${String(manifest.deployment.manifests.length)} (see \`deployment.json\`)\n- Frameworks: ${(manifest.deployment.summary?.frameworks ?? []).map((framework) => `${framework.name ?? "unknown"} ${framework.version ?? ""}`.trim()).join(", ") || "none recorded"}\n- NuGet packages: ${String(manifest.deployment.summary?.package_count ?? 0)}`;
  const adjacentRows = (manifest.adjacent ?? [])
    .map(
      (file) =>
        `- \`${file.path}\` (${file.kind}, ${file.bytes === null ? "unknown size" : `${String(file.bytes)} bytes`})${file.output === null || file.output === undefined ? ": recorded only" : `: copied to \`${file.output}\``}`,
    )
    .join("\n");
  const adjacentSection =
    manifest.adjacent === null || manifest.deployment === null
      ? "- Adjacent-file collection was disabled with --no-deployment."
      : `${adjacentRows || "- None found."}`;
  const report = `# .NET / Unity extraction report

- Input: \`${inputPath}\`
- Output: \`${outputPath}\`
- Generated: ${manifest.generated_at}
- REA: ${manifest.tools.rea ?? "unknown"} | .NET: ${manifest.tools.dotnet ?? "unknown"} | ILSpy: ${manifest.tools.ilspy ?? "unknown"}

## Managed assemblies

| Assembly | Runtime | Types | Methods | .cs files | Status |
|---|---|---|---:|---|---:|---|
${managedRows || "| - | - | - | - | 0 | none |"}

## Hashes and obfuscated names

${hashSection}

## License-dongle checks

${licenseSection}

## Symbols and embedded sources

${symbolSection}

## Managed resources

${resourceSection}

## Deployment manifests

${deploymentSection}

## Adjacent files

${adjacentSection}

## .NET single-file bundles

| Bundle | Format | Entries | .cs files | Status |
|---|---|---:|---:|---|
${bundleRows || "| - | - | 0 | 0 | none |"}

## Unity IL2CPP

${il2cppSection}

${repoSection}## Native binaries

${nativeLines || "- None"}

## Skipped inputs

${skippedLines || "- None"}

## Limitations

- Static analysis only; target assemblies are never loaded or executed.
- Decompiled C# is reconstructed, not original source. REA metadata Evidence remains authoritative.
- ILSpy may produce partial output when dependencies are missing or code is obfuscated.
- IL2CPP dummy assemblies contain names, fields and method addresses but empty method bodies.
- Native, mixed-mode, and managed resources are not fully reconstructed by this workflow.
- PDB sidecars larger than 4 MiB are recorded but not copied; read them in place.
- SourceLink mappings are recorded as evidence only and are never fetched.
`;
  await writeFile(join(outputPath, "REPORT.md"), report);

  if (options.json) {
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
  } else {
    progress(
      `\nManaged: ${String(manifest.counts.managed)} | bundles: ${String(manifest.counts.bundles)} | IL2CPP: ${String(manifest.counts.il2cpp)} | native: ${String(manifest.counts.native)} | skipped: ${String(manifest.counts.skipped)} | .cs files: ${String(manifest.counts.source_files)}\n`,
    );
    progress(
      `Manifest: ${join(outputPath, "manifest.json")}\nReport: ${join(outputPath, "REPORT.md")}\n`,
    );
  }
  return manifest.counts.decompiled > 0 ||
    manifest.counts.bundles > 0 ||
    manifest.counts.il2cpp > 0
    ? 0
    : 1;
};

try {
  process.exitCode = await main();
} catch (cause) {
  process.stderr.write(
    `${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  process.exitCode = 1;
}
