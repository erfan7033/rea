#!/usr/bin/env node

/**
 * Goal-driven agent runner for REA.
 *
 * Creates an isolated OpenCode configuration that exposes this checkout's REA
 * MCP server, writes a decompilation playbook, and runs OpenCode headlessly
 * against the goal. The global OpenCode configuration is never modified.
 *
 * Usage:
 *   rea-goal --goal "decompile this product" --target <path> [options]
 *   node scripts/rea-goal.mjs --goal "decompile this product" --target <path> [options]
 *
 * Options:
 *   --out <directory>   Run directory (default: ~/rea-runs/<timestamp>)
 *   --model <id>        OpenCode model, e.g. opencode-go/deepseek-v4.1-flash
  --opencode <path>   OpenCode executable (default: PATH, then ~/.opencode/bin/opencode)
  --local-model <id>  Use an OpenAI-compatible local model, e.g. qwen2.5-coder:7b
  --base-url <url>    Local provider base URL (default: http://127.0.0.1:11434/v1, Ollama)
  --provider-id <id>  Local provider id (default: ollama)
 *   --agent <name>      OpenCode agent (default: build)
 *   --auto              Auto-approve permissions (default)
 *   --no-auto           Require normal OpenCode permission handling
 *   --dry-run           Write the setup and print the command without running it
 */

import { spawn } from "node:child_process";
import { access, mkdir, readdir, writeFile } from "node:fs/promises";
import { constants as fsConstants, createWriteStream } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const WINDOWS = process.platform === "win32";
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const reaEntry = join(repoRoot, "scripts", "rea.mjs");
const decompileScript = join(repoRoot, "scripts", "rea-dotnet-decompile.mjs");

const parseArgs = (argv) => {
  const options = { auto: true };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--goal") options.goal = argv[++index];
    else if (value === "--target") options.target = argv[++index];
    else if (value === "--out") options.out = argv[++index];
    else if (value === "--model") options.model = argv[++index];
    else if (value === "--opencode") options.opencode = argv[++index];
    else if (value === "--local-model") options.localModel = argv[++index];
    else if (value === "--base-url") options.baseUrl = argv[++index];
    else if (value === "--provider-id") options.providerId = argv[++index];
    else if (value === "--agent") options.agent = argv[++index];
    else if (value === "--auto") options.auto = true;
    else if (value === "--no-auto") options.auto = false;
    else if (value === "--dry-run") options.dryRun = true;
    else if (value === "--help" || value === "-h") options.help = true;
    else throw new Error(`Unknown argument: ${value}`);
  }
  return options;
};

const usage = () => `Usage: rea-goal --goal "<goal>" [options]
       node scripts/rea-goal.mjs --goal "<goal>" [options]

Options:
  --target <path>     Target file or directory the goal refers to
  --out <directory>   Run directory (default: ~/rea-runs/<timestamp>)
  --model <id>        OpenCode model, e.g. opencode-go/deepseek-v4.1-flash
  --opencode <path>   OpenCode executable (default: PATH, then ~/.opencode/bin/opencode)
  --local-model <id>  Use an OpenAI-compatible local model, e.g. qwen2.5-coder:7b
  --base-url <url>    Local provider base URL (default: http://127.0.0.1:11434/v1, Ollama)
  --provider-id <id>  Local provider id (default: ollama)
  --agent <name>      OpenCode agent (default: build)
  --auto              Auto-approve permissions (default)
  --no-auto           Require normal OpenCode permission handling
  --dry-run           Write setup, print command, do not run
  --help              Show this help
`;

const exists = async (path) => {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
};

const slug = (value) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 48) || "goal";

const timestamp = () => new Date().toISOString().replace(/[:.]/gu, "-");

const resolveOpenCode = async (explicitPath) => {
  const executable = WINDOWS ? "opencode.exe" : "opencode";
  const candidates = [
    explicitPath,
    process.env.OPENCODE_BIN,
    join(homedir(), ".opencode", "bin", executable),
    process.env.LOCALAPPDATA === undefined
      ? undefined
      : join(process.env.LOCALAPPDATA, "opencode", "bin", executable),
  ].filter((value) => typeof value === "string" && value.length > 0);
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return "opencode";
};

const playbook = (goal, target, runDirectory) => `# REA goal run

## Goal

${goal}

${target === undefined ? "" : `## Target\n\n\`${target}\`\n`}
## Workspace

- Your working directory is \`${runDirectory}\`.
- Create all outputs below this directory. Treat it as the only writable workspace.
- Never modify \`${repoRoot}\` or any other repository. Do not \`cd\` into the REA checkout.
- Invoke \`${reaEntry}\` and \`${decompileScript}\` by absolute path.

## Operating rules

- Analyze statically. Never execute the target product, never run decompiled code.
- Never upload, publish, or send artifacts/source to a remote service.
- Use the local \`rea\` CLI for structured Evidence. Prefer \`--format json\` when parsing.
- Managed code evidence:
  - \`rea inspect-managed-artifact <path>\`
  - \`rea inspect-managed-members <path> --detail summary --evidence-bundle <path>\`
  - \`rea inspect-managed-native-boundaries <path>\`
- Complete .NET extraction (evidence + ILSpy project):
  - \`node ${decompileScript} <target> <output> --repo\`
  - Then read \`<output>/manifest.json\` and \`<output>/REPORT.md\`.
  - The extractor rewrites ILSpy references to recovered projects (or vendored
    copies under \`references/\`) and records the outcome in
    \`manifest.references\`, \`dependencies.md\`, and \`REPORT.md\`.
  - Hash-shaped literals, obfuscated names, and license-dongle checks are
    recorded in \`manifest.hash_scan\` / \`manifest.license_scan\` and
    \`REPORT.md\`. Findings describe observed checks only; never provide
    bypass, defeat, or circumvention guidance.
- Unity IL2CPP: the extractor runs \`rea inspect-il2cpp-metadata\` and Il2CppDumper, then decompiles dummy assemblies. Dummy assemblies contain names, fields and method addresses but empty method bodies; native bodies require a native decompiler.
- Native code: use \`rea decompile\` with the Hopper provider where available. Ghidra may be unavailable.
- ILSpy is installed as \`ilspycmd\`. C# output is reconstructed source, not original source.
- Report exact commands, paths, row counts, failures, and limitations.
- Never fabricate tool output or claim coverage you did not verify.
- If a dependency or provider is missing, report it and continue with independent work.
- Finish with: what was produced, where it is, what is missing, and the next concrete step.
`;

const runStreaming = (command, args, { cwd, env, logPath }) =>
  new Promise((settle, reject) => {
    const log = createWriteStream(logPath);
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const write = (stream, chunk) => {
      stream.write(chunk);
      log.write(chunk);
    };
    child.stdout.on("data", (chunk) => write(process.stdout, chunk));
    child.stderr.on("data", (chunk) => write(process.stderr, chunk));
    child.on("error", (cause) => {
      log.end();
      reject(
        cause?.code === "ENOENT"
          ? new Error(
              "OpenCode was not found. Install it from https://opencode.ai or pass --opencode <path>.",
            )
          : cause,
      );
    });
    child.on("close", (code) => {
      log.end(() => settle(code ?? 1));
    });
  });

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  if (options.help || options.goal === undefined) {
    process.stdout.write(usage());
    return options.help ? 0 : 2;
  }
  if (options.target !== undefined) {
    const target = resolve(options.target);
    if (!(await exists(target)))
      throw new Error(`Target does not exist: ${target}`);
    options.target = target;
  }
  if (!(await exists(join(repoRoot, "dist", "mcp", "main.js")))) {
    throw new Error(
      `REA build output is missing; run \`npm run build:cached\` in ${repoRoot}.`,
    );
  }

  const runDirectory = resolve(
    options.out ??
      join(homedir(), "rea-runs", `${timestamp()}-${slug(options.goal)}`),
  );
  if (await exists(runDirectory)) {
    const entries = await readdir(runDirectory);
    if (entries.length > 0)
      throw new Error(`Run directory is not empty: ${runDirectory}`);
  }
  await mkdir(runDirectory, { recursive: true });
  const configPath = join(runDirectory, "opencode.json");
  const ilspyTool =
    process.env.REA_ILSPY_CMD_PATH ??
    join(homedir(), ".dotnet", "tools", WINDOWS ? "ilspycmd.exe" : "ilspycmd");
  const homebrewDotnetRoot = "/opt/homebrew/opt/dotnet/libexec";
  const dotnetRoot =
    process.env.DOTNET_ROOT ??
    ((await exists(homebrewDotnetRoot)) ? homebrewDotnetRoot : undefined);
  const toolEnvironment = {
    REA_ILSPY_CMD_PATH: ilspyTool,
    ...(dotnetRoot === undefined ? {} : { DOTNET_ROOT: dotnetRoot }),
  };
  const localModel = options.localModel;
  const providerId = options.providerId ?? "ollama";
  const baseUrl = options.baseUrl ?? "http://127.0.0.1:11434/v1";
  const provider =
    localModel === undefined
      ? {}
      : {
          [providerId]: {
            npm: "@ai-sdk/openai-compatible",
            name: `${providerId} (local)`,
            options: { baseURL: baseUrl },
            models: { [localModel]: { name: localModel } },
          },
        };
  const openCodeConfig = {
    $schema: "https://opencode.ai/config.json",
    ...(localModel === undefined ? {} : { provider }),
    mcp: {
      servers: {
        rea: {
          type: "local",
          command: [process.execPath, reaEntry, "mcp"],
          environment: toolEnvironment,
          disabled: false,
        },
      },
    },
  };
  await writeFile(configPath, `${JSON.stringify(openCodeConfig, null, 2)}\n`);
  await writeFile(
    join(runDirectory, "AGENTS.md"),
    playbook(options.goal, options.target, runDirectory),
  );
  await writeFile(
    join(runDirectory, "run.json"),
    `${JSON.stringify({ goal: options.goal, target: options.target ?? null, model: options.model ?? (localModel === undefined ? null : `${providerId}/${localModel}`), local_model: localModel ?? null, created_at: new Date().toISOString() }, null, 2)}\n`,
  );

  const prompt = [
    options.goal,
    options.target === undefined ? "" : `Target: ${options.target}`,
    `Working directory: ${runDirectory}`,
    "Follow AGENTS.md. Stay inside the working directory; use the rea MCP tools and the local rea CLI by absolute path. Produce verifiable output.",
  ]
    .filter((line) => line.length > 0)
    .join("\n\n");

  const args = [
    "--standalone",
    "run",
    "--title",
    `REA: ${options.goal.slice(0, 60)}`,
  ];
  if (options.auto) args.push("--auto");
  if (options.agent !== undefined) args.push("--agent", options.agent);
  if (options.model !== undefined) args.push("--model", options.model);
  else if (localModel !== undefined)
    args.push("--model", `${providerId}/${localModel}`);
  args.push(prompt);

  const openCode = await resolveOpenCode(options.opencode);

  const env = {
    ...process.env,
    OPENCODE_CONFIG: configPath,
    ...toolEnvironment,
  };

  process.stdout.write(`Run directory: ${runDirectory}\n`);
  process.stdout.write(
    `Command: ${openCode} ${args.map((value) => JSON.stringify(value)).join(" ")}\n\n`,
  );
  if (options.dryRun) return 0;

  const code = await runStreaming(openCode, args, {
    cwd: runDirectory,
    env,
    logPath: join(runDirectory, "session.log"),
  });
  process.stdout.write(`\nSession log: ${join(runDirectory, "session.log")}\n`);
  return code;
};

try {
  process.exitCode = await main();
} catch (cause) {
  process.stderr.write(
    `${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  process.exitCode = 1;
}
