import { spawn } from "node:child_process";
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it, onTestFinished } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const run = promisify(execFile);
const repoRoot = new URL("../../..", import.meta.url).pathname;
const guiScript = join(repoRoot, "scripts", "rea-gui.mjs");

interface GuiServer {
  base: string;
  token: string;
  kill: () => void;
}

const startServer = async (): Promise<GuiServer> => {
  const child = spawn(process.execPath, [guiScript, "--port", "0", "--no-open"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  onTestFinished(() => {
    child.kill("SIGKILL");
  });
  const firstLine = await new Promise<string>((settle, reject) => {
    const timer = setTimeout(
      () => reject(new Error("GUI server did not print its URL")),
      15000,
    );
    let text = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      text += chunk;
      const lines = text.split("\n");
      const line = lines[0] ?? "";
      if (line.startsWith("REA Workbench: ")) {
        clearTimeout(timer);
        settle(line);
      }
    });
    child.on("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      reject(new Error(`GUI server exited ${String(code)}: ${text}`));
    });
  });
  const url = new URL(firstLine.slice("REA Workbench: ".length).trim());
  const token = url.searchParams.get("token") ?? "";
  expect(token.length).toBeGreaterThan(0);
  return {
    base: `${url.protocol}//${url.host}`,
    token,
    kill: () => child.kill("SIGKILL"),
  };
};

const post = async (server: GuiServer, path: string, body: unknown, token?: string) =>
  fetch(`${server.base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-rea-token": token ?? server.token,
    },
    body: JSON.stringify(body),
  });

it("documents the wizard in help output", async () => {
  const { stdout } = await run(process.execPath, [guiScript, "--help"]);
  expect(stdout).toContain("--port");
  expect(stdout).toContain("--no-open");
}, 30000);

it("serves the wizard page and guards the API with the session token", async () => {
  const server = await startServer();
  try {
    const page = await fetch(`${server.base}/?token=${server.token}`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("REA Workbench");
    expect(html).toContain("Pick your target");

    const denied = await fetch(`${server.base}/api/health`);
    expect(denied.status).toBe(403);

    const health = await fetch(`${server.base}/api/health?token=${server.token}`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });
  } finally {
    server.kill();
  }
}, 60000);

it("confines tree and file reads to the output folder", async () => {
  const server = await startServer();
  try {
    const root = await createTestTempDirectory("rea-gui-confine-");
    await mkdir(join(root, "decompiled"), { recursive: true });
    await writeFile(join(root, "decompiled", "App.cs"), "class A {}");
    await writeFile(join(root, "blob.bin"), Buffer.from([0x00, 0x01, 0x02]));

    const escape = await post(server, "/api/tree", { path: root, rel: "../../etc" });
    expect(escape.status).toBe(400);

    const tree = await post(server, "/api/tree", { path: root, rel: "decompiled" });
    expect(tree.status).toBe(200);
    expect(await tree.json()).toEqual({
      entries: [
        { name: "App.cs", type: "file", size: 10, rel: "decompiled/App.cs" },
      ],
      truncated: false,
    });

    const missing = await post(server, "/api/tree", { path: root, rel: "nope" });
    expect(missing.status).toBe(404);

    const fileEscape = await post(server, "/api/file", { path: root, file: "../x" });
    expect(fileEscape.status).toBe(400);

    const absent = await post(server, "/api/file", { path: root, file: "nope.cs" });
    expect(absent.status).toBe(404);

    const binary = await post(server, "/api/file", { path: root, file: "blob.bin" });
    expect(binary.status).toBe(200);
    expect(await binary.json()).toEqual({ binary: true, size: 3 });

    const textFile = await post(server, "/api/file", {
      path: root,
      file: "decompiled/App.cs",
    });
    expect(textFile.status).toBe(200);
    expect(await textFile.json()).toEqual({ text: "class A {}" });
  } finally {
    server.kill();
  }
}, 60000);

it("reports missing results and validates run input", async () => {
  const server = await startServer();
  try {
    const root = await createTestTempDirectory("rea-gui-result-");
    const absent = await post(server, "/api/result", { path: root });
    expect(absent.status).toBe(404);

    const noTarget = await post(server, "/api/run", { path: "", output: root });
    expect(noTarget.status).toBe(400);

    const noOutput = await post(server, "/api/build", { output: join(root, "nope") });
    expect(noOutput.status).toBe(404);
  } finally {
    server.kill();
  }
}, 60000);

it("streams a build run that finds no projects", async () => {
  const server = await startServer();
  try {
    const root = await createTestTempDirectory("rea-gui-build-");
    const started = await post(server, "/api/build", { output: root });
    expect(started.status).toBe(200);
    const { id } = (await started.json()) as { id: string };
    const stream = await fetch(`${server.base}/api/stream/${id}?token=${server.token}`);
    expect(stream.status).toBe(200);
    const body = await stream.text();
    expect(body).toContain("### REA-BUILD none");
    expect(body).toContain('"type":"done"');
  } finally {
    server.kill();
  }
}, 120000);
