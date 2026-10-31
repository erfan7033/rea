import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";

import {
  classifyMemberName,
  identifyHash,
  isFrameworkAssembly,
  isManagedExtension,
  matchDongleApi,
  matchDongleModule,
  matchDongleSignals,
  rewriteProjectReferences,
  safeName,
  scanDecompiledDirectory,
} from "../../../scripts/lib/dotnet-extraction.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const run = promisify(execFile);
const repoRoot = new URL("../../..", import.meta.url).pathname;

it("classifies framework and product assemblies by name", () => {
  expect(isFrameworkAssembly("System.Runtime")).toBe(true);
  expect(isFrameworkAssembly("UnityEngine.CoreModule")).toBe(true);
  expect(isFrameworkAssembly("SampleApp")).toBe(false);
  expect(isManagedExtension("app.dll")).toBe(true);
  expect(isManagedExtension("app.exe")).toBe(true);
  expect(isManagedExtension("app.so")).toBe(false);
  expect(safeName("a/b\\c:d")).toBe("a_b_c_d");
});

it("rewrites recovered references to projects and vendors local copies", async () => {
  const root = await createTestTempDirectory("rea-dotnet-refs-");
  const appProject = join(root, "decompiled", "App", "App.csproj");
  const libProject = join(root, "decompiled", "Lib", "Lib.csproj");
  await mkdir(join(root, "decompiled", "App"), { recursive: true });
  await mkdir(join(root, "decompiled", "Lib"), { recursive: true });
  await writeFile(
    appProject,
    `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><AssemblyName>App</AssemblyName></PropertyGroup>` +
      `<ItemGroup><Reference Include="Lib"><HintPath>..\\Lib\\Lib.dll</HintPath></Reference>` +
      `<Reference Include="ThirdParty"><HintPath>/tmp/rea-third-party/ThirdParty.dll</HintPath></Reference>` +
      `<Reference Include="Missing"><HintPath>/tmp/rea-third-party/Missing.dll</HintPath></Reference>` +
      `</ItemGroup></Project>`,
  );
  await writeFile(
    libProject,
    `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><AssemblyName>Lib</AssemblyName></PropertyGroup></Project>`,
  );
  const thirdPartyDirectory = join(root, "third-party");
  await mkdir(thirdPartyDirectory, { recursive: true });
  const thirdParty = join(thirdPartyDirectory, "ThirdParty.dll");
  await writeFile(thirdParty, "third-party-bytes");
  const text = await readFile(appProject, "utf8");
  await writeFile(
    appProject,
    text.replace("/tmp/rea-third-party/ThirdParty.dll", thirdParty),
  );

  const result = await rewriteProjectReferences({
    outputPath: root,
    projects: [appProject, libProject],
  });

  const rewritten = await readFile(appProject, "utf8");
  expect(rewritten).toContain('<ProjectReference Include="../Lib/Lib.csproj"');
  expect(rewritten).toContain("references/ThirdParty.dll");
  expect(result.rewritten).toEqual(["decompiled/App/App.csproj"]);
  expect(result.references).toHaveLength(1);
  expect(result.references[0]?.output).toBe("references/ThirdParty.dll");
  expect(result.unresolved.map((entry) => entry.reference)).toEqual([
    "Missing",
  ]);
});

it("rewrites nothing when reference rewriting is disabled at the call site", async () => {
  const root = await createTestTempDirectory("rea-dotnet-norewrite-");
  const project = join(root, "App.csproj");
  const before =
    `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>` +
    `<Reference Include="Lib"><HintPath>Lib.dll</HintPath></Reference>` +
    `</ItemGroup></Project>`;
  await writeFile(project, before);
  const result = await rewriteProjectReferences({
    outputPath: root,
    projects: [],
  });
  expect(result).toEqual({ references: [], rewritten: [], unresolved: [] });
  expect(await readFile(project, "utf8")).toBe(before);
});

it("documents the new extraction flags in help output", async () => {
  const { stdout } = await run(process.execPath, [
    join(repoRoot, "scripts", "rea-dotnet-decompile.mjs"),
    "--help",
  ]);
  for (const flag of [
    "--repo",
    "--build",
    "--include-framework",
    "--no-pdb",
    "--no-reference-rewrite",
    "--no-hash-scan",
    "--no-license-scan",
    "--no-symbols",
    "--no-resources",
    "--no-deployment",
    "--json",
    "--quiet",
  ]) {
    expect(stdout).toContain(flag);
  }
}, 30_000);

it("identifies hashes by shape without claiming certainty", () => {
  const md5 = identifyHash("5d41402abc4b2a76b9719d911017c592");
  expect(md5.kind).toBe("hex");
  expect(md5.candidates.map((candidate) => candidate.algorithm)).toContain(
    "MD5",
  );
  expect(md5.candidates.map((candidate) => candidate.algorithm)).toContain(
    "NTLM",
  );
  for (const candidate of md5.candidates) {
    expect(["medium", "low"]).toContain(candidate.confidence);
  }
  const sha1 = identifyHash("da39a3ee5e6b4b0d3255bfef95601890afd80709");
  expect(sha1.candidates.map((candidate) => candidate.algorithm)).toContain(
    "SHA-1",
  );
  const bcrypt = identifyHash(
    "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  );
  expect(bcrypt).toMatchObject({
    kind: "modular",
    candidates: [
      { algorithm: "bcrypt", confidence: "high", reason: expect.any(String) },
    ],
  });
  const argon2 = identifyHash(
    "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$RdescudvJDNYdl6pArewq6rJClsxRzR1tJ7x4",
  );
  expect(argon2.candidates[0]?.algorithm).toBe("argon2");
  expect(argon2.candidates[0]?.confidence).toBe("high");
  expect(identifyHash("123e4567-e89b-12d3-a456-426614174000")).toMatchObject({
    kind: "uuid",
    candidates: [],
  });
  expect(identifyHash("hello")).toMatchObject({
    kind: "unknown",
    candidates: [],
  });
  expect(identifyHash("")).toMatchObject({ kind: "empty", candidates: [] });
  const base64md5 = identifyHash("XUFAKrxLKna5cZ2REBfFkg==");
  expect(base64md5.kind).toBe("base64");
  expect(
    base64md5.candidates.map((candidate) => candidate.algorithm),
  ).toContain("MD5");
});

it("classifies recovered member names", () => {
  expect(classifyMemberName("Customer").kind).toBe("readable");
  expect(classifyMemberName("T").kind).toBe("readable");
  expect(classifyMemberName("a").kind).toBe("minified");
  expect(classifyMemberName("A3F9C2E17B4D").kind).toBe("hash-like");
  expect(classifyMemberName("<PrivateImplementationDetails>").kind).toBe(
    "compiler-generated",
  );
});

it("matches dongle vendors by module, api, and keyword", () => {
  const module = matchDongleModule("hasp_windows_x64.dll");
  expect(module).toHaveLength(1);
  expect(module[0]).toMatchObject({
    product: "Sentinel HASP HL/SRM",
    signal: "module-reference",
    confidence: "high",
  });
  expect(matchDongleModule("kernel32.dll")).toEqual([]);
  const api = matchDongleApi("hasp_login");
  expect(api).toHaveLength(1);
  expect(api[0]).toMatchObject({
    product: "Sentinel HASP HL/SRM",
    purpose: expect.stringContaining("license session"),
  });
  expect(matchDongleApi("MessageBoxW")).toEqual([]);
  const present = matchDongleSignals({
    moduleRefs: ["WibuCm64.dll"],
    pinvokeImports: ["CmCrypt"],
    keywordHits: [],
  });
  expect(present.status).toBe("present");
  expect(
    present.findings.some((finding) => finding.product === "CodeMeter"),
  ).toBe(true);
  const suspicious = matchDongleSignals({
    keywordHits: [{ keyword: "dongle" }],
  });
  expect(suspicious.status).toBe("suspicious");
  expect(matchDongleSignals({}).status).toBe("none");
  for (const finding of present.findings) {
    expect(JSON.stringify(finding).toLowerCase()).not.toContain("bypass");
  }
});

it("scans reconstructed sources for hashes, names, and keywords", async () => {
  const root = await createTestTempDirectory("rea-dotnet-scan-");
  await mkdir(root, { recursive: true });
  await writeFile(
    join(root, "Lic.cs"),
    `namespace Shop;
public static class Lic {
  public const string Token = "5d41402abc4b2a76b9719d911017c592";
  public const string Note = "Confused by ConfuserEx";
  public static void a() {}
}
`,
  );
  await writeFile(
    join(root, "Check.cs"),
    `namespace Shop;
public static class Check {
  public static bool HasDongle() { return false; }
}
`,
  );
  const scanned = await scanDecompiledDirectory(root);
  expect(scanned.files_scanned).toBe(2);
  expect(Object.keys(scanned.hash_strings.by_algorithm)).toContain("MD5");
  expect(scanned.hash_strings.samples[0]?.value).toContain("5d41402abc");
  expect(scanned.member_names.minified).toBeGreaterThanOrEqual(1);
  expect(scanned.keyword_hits.map((hit) => hit.keyword)).toContain("dongle");
  expect(scanned.obfuscation_hits.map((hit) => hit.marker)).toContain(
    "confusedby",
  );
});
