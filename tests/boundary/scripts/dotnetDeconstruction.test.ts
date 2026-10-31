import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { mkdir, writeFile } from "node:fs/promises";
import { expect, it } from "vitest";

import {
  classifyRuntimeKind,
  collectAdjacentFiles,
  collectDeployment,
  deploymentSummary,
  findEmbeddedPortablePdb,
  matchObfuscatorSignals,
  parseDepsJson,
  parseRuntimeConfig,
  readPortablePdb,
  recoverSymbols,
  sourceOutputName,
  summarizeSigning,
} from "../../../scripts/lib/dotnet-deconstruction.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const guidBytes = (text: string): Buffer => {
  const compact = text.replaceAll("-", "");
  const data1 = Buffer.alloc(4);
  data1.writeUInt32LE(Number.parseInt(compact.slice(0, 8), 16), 0);
  const data2 = Buffer.alloc(2);
  data2.writeUInt16LE(Number.parseInt(compact.slice(8, 12), 16), 0);
  const data3 = Buffer.alloc(2);
  data3.writeUInt16LE(Number.parseInt(compact.slice(12, 16), 16), 0);
  return Buffer.concat([
    data1,
    data2,
    data3,
    Buffer.from(compact.slice(16), "hex"),
  ]);
};

const compressedBlob = (payload: Buffer): Buffer => {
  const length = payload.length;
  if (length >= 128) throw new Error("fixture blob too large");
  return Buffer.concat([Buffer.from([length]), payload]);
};

/** Minimal portable PDB: one Document, one embedded source, one SourceLink. */
const buildSyntheticPdb = (): Buffer => {
  const sourceText = Buffer.from("hello source", "utf8");
  const deflated = deflateRawSync(sourceText);
  const declared = Buffer.alloc(4);
  declared.writeInt32LE(sourceText.length, 0);
  const sourceValue = compressedBlob(
    Buffer.concat([declared, deflated]),
  );
  const linkJson = Buffer.from(
    '{"documents":{"/app/*":"https://example.invalid/*"}}',
    "utf8",
  );
  const linkValue = compressedBlob(linkJson);

  // Blob heap layout, all offsets below 128 for single-byte encodings.
  const emptyPart = compressedBlob(Buffer.alloc(0));
  const appPart = compressedBlob(Buffer.from("app", "utf8"));
  const filePart = compressedBlob(Buffer.from("a.cs", "utf8"));
  const hashBytes = Buffer.alloc(32, 0xab);
  const hashBlob = compressedBlob(hashBytes);
  const offsets = new Map<string, number>();
  const chunks: Buffer[] = [];
  const place = (name: string, chunk: Buffer): void => {
    offsets.set(name, chunks.reduce((total, entry) => total + entry.length, 0));
    chunks.push(chunk);
  };
  const at = (name: string): number => {
    const value = offsets.get(name);
    if (value === undefined) throw new Error(`missing blob ${name}`);
    return value;
  };
  place("empty", emptyPart);
  place("app", appPart);
  place("file", filePart);
  const nameBlob = compressedBlob(
    Buffer.from([0x2f, at("empty"), at("app"), at("file")]),
  );
  place("name", nameBlob);
  place("hash", hashBlob);
  place("source", sourceValue);
  place("link", linkValue);
  const blobHeap = Buffer.concat(chunks);

  const stringHeap = Buffer.from([0x00]);
  const guidHeap = Buffer.concat([
    guidBytes("8829d00f-11b8-4213-878b-770e8597ac16"),
    guidBytes("3f5162f8-07c6-11d3-9053-00c04fa302a1"),
    guidBytes("0e8a571b-6926-466e-b4ad-8ab04611f5fe"),
    guidBytes("cc110556-a091-4d38-9fec-25ab9a351a6a"),
  ]);

  const header = Buffer.alloc(24);
  header.writeUInt32LE(0, 0);
  header.writeUInt8(2, 4);
  header.writeUInt8(0, 5);
  header.writeUInt8(0, 6);
  header.writeUInt8(1, 7);
  header.writeBigUInt64LE((1n << 48n) | (1n << 55n), 8);
  header.writeBigUInt64LE(0n, 16);
  const rowCounts = Buffer.alloc(8);
  rowCounts.writeUInt32LE(1, 0);
  rowCounts.writeUInt32LE(2, 4);
  const rows = Buffer.alloc(8 + 12);
  rows.writeUInt16LE(at("name"), 0);
  rows.writeUInt16LE(1, 2);
  rows.writeUInt16LE(at("hash"), 4);
  rows.writeUInt16LE(2, 6);
  // EmbeddedSource on Document row 1.
  rows.writeUInt16LE((1 << 5) | 22, 8);
  rows.writeUInt16LE(3, 10);
  rows.writeUInt16LE(at("source"), 12);
  // SourceLink on the (absent) Module row 1; the parser records it by kind.
  rows.writeUInt16LE((1 << 5) | 7, 14);
  rows.writeUInt16LE(4, 16);
  rows.writeUInt16LE(at("link"), 18);
  const tableStream = Buffer.concat([header, rowCounts, rows]);

  const streams: { name: string; data: Buffer }[] = [
    { name: "#~", data: tableStream },
    { name: "#Strings", data: stringHeap },
    { name: "#US", data: Buffer.alloc(4) },
    { name: "#GUID", data: guidHeap },
    { name: "#Blob", data: blobHeap },
  ];
  // Offsets are relative to the metadata root; compute after sizing the head.
  const directoryBody: Buffer[] = [];
  const directoryEntries: Buffer[] = [];
  let headSize = 16 + 12 + 4;
  for (const stream of streams) {
    const nameBytes = Buffer.from(`${stream.name}\0`, "utf8");
    headSize += 8 + ((nameBytes.length + 3) & ~3);
  }
  let cursor = headSize;
  for (const stream of streams) {
    const nameBytes = Buffer.from(`${stream.name}\0`, "utf8");
    const padded = Buffer.alloc((nameBytes.length + 3) & ~3);
    nameBytes.copy(padded);
    const entry = Buffer.alloc(8 + padded.length);
    entry.writeUInt32LE(cursor, 0);
    entry.writeUInt32LE(stream.data.length, 4);
    padded.copy(entry, 8);
    directoryBody.push(entry);
    directoryEntries.push(stream.data);
    cursor += stream.data.length;
  }
  const root = Buffer.concat([
    (() => {
      const signature = Buffer.alloc(16);
      signature.writeUInt32LE(0x424a5342, 0);
      signature.writeUInt16LE(1, 4);
      signature.writeUInt16LE(1, 6);
      signature.writeUInt32LE(0, 8);
      signature.writeUInt32LE(12, 12);
      return signature;
    })(),
    Buffer.from("v4.0.30319\0\0", "utf8"),
    (() => {
      const counts = Buffer.alloc(4);
      counts.writeUInt16LE(0, 0);
      counts.writeUInt16LE(streams.length, 2);
      return counts;
    })(),
    ...directoryBody,
  ]);
  return Buffer.concat([root, ...directoryEntries]);
};

/** Minimal PE64 with one debug directory entry carrying an embedded PDB. */
const buildPeWithEmbeddedPdb = (pdb: Buffer): Buffer => {
  const compressed = deflateRawSync(pdb);
  const mpdb = Buffer.concat([
    Buffer.from([0x4d, 0x50, 0x44, 0x42]),
    (() => {
      const size = Buffer.alloc(4);
      size.writeUInt32LE(pdb.length, 0);
      return size;
    })(),
    compressed,
  ]);
  const peOffset = 0x80;
  const debugEntryOffset = 0x200;
  const mpdbOffset = debugEntryOffset + 28;
  const imageSize = mpdbOffset + mpdb.length;
  const image = Buffer.alloc(imageSize);
  image.writeUInt16LE(0x5a4d, 0);
  image.writeUInt32LE(peOffset, 0x3c);
  image.writeUInt32LE(0x00004550, peOffset);
  image.writeUInt16LE(0x8664, peOffset + 4);
  image.writeUInt16LE(1, peOffset + 4 + 2);
  image.writeUInt16LE(0xf0, peOffset + 4 + 16);
  const optional = peOffset + 24;
  image.writeUInt16LE(0x20b, optional);
  const debugRva = 0x1000;
  image.writeUInt32LE(debugRva, optional + 112 + 6 * 8);
  image.writeUInt32LE(28, optional + 112 + 6 * 8 + 4);
  const sectionTable = optional + 0xf0;
  image.writeUInt32LE(0x1000, sectionTable + 8);
  image.writeUInt32LE(debugRva, sectionTable + 12);
  image.writeUInt32LE(0x1000, sectionTable + 16);
  image.writeUInt32LE(debugEntryOffset, sectionTable + 20);
  image.writeUInt32LE(17, debugEntryOffset + 12);
  image.writeUInt32LE(mpdb.length, debugEntryOffset + 16);
  image.writeUInt32LE(mpdbOffset, debugEntryOffset + 24);
  mpdb.copy(image, mpdbOffset);
  return image;
};

it("parses PDB documents, embedded sources, and SourceLink", () => {
  const parsed = readPortablePdb(buildSyntheticPdb());
  expect(parsed).not.toBeNull();
  expect(parsed?.documents).toHaveLength(1);
  expect(parsed?.documents[0]).toMatchObject({
    row: 1,
    path: "/app/a.cs",
    language: "C#",
    hash_algorithm: "SHA256",
    hash: Buffer.alloc(32, 0xab).toString("hex"),
  });
  expect(parsed?.embedded_sources).toHaveLength(1);
  expect(parsed?.embedded_sources[0]?.path).toBe("/app/a.cs");
  expect(parsed?.embedded_sources[0]?.bytes.toString("utf8")).toBe(
    "hello source",
  );
  expect(parsed?.source_link?.documents).toEqual({
    "/app/*": "https://example.invalid/*",
  });
});

it("rejects non-metadata bytes as a PDB", () => {
  expect(readPortablePdb(Buffer.from("not a pdb"))).toBeNull();
  expect(readPortablePdb(Buffer.alloc(0))).toBeNull();
});

it("locates an embedded PDB in a minimal PE", () => {
  const pdb = buildSyntheticPdb();
  const image = buildPeWithEmbeddedPdb(pdb);
  const found = findEmbeddedPortablePdb(image);
  expect(found).not.toBeNull();
  expect(found?.subarray(0, 4).toString("hex")).toBe(
    pdb.subarray(0, 4).toString("hex"),
  );
  expect(readPortablePdb(found ?? Buffer.alloc(0))?.documents[0]?.path).toBe(
    "/app/a.cs",
  );
});

it("finds no embedded PDB in non-PE or debugless images", () => {
  expect(findEmbeddedPortablePdb(Buffer.from("MZ"))).toBeNull();
  expect(findEmbeddedPortablePdb(Buffer.alloc(0))).toBeNull();
  const plain = Buffer.alloc(0x100);
  plain.writeUInt16LE(0x5a4d, 0);
  plain.writeUInt32LE(0x40, 0x3c);
  expect(findEmbeddedPortablePdb(plain)).toBeNull();
});

it("recovers symbols from sidecar and embedded PDBs", async () => {
  const root = await createTestTempDirectory("rea-dotnet-symbols-");
  const pdb = buildSyntheticPdb();
  await writeFile(join(root, "App.dll"), buildPeWithEmbeddedPdb(pdb));
  const embedded = await recoverSymbols(join(root, "App.dll"));
  expect(embedded.kind).toBe("embedded");
  expect(embedded.documents[0]?.path).toBe("/app/a.cs");
  expect(embedded.embedded_sources).toHaveLength(1);

  await writeFile(join(root, "Bare.dll"), Buffer.from("not a pe"));
  await writeFile(join(root, "Bare.pdb"), pdb);
  const sidecar = await recoverSymbols(join(root, "Bare.dll"));
  expect(sidecar.kind).toBe("sidecar");
  expect(sidecar.documents).toHaveLength(1);
  expect(sidecar.embedded_sources[0]?.bytes.toString("utf8")).toBe(
    "hello source",
  );

  await writeFile(join(root, "None.dll"), Buffer.from("not a pe"));
  const missing = await recoverSymbols(join(root, "None.dll"));
  expect(missing.kind).toBeNull();
  expect(missing.embedded_sources).toEqual([]);

  const absent = await recoverSymbols(join(root, "Absent.dll"));
  expect(absent.kind).toBeNull();
  expect(typeof absent.error).toBe("string");
});

it("parses deployment manifests and summarizes them", async () => {
  const root = await createTestTempDirectory("rea-dotnet-deploy-");
  await writeFile(
    join(root, "App.deps.json"),
    JSON.stringify({
      runtimeTarget: { name: ".NETCoreApp,Version=v9.0" },
      targets: {
        ".NETCoreApp,Version=v9.0": {
          "App/1.0.0": {
            runtime: { "App.dll": {} },
            native: { "runtimes/win-x64/native/hostfxr.dll": {} },
          },
        },
      },
      libraries: {
        "App/1.0.0": { type: "project", serviceable: false },
        "Newtonsoft.Json/13.0.3": { type: "package", serviceable: true },
      },
    }),
  );
  await writeFile(
    join(root, "App.runtimeconfig.json"),
    JSON.stringify({
      runtimeOptions: {
        tfm: "net9.0",
        framework: { name: "Microsoft.NETCore.App", version: "9.0.0" },
        rollForward: "Minor",
        configProperties: { "System.GC.Server": true },
      },
    }),
  );
  await writeFile(join(root, "notes.txt"), "ignored");
  const manifests = await collectDeployment(root);
  expect(manifests).toHaveLength(2);
  const summary = deploymentSummary(manifests);
  expect(summary.package_count).toBe(1);
  expect(summary.packages[0]).toMatchObject({
    name: "Newtonsoft.Json",
    version: "13.0.3",
  });
  expect(summary.frameworks).toContainEqual({
    name: "Microsoft.NETCore.App",
    version: "9.0.0",
  });
  expect(parseDepsJson("nope")).toBeNull();
  expect(parseRuntimeConfig("{}")).toBeNull();
});

it("lists adjacent product files by kind", async () => {
  const root = await createTestTempDirectory("rea-dotnet-adjacent-");
  await mkdir(join(root, "sub"), { recursive: true });
  await writeFile(join(root, "App.pdb"), "pdb");
  await writeFile(join(root, "App.dll.config"), "config");
  await writeFile(join(root, "appsettings.Production.json"), "{}");
  await writeFile(join(root, "sub", "App.xml"), "<doc/>");
  await writeFile(join(root, "ignore.txt"), "nope");
  await writeFile(join(root, "App.dll"), "dll");
  const found = await collectAdjacentFiles(root);
  expect(found.map((entry) => entry.kind)).toEqual([
    "net-config",
    "pdb-sidecar",
    "appsettings",
    "xml-docs",
  ]);
});

it("names embedded-source outputs without leaking producer paths", () => {
  expect(sourceOutputName("/a/b/Program.cs", 1)).toBe("0001-Program.cs");
  expect(sourceOutputName("C:\\src\\a:b.cs", 12)).toBe("0012-a_b.cs");
  expect(sourceOutputName("", 0)).toBe("0000-source");
});

it("matches obfuscator identity by signal strength", () => {
  expect(matchObfuscatorSignals({})).toEqual({ status: "none", indicators: [] });

  const attribute = matchObfuscatorSignals({
    attributeNames: ["System.Reflection.ConfusedByAttribute"],
  });
  expect(attribute.status).toBe("likely");
  expect(
    attribute.indicators.some(
      (indicator) =>
        indicator.tool === "ConfuserEx" &&
        indicator.signal === "obfuscator-attribute" &&
        indicator.confidence === "high",
    ),
  ).toBe(true);

  const reference = matchObfuscatorSignals({
    references: ["SmartAssembly.Core", "System.Runtime"],
  });
  expect(reference.status).toBe("likely");
  expect(
    reference.indicators.some(
      (indicator) =>
        indicator.tool === "SmartAssembly" &&
        indicator.signal === "assembly-reference",
    ),
  ).toBe(true);

  const pinvoke = matchObfuscatorSignals({
    pinvokeModules: ["VMProtectSDK64.dll"],
  });
  expect(pinvoke.status).toBe("likely");
  expect(pinvoke.indicators[0]).toMatchObject({
    tool: "VMProtect",
    signal: "pinvoke-module",
  });

  const resource = matchObfuscatorSignals({
    resourceNames: ["Xenocode.Postbuild.exe"],
  });
  expect(resource.status).toBe("likely");
  expect(resource.indicators[0]?.tool).toBe("Xenocode Postbuild");

  // Watermark strings alone are suspicious, never likely; whitespace is ignored.
  const watermark = matchObfuscatorSignals({
    stringLiterals: ["Powered   by SmartAssembly (build 8)"],
  });
  expect(watermark.status).toBe("suspicious");
  expect(watermark.indicators[0]).toMatchObject({
    tool: "SmartAssembly",
    signal: "watermark-string",
    confidence: "medium",
  });

  // A generic opt-out attribute is not a signal.
  const optOut = matchObfuscatorSignals({
    attributeNames: ["System.Reflection.ObfuscationAttribute"],
  });
  expect(optOut.status).toBe("none");

  // Heavy renaming without a tool fingerprint stays suspicious and generic.
  const renamed = matchObfuscatorSignals({
    memberNames: { hash_like: 40, minified: 5, readable: 30 },
  });
  expect(renamed.status).toBe("suspicious");
  expect(renamed.indicators[0]).toMatchObject({
    tool: null,
    signal: "renamed-symbols",
  });

  // Few renamed names are not a signal.
  expect(
    matchObfuscatorSignals({
      memberNames: { hash_like: 1, minified: 0, readable: 50 },
    }).status,
  ).toBe("none");
});

it("classifies runtime kinds from metadata facts", () => {
  expect(
    classifyRuntimeKind({
      runtimeFamily: "modern-dotnet",
      implementation: "cil",
      flagNames: ["il-only"],
      entryPointKind: "metadata-token",
      managedArchitecture: "anycpu",
    }).kind,
  ).toBe("il-only (modern-dotnet)");
  expect(
    classifyRuntimeKind({
      runtimeFamily: "mixed-clr-native",
      implementation: "cpp-cli-mixed",
      flagNames: [],
      entryPointKind: "native-rva",
    }).kind,
  ).toBe("mixed-mode");
  expect(
    classifyRuntimeKind({
      runtimeFamily: "modern-dotnet",
      implementation: "cil-and-ready-to-run",
      flagNames: ["il-library"],
      readyToRun: true,
      entryPointKind: "metadata-token",
    }).kind,
  ).toBe("readytorun");
  expect(classifyRuntimeKind({}).kind).toBe("unknown");
});

it("summarizes signing without verifying anything", () => {
  expect(
    summarizeSigning({
      publicKey: { kind: "none", token: null },
      assemblyFlags: 0,
      flagNames: ["il-only"],
      certificates: { entries: [] },
    }),
  ).toEqual({
    strong_named: false,
    public_key_token: null,
    authenticode: { present: false, count: 0, signers: [] },
  });
  const signed = summarizeSigning({
    publicKey: { kind: "full", token: "b77a5c561934e089" },
    assemblyFlags: 8,
    flagNames: ["strong-name-signed"],
    certificates: {
      entries: [{ signer_subject: "CN=Example Corp" }, { subject: "CN=Other" }],
    },
  });
  expect(signed.strong_named).toBe(true);
  expect(signed.public_key_token).toBe("b77a5c561934e089");
  expect(signed.authenticode).toEqual({
    present: true,
    count: 2,
    signers: ["CN=Example Corp", "CN=Other"],
  });
});

it("bounds adjacent-file collection", async () => {
  const root = await createTestTempDirectory("rea-dotnet-adjacent-max-");
  await writeFile(join(root, "App.pdb"), "pdb");
  const found = await collectAdjacentFiles(root, { maxFiles: 1 });
  expect(found).toHaveLength(1);
  expect(found[0]?.kind).toBe("pdb-sidecar");
});
