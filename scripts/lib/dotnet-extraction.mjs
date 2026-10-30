import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { constants as fsConstants } from "node:fs";
import {
  access,
  copyFile,
  mkdir,
  open,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";

/**
 * Assemblies that ship with a framework, Unity runtime, or IL2CPP dump rather
 * than the application. They are skipped by default when extracting a folder so
 * the recovered repository describes the product, not its platform.
 */
export const FRAMEWORK_PREFIXES = [
  "System.",
  "System",
  "Microsoft.",
  "mscorlib",
  "netstandard",
  "WindowsBase",
  "PresentationCore",
  "PresentationFramework",
  "Accessibility",
  "Mono.",
  "UnityEngine.",
  "UnityEngine",
  "Unity.",
  "Il2CppDummyDll",
];

export const isFrameworkAssembly = (name) =>
  FRAMEWORK_PREFIXES.some((prefix) =>
    name.toLowerCase().startsWith(prefix.toLowerCase()),
  );

export const isManagedExtension = (path) => {
  const extension = path.slice(path.lastIndexOf(".")).toLowerCase();
  return extension === ".dll" || extension === ".exe";
};

/** Produce a stable, filesystem-safe name while retaining the original stem. */
export const safeName = (value) =>
  value
    .replaceAll("\\", "/")
    .replace(/^\.\//u, "")
    .replace(/[^A-Za-z0-9._-]+/gu, "_")
    .replace(/^_+/u, "")
    .slice(0, 120) || "artifact";

export const exists = async (path) => {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
};

export const sha256File = async (path) => {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
};

export const countSourceFiles = async (directory) => {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return 0;
  }
  let count = 0;
  for (const entry of entries) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) count += await countSourceFiles(entryPath);
    else if (entry.isFile() && entry.name.endsWith(".cs")) count += 1;
  }
  return count;
};

export const findProjectFiles = async (directory) => {
  const projects = [];
  const walk = async (current) => {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const entryPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "bin" && entry.name !== "obj") await walk(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".csproj")) {
        projects.push(entryPath);
      }
    }
  };
  await walk(directory);
  return projects.sort();
};

const xmlEscape = (value) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

/**
 * Identify a hash-like value by shape only. Hex digests are ambiguous by
 * construction (MD5 and NTLM share a shape), so every unprefixed digest lists
 * each plausible algorithm at medium confidence or below. Only prefixed
 * modular-crypt formats identify one algorithm at high confidence. UUIDs are
 * reported as identifiers, never as hashes. Returns no candidates when the
 * value does not look like a hash at all.
 */
const HEX_PATTERN = /^[0-9a-fA-F]+$/u;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/u;
const UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/u;

const MODULAR_FORMATS = [
  {
    test: (value) => /^\$2[aby]\$\d{2}\$.{53}$/u.test(value),
    algorithm: "bcrypt",
    reason: "modular crypt identifier for bcrypt ($2a$/$2b$/$2y$)",
  },
  {
    test: (value) => /^\$1\$[^$]{1,8}\$.{22}$/u.test(value),
    algorithm: "md5-crypt",
    reason: "modular crypt identifier for md5-crypt ($1$)",
  },
  {
    test: (value) => /^\$5\$([^$=]{1,16}\$)?[./0-9A-Za-z]{43}$/u.test(value),
    algorithm: "sha256-crypt",
    reason: "modular crypt identifier for sha256-crypt ($5$)",
  },
  {
    test: (value) => /^\$6\$([^$=]{1,16}\$)?[./0-9A-Za-z]{86}$/u.test(value),
    algorithm: "sha512-crypt",
    reason: "modular crypt identifier for sha512-crypt ($6$)",
  },
  {
    test: (value) => /^\$argon2(i|d|id)\$v=\d+\$[^$]+\$[^$]+\$.+$/u.test(value),
    algorithm: "argon2",
    reason: "modular crypt identifier for Argon2",
  },
  {
    test: (value) => /^\$scrypt\$[^$]+\$.+$/u.test(value),
    algorithm: "scrypt",
    reason: "modular crypt identifier for scrypt",
  },
  {
    test: (value) => /^\{SHA\}[A-Za-z0-9+/=]+$/u.test(value),
    algorithm: "SHA-1 (LDAP)",
    reason: "LDAP {SHA} prefix with base64 SHA-1 digest",
  },
  {
    test: (value) => /^\{SSHA\}[A-Za-z0-9+/=]+$/u.test(value),
    algorithm: "salted SHA-1 (LDAP)",
    reason: "LDAP {SSHA} prefix with base64 salted SHA-1 digest",
  },
];

const HEX_LENGTH_CANDIDATES = {
  8: [{ algorithm: "CRC-32/Adler-32", confidence: "low" }],
  16: [{ algorithm: "truncated digest (64-bit)", confidence: "low" }],
  32: [
    { algorithm: "MD5", confidence: "medium" },
    { algorithm: "NTLM", confidence: "medium" },
    { algorithm: "MD4", confidence: "medium" },
    { algorithm: "LM", confidence: "low" },
  ],
  40: [
    { algorithm: "SHA-1", confidence: "medium" },
    { algorithm: "RIPEMD-160", confidence: "medium" },
  ],
  48: [{ algorithm: "Tiger-192", confidence: "low" }],
  56: [
    { algorithm: "SHA-224", confidence: "medium" },
    { algorithm: "SHA3-224", confidence: "medium" },
  ],
  64: [
    { algorithm: "SHA-256", confidence: "medium" },
    { algorithm: "SHA3-256", confidence: "medium" },
  ],
  96: [
    { algorithm: "SHA-384", confidence: "medium" },
    { algorithm: "SHA3-384", confidence: "medium" },
  ],
  128: [
    { algorithm: "SHA-512", confidence: "medium" },
    { algorithm: "SHA3-512", confidence: "medium" },
    { algorithm: "Whirlpool", confidence: "low" },
  ],
};

const BASE64_BYTE_CANDIDATES = {
  16: [
    { algorithm: "MD5", confidence: "low" },
    { algorithm: "NTLM", confidence: "low" },
  ],
  20: [{ algorithm: "SHA-1", confidence: "low" }],
  28: [{ algorithm: "SHA-224", confidence: "low" }],
  32: [{ algorithm: "SHA-256", confidence: "low" }],
  48: [{ algorithm: "SHA-384", confidence: "low" }],
  64: [{ algorithm: "SHA-512", confidence: "low" }],
};

export const identifyHash = (raw) => {
  const value = String(raw ?? "").trim();
  if (value.length === 0) return { kind: "empty", candidates: [] };
  if (UUID_PATTERN.test(value)) return { kind: "uuid", candidates: [] };
  for (const format of MODULAR_FORMATS) {
    if (format.test(value)) {
      return {
        kind: "modular",
        candidates: [
          {
            algorithm: format.algorithm,
            confidence: "high",
            reason: format.reason,
          },
        ],
      };
    }
  }
  const compact = value.replace(/^0x/iu, "").replace(/[\s_:-]/gu, "");
  if (compact.length >= 8 && HEX_PATTERN.test(compact)) {
    const candidates = HEX_LENGTH_CANDIDATES[compact.length] ?? [
      {
        algorithm: "unrecognized hex digest length",
        confidence: "low",
      },
    ];
    return {
      kind: "hex",
      charset: "hex",
      length: compact.length,
      candidates: candidates.map((candidate) => ({
        ...candidate,
        reason: `${String(compact.length)} hex characters`,
      })),
    };
  }
  if (
    compact.length >= 20 &&
    BASE64_PATTERN.test(compact) &&
    /[A-Z]/u.test(compact) &&
    /[a-z]/u.test(compact) &&
    /[0-9+/=]/u.test(compact)
  ) {
    const padding = (compact.match(/=+$/) ?? [""])[0].length;
    const bytes = Math.floor((compact.length * 3) / 4) - padding;
    const candidates = BASE64_BYTE_CANDIDATES[bytes] ?? [
      { algorithm: "opaque base64 blob", confidence: "low" },
    ];
    return {
      kind: "base64",
      charset: "base64",
      length: compact.length,
      candidates: candidates.map((candidate) => ({
        ...candidate,
        reason: `base64 decoding to ~${String(bytes)} bytes`,
      })),
    };
  }
  return { kind: "unknown", candidates: [] };
};

/**
 * Classify a recovered type or member name. Obfuscators commonly emit
 * hash-like hex names or single-character minified names; compiler-generated
 * names keep their angle brackets. Anything else is readable.
 */
const HASH_NAME_PATTERN = /[0-9a-fA-F]{12,}/u;

export const classifyMemberName = (raw) => {
  const name = String(raw ?? "");
  if (name.startsWith("<") || name.includes("<"))
    return { kind: "compiler-generated", reason: "angle-bracket name" };
  if (/^[a-z]$|[a-z][0-9]$/u.test(name) && name.length <= 2)
    return { kind: "minified", reason: "single-character name" };
  if (
    (HEX_PATTERN.test(name) && name.length >= 8) ||
    HASH_NAME_PATTERN.test(name)
  )
    return { kind: "hash-like", reason: "hex-like gibberish name" };
  return { kind: "readable", reason: "ordinary identifier" };
};

/**
 * Known license-dongle vendors, matched by module name, imported API, or
 * keyword. API purposes describe what the call does inside a license check;
 * they are not bypass instructions.
 */
export const DONGLE_VENDORS = [
  {
    vendor: "Thales (formerly Gemalto/SafeNet/Aladdin)",
    product: "Sentinel HASP HL/SRM",
    modules: [
      "hasp_windows",
      "hasp_windows_x64",
      "hasp_net_windows",
      "hasp_linux",
      "hasp_macos",
      "hasp_darwin",
      "libhasp",
    ],
    drivers: ["aksusb", "akshasp", "akshhl", "aksfridge", "hardlock"],
    apis: [
      {
        name: "hasp_login",
        purpose: "open a license session for a feature id",
      },
      {
        name: "hasp_login_scope",
        purpose: "open a scoped license session",
      },
      { name: "hasp_logout", purpose: "close a license session" },
      {
        name: "hasp_encrypt",
        purpose: "encrypt data with the dongle key",
      },
      {
        name: "hasp_decrypt",
        purpose: "decrypt data with the dongle key",
      },
      { name: "hasp_read", purpose: "read dongle memory" },
      { name: "hasp_write", purpose: "write dongle memory" },
      {
        name: "hasp_get_info",
        purpose: "query license and dongle information",
      },
      {
        name: "hasp_get_sessioninfo",
        purpose: "query session information",
      },
      { name: "hasp_get_size", purpose: "query dongle memory size" },
    ],
    keywords: ["hasp", "hardlock", "sentinel", "aksusb", "akshasp"],
    envelope: "HASP Envelope / SRM envelope",
  },
  {
    vendor: "Wibu-Systems",
    product: "CodeMeter",
    modules: ["wibucm32", "wibucm64", "codemeter", "wibu"],
    drivers: ["codemeter"],
    apis: [
      { name: "CmCrypt", purpose: "CodeMeter encryption operation" },
      { name: "CmAccess", purpose: "CodeMeter license access" },
    ],
    keywords: ["codemeter", "wibu", "cmcrypt", "axprotector"],
    envelope: "AxProtector",
  },
  {
    vendor: "Software Security Inc.",
    product: "KeyLok",
    modules: ["keylok"],
    drivers: [],
    apis: [],
    keywords: ["keylok"],
    envelope: "KeyLok envelope",
  },
  {
    vendor: "Microcosm",
    product: "Dinkey",
    modules: ["dinkey", "dk2ax"],
    drivers: [],
    apis: [],
    keywords: ["dinkey"],
    envelope: "Dinkey envelope",
  },
  {
    vendor: "Feitian",
    product: "Rockey",
    modules: ["rockey2", "rockey4nd", "rockey"],
    drivers: ["rockey"],
    apis: [],
    keywords: ["rockey"],
    envelope: "Rockey envelope",
  },
  {
    vendor: "Guardant",
    product: "Guardant",
    modules: ["grdctl"],
    drivers: ["grdkey", "grdusb"],
    apis: [],
    keywords: ["guardant"],
    envelope: "Guardant envelope",
  },
  {
    vendor: "SecuTech",
    product: "UniKey",
    modules: ["unikey"],
    drivers: [],
    apis: [],
    keywords: ["unikey"],
    envelope: "UniKey shell",
  },
];

const moduleStem = (name) =>
  String(name ?? "")
    .toLowerCase()
    .replace(/\.(dll|so|dylib)$/u, "");

export const matchDongleModule = (moduleName) => {
  const stem = moduleStem(moduleName);
  const matches = [];
  for (const vendor of DONGLE_VENDORS) {
    for (const known of [...vendor.modules, ...vendor.drivers]) {
      if (
        stem === known ||
        stem.startsWith(`${known}.`) ||
        stem.startsWith(known)
      ) {
        matches.push({
          vendor: vendor.vendor,
          product: vendor.product,
          signal: "module-reference",
          detail: String(moduleName),
          confidence: "high",
        });
        break;
      }
    }
  }
  return matches;
};

export const matchDongleApi = (importName) => {
  const normalized = String(importName ?? "").toLowerCase();
  const matches = [];
  for (const vendor of DONGLE_VENDORS) {
    for (const api of vendor.apis) {
      if (normalized === api.name.toLowerCase()) {
        matches.push({
          vendor: vendor.vendor,
          product: vendor.product,
          signal: "pinvoke-api",
          detail: String(importName),
          purpose: api.purpose,
          confidence: "high",
        });
      }
    }
  }
  return matches;
};

/**
 * Combine assembly references, P/Invoke module/API rows, and keyword hits
 * into one verdict. A module, driver, assembly, or API match establishes
 * presence; keywords alone are only suspicious. Findings never include
 * bypass, defeat, or circumvention guidance.
 */
export const matchDongleSignals = ({
  assemblyReferences = [],
  moduleRefs = [],
  pinvokeImports = [],
  keywordHits = [],
} = {}) => {
  const findings = [];
  for (const reference of assemblyReferences) {
    for (const match of matchDongleModule(reference)) {
      findings.push({ ...match, signal: "assembly-reference" });
    }
  }
  for (const module of moduleRefs) {
    findings.push(...matchDongleModule(module));
  }
  for (const entry of pinvokeImports) {
    findings.push(...matchDongleApi(entry));
  }
  if (findings.length > 0) return { status: "present", findings };
  const keywords = [...new Set(keywordHits.map((hit) => hit.keyword))];
  if (keywords.length > 0) {
    return {
      status: "suspicious",
      findings: keywords.map((keyword) => ({
        signal: "string-keyword",
        detail: keyword,
        confidence: "low",
      })),
    };
  }
  return { status: "none", findings: [] };
};

const STRING_LITERAL_PATTERN =
  /@"((?:""|[^"]){8,512})"|"((?:[^"\\\n]|\\.){8,256})"/gu;
const TYPE_DECLARATION_PATTERN =
  /(?:^|[\s{;}])(?:class|struct|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_.`]*)/gu;
const METHOD_DECLARATION_PATTERN =
  /(?:^|[\s{;}])[\w<>\[\],\s?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
const DONGLE_KEYWORD_PATTERN =
  /hasp|hardlock|sentinel|aksusb|akshasp|codemeter|wibu|cmcrypt|axprotector|keylok|dinkey|rockey|guardant|unikey|dongle/giu;

const truncateSample = (value, limit = 48) =>
  value.length > limit ? `${value.slice(0, limit)}...` : value;

/**
 * Scan reconstructed C# for hash-shaped string literals, obfuscated member
 * names, and dongle keywords. All bounds keep the manifest small: capped
 * files, capped bytes per file, capped literals, capped samples.
 */
export const scanDecompiledDirectory = async (
  directory,
  { maxFiles = 400, maxBytesPerFile = 262144, maxLiterals = 2000 } = {},
) => {
  const files = [];
  const walk = async (current) => {
    if (files.length >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      const entryPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "bin" && entry.name !== "obj") await walk(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".cs")) {
        files.push(entryPath);
      }
    }
  };
  await walk(directory);

  const byAlgorithm = new Map();
  const samples = [];
  const seen = new Set();
  const memberNames = { hash_like: 0, minified: 0, readable: 0, samples: [] };
  const keywordFiles = new Map();
  let literals = 0;
  let truncated = false;

  for (const file of files) {
    let text;
    try {
      const handle = await open(file, "r");
      try {
        const info = await handle.stat();
        const size = Math.min(info.size, maxBytesPerFile);
        if (info.size > maxBytesPerFile) truncated = true;
        const buffer = Buffer.alloc(size);
        await handle.read(buffer, 0, size, 0);
        text = buffer.toString("utf8");
      } finally {
        await handle.close();
      }
    } catch {
      continue;
    }
    for (const match of text.matchAll(STRING_LITERAL_PATTERN)) {
      if (literals >= maxLiterals) {
        truncated = true;
        break;
      }
      literals += 1;
      const literal = (match[1] ?? match[2] ?? "").replaceAll('""', '"');
      if (seen.has(literal)) continue;
      seen.add(literal);
      const identified = identifyHash(literal);
      if (identified.candidates.length === 0) continue;
      for (const candidate of identified.candidates) {
        byAlgorithm.set(
          candidate.algorithm,
          (byAlgorithm.get(candidate.algorithm) ?? 0) + 1,
        );
      }
      if (samples.length < 8) {
        samples.push({
          value: truncateSample(literal),
          kind: identified.kind,
          candidates: identified.candidates.map(
            (candidate) => candidate.algorithm,
          ),
        });
      }
    }
    for (const match of text.matchAll(TYPE_DECLARATION_PATTERN)) {
      const classified = classifyMemberName(match[1]);
      if (classified.kind === "readable") memberNames.readable += 1;
      else if (classified.kind === "minified") memberNames.minified += 1;
      else if (classified.kind === "hash-like") {
        memberNames.hash_like += 1;
        if (memberNames.samples.length < 12) memberNames.samples.push(match[1]);
      }
    }
    for (const match of text.matchAll(METHOD_DECLARATION_PATTERN)) {
      const classified = classifyMemberName(match[1]);
      if (classified.kind === "minified") {
        memberNames.minified += 1;
        if (memberNames.samples.length < 12) memberNames.samples.push(match[1]);
      } else if (classified.kind === "hash-like") {
        memberNames.hash_like += 1;
        if (memberNames.samples.length < 12) memberNames.samples.push(match[1]);
      } else if (classified.kind === "readable") {
        memberNames.readable += 1;
      }
    }
    for (const match of text.matchAll(DONGLE_KEYWORD_PATTERN)) {
      const keyword = match[0].toLowerCase();
      if (!keywordFiles.has(keyword)) keywordFiles.set(keyword, new Set());
      keywordFiles.get(keyword).add(relative(directory, file));
    }
  }

  return {
    files_scanned: files.length,
    truncated,
    hash_strings: {
      literals_examined: literals,
      distinct_values: seen.size,
      by_algorithm: Object.fromEntries(byAlgorithm),
      samples,
    },
    member_names: memberNames,
    keyword_hits: [...keywordFiles.entries()].map(([keyword, files]) => ({
      keyword,
      files: [...files].slice(0, 8),
    })),
  };
};

const relativePath = (from, to) => relative(from, to).replaceAll("\\", "/");

const referencePattern =
  /<Reference\s+Include="([^"]+)"\s*(?:\/>|>([\s\S]*?)<\/Reference>)/gu;
const hintPathPattern = /<HintPath>([\s\S]*?)<\/HintPath>/u;

/**
 * Rewrite ILSpy project references so the recovered repository builds from its
 * own contents. References to recovered assemblies become project references;
 * other local assembly references are copied under `references/` and pointed at
 * the copy. Missing HintPaths are preserved as an explicit unknown rather than
 * silently dropped.
 *
 * Accepts project paths or `{ path, assemblyName }` records.
 */
export const rewriteProjectReferences = async ({
  outputPath,
  projects,
  referenceDirectoryName = "references",
}) => {
  const normalized = projects.map((project) =>
    typeof project === "string" ? { path: project } : project,
  );
  const referenceDirectory = join(outputPath, referenceDirectoryName);
  const recovered = new Map();
  for (const project of normalized) {
    let name = project.assemblyName;
    if (name === undefined) {
      try {
        name =
          (await readFile(project.path, "utf8")).match(
            /<AssemblyName>([^<]+)<\/AssemblyName>/u,
          )?.[1] ?? basename(project.path, ".csproj");
      } catch {
        name = basename(project.path, ".csproj");
      }
    }
    if (!recovered.has(name.toLowerCase())) {
      recovered.set(name.toLowerCase(), project.path);
    }
  }

  const copied = new Map();
  const references = [];
  const rewritten = [];
  const unresolved = [];

  const copyReference = async (sourcePath, projectPath) => {
    const resolved = resolve(dirname(projectPath), sourcePath);
    if (!(await exists(resolved))) return undefined;
    let info;
    try {
      info = await stat(resolved);
    } catch {
      return undefined;
    }
    if (!info.isFile()) return undefined;

    const digest = await sha256File(resolved);
    const existing = copied.get(digest);
    if (existing !== undefined) return existing;

    await mkdir(referenceDirectory, { recursive: true });
    const originalName = basename(resolved);
    let targetName = safeName(originalName);
    let targetPath = join(referenceDirectory, targetName);
    if (await exists(targetPath)) {
      const targetDigest = await sha256File(targetPath);
      if (targetDigest !== digest) {
        const extension = originalName.slice(originalName.lastIndexOf("."));
        const stem = originalName.slice(0, originalName.lastIndexOf("."));
        targetName = `${safeName(stem)}-${digest.slice(0, 8)}${extension}`;
        targetPath = join(referenceDirectory, targetName);
      }
    }
    if (!(await exists(targetPath))) await copyFile(resolved, targetPath);
    const record = {
      source: resolved,
      output: relativePath(outputPath, targetPath),
      sha256: digest,
    };
    copied.set(digest, targetPath);
    references.push(record);
    return targetPath;
  };

  for (const project of normalized) {
    let text;
    try {
      text = await readFile(project.path, "utf8");
    } catch {
      continue;
    }

    let changed = false;
    const replacements = [];
    for (const match of text.matchAll(referencePattern)) {
      const name = match[1];
      const body = match[2] ?? "";
      const hint = body.match(hintPathPattern)?.[1]?.trim();
      const recoveredProject = recovered.get(name.toLowerCase());
      if (recoveredProject !== undefined) {
        const include = relativePath(dirname(project.path), recoveredProject);
        replacements.push({
          start: match.index,
          end: match.index + match[0].length,
          value: `<ProjectReference Include="${xmlEscape(include)}" />`,
        });
        changed = true;
        continue;
      }
      if (hint === undefined) continue;
      const target = await copyReference(hint, project.path);
      if (target === undefined) {
        unresolved.push({
          project: relativePath(outputPath, project.path),
          reference: name,
          hint,
        });
        continue;
      }
      const include = relativePath(dirname(project.path), target);
      replacements.push({
        start: match.index,
        end: match.index + match[0].length,
        value: `<Reference Include="${xmlEscape(name)}"><HintPath>${xmlEscape(include)}</HintPath></Reference>`,
      });
      changed = true;
    }

    if (!changed) continue;
    let next = "";
    let cursor = 0;
    for (const replacement of replacements) {
      next += text.slice(cursor, replacement.start);
      next += replacement.value;
      cursor = replacement.end;
    }
    next += text.slice(cursor);
    await writeFile(project.path, next);
    rewritten.push(relativePath(outputPath, project.path));
  }

  return { references, rewritten, unresolved };
};
