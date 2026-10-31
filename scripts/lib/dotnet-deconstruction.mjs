import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { inflateRawSync, inflateSync } from "node:zlib";

/**
 * Static readers for the parts of a managed product that ILSpy does not
 * reconstruct: symbol documents and embedded sources, SourceLink mappings, and
 * the deployment manifests that name the product's real dependencies.
 *
 * Everything here reads bytes only. Nothing is loaded into a CLR, and no
 * SourceLink URL is fetched.
 */

const METADATA_SIGNATURE = 0x424a5342; // "BSJB"
const EMBEDDED_PDB_SIGNATURE = 0x4244504d; // "MPDB"

const COFF_PE_SIGNATURE = 0x00004550;

const GUID_EMBEDDED_SOURCE = "0e8a571b-6926-466e-b4ad-8ab04611f5fe";
const GUID_SOURCE_LINK = "cc110556-a091-4d38-9fec-25ab9a351a6a";
const GUID_HASH_SHA1 = "ff1816ec-aa5e-4d10-87f7-6f4963833460";
const GUID_HASH_SHA256 = "8829d00f-11b8-4213-878b-770e8597ac16";

const LANGUAGE_GUIDS = new Map([
  ["3f5162f8-07c6-11d3-9053-00c04fa302a1", "C#"],
  ["3a12d0b8-c26c-11d0-b442-00a0244a1dd2", "Visual Basic"],
  ["abde8324-b5a4-4f1e-8f6e-8e2a4c2b7d6c", "F#"],
]);

/** Portable PDB tables. A portable PDB metadata image carries only these. */
const PDB_TABLES = {
  0x00: {
    name: "Module",
    columns: [
      ["generation", "u16"],
      ["name", "string"],
      ["mvid", "guid"],
      ["encId", "guid"],
      ["encBaseId", "guid"],
    ],
  },
  0x30: {
    name: "Document",
    columns: [
      ["name", "blob"],
      ["hashAlgorithm", "guid"],
      ["hash", "blob"],
      ["language", "guid"],
    ],
  },
  0x31: {
    name: "MethodDebugInformation",
    columns: [
      ["document", ["table", 0x30]],
      ["sequencePoints", "blob"],
    ],
  },
  0x32: {
    name: "LocalScope",
    columns: [
      ["method", ["table", 0x06]],
      ["importScope", ["table", 0x35]],
      ["variableList", ["table", 0x33]],
      ["constantList", ["table", 0x34]],
      ["startOffset", "u32"],
      ["length", "u32"],
    ],
  },
  0x33: {
    name: "LocalVariable",
    columns: [
      ["attributes", "u16"],
      ["index", "u16"],
      ["name", "string"],
    ],
  },
  0x34: {
    name: "LocalConstant",
    columns: [
      ["name", "string"],
      ["signature", "blob"],
    ],
  },
  0x35: {
    name: "ImportScope",
    columns: [
      ["parent", ["table", 0x35]],
      ["imports", "blob"],
    ],
  },
  0x36: {
    name: "StateMachineMethod",
    columns: [
      ["moveNextMethod", ["table", 0x06]],
      ["kickoffMethod", ["table", 0x06]],
    ],
  },
  0x37: {
    name: "CustomDebugInformation",
    columns: [
      ["parent", ["coded", "HasCustomDebugInformation"]],
      ["kind", "guid"],
      ["value", "blob"],
    ],
  },
};

/**
 * HasCustomDebugInformation coded-index tables, in tag order. Only the
 * position of each table affects the tag; Document sits at index 22.
 */
const HAS_CUSTOM_DEBUG_INFORMATION_TABLES = [
  0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11,
  0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b, 0x30, 0x32,
  0x33, 0x34, 0x35,
];
const HAS_CUSTOM_DEBUG_INFORMATION_TAG_BITS = 5;

const readGuid = (buffer, offset) => {
  if (offset < 0 || offset + 16 > buffer.length) return null;
  const data1 = buffer.readUInt32LE(offset);
  const data2 = buffer.readUInt16LE(offset + 4);
  const data3 = buffer.readUInt16LE(offset + 6);
  const rest = buffer.subarray(offset + 8, offset + 16);
  const hex = (value, width) =>
    value.toString(16).padStart(width, "0");
  return [
    hex(data1, 8),
    hex(data2, 4),
    hex(data3, 4),
    rest.subarray(0, 2).toString("hex"),
    rest.subarray(2, 8).toString("hex"),
  ].join("-");
};

/**
 * Locate an embedded portable PDB in a PE image. Returns the decompressed PDB
 * bytes, or null when the image has no debug directory or no embedded PDB.
 */
export const findEmbeddedPortablePdb = (image, { maxBytes = 64 * 1024 * 1024 } = {}) => {
  if (image.length < 0x40 || image[0] !== 0x4d || image[1] !== 0x5a)
    return null;
  const peOffset = image.readUInt32LE(0x3c);
  if (peOffset + 24 > image.length) return null;
  if (image.readUInt32LE(peOffset) !== COFF_PE_SIGNATURE) return null;

  const coff = peOffset + 4;
  const sectionCount = image.readUInt16LE(coff + 2);
  const optionalSize = image.readUInt16LE(coff + 16);
  const optional = coff + 20;
  if (optional + optionalSize > image.length) return null;
  const magic = image.readUInt16LE(optional);
  const pe32Plus = magic === 0x20b;
  if (magic !== 0x10b && !pe32Plus) return null;

  const dataDirectoryOffset = optional + (pe32Plus ? 112 : 96);
  const sectionTable = optional + optionalSize;
  const sections = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const entry = sectionTable + index * 40;
    if (entry + 40 > image.length) break;
    sections.push({
      virtualSize: image.readUInt32LE(entry + 8),
      virtualAddress: image.readUInt32LE(entry + 12),
      rawSize: image.readUInt32LE(entry + 16),
      rawPointer: image.readUInt32LE(entry + 20),
    });
  }

  const rvaToOffset = (rva) => {
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
        const offset = rva - section.virtualAddress + section.rawPointer;
        return offset < image.length ? offset : null;
      }
    }
    return null;
  };

  const debugRva = image.readUInt32LE(dataDirectoryOffset + 6 * 8);
  const debugSize = image.readUInt32LE(dataDirectoryOffset + 6 * 8 + 4);
  if (debugRva === 0 || debugSize === 0) return null;
  const debugOffset = rvaToOffset(debugRva);
  if (debugOffset === null) return null;

  for (let offset = debugOffset; offset + 28 <= debugOffset + debugSize; offset += 28) {
    const type = image.readUInt32LE(offset + 12);
    if (type !== 17) continue;
    const size = image.readUInt32LE(offset + 16);
    const rawPointer = image.readUInt32LE(offset + 24);
    if (rawPointer === 0 || size < 8 || rawPointer + size > image.length)
      continue;
    if (image.readUInt32LE(rawPointer) !== EMBEDDED_PDB_SIGNATURE) continue;
    const declared = image.readUInt32LE(rawPointer + 4);
    if (declared === 0 || declared > maxBytes) continue;
    const compressed = image.subarray(rawPointer + 8, rawPointer + size);
    try {
      return inflateRawSync(compressed, { maxOutputLength: declared });
    } catch {
      try {
        return inflateSync(compressed, { maxOutputLength: declared });
      } catch {
        continue;
      }
    }
  }
  return null;
};

const readCompressedUInt = (buffer, offset) => {
  const first = buffer[offset];
  if (first === undefined) return null;
  if ((first & 0x80) === 0) return { value: first, length: 1 };
  if ((first & 0xc0) === 0x80)
    return {
      value: ((first & 0x3f) << 8) | buffer[offset + 1],
      length: 2,
    };
  if ((first & 0xe0) === 0xc0)
    return {
      value:
        ((first & 0x1f) << 24) |
        (buffer[offset + 1] << 16) |
        (buffer[offset + 2] << 8) |
        buffer[offset + 3],
      length: 4,
    };
  return null;
};

const parseMetadataStreams = (buffer) => {
  if (buffer.length < 20 || buffer.readUInt32LE(0) !== METADATA_SIGNATURE)
    return null;
  const versionLength = buffer.readUInt32LE(12);
  if (versionLength > buffer.length) return null;
  let offset = 16 + versionLength;
  if (offset + 4 > buffer.length) return null;
  const streamCount = buffer.readUInt16LE(offset + 2);
  offset += 4;

  const streams = new Map();
  for (let index = 0; index < streamCount; index += 1) {
    if (offset + 8 > buffer.length) return null;
    const streamOffset = buffer.readUInt32LE(offset);
    const streamSize = buffer.readUInt32LE(offset + 4);
    offset += 8;
    const nameStart = offset;
    while (offset < buffer.length && buffer[offset] !== 0) offset += 1;
    const name = buffer.subarray(nameStart, offset).toString("utf8");
    offset += 1;
    offset = (offset + 3) & ~3;
    if (streamOffset + streamSize > buffer.length) return null;
    streams.set(name, {
      offset: streamOffset,
      size: streamSize,
      data: buffer.subarray(streamOffset, streamOffset + streamSize),
    });
  }
  return streams;
};

const columnSize = (column, heapSizes, rowCounts) => {
  if (Array.isArray(column)) {
    if (column[0] === "table") {
      const rows = rowCounts.get(column[1]) ?? 0;
      return rows > 0xffff ? 4 : 2;
    }
    if (column[0] === "coded") {
      const maxRows = Math.max(
        ...HAS_CUSTOM_DEBUG_INFORMATION_TABLES.map(
          (table) => rowCounts.get(table) ?? 0,
        ),
      );
      const limit =
        1 << (16 - HAS_CUSTOM_DEBUG_INFORMATION_TAG_BITS);
      return maxRows < limit ? 2 : 4;
    }
    throw new Error(`Unsupported coded index: ${String(column[0])}`);
  }
  if (column === "string") return heapSizes.string ? 4 : 2;
  if (column === "guid") return heapSizes.guid ? 4 : 2;
  if (column === "blob") return heapSizes.blob ? 4 : 2;
  if (column === "u16") return 2;
  if (column === "u32") return 4;
  throw new Error(`Unsupported column type: ${column}`);
};

const readBlob = (blobHeap, index) => {
  // Blob heap indexes are byte offsets into the heap (ECMA-335 II.24.2.4),
  // not 1-based slot numbers. Index 0 is the reserved empty blob.
  if (index === 0) return Buffer.alloc(0);
  if (index < 0 || index >= blobHeap.length) return null;
  const length = readCompressedUInt(blobHeap, index);
  if (length === null) return null;
  const start = index + length.length;
  const end = start + length.value;
  if (end > blobHeap.length) return null;
  return blobHeap.subarray(start, end);
};

/**
 * Decode a portable-PDB document-name blob: one separator byte followed by a
 * run of compressed blob-heap offsets, one per path part. Parts join with the
 * separator, so an absolute Unix path starts with an empty (offset-0) part.
 * Returns null when the blob is malformed rather than guessing.
 */
const readDocumentName = (blobHeap, blob) => {
  if (blob.length < 1) return "";
  const separator = String.fromCharCode(blob[0]);
  const parts = [];
  let position = 1;
  while (position < blob.length) {
    const coded = readCompressedUInt(blob, position);
    if (coded === null) return null;
    position += coded.length;
    const part = readBlob(blobHeap, coded.value);
    if (part === null) return null;
    parts.push(part.toString("utf8"));
  }
  return parts.join(separator);
};

const readString = (stringHeap, index) => {
  if (index === 0) return "";
  if (index >= stringHeap.length) return null;
  let end = index;
  while (end < stringHeap.length && stringHeap[end] !== 0) end += 1;
  return stringHeap.subarray(index, end).toString("utf8");
};

/**
 * Parse a portable PDB (embedded or sidecar) for document names, embedded
 * source files, and SourceLink mappings. Only the portable format is
 * supported; Windows PDBs are reported as unsupported rather than guessed.
 */
export const readPortablePdb = (
  buffer,
  { maxDocuments = 20000, maxEmbeddedSources = 2000, maxSourceBytes = 32 * 1024 * 1024 } = {},
) => {
  const streams = parseMetadataStreams(buffer);
  if (streams === null) return null;
  const tableStream = streams.get("#~") ?? streams.get("#-");
  if (tableStream === undefined) return null;
  const stringHeap = streams.get("#Strings")?.data ?? Buffer.alloc(0);
  const blobHeap = streams.get("#Blob")?.data ?? Buffer.alloc(0);
  const guidHeap = streams.get("#GUID")?.data ?? Buffer.alloc(0);

  const data = tableStream.data;
  if (data.length < 24) return null;
  const heapSizesByte = data.readUInt8(6);
  const heapSizes = {
    string: (heapSizesByte & 0x01) !== 0,
    guid: (heapSizesByte & 0x02) !== 0,
    blob: (heapSizesByte & 0x04) !== 0,
  };
  const valid = data.readBigUInt64LE(8);
  let offset = 24;
  const rowCounts = new Map();
  for (let table = 0; table < 64; table += 1) {
    if ((valid >> BigInt(table)) & 1n) {
      rowCounts.set(table, data.readUInt32LE(offset));
      offset += 4;
    }
  }

  const layouts = new Map();
  for (const [table, definition] of Object.entries(PDB_TABLES)) {
    const tableIndex = Number(table);
    const rows = rowCounts.get(tableIndex) ?? 0;
    if (rows === 0) continue;
    const columns = [];
    let rowSize = 0;
    for (const [name, type] of definition.columns) {
      const size = columnSize(type, heapSizes, rowCounts);
      columns.push({ name, type, size, offset: rowSize });
      rowSize += size;
    }
    layouts.set(tableIndex, { rows, rowSize, columns, start: offset });
    offset += rows * rowSize;
  }
  if (offset > data.length) return null;

  const readRow = (tableIndex, rowIndex) => {
    const layout = layouts.get(tableIndex);
    if (layout === undefined || rowIndex < 1 || rowIndex > layout.rows)
      return null;
    const base = layout.start + (rowIndex - 1) * layout.rowSize;
    const values = {};
    for (const column of layout.columns) {
      const at = base + column.offset;
      if (column.type === "u16") values[column.name] = data.readUInt16LE(at);
      else if (column.type === "u32") values[column.name] = data.readUInt32LE(at);
      else if (column.type === "string")
        values[column.name] = readString(
          stringHeap,
          column.size === 4 ? data.readUInt32LE(at) : data.readUInt16LE(at),
        );
      else if (column.type === "blob")
        values[column.name] = readBlob(
          blobHeap,
          column.size === 4 ? data.readUInt32LE(at) : data.readUInt16LE(at),
        );
      else if (column.type === "guid") {
        const index =
          column.size === 4 ? data.readUInt32LE(at) : data.readUInt16LE(at);
        values[column.name] =
          index === 0 ? null : readGuid(guidHeap, (index - 1) * 16);
      } else if (Array.isArray(column.type) && column.type[0] === "table")
        values[column.name] =
          column.size === 4 ? data.readUInt32LE(at) : data.readUInt16LE(at);
      else if (Array.isArray(column.type) && column.type[0] === "coded") {
        const raw =
          column.size === 4 ? data.readUInt32LE(at) : data.readUInt16LE(at);
        const tag = raw & ((1 << HAS_CUSTOM_DEBUG_INFORMATION_TAG_BITS) - 1);
        values[column.name] = {
          table: HAS_CUSTOM_DEBUG_INFORMATION_TABLES[tag] ?? null,
          row: raw >>> HAS_CUSTOM_DEBUG_INFORMATION_TAG_BITS,
        };
      }
    }
    return values;
  };

  const documents = [];
  const documentLayout = layouts.get(0x30);
  if (documentLayout !== undefined) {
    const count = Math.min(documentLayout.rows, maxDocuments);
    for (let index = 1; index <= count; index += 1) {
      const row = readRow(0x30, index);
      if (row?.name === null || row?.name === undefined) continue;
      const blob = row.name;
      if (blob.length < 1) continue;
      const path = readDocumentName(blobHeap, blob);
      if (path === null) continue;
      documents.push({
        row: index,
        path,
        language: row.language === null ? null : LANGUAGE_GUIDS.get(row.language) ?? "unknown",
        hash_algorithm:
          row.hashAlgorithm === null
            ? null
            : row.hashAlgorithm === GUID_HASH_SHA256
              ? "SHA256"
              : row.hashAlgorithm === GUID_HASH_SHA1
                ? "SHA1"
                : "unknown",
        hash: row.hash === null ? null : row.hash.toString("hex"),
      });
    }
  }

  const documentByRow = new Map(documents.map((document) => [document.row, document]));
  const embeddedSources = [];
  let sourceLink = null;
  let embeddedBytes = 0;
  const cdiLayout = layouts.get(0x37);
  if (cdiLayout !== undefined) {
    for (let index = 1; index <= cdiLayout.rows; index += 1) {
      const row = readRow(0x37, index);
      if (row?.kind === null || row?.kind === undefined) continue;
      if (row.kind === GUID_SOURCE_LINK) {
        if (row.value === null) continue;
        try {
          sourceLink = JSON.parse(row.value.toString("utf8"));
        } catch {
          sourceLink = null;
        }
        continue;
      }
      if (row.kind !== GUID_EMBEDDED_SOURCE) continue;
      if (row.parent?.table !== 0x30) continue;
      const document = documentByRow.get(row.parent.row);
      if (document === undefined || row.value === null) continue;
      if (row.value.length < 4) continue;
      const declared = row.value.readInt32LE(0);
      if (declared <= 0) continue; // 0 marks a source the producer removed.
      if (declared > maxSourceBytes) continue;
      if (embeddedSources.length >= maxEmbeddedSources) break;
      if (embeddedBytes + declared > maxSourceBytes) break;
      let bytes;
      try {
        bytes = inflateRawSync(row.value.subarray(4), {
          maxOutputLength: declared,
        });
      } catch {
        try {
          bytes = inflateSync(row.value.subarray(4), {
            maxOutputLength: declared,
          });
        } catch {
          continue;
        }
      }
      embeddedBytes += bytes.length;
      embeddedSources.push({ path: document.path, bytes });
    }
  }

  return {
    documents,
    embedded_sources: embeddedSources,
    source_link:
      sourceLink === null
        ? null
        : {
            documents:
              typeof sourceLink.documents === "object" &&
              sourceLink.documents !== null
                ? sourceLink.documents
                : {},
          },
  };
};

/**
 * Recover symbol information for one assembly. The embedded portable PDB wins
 * over a sidecar file, matching the runtime's own preference.
 */
export const recoverSymbols = async (
  assemblyPath,
  { maxEmbeddedSources = 2000 } = {},
) => {
  let image;
  try {
    image = await readFile(assemblyPath);
  } catch (cause) {
    return { kind: null, error: String(cause?.message ?? cause) };
  }

  const embedded = findEmbeddedPortablePdb(image);
  if (embedded !== null) {
    const parsed = readPortablePdb(embedded, { maxEmbeddedSources });
    if (parsed !== null) return { kind: "embedded", ...parsed, error: null };
    return {
      kind: "embedded",
      documents: [],
      embedded_sources: [],
      source_link: null,
      error: "embedded PDB is not a readable portable PDB",
    };
  }

  const sidecarPath = `${assemblyPath.slice(0, assemblyPath.lastIndexOf("."))}.pdb`;
  try {
    const info = await stat(sidecarPath);
    if (!info.isFile()) throw new Error("not a file");
  } catch {
    return {
      kind: null,
      documents: [],
      embedded_sources: [],
      source_link: null,
      error: null,
    };
  }
  try {
    const parsed = readPortablePdb(await readFile(sidecarPath), {
      maxEmbeddedSources,
    });
    if (parsed !== null)
      return { kind: "sidecar", ...parsed, path: sidecarPath, error: null };
    return {
      kind: "sidecar",
      path: sidecarPath,
      documents: [],
      embedded_sources: [],
      source_link: null,
      error: "sidecar PDB is not a portable PDB (Windows PDB is unsupported)",
    };
  } catch (cause) {
    return {
      kind: "sidecar",
      path: sidecarPath,
      documents: [],
      embedded_sources: [],
      source_link: null,
      error: String(cause?.message ?? cause),
    };
  }
};

const splitLibraryId = (id) => {
  const slash = id.lastIndexOf("/");
  if (slash === -1) return { name: id, version: null };
  return { name: id.slice(0, slash), version: id.slice(slash + 1) };
};

const isRecord = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Parse a `.deps.json` document into the dependency graph the product actually
 * deploys: target framework, libraries with their kind, and the runtime and
 * native assets each library contributes.
 */
export const parseDepsJson = (text) => {
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(document)) return null;
  const runtimeTargetName =
    isRecord(document.runtimeTarget) &&
    typeof document.runtimeTarget.name === "string"
      ? document.runtimeTarget.name
      : null;
  const targets = isRecord(document.targets) ? document.targets : {};
  const libraries = isRecord(document.libraries) ? document.libraries : {};

  const packages = [];
  for (const [id, library] of Object.entries(libraries)) {
    if (!isRecord(library)) continue;
    const { name, version } = splitLibraryId(id);
    packages.push({
      id,
      name,
      version,
      type: typeof library.type === "string" ? library.type : "unknown",
      serviceable: library.serviceable === true,
    });
  }

  const assets = [];
  const target = runtimeTargetName ?? Object.keys(targets)[0] ?? null;
  const targetLibraries = target === null ? {} : targets[target] ?? {};
  for (const [id, library] of Object.entries(targetLibraries)) {
    if (!isRecord(library)) continue;
    const { name, version } = splitLibraryId(id);
    const runtime = isRecord(library.runtime) ? Object.keys(library.runtime) : [];
    const native = isRecord(library.native) ? Object.keys(library.native) : [];
    const resources = isRecord(library.resources) ? Object.keys(library.resources) : [];
    if (runtime.length + native.length + resources.length === 0) continue;
    assets.push({ id, name, version, runtime, native, resources });
  }

  return {
    runtime_target: runtimeTargetName,
    target_frameworks: Object.keys(targets),
    packages: packages.sort((left, right) => left.id.localeCompare(right.id)),
    assets: assets.sort((left, right) => left.id.localeCompare(right.id)),
  };
};

/**
 * Parse a `.runtimeconfig.json` document for the framework the product targets
 * and any runtime knobs it relies on.
 */
export const parseRuntimeConfig = (text) => {
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(document) || !isRecord(document.runtimeOptions)) return null;
  const options = document.runtimeOptions;
  const framework = isRecord(options.framework)
    ? {
        name: options.framework.name ?? null,
        version: options.framework.version ?? null,
      }
    : null;
  return {
    tfm: typeof options.tfm === "string" ? options.tfm : null,
    framework,
    frameworks: Array.isArray(options.frameworks)
      ? options.frameworks.filter(isRecord).map((entry) => ({
          name: entry.name ?? null,
          version: entry.version ?? null,
        }))
      : [],
    roll_forward:
      typeof options.rollForward === "string" ? options.rollForward : null,
    config_properties: isRecord(options.configProperties)
      ? options.configProperties
      : {},
  };
};

const MAX_DEPLOYMENT_FILES = 200;

/**
 * Read every deployment manifest under a product directory. Bounded so a large
 * tree cannot turn into unbounded reads.
 */
export const collectDeployment = async (rootPath, { maxFiles = MAX_DEPLOYMENT_FILES } = {}) => {
  const manifests = [];
  const stack = [rootPath];
  let visited = 0;
  while (stack.length > 0 && visited < maxFiles) {
    const current = stack.pop();
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      if (entry.isDirectory()) {
        if (
          entry.name === "bin" ||
          entry.name === "obj" ||
          entry.name === "node_modules" ||
          entry.name === ".git"
        )
          continue;
        stack.push(join(current, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      if (
        !entry.name.endsWith(".deps.json") &&
        !entry.name.endsWith(".runtimeconfig.json")
      )
        continue;
      visited += 1;
      if (visited > maxFiles) break;
      const path = join(current, entry.name);
      let text;
      try {
        text = await readFile(path, "utf8");
      } catch {
        continue;
      }
      manifests.push(
        entry.name.endsWith(".deps.json")
          ? { path, kind: "deps", parsed: parseDepsJson(text) }
          : { path, kind: "runtimeconfig", parsed: parseRuntimeConfig(text) },
      );
    }
  }
  return manifests.filter((manifest) => manifest.parsed !== null);
};

/**
 * Known .NET obfuscator/packer markers. Detection is by static identity only:
 * attribute and reference names injected by the tool, resource names,
 * P/Invoke modules, and watermark strings. Name and string matches alone are
 * suspicious; attribute, reference, module, or resource matches are likely.
 * Nothing here defeats, removes, or bypasses any protection.
 */
export const OBFUSCATOR_SIGNALS = [
  {
    tool: "ConfuserEx",
    markers: {
      attributes: ["confusedbyattribute"],
      strings: ["confuserex", "confused by", "github.com/yck1509/confuserex"],
    },
    note: "Open-source obfuscator; renames symbols and can encrypt strings and pack resources.",
  },
  {
    tool: "Confuser",
    markers: {
      attributes: ["confusedbyattribute"],
      strings: ["confuser.codeplex.com"],
    },
    note: "Classic open-source obfuscator; distinguish from ConfuserEx by the watermark string.",
  },
  {
    tool: ".NET Reactor",
    vendor: "Eziriz",
    markers: {
      strings: [".net reactor", "netreactor", "eziriz", "netguard"],
    },
    note: "Commercial protector; string encryption and native stub are common, so metadata strings may be unreadable.",
  },
  {
    tool: "SmartAssembly",
    vendor: "Red Gate",
    markers: {
      attributes: ["smartassembly.attributes.poweredbyattribute"],
      references: ["smartassembly"],
      resources: ["smartassembly"],
      strings: ["smartassembly", "powered by smartassembly"],
    },
    note: "Red Gate protector; look for SmartAssembly.* resources carrying the real payload.",
  },
  {
    tool: "Dotfuscator",
    vendor: "PreEmptive",
    markers: {
      attributes: [
        "preemptive.attributes.setupattribute",
        "preemptive.attributes.featureattribute",
      ],
      strings: ["preemptive", "dotfuscator"],
    },
    note: "PreEmptive protector; Feature attributes name the applied transforms.",
  },
  {
    tool: "Eazfuscator.NET",
    markers: {
      strings: ["eazfuscator"],
      resources: ["eazfuscator"],
    },
    note: "Commercial obfuscator with code virtualization; method bodies may not decompile to readable C#.",
  },
  {
    tool: "Babel.NET",
    markers: {
      attributes: ["babelattribute"],
      strings: ["babelfor.net", "babelattribute"],
    },
    note: "Commercial obfuscator; BabelAttribute marks processed assemblies.",
  },
  {
    tool: "Crypto Obfuscator",
    vendor: "LogicNP",
    markers: {
      attributes: [
        "cryptoobfuscator.protectedwithcryptoobfuscatorattribute",
      ],
      strings: ["cryptoobfuscator", "logicnp"],
    },
    note: "LogicNP protector; the marker attribute names the product directly.",
  },
  {
    tool: "Agile.NET",
    vendor: "SecureTeam",
    markers: {
      strings: ["agile.net", "agiledotnet"],
    },
    note: "SecureTeam obfuscator; also see CliSecure below.",
  },
  {
    tool: "CliSecure",
    vendor: "SecureTeam",
    markers: {
      strings: ["clisecure"],
    },
    note: "SecureTeam protector, often paired with Agile.NET.",
  },
  {
    tool: "ILProtector",
    markers: {
      strings: ["ilprotector", "vmsoft"],
    },
    note: "Virtualizing protector; IL becomes native-backed and ILSpy output goes partial.",
  },
  {
    tool: "Xenocode Postbuild",
    markers: {
      attributes: ["xenocode"],
      resources: ["xenocode"],
      strings: ["xenocode"],
    },
    note: "Post-build protector; virtualized methods resist static C# recovery.",
  },
  {
    tool: "VMProtect",
    markers: {
      pinvoke: ["vmprotectsdk32", "vmprotectsdk64"],
      strings: ["vmprotect"],
    },
    note: "Native virtualizer, usually guarding a stub or license check around managed code.",
  },
  {
    tool: "Enigma Protector",
    markers: {
      strings: ["enigma protector", "enigma_ide"],
    },
    note: "Native packer/licensing shell; managed payloads hide behind it.",
  },
  {
    tool: "Themida / WinLicense",
    vendor: "Oreans",
    markers: {
      strings: ["themida", "winlicense", "oreans"],
    },
    note: "Oreans shell; static metadata may be intact while entry behavior is virtualized.",
  },
  {
    tool: "DNGuard / NetGuard",
    markers: {
      strings: ["dnguard", "netguard"],
    },
    note: "Commercial protector with string encryption.",
  },
  {
    tool: "MaxtoCode",
    markers: {
      strings: ["maxtocode"],
    },
    note: "X86/X64 encryption engine for managed code; decompiled bodies may be stubs.",
  },
  {
    tool: "Spices.NET",
    vendor: "9Rays",
    markers: {
      attributes: ["ninerays.obfuscator"],
      strings: ["ninerays", "spices.net"],
    },
    note: "9Rays obfuscator; evaluation attributes mark trial-protected builds.",
  },
];

/** Watermark substrings matched against decompiled text and #US literals. */
export const OBFUSCATION_TEXT_MARKERS = [
  "confusedby",
  "confuserex",
  "confused by",
  ".net reactor",
  "netreactor",
  "eziriz",
  "smartassembly",
  "preemptive",
  "dotfuscator",
  "eazfuscator",
  "babelfor.net",
  "babelattribute",
  "cryptoobfuscator",
  "logicnp",
  "agile.net",
  "agiledotnet",
  "clisecure",
  "ilprotector",
  "xenocode",
  "vmprotect",
  "enigma protector",
  "enigma_ide",
  "themida",
  "winlicense",
  "oreans",
  "dnguard",
  "maxtocode",
  "ninerays",
  "spices.net",
  "obfuscation(exclude=false",
  "obfuscation(exclude = false",
  "obfuscation(false",
];

const lowerIncludes = (haystack, needle) =>
  String(haystack ?? "").toLowerCase().includes(needle);

const firstMatch = (values, needle) =>
  values.find((value) => lowerIncludes(value, needle)) ?? null;

/** Watermark comparison ignores whitespace: decompiled and collapsed forms match. */
const collapseWhitespace = (value) =>
  String(value ?? "").toLowerCase().replace(/\s+/gu, "");

const firstCollapsedMatch = (values, needle) => {
  const wanted = collapseWhitespace(needle);
  return (
    values.find((value) => collapseWhitespace(value).includes(wanted)) ?? null
  );
};

/**
 * Combine every static identity signal into one protection verdict.
 * Attribute, reference, P/Invoke, and resource-name matches are likely;
 * watermark strings and renamed-symbol ratios alone are suspicious.
 * A generic ObfuscationAttribute opt-out (Exclude=true) is not a signal.
 */
export const matchObfuscatorSignals = ({
  references = [],
  resourceNames = [],
  attributeNames = [],
  pinvokeModules = [],
  stringLiterals = [],
  memberNames = null,
  textMarkers = [],
} = {}) => {
  const indicators = [];
  for (const entry of OBFUSCATOR_SIGNALS) {
    const { tool, vendor, markers, note } = entry;
    let finding = null;
    for (const name of markers.attributes ?? []) {
      const hit = firstMatch(attributeNames, name);
      if (hit !== null) {
        finding = { signal: "obfuscator-attribute", detail: hit, confidence: "high" };
        break;
      }
    }
    if (finding === null) {
      for (const name of markers.references ?? []) {
        const hit = firstMatch(references, name);
        if (hit !== null) {
          finding = { signal: "assembly-reference", detail: hit, confidence: "high" };
          break;
        }
      }
    }
    if (finding === null) {
      for (const name of markers.pinvoke ?? []) {
        const hit = firstMatch(pinvokeModules, name);
        if (hit !== null) {
          finding = { signal: "pinvoke-module", detail: hit, confidence: "high" };
          break;
        }
      }
    }
    if (finding === null) {
      for (const name of markers.resources ?? []) {
        const hit = firstMatch(resourceNames, name);
        if (hit !== null) {
          finding = { signal: "resource-name", detail: hit, confidence: "high" };
          break;
        }
      }
    }
    if (finding === null) {
      const pools = [...stringLiterals, ...textMarkers];
      for (const marker of markers.strings ?? []) {
        const hit = firstCollapsedMatch(pools, marker);
        if (hit !== null) {
          finding = { signal: "watermark-string", detail: hit, confidence: "medium" };
          break;
        }
      }
    }
    if (finding !== null) {
      indicators.push({
        tool,
        vendor: vendor ?? null,
        ...finding,
        note,
      });
    }
  }

  // Renamed symbols without a tool fingerprint: Obfuscar-style renaming and
  // aggressive minification erase original names beyond static recovery.
  if (memberNames !== null && typeof memberNames === "object") {
    const renamed = (memberNames.hash_like ?? 0) + (memberNames.minified ?? 0);
    const total =
      renamed + (memberNames.readable ?? 0) + (memberNames.compiler_generated ?? 0);
    if (total >= 20 && renamed / total >= 0.3) {
      indicators.push({
        tool: null,
        vendor: null,
        signal: "renamed-symbols",
        detail: `${String(renamed)} of ${String(total)} sampled names are hash-like or minified`,
        confidence: "medium",
        note: "Symbol renaming (Obfuscar-style or minifier); original names are not recoverable statically.",
      });
    }
  }

  if (indicators.some((indicator) => indicator.confidence === "high"))
    return { status: "likely", indicators };
  if (indicators.length > 0) return { status: "suspicious", indicators };
  return { status: "none", indicators: [] };
};

/**
 * Classify how an assembly is meant to run from REA's own metadata facts.
 * No bytes are re-read here; every input comes from inspect-managed-artifact.
 */
export const classifyRuntimeKind = ({
  runtimeFamily = "unknown",
  implementation = "unknown",
  flagNames = [],
  readyToRun = false,
  entryPointKind = "none",
  managedArchitecture = "unknown",
} = {}) => {
  const notes = [];
  if (
    runtimeFamily === "mixed-clr-native" ||
    implementation === "cpp-cli-mixed" ||
    (!flagNames.includes("il-only") && entryPointKind === "native-rva")
  ) {
    notes.push("Native code is linked into this image (C++/CLI or mixed mode).");
    return { kind: "mixed-mode", notes };
  }
  if (readyToRun || implementation === "cil-and-ready-to-run") {
    notes.push("ReadyToRun precompiled code ships alongside IL; decompilation reads the IL.");
    return { kind: "readytorun", notes };
  }
  if (entryPointKind === "native-rva") {
    notes.push("The entry point is a native RVA, not a managed token.");
    return { kind: "native-entry", notes };
  }
  if (implementation === "metadata-only") {
    notes.push("Reference assembly: metadata without method bodies.");
    return { kind: "metadata-only", notes };
  }
  if (runtimeFamily !== "unknown") {
    if (managedArchitecture !== "unknown")
      notes.push(`Managed architecture ${managedArchitecture}.`);
    return { kind: `il-only (${runtimeFamily})`, notes };
  }
  notes.push("Runtime family could not be established from the CLI header.");
  return { kind: "unknown", notes };
};

/**
 * Summarize signing identity from metadata facts plus the PE certificate
 * table. Presence is reported; chains, timestamps, and digest coverage are
 * explicitly out of scope and left to platform tooling.
 */
export const summarizeSigning = ({
  publicKey = null,
  assemblyFlags = 0,
  flagNames = [],
  certificates = null,
} = {}) => {
  const strongNamed =
    flagNames.includes("strong-name-signed") ||
    (typeof assemblyFlags === "number" && (assemblyFlags & 0x8) !== 0) ||
    (publicKey !== null &&
      publicKey !== undefined &&
      publicKey.kind !== undefined &&
      publicKey.kind !== "none");
  const entries = Array.isArray(certificates?.entries) ? certificates.entries : [];
  const signers = [];
  for (const entry of entries) {
    const candidate =
      entry?.signer_subject ??
      entry?.subject ??
      entry?.certificate_subject ??
      null;
    if (typeof candidate === "string" && candidate.length > 0) signers.push(candidate);
    if (signers.length >= 4) break;
  }
  return {
    strong_named: strongNamed,
    public_key_token: publicKey?.token ?? null,
    authenticode: {
      present: entries.length > 0,
      count: entries.length,
      signers,
    },
  };
};

export const deploymentSummary = (manifests) => {
  const packages = new Map();
  const frameworkMap = new Map();
  for (const manifest of manifests) {
    if (manifest.kind !== "deps") continue;
    for (const entry of manifest.parsed.packages) {
      if (entry.type !== "package") continue;
      packages.set(entry.id, entry);
    }
  }
  for (const manifest of manifests) {
    if (manifest.kind !== "runtimeconfig") continue;
    const { framework, frameworks } = manifest.parsed;
    if (framework?.name !== null && framework?.name !== undefined)
      frameworkMap.set(`${framework.name}/${framework.version}`, framework);
    for (const entry of frameworks ?? []) {
      if (entry.name !== null)
        frameworkMap.set(`${entry.name}/${entry.version}`, entry);
    }
  }
  return {
    package_count: packages.size,
    frameworks: [...frameworkMap.values()],
    packages: [...packages.values()].sort((left, right) =>
      left.id.localeCompare(right.id),
    ),
  };
};

/**
 * File name for a recovered embedded source: the PDB document row keeps
 * outputs ordered and stable, the sanitized base name keeps them readable.
 * Absolute producer paths never reach the filesystem.
 */
export const sourceOutputName = (documentPath, row) => {
  const base = String(documentPath ?? "").split(/[/\\]/u).pop() || "source";
  const safe = base
    .replace(/[^A-Za-z0-9._-]+/gu, "_")
    .replace(/^_+/u, "")
    .slice(0, 80) || "source";
  return `${String(row).padStart(4, "0")}-${safe}`;
};

const ADJACENT_PATTERNS = [
  { kind: "pdb-sidecar", test: (name) => name.endsWith(".pdb") },
  {
    kind: "net-config",
    test: (name) =>
      name.endsWith(".exe.config") ||
      name.endsWith(".dll.config") ||
      name === "app.config" ||
      name === "web.config",
  },
  {
    kind: "appsettings",
    test: (name) =>
      name === "appsettings.json" || name.startsWith("appsettings."),
  },
  { kind: "xml-docs", test: (name) => name.endsWith(".xml") },
];

const classifyAdjacent = (fileName) => {
  const lower = fileName.toLowerCase();
  for (const pattern of ADJACENT_PATTERNS) {
    if (pattern.test(lower)) return pattern.kind;
  }
  return null;
};

/**
 * List deployment-adjacent files under a product directory: sidecar PDBs,
 * .NET config files, appsettings variants, and XML documentation files.
 * Returns paths, kinds, and sizes; copying stays with the caller so tests
 * can inspect the listing without touching the filesystem beyond reads.
 */
export const collectAdjacentFiles = async (
  rootPath,
  { maxFiles = 200 } = {},
) => {
  const found = [];
  const stack = [rootPath];
  while (stack.length > 0 && found.length < maxFiles) {
    const current = stack.pop();
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      if (found.length >= maxFiles) break;
      const entryPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (
          entry.name === "bin" ||
          entry.name === "obj" ||
          entry.name === "node_modules" ||
          entry.name === ".git"
        )
          continue;
        stack.push(entryPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = classifyAdjacent(entry.name);
      if (kind === null) continue;
      let bytes = null;
      try {
        bytes = (await stat(entryPath)).size;
      } catch {
        continue;
      }
      found.push({ path: entryPath, kind, bytes });
    }
  }
  return found.sort((left, right) => left.path.localeCompare(right.path));
};
