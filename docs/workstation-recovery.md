# Workstation recovery runbook: .NET product deconstruction

This is the complete, start-to-finish procedure for taking a Windows, macOS,
or Linux workstation (or a disk image of one), extracting every recoverable
byte from a .NET product you own, and proving the recovery worked. Follow it
top to bottom; every command below was executed against this checkout during
verification, with the exact versions in step 2.

What "everything" means here: decompiled C# for every managed assembly,
PDB symbol evidence with byte-identical embedded sources, managed resources,
deployment manifests (frameworks, NuGet packages, native assets), adjacent
files (configs, sidecar PDBs), hash-shape identification, license-dongle
evidence, obfuscator/runtime/signing verdicts, and a recovered solution that
builds. Static analysis only — the product is never executed, nothing is
uploaded, and SourceLink mappings are recorded but never fetched.

## 1. Prepare the workstation

1. Use a dedicated machine or VM you can snapshot (UTM, VirtualBox, Hyper-V,
   or any hypervisor). Take the snapshot **before** you copy the product in,
   so every run starts from a clean room.
2. Reserve disk space: the output runs about 3× the product size (a 144 KiB
   product folder produced a 468 KiB recovery in verification).
3. The workstation needs outbound network **only** for installing tools. The
   extraction itself needs no network access.

## 2. Install the toolchain

| Tool | Verified version | Install |
|---|---|---|
| Node.js | v24.22.1 (see `.nvmrc`) | `nvm use` or the pinned installer; Cursor Cloud users: prefix `PATH="/usr/local/bin:$PATH"` |
| npm | 11.x (`packageManager` pins `npm@11.16.0`) | ships with Node.js |
| REA (this checkout) | `6.8.0` | `npm ci` then `npm run compile` (produces `dist/`, required by `rea-dotnet`) |
| .NET SDK | 10.0.403 | vendor installer; verify with `dotnet --version` |
| ilspycmd | 11.2.0.10050 (ILSpy 11) | `dotnet tool install -g ilspycmd`; verify with `ilspycmd --version` |
| Il2CppDumper (Unity only) | any recent `Il2CppDumper.dll` | set `IL2CPP_DUMPER_PATH` or pass `--il2cpp-dumper` |

Verify each tool prints its version before continuing. `rea-dotnet` refuses
to run when `dist/cli.js` is missing and tells you to run the compile step.

## 3. Capture the source machine data

Work from a **copy**. Never point the extractor at the only copy of anything.

- **Installed product folder (usual case).** Copy the whole application
  directory: the `.exe`/`.dll` files next to each other, plus any
  `.deps.json`, `.runtimeconfig.json`, `.config`, `appsettings*.json`,
  `.xml`, and `.pdb` files sitting beside them. The extractor collects these
  adjacent files automatically.
- **Full-disk image.** Mount the image read-only (or export the file tree
  with your forensic tooling) and point the extractor at the mounted product
  directory. REA reads file bytes only; mounting read-only guarantees the
  image is never modified.
- **Single `.dll`/`.exe`.** Point the extractor at the file directly; its own
  folder is used for dependency context (`deps.json`, sidecar PDBs).
- **Unity IL2CPP game.** Copy the folder containing `global-metadata.dat`
  next to `GameAssembly.dll` (or the platform equivalent).

Record a hash of your copy (for example `sha256sum` over the tree) so you
can prove later that the source never changed.

## 4. Detect the layout

```bash
node scripts/rea-dotnet-decompile.mjs --detect /path/to/product-copy
```

Expected: JSON with `managed`, `single_file`, `native`, and `unknown`
counts plus an `il2cpp` pair when present. This opens nothing, runs nothing,
and writes nothing. If the kind comes back `Unknown`, the target is not a
managed product — use the native providers instead
([native investigation](native-investigation.md)).

## 5. Run the full extraction

```bash
node scripts/rea-dotnet-decompile.mjs /path/to/product-copy /path/to/product-rea-out --repo --build
```

Defaults already do the complete job: REA member summaries, ILSpy project
decompilation, PDB symbol recovery with embedded-source extraction, managed
resource enumeration and recovery, deployment-manifest parsing, adjacent-file
collection, hash-shape and obfuscated-name scanning, license-dongle checks,
protection analysis, reference rewriting, solution generation, and a build
attempt. Add `--include-framework` only if you also want `System.*` /
`UnityEngine.*` decompiled; add `--git-init` to version the output.

Per assembly the log prints one line,
`[i/n] Name -> status (N .cs)`. Large products and single-file bundles take
minutes; IL2CPP dummy-DLL decompilation is the slowest stage.

## 6. Review the recovery (or use the wizard)

`rea-gui` walks the same eight steps with a how-to on each screen:

```bash
node scripts/rea-gui.mjs
```

It prints a `http://127.0.0.1:<port>/?token=...` URL (localhost only,
per-session token): 1 pick target, 2 configure, 3 run with live log and
progress bar, 4 review the manifest dashboard and `REPORT.md`, 5 inspect one
assembly (overview, protection, symbols, resources, hashes, license), 6
browse `decompiled/`, `sources/`, `resources/`, `config/`, `evidence/` with
previews, 7 build now with streamed `dotnet` output, 8 hand off with
`AGENT_TASK.md`, `LIMITATIONS.md`, and the exact `rea-goal` command.

Without the wizard, the output layout is:

| Path | Contents (authoritative record first) |
|---|---|
| `manifest.json` | Machine-readable record, schema `rea.dotnet-decompile/6`: per-assembly metadata, member counts, symbols, resources, protection, hashes, license, references; bundles; IL2CPP; deployment summary; adjacent files; repo and build results |
| `REPORT.md` | Human narrative: inventory tables, protection verdicts, limitations |
| `evidence/` | REA metadata bundles plus one `*.symbols.json` per assembly (PDB documents, SourceLink maps) |
| `decompiled/` | ILSpy C# reconstruction and `.csproj` files (inference, not original source) |
| `sources/` | Byte-identical embedded sources recovered from PDBs — these outrank decompiled text on conflicts |
| `resources/` | Managed resources missing from project output, with sha256 |
| `config/` | Small adjacent files (configs, sidecar PDBs within the copy bound) |
| `deployment.json` | Parsed `.deps.json` / `.runtimeconfig.json`: frameworks, NuGet packages, runtime and native assets |
| `Recovered.sln*`, `build.ps1`/`build.sh` | Rebuildable solution (`--repo`) |
| `AGENT_TASK.md`, `TESTING.md`, `LIMITATIONS.md`, `dependencies.md` | Agent playbook, verification checklist, honesty bounds, reference graph |
| `BUILD_RESULTS.md` | Per-project build outcome (`--build`) |

## 7. Prove everything works

Run these checks against the output; all of them passed in verification on
this checkout (schema `/6`, recovered solution building with 0 errors,
embedded sources byte-identical to the originals):

1. **Manifest is complete.** Every assembly row has non-null `symbols`,
   `resources`, and `protection`; `protection.obfuscation` is `none`,
   `suspicious`, or `likely` (never absent); `protection.signing` records
   strong-name and Authenticode presence.
2. **Embedded sources are byte-identical.** Each `sources/` file's sha256 in
   the manifest matches the file, and its `hash` matches the PDB document
   hash in `evidence/*.symbols.json`.
3. **Resources are accounted for.** Every `--list-resources` entry is either
   `recovered-via-project` with a path or `extracted` with bytes and sha256.
4. **Deployment matches the product.** `deployment.json` frameworks and
   package counts agree with the shipped `.deps.json` files.
5. **The solution builds.** `BUILD_RESULTS.md` shows every project `ok`, or
   lists the exact failing projects with the last compiler error lines.
6. **Dehashing is recorded.** `hash_scan.by_algorithm` lists every
   hash-shaped literal with all plausible algorithms at capped confidence
   (prefixed modular-crypt formats identify one algorithm at high
   confidence; bare hex digests stay ambiguous by construction).
7. **Unknowns are explicit, not silent.** `skipped`, `unresolved`,
   `native` (with the native-provider handoff), and `LIMITATIONS.md` say
   what cannot be proven — including virtualized methods, encrypted
   resources, and IL2CPP bodies, which need dynamic or native analysis.

## 8. Hand off reconstruction

Give an agent the output folder with `AGENT_TASK.md`, or run headlessly:

```bash
node scripts/rea-goal.mjs --goal "Make this recovered repository build" --target /path/to/product-rea-out --dry-run
```

Remove `--dry-run` to execute. The agent fixes target frameworks first, then
references, then namespaces — diffing `sources/` against `decompiled/` where
both cover a file — and records every command and result.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `REA build output is missing` | Run `npm run compile` in this checkout first |
| `ilspycmd was not found` | `dotnet tool install -g ilspycmd` or pass `--ilspy <path>` |
| `no PDB (embedded or sidecar)` | Normal for release builds without symbols; local variable names become ILSpy inference |
| Windows PDB reported, not parsed | Only portable PDBs are decoded; use the producer's toolchain for the rest |
| Assembly `partial` with ILSpy errors | Obfuscation or missing dependencies; check `protection.obfuscation` and `REPORT.md` |
| IL2CPP method bodies empty | Expected: IL2CPP compiles IL to native code; use `NATIVE_ANALYSIS.md` with a native provider |
| `dotnet` build failures | Follow `AGENT_TASK.md` order; third-party assemblies under `references/` are vendored copies |
| Sidecar PDB over the copy bound | Recorded in the manifest but not copied; read it in place |

## Policy

Lawful use only: analyze software you own or are authorized to examine (see
[DISCLAIMER.md](../DISCLAIMER.md)). This workflow detects and explains
license checks and obfuscation from static evidence; it provides no bypass,
defeat, or circumvention guidance anywhere.
