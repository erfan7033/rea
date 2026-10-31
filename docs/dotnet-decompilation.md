# .NET decompilation workflow

REA inspects .NET PE/CLI artifacts without loading or executing their code
([managed-code analysis](managed-code-analysis.md)). This guide covers the
optional reconstruction workflow that turns that static Evidence plus
`ilspycmd` output into a buildable recovered repository: `rea-dotnet`,
`rea-gui`, and `rea-goal`.

All three entry points are static analysis only. Targets are never executed,
decompiled code is never run, and no network access is required. Decompiled C#
is reconstructed source, not original source; `manifest.json` and `evidence/`
remain the authoritative record.

## Prerequisites

- REA built (`npm run build:cached`).
- `ilspycmd` (ILSpy 8+): `dotnet tool install -g ilspycmd`.
- `dotnet` SDK for `--repo` solution creation and `--build`.
- Optional: `Il2CppDumper.dll` (`IL2CPP_DUMPER_PATH` or `--il2cpp-dumper`) for
  Unity IL2CPP products.

REA never installs or upgrades these tools.

## Quick start

```bash
rea-dotnet /path/to/product /path/to/product-rea-out --repo --build
```

What you get in the output directory:

- `decompiled/` — reconstructed C# and project files.
- `evidence/` — REA evidence bundles (metadata, hashes, coverage), plus one
  `*.symbols.json` per assembly with PDB documents and SourceLink mappings.
- `sources/` — byte-identical embedded sources recovered from PDBs.
- `resources/` — managed resources missing from ILSpy project output.
- `config/` — small adjacent files (configs, sidecar PDBs within the copy bound).
- `deployment.json` — deployment manifests (`.deps.json`, `.runtimeconfig.json`)
  with the shipped frameworks, NuGet packages, and runtime/native assets.
- `manifest.json` — machine-readable extraction record (schema
  `rea.dotnet-decompile/6`).
- `REPORT.md` — extraction report and limitations.
- With `--repo`: `README.md`, `AGENT_TASK.md`, `dependencies.md`,
  `LIMITATIONS.md`, `TESTING.md`, `build.ps1`/`build.sh`, and
  `Recovered.sln*`. With `--build`, also `BUILD_RESULTS.md`.

Preview the layout without writing anything:

```bash
rea-dotnet --detect /path/to/product
```

## Reference rewriting

ILSpy project files point at the original build paths. With rewriting enabled
(the default), the extractor:

1. Converts references to recovered assemblies into `ProjectReference` items.
2. Copies other locally referenced assemblies under `references/` and rewrites
   their `HintPath` at the copy.
3. Records unresolvable references as explicit unknowns instead of silently
   dropping them.

The outcome is recorded in `manifest.references`,
`manifest.repo.reference_rewrite`, `dependencies.md`, and `REPORT.md`.
Pass `--no-reference-rewrite` to keep ILSpy's original reference paths.

## Options

| Flag                     | Effect                                                                |
| ------------------------ | --------------------------------------------------------------------- |
| `--repo`                 | Write the recovered repository scaffold and solution.                 |
| `--build`                | Build every recovered project; implies `--repo`.                      |
| `--git-init`             | Initialize a git repository in the output directory.                  |
| `--all-bundles`          | Decompile every single-file bundle entry (default: app entries only). |
| `--all-il2cpp`           | Decompile every IL2CPP dummy DLL (default: app assemblies only).      |
| `--no-il2cpp-code`       | Run Il2CppDumper without decompiling dummy assemblies.                |
| `--include-framework`    | Also decompile framework assemblies in a folder scan.                 |
| `--no-members`           | Skip per-assembly REA member summaries.                               |
| `--no-pdb`               | Do not use sidecar PDBs for local variable names.                     |
| `--no-reference-rewrite` | Keep ILSpy's original reference paths.                                |
| `--no-hash-scan`         | Skip hash and obfuscated-name scanning.                               |
| `--no-license-scan`      | Skip license-dongle check detection.                                  |
| `--no-symbols`           | Skip PDB symbol recovery and embedded-source extraction.              |
| `--no-resources`         | Skip managed-resource enumeration and recovery.                       |
| `--no-deployment`        | Skip deployment-manifest and adjacent-file collection.                |
| `--force`                | Allow writing into a non-empty output directory.                      |
| `--json`                 | Print the final manifest as JSON on stdout.                           |
| `--quiet`                | Send progress to stderr instead of stdout.                            |
| `--detect`               | Report the detected layout as JSON without writing anything.          |

## Symbols, embedded sources, and SourceLink

Each assembly's embedded portable PDB is read first, falling back to a
sidecar `.pdb` (Windows PDBs are reported, not parsed). PDB documents record
original paths, languages, and source hashes; producer-embedded sources are
recovered byte-identically under `sources/` (one file per PDB document row,
mapped in per-assembly `symbols` and `evidence/*.symbols.json`). SourceLink
mappings are recorded as evidence only and are never fetched. ILSpy still
receives the sidecar PDB via `-usepdb` for local variable names when one
exists next to the assembly. Disable with `--no-symbols`.

## Managed resources and deployment

`ilspycmd --list-resources` enumerates every managed resource. Entries already
materialized by ILSpy project output (config JSON, `.resx` from `.resources`,
XAML from BAML) are recorded with their recovered path, not duplicated;
missing entries are extracted with `ilspycmd --resource` under `resources/`
within size bounds. `.deps.json` and `.runtimeconfig.json` files are parsed
into `deployment.json` (target frameworks, NuGet packages, runtime and native
assets per library), and adjacent files — sidecar PDBs, `*.config`,
`appsettings*.json`, XML docs — are recorded and copied when small. Disable
with `--no-resources` and `--no-deployment`.

## Hash identification and obfuscated names

Each decompiled assembly is scanned for hash-shaped string literals and
obfuscated member names; results land in `manifest.hash_scan`,
per-assembly `hash_scan`, and `REPORT.md`. Identification is by shape only:
prefixed modular-crypt formats (bcrypt, Argon2, md5-crypt, sha512-crypt, LDAP
`{SHA}`) identify one algorithm at high confidence, while bare hex digests are
ambiguous by construction — a 32-character hex value may be MD5, NTLM, or MD4
and is reported as every plausible candidate at medium confidence or below.
UUIDs are classified as identifiers, never as hashes. Member names are
classified as `readable`, `minified` (single-character, typical of minifiers),
`hash-like` (hex gibberish, typical of obfuscator renaming), or
`compiler-generated`. Scans are bounded (capped files, bytes, literals, and
samples) so the manifest stays small.

## License-dongle checks

Each managed assembly is inspected with REA's `inspect-managed-native-boundaries`
evidence plus its assembly references and reconstructed text. P/Invoke modules
and imports are matched against a vendor table covering Sentinel HASP (Thales),
CodeMeter (Wibu-Systems), KeyLok, Dinkey, Rockey, Guardant, and UniKey. A
module, assembly, or API match reports presence with the vendor, product, and
the purpose of each known API (for example, `hasp_login` opens a license
session for a feature id). Keyword-only matches are reported as suspicious at
low confidence. Results land in `manifest.license_scan`, per-assembly
`license_scan`, `dependencies.md`, and `REPORT.md`.

This workflow detects and explains license checks from static evidence only.
It does not provide instructions to bypass, defeat, or circumvent license
enforcement, and recovered output must be analyzed only where lawful and
authorized.

## Protection, runtime kind, and signing

Every assembly gets a protection verdict from static identity alone, recorded
in per-assembly `protection` and `REPORT.md`:

- **Obfuscation** matches marker attributes (`ConfusedByAttribute`,
  SmartAssembly/Dotfuscator/Crypto Obfuscator/Babel/Xenocode/Spices markers),
  tool references, P/Invoke modules (VMProtect), resource names, watermark
  strings from `#US` literals and decompiled text, and renamed-symbol ratios.
  Attribute, reference, module, and resource matches are `likely`; watermark
  strings and heavy renaming alone are `suspicious`. A generic
  `ObfuscationAttribute` opt-out (`Exclude=true`) is not a signal.
- **Runtime kind** is classified from REA metadata facts: IL-only with the
  framework family, `mixed-mode` for C++/CLI, `readytorun` when precompiled
  code ships alongside IL, and `metadata-only` for reference assemblies.
- **Signing** reports strong-name status with the public-key token and
  Authenticode table presence with signer subjects. Chains, timestamps, and
  digest coverage are never verified — that stays with platform tooling.

Nothing here defeats, removes, or bypasses any protection. Obfuscated
assemblies decompile partially at best: virtualized methods and encrypted
resources need dynamic or native analysis beyond this workflow.

## Graphical workbench

```bash
rea-gui
```

`rea-gui` serves a local-only wizard (bound to `127.0.0.1` with a
per-session token) over the same extraction pipeline: each of the eight steps
below carries its own plain-English how-to, and every step is clickable in the
left-hand stepper.

1. **Pick target** — paste a product folder, `.exe`, `.dll`, or `.app` (or
   use Browse), then **Scan target** for header-only detection: managed,
   single-file, IL2CPP, or native.
2. **Configure** — grouped options with one-line explanations: repository
   scaffold, build, scope (bundles, IL2CPP, framework assemblies), and every
   evidence switch (members, PDBs, symbols, resources, deployment, hashes,
   license, reference rewriting).
3. **Run** — start the extraction with a live log, a `[i/n]` progress bar,
   cancel, and open-output-folder.
4. **Review** — the manifest dashboard: counts, repo, references, symbols,
   resources, deployment frameworks and NuGet packages, hashes, license, plus
   the full `REPORT.md`.
5. **Assembly** — per-assembly tabs: overview, symbols and embedded sources,
   resources, hashes and names, license findings.
6. **Files** — browse `decompiled/`, `sources/` (byte-identical embedded
   sources win on conflicts), `resources/`, `config/`, and `evidence/` with
   capped text previews; binaries are labelled, never dumped.
7. **Build** — **Build now** compiles the recovered solution (or every
   project) through a streamed `dotnet` run, then shows the `TESTING.md`
   verification checklist.
8. **Next steps** — `AGENT_TASK.md`, `LIMITATIONS.md`, the exact `rea-goal`
   command for headless runs, and an optional local-model agent launch.

`rea-gui` never executes the target. The file browser and preview endpoints
are confined to the chosen output folder, and every API call requires the
session token printed with the server URL.

## Goal-driven agent runs

```bash
rea-goal --goal "Make this recovered repository build" --target /path/to/product-rea-out
```

`rea-goal` creates an isolated OpenCode configuration exposing this checkout's
REA MCP server plus `ilspycmd`, writes a playbook (`AGENTS.md`), and runs
OpenCode headlessly. The global OpenCode configuration is never modified.
Use `--dry-run` to inspect the run directory and command without executing,
and `--no-auto` to require normal permission handling. Local-model selection
uses `--local-model`, `--base-url`, and `--provider-id`; hosted models use
`--model`. The user was asked not to run the local-model lane here, so that
path remains unverified in this checkout.

## Limitations

- Static analysis only; assemblies are never loaded or executed.
- Decompiled C# is inference. REA metadata Evidence remains authoritative;
  `sources/` files are byte-identical PDB copies and outrank decompiled text.
- IL2CPP dummy assemblies carry names, fields, and RVA addresses but empty
  method bodies; native bodies need a native decompiler.
- SourceLink mappings are evidence only and are never fetched by the workflow.
- Strong-name and Authenticode presence are reported, never verified.
- Obfuscator identity is static evidence only; virtualized or encrypted
  methods do not recover as readable C#.
- PDB sidecars above the copy bound are recorded, not copied; Windows PDBs are
  reported, not parsed.
- Obfuscated code, reflection, dependency injection, and dynamic loading remain
  unknown unless separately verified.
