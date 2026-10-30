export const FRAMEWORK_PREFIXES: readonly string[];
export function isFrameworkAssembly(name: string): boolean;
export function isManagedExtension(path: string): boolean;
export function safeName(value: string): string;
export function exists(path: string): Promise<boolean>;
export function sha256File(path: string): Promise<string>;
export function countSourceFiles(directory: string): Promise<number>;
export function findProjectFiles(directory: string): Promise<string[]>;
export interface DotnetProjectReference {
  readonly path: string;
  readonly assemblyName?: string;
}
export interface DotnetCopiedReference {
  readonly source: string;
  readonly output: string;
  readonly sha256: string;
}
export interface DotnetUnresolvedReference {
  readonly project: string;
  readonly reference: string;
  readonly hint: string;
}
export interface DotnetReferenceRewrite {
  readonly references: readonly DotnetCopiedReference[];
  readonly rewritten: readonly string[];
  readonly unresolved: readonly DotnetUnresolvedReference[];
}
export function rewriteProjectReferences(options: {
  readonly outputPath: string;
  readonly projects: readonly (string | DotnetProjectReference)[];
  readonly referenceDirectoryName?: string;
}): Promise<DotnetReferenceRewrite>;
export function identifyHash(raw: unknown): {
  readonly kind: string;
  readonly charset?: string;
  readonly length?: number;
  readonly candidates: readonly {
    readonly algorithm: string;
    readonly confidence: string;
    readonly reason: string;
  }[];
};
export function classifyMemberName(raw: unknown): {
  readonly kind: string;
  readonly reason: string;
};
export const DONGLE_VENDORS: readonly unknown[];
export interface DongleFinding {
  readonly signal: string;
  readonly detail: string;
  readonly vendor?: string;
  readonly product?: string;
  readonly purpose?: string;
  readonly confidence: string;
}
export function matchDongleModule(moduleName: string): readonly {
  readonly vendor: string;
  readonly product: string;
  readonly signal: string;
  readonly detail: string;
  readonly confidence: string;
}[];
export function matchDongleApi(importName: string): readonly {
  readonly vendor: string;
  readonly product: string;
  readonly signal: string;
  readonly detail: string;
  readonly purpose: string;
  readonly confidence: string;
}[];
export function matchDongleSignals(options?: {
  readonly assemblyReferences?: readonly string[];
  readonly moduleRefs?: readonly string[];
  readonly pinvokeImports?: readonly string[];
  readonly keywordHits?: readonly { readonly keyword: string }[];
}): { readonly status: string; readonly findings: readonly DongleFinding[] };
export interface DotnetHashSample {
  readonly value: string;
  readonly kind: string;
  readonly candidates: readonly string[];
}
export function scanDecompiledDirectory(
  directory: string,
  options?: {
    readonly maxFiles?: number;
    readonly maxBytesPerFile?: number;
    readonly maxLiterals?: number;
  },
): Promise<{
  readonly files_scanned: number;
  readonly truncated: boolean;
  readonly hash_strings: {
    readonly literals_examined: number;
    readonly distinct_values: number;
    readonly by_algorithm: Record<string, number>;
    readonly samples: readonly DotnetHashSample[];
  };
  readonly member_names: {
    readonly hash_like: number;
    readonly minified: number;
    readonly readable: number;
    readonly samples: readonly string[];
  };
  readonly keyword_hits: readonly {
    readonly keyword: string;
    readonly files: readonly string[];
  }[];
}>;
