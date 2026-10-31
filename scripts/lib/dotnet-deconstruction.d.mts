export function findEmbeddedPortablePdb(
  image: Buffer,
  options?: { readonly maxBytes?: number },
): Buffer | null;
export function readPortablePdb(
  buffer: Buffer,
  options?: {
    readonly maxDocuments?: number;
    readonly maxEmbeddedSources?: number;
    readonly maxSourceBytes?: number;
  },
): {
  readonly documents: readonly {
    readonly row: number;
    readonly path: string | null;
    readonly language: string | null;
    readonly hash_algorithm: string | null;
    readonly hash: string | null;
  }[];
  readonly embedded_sources: readonly {
    readonly path: string;
    readonly bytes: Buffer;
  }[];
  readonly source_link: {
    readonly documents: Record<string, unknown>;
  } | null;
} | null;
export function recoverSymbols(
  assemblyPath: string,
  options?: { readonly maxEmbeddedSources?: number },
): Promise<{
  readonly kind: string | null;
  readonly documents: readonly {
    readonly row?: number;
    readonly path: string | null;
    readonly language: string | null;
    readonly hash_algorithm: string | null;
    readonly hash: string | null;
  }[];
  readonly embedded_sources: readonly {
    readonly path: string;
    readonly bytes: Buffer;
  }[];
  readonly source_link: {
    readonly documents: Record<string, unknown>;
  } | null;
  readonly path?: string;
  readonly error: string | null;
}>;
export function parseDepsJson(text: string): {
  readonly runtime_target: string | null;
  readonly target_frameworks: readonly string[];
  readonly packages: readonly {
    readonly id: string;
    readonly name: string;
    readonly version: string | null;
    readonly type: string;
    readonly serviceable: boolean;
  }[];
  readonly assets: readonly {
    readonly id: string;
    readonly name: string;
    readonly version: string | null;
    readonly runtime: readonly string[];
    readonly native: readonly string[];
    readonly resources: readonly string[];
  }[];
} | null;
export function parseRuntimeConfig(text: string): {
  readonly tfm: string | null;
  readonly framework: {
    readonly name: string | null;
    readonly version: string | null;
  } | null;
  readonly frameworks: readonly {
    readonly name: string | null;
    readonly version: string | null;
  }[];
  readonly roll_forward: string | null;
  readonly config_properties: Record<string, unknown>;
} | null;
export function collectDeployment(
  rootPath: string,
  options?: { readonly maxFiles?: number },
): Promise<
  readonly {
    readonly path: string;
    readonly kind: string;
    readonly parsed: NonNullable<ReturnType<typeof parseDepsJson>> | NonNullable<ReturnType<typeof parseRuntimeConfig>>;
  }[]
>;
export function deploymentSummary(
  manifests: readonly {
    readonly kind: string;
    readonly parsed: {
      readonly packages?: readonly {
        readonly id: string;
        readonly name: string;
        readonly version: string | null;
        readonly type: string;
        readonly serviceable: boolean;
      }[];
      readonly framework?: {
        readonly name: string | null;
        readonly version: string | null;
      } | null;
      readonly frameworks?: readonly {
        readonly name: string | null;
        readonly version: string | null;
      }[];
    };
  }[],
): {
  readonly package_count: number;
  readonly frameworks: readonly {
    readonly name: string | null;
    readonly version: string | null;
  }[];
  readonly packages: readonly {
    readonly id: string;
    readonly name: string;
    readonly version: string | null;
    readonly type: string;
    readonly serviceable: boolean;
  }[];
};
export function sourceOutputName(
  documentPath: string | null | undefined,
  row: number,
): string;
export interface ObfuscatorIndicator {
  readonly tool: string | null;
  readonly vendor: string | null;
  readonly signal: string;
  readonly detail: string;
  readonly confidence: string;
  readonly note: string;
}
export const OBFUSCATOR_SIGNALS: readonly {
  readonly tool: string;
  readonly vendor?: string;
  readonly markers: {
    readonly attributes?: readonly string[];
    readonly references?: readonly string[];
    readonly resources?: readonly string[];
    readonly pinvoke?: readonly string[];
    readonly strings?: readonly string[];
  };
  readonly note: string;
}[];
export const OBFUSCATION_TEXT_MARKERS: readonly string[];
export function matchObfuscatorSignals(options?: {
  readonly references?: readonly string[];
  readonly resourceNames?: readonly string[];
  readonly attributeNames?: readonly string[];
  readonly pinvokeModules?: readonly string[];
  readonly stringLiterals?: readonly string[];
  readonly memberNames?: {
    readonly hash_like?: number;
    readonly minified?: number;
    readonly readable?: number;
    readonly compiler_generated?: number;
  } | null;
  readonly textMarkers?: readonly string[];
}): { readonly status: string; readonly indicators: readonly ObfuscatorIndicator[] };
export function classifyRuntimeKind(options?: {
  readonly runtimeFamily?: string;
  readonly implementation?: string;
  readonly flagNames?: readonly string[];
  readonly readyToRun?: boolean;
  readonly entryPointKind?: string;
  readonly managedArchitecture?: string;
}): { readonly kind: string; readonly notes: readonly string[] };
export function summarizeSigning(options?: {
  readonly publicKey?: { readonly kind?: string; readonly token?: string | null } | null;
  readonly assemblyFlags?: number;
  readonly flagNames?: readonly string[];
  readonly certificates?: { readonly entries?: readonly unknown[] } | null;
}): {
  readonly strong_named: boolean;
  readonly public_key_token: string | null;
  readonly authenticode: {
    readonly present: boolean;
    readonly count: number;
    readonly signers: readonly string[];
  };
};
export function collectAdjacentFiles(
  rootPath: string,
  options?: { readonly maxFiles?: number },
): Promise<
  readonly {
    readonly path: string;
    readonly kind: string;
    readonly bytes: number | null;
  }[]
>;
