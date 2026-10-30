// SPDX-License-Identifier: LGPL-3.0-only
import { createHash } from "crypto";
import * as fs from "fs";
import { load } from "js-yaml";
import * as path from "path";
import { fileURLToPath } from "url";

export interface StorageVar {
  astId: number;
  contract: string;
  label: string;
  offset: number;
  slot: string;
  type: string;
}

export interface StorageType {
  base?: string;
  encoding: string;
  key?: string;
  label: string;
  members?: StorageVar[];
  numberOfBytes: string;
  value?: string;
}

export interface StorageLayout {
  storage: StorageVar[];
  types: Record<string, StorageType>;
}

export interface PersistedTypeDefinition {
  kind: "enum" | "struct";
  members: Array<{ name: string; type?: string }>;
}

export interface StorageNamespace {
  root: string;
  types: Record<string, PersistedTypeDefinition>;
}

export interface StorageMetadata {
  enums: Record<string, string[]>;
  namespaces: Record<string, StorageNamespace>;
}

export interface StandardCompilerInput {
  language: string;
  settings: {
    evmVersion?: string;
    optimizer?: { runs?: number };
    [key: string]: unknown;
  };
  sources: Record<string, { content: string }>;
}

export interface StorageSnapshot extends StorageLayout {
  _format: "interfold-storage-layout-v2";
  baseline: {
    buildInfoId: string;
    compiler: string;
    compilerInputSha256: string;
    dependencyLockSha256: string;
    evmVersion: string;
    optimizerRuns: number;
    sourceCommit: string;
    sourceSha256: string;
  };
  contract: string;
  metadata: StorageMetadata;
  source: string;
}

export const UPGRADEABLE_CONTRACTS = [
  { source: "contracts/Interfold.sol", contract: "Interfold" },
  {
    source: "contracts/registry/CiphernodeRegistryOwnable.sol",
    contract: "CiphernodeRegistryOwnable",
  },
  {
    source: "contracts/registry/BondingRegistry.sol",
    contract: "BondingRegistry",
  },
  {
    source: "contracts/E3RefundManager.sol",
    contract: "E3RefundManager",
  },
] as const;

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const PACKAGE_DIR = path.resolve(SCRIPT_DIR, "..");
export const WORKSPACE_DIR = path.resolve(PACKAGE_DIR, "../..");
export const SNAPSHOT_DIR = path.join(PACKAGE_DIR, "audits/storage-layouts");
export const COMPILER_INPUT_DIR = path.join(SNAPSHOT_DIR, "compiler-inputs");
export const BUILD_INFO_DIR = path.join(PACKAGE_DIR, "artifacts/build-info");

interface BuildInfoInput {
  id: string;
  input: StandardCompilerInput;
  solcLongVersion?: string;
  solcVersion: string;
}

interface AstNode {
  canonicalName?: string;
  documentation?: string | { text?: string };
  id?: number;
  linearizedBaseContracts?: number[];
  members?: AstNode[];
  name?: string;
  nodeType?: string;
  nodes?: AstNode[];
  referencedDeclaration?: number;
  typeDescriptions?: { typeString?: string };
  typeName?: AstNode;
  [key: string]: unknown;
}

interface BuildInfoOutput {
  output: {
    contracts: Record<
      string,
      Record<string, { storageLayout?: StorageLayout }>
    >;
    sources?: Record<string, { ast?: AstNode }>;
  };
}

export interface LocatedLayout {
  buildInfoId: string;
  compiler: string;
  compilerInput: StandardCompilerInput;
  evmVersion: string;
  layout: StorageLayout;
  metadata: StorageMetadata;
  optimizerRuns: number;
  sourceContent: string;
  sourceKey: string;
}

function pairedInputPath(outputPath: string): string {
  if (!outputPath.endsWith(".output.json")) {
    throw new Error(`Expected a *.output.json build-info path: ${outputPath}`);
  }
  return outputPath.replace(/\.output\.json$/, ".json");
}

function sourceKeys(source: string): string[] {
  return [source, `project/${source}`];
}

function walkAst(node: AstNode | undefined, visit: (node: AstNode) => void) {
  if (!node) return;
  visit(node);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child === "object") {
          walkAst(child as AstNode, visit);
        }
      }
    } else if (value && typeof value === "object") {
      walkAst(value as AstNode, visit);
    }
  }
}

function documentationText(node: AstNode): string {
  if (typeof node.documentation === "string") return node.documentation;
  return node.documentation?.text ?? "";
}

function sortedRecord<T>(entries: Array<[string, T]>): Record<string, T> {
  return Object.fromEntries(
    entries.sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function persistedEnumName(type: StorageType): string | undefined {
  if (type.encoding !== "inplace" || !/^enum [\w.$]+$/.test(type.label)) {
    return undefined;
  }
  return type.label.slice("enum ".length);
}

export function pnpmPackageKeys(lockfile: string): Set<string> {
  const parsed = load(lockfile);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("pnpm-lock.yaml must contain a YAML mapping.");
  }

  const packages = (parsed as { packages?: unknown }).packages;
  if (!packages || typeof packages !== "object" || Array.isArray(packages)) {
    throw new Error("pnpm-lock.yaml must contain a packages mapping.");
  }

  return new Set(Object.keys(packages as Record<string, unknown>));
}

function collectStorageMetadata(
  output: BuildInfoOutput,
  sourceKey: string,
  contract: string,
  layout: StorageLayout,
): StorageMetadata {
  const nodesById = new Map<number, AstNode>();
  const enumMembers = new Map<string, string[]>();
  const contractNodes = new Map<number, AstNode>();

  for (const source of Object.values(output.output.sources ?? {})) {
    walkAst(source.ast, (node) => {
      if (node.id !== undefined) nodesById.set(node.id, node);
      if (node.nodeType === "ContractDefinition" && node.id !== undefined) {
        contractNodes.set(node.id, node);
      }
      if (node.nodeType === "EnumDefinition" && node.canonicalName) {
        enumMembers.set(
          node.canonicalName,
          (node.members ?? []).map((member) => member.name ?? ""),
        );
      }
    });
  }

  const persistedEnums: Array<[string, string[]]> = [];
  for (const type of Object.values(layout.types)) {
    const name = persistedEnumName(type);
    if (!name) continue;
    const members = enumMembers.get(name);
    if (!members) {
      throw new Error(`Persisted enum ${name} is missing from compiler AST.`);
    }
    persistedEnums.push([name, members]);
  }

  const targetSource = output.output.sources?.[sourceKey]?.ast;
  let target: AstNode | undefined;
  for (const node of targetSource?.nodes ?? []) {
    if (node.nodeType === "ContractDefinition" && node.name === contract) {
      target = node;
      break;
    }
  }
  if (!target) {
    throw new Error(`${sourceKey}:${contract} is missing from compiler AST.`);
  }

  const namespaces: Array<[string, StorageNamespace]> = [];
  for (const contractId of target.linearizedBaseContracts ?? []) {
    const base = contractNodes.get(contractId);
    for (const node of base?.nodes ?? []) {
      if (node.nodeType !== "StructDefinition" || !node.canonicalName) continue;
      const match = documentationText(node).match(
        /@custom:storage-location\s+(erc7201:[^\s]+)/,
      );
      if (!match?.[1]) continue;

      const definitions = new Map<string, PersistedTypeDefinition>();
      const addDefinition = (definition: AstNode): void => {
        if (
          !definition.canonicalName ||
          definitions.has(definition.canonicalName)
        )
          return;
        if (definition.nodeType === "EnumDefinition") {
          definitions.set(definition.canonicalName, {
            kind: "enum",
            members: (definition.members ?? []).map((member) => ({
              name: member.name ?? "",
            })),
          });
          return;
        }
        if (definition.nodeType !== "StructDefinition") return;

        definitions.set(definition.canonicalName, {
          kind: "struct",
          members: (definition.members ?? []).map((member) => ({
            name: member.name ?? "",
            type: member.typeDescriptions?.typeString ?? "unknown",
          })),
        });
        for (const member of definition.members ?? []) {
          walkAst(member.typeName, (typeNode) => {
            if (typeNode.referencedDeclaration === undefined) return;
            const referenced = nodesById.get(typeNode.referencedDeclaration);
            if (referenced) addDefinition(referenced);
          });
        }
      };

      addDefinition(node);
      namespaces.push([
        match[1],
        {
          root: node.canonicalName,
          types: sortedRecord([...definitions]),
        },
      ]);
    }
  }

  return {
    enums: sortedRecord(persistedEnums),
    namespaces: sortedRecord(namespaces),
  };
}

function parseNpmSourceKey(
  sourceKey: string,
): { packageName: string; relativePath: string; version: string } | undefined {
  const match = sourceKey.match(/^npm\/(@[^/]+\/[^@/]+|[^/@]+)@([^/]+)\/(.+)$/);
  if (!match?.[1] || !match[2] || !match[3]) return undefined;
  return {
    packageName: match[1],
    version: match[2],
    relativePath: match[3],
  };
}

export function sourceContentFromWorkingTree(
  sourceKey: string,
): string | undefined {
  if (sourceKey.startsWith("project/")) {
    const sourcePath = path.resolve(
      PACKAGE_DIR,
      sourceKey.slice("project/".length),
    );
    if (!sourcePath.startsWith(`${PACKAGE_DIR}${path.sep}`)) return undefined;
    return fs.existsSync(sourcePath)
      ? fs.readFileSync(sourcePath, "utf8")
      : undefined;
  }

  const npmSource = parseNpmSourceKey(sourceKey);
  if (!npmSource) return undefined;
  const packageDirs = [
    path.join(PACKAGE_DIR, "node_modules", npmSource.packageName),
  ];
  const pnpmStore = path.join(WORKSPACE_DIR, "node_modules", ".pnpm");
  if (fs.existsSync(pnpmStore)) {
    const packagePrefix = `${npmSource.packageName.replace("/", "+")}@${
      npmSource.version
    }`;
    for (const entry of fs.readdirSync(pnpmStore).sort()) {
      if (entry === packagePrefix || entry.startsWith(`${packagePrefix}_`)) {
        packageDirs.push(
          path.join(pnpmStore, entry, "node_modules", npmSource.packageName),
        );
      }
    }
  }

  for (const packageDir of packageDirs) {
    const packageJsonPath = path.join(packageDir, "package.json");
    const sourcePath = path.resolve(packageDir, npmSource.relativePath);
    if (!sourcePath.startsWith(`${packageDir}${path.sep}`)) continue;
    if (!fs.existsSync(packageJsonPath) || !fs.existsSync(sourcePath)) continue;
    const packageVersion = (
      JSON.parse(fs.readFileSync(packageJsonPath, "utf8")) as {
        version?: string;
      }
    ).version;
    if (packageVersion !== npmSource.version) continue;
    return fs.readFileSync(sourcePath, "utf8");
  }
  return undefined;
}

export function compilerInputMatchesWorkingTree(
  input: StandardCompilerInput,
): boolean {
  return Object.entries(input.sources).every(
    ([sourceKey, source]) =>
      sourceContentFromWorkingTree(sourceKey) === source.content,
  );
}

export function compilerInputSha256(input: StandardCompilerInput): string {
  return sha256(JSON.stringify(input));
}

export function compilerInputPath(inputSha256: string): string {
  return path.join(COMPILER_INPUT_DIR, `${inputSha256}.json`);
}

export function loadLayoutFromBuildInfo(
  outputPath: string,
  source: string,
  contract: string,
): LocatedLayout {
  const inputPath = pairedInputPath(outputPath);
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Paired build-info input is missing: ${inputPath}`);
  }

  const input = JSON.parse(
    fs.readFileSync(inputPath, "utf8"),
  ) as BuildInfoInput;
  const output = JSON.parse(
    fs.readFileSync(outputPath, "utf8"),
  ) as BuildInfoOutput;

  for (const sourceKey of sourceKeys(source)) {
    const layout =
      output.output.contracts?.[sourceKey]?.[contract]?.storageLayout;
    const sourceContent = input.input.sources?.[sourceKey]?.content;
    if (layout && sourceContent !== undefined) {
      return {
        buildInfoId: input.id,
        compiler: input.solcLongVersion ?? input.solcVersion,
        compilerInput: input.input,
        evmVersion: input.input.settings.evmVersion ?? "unknown",
        layout,
        metadata: collectStorageMetadata(output, sourceKey, contract, layout),
        optimizerRuns: input.input.settings.optimizer?.runs ?? 0,
        sourceContent,
        sourceKey,
      };
    }
  }

  throw new Error(`${source}:${contract} is not present in ${outputPath}.`);
}

export function findCurrentLayout(
  source: string,
  contract: string,
): LocatedLayout {
  if (!fs.existsSync(BUILD_INFO_DIR)) {
    throw new Error(`No build-info directory. Run Hardhat compile first.`);
  }

  const currentSource = fs.readFileSync(path.join(PACKAGE_DIR, source), "utf8");
  const outputs = fs
    .readdirSync(BUILD_INFO_DIR)
    .filter((name) => name.endsWith(".output.json"))
    .map((name) => path.join(BUILD_INFO_DIR, name))
    .sort(
      (left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs,
    );

  for (const outputPath of outputs) {
    try {
      const located = loadLayoutFromBuildInfo(outputPath, source, contract);
      if (
        located.sourceContent === currentSource &&
        compilerInputMatchesWorkingTree(located.compilerInput)
      ) {
        return located;
      }
    } catch {
      // Incremental Hardhat build-info files contain only their compilation job.
    }
  }

  throw new Error(
    `No build-info storage layout matches the current ${source}:${contract}. ` +
      `Run \`pnpm compile:contracts --force\` and retry.`,
  );
}

export function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function compareType(
  contract: string,
  pathLabel: string,
  previous: StorageLayout,
  previousTypeId: string,
  current: StorageLayout,
  currentTypeId: string,
  errors: string[],
  visited: Set<string>,
  requiresStableArrayStride = false,
): void {
  const visitKey = `${previousTypeId}:${currentTypeId}:${requiresStableArrayStride}`;
  if (visited.has(visitKey)) return;
  visited.add(visitKey);

  const before = previous.types[previousTypeId];
  const after = current.types[currentTypeId];
  if (!before || !after) {
    errors.push(
      `${contract}: ${pathLabel} has unresolved storage type metadata.`,
    );
    return;
  }
  if (before.encoding !== after.encoding || before.label !== after.label) {
    errors.push(
      `${contract}: ${pathLabel} type changed from ${before.label}/${before.encoding} ` +
        `to ${after.label}/${after.encoding}.`,
    );
    return;
  }
  const sizeChanged = before.numberOfBytes !== after.numberOfBytes;
  if (requiresStableArrayStride && sizeChanged) {
    errors.push(
      `${contract}: ${pathLabel} dynamic-array element stride changed from ` +
        `${before.numberOfBytes} to ${after.numberOfBytes} bytes.`,
    );
  }

  for (const key of ["base", "key", "value"] as const) {
    const beforeChild = before[key];
    const afterChild = after[key];
    if ((beforeChild === undefined) !== (afterChild === undefined)) {
      errors.push(`${contract}: ${pathLabel} ${key} type changed.`);
    } else if (beforeChild && afterChild) {
      compareType(
        contract,
        `${pathLabel}.${key}`,
        previous,
        beforeChild,
        current,
        afterChild,
        errors,
        visited,
        before.encoding === "dynamic_array" && key === "base",
      );
    }
  }

  if (before.members) {
    if (!after.members) {
      errors.push(
        `${contract}: ${pathLabel} no longer exposes struct members.`,
      );
      return;
    }
    for (const oldMember of before.members) {
      const newMember = after.members.find(
        (candidate) => candidate.label === oldMember.label,
      );
      if (!newMember) {
        errors.push(
          `${contract}: ${pathLabel}.${oldMember.label} was removed or renamed.`,
        );
        continue;
      }
      if (
        oldMember.slot !== newMember.slot ||
        oldMember.offset !== newMember.offset
      ) {
        errors.push(
          `${contract}: ${pathLabel}.${oldMember.label} moved from ` +
            `${oldMember.slot}+${oldMember.offset} to ` +
            `${newMember.slot}+${newMember.offset}.`,
        );
      }
      compareType(
        contract,
        `${pathLabel}.${oldMember.label}`,
        previous,
        oldMember.type,
        current,
        newMember.type,
        errors,
        visited,
      );
    }
  } else if (sizeChanged && !requiresStableArrayStride) {
    errors.push(
      `${contract}: ${pathLabel} size changed from ${before.numberOfBytes} ` +
        `to ${after.numberOfBytes} bytes.`,
    );
  }
}

function compareMemberDefinitions(
  contract: string,
  pathLabel: string,
  before: PersistedTypeDefinition,
  after: PersistedTypeDefinition,
  allowAppend: boolean,
  errors: string[],
): void {
  if (before.kind !== after.kind) {
    errors.push(`${contract}: ${pathLabel} changed definition kind.`);
    return;
  }
  if (
    after.members.length < before.members.length ||
    (!allowAppend && after.members.length !== before.members.length)
  ) {
    errors.push(`${contract}: ${pathLabel} member list changed.`);
    return;
  }
  for (let index = 0; index < before.members.length; index++) {
    const oldMember = before.members[index];
    const newMember = after.members[index];
    if (
      !oldMember ||
      !newMember ||
      oldMember.name !== newMember.name ||
      oldMember.type !== newMember.type
    ) {
      errors.push(`${contract}: ${pathLabel} member order or type changed.`);
      return;
    }
  }
}

function compareMetadata(
  contract: string,
  previous: StorageMetadata,
  current: StorageMetadata,
): string[] {
  const errors: string[] = [];

  for (const [name, oldMembers] of Object.entries(previous.enums)) {
    const newMembers = current.enums[name];
    // Appending keeps every stored value's meaning; rolling back past it is a rollout decision.
    if (
      !newMembers ||
      oldMembers.some((member, index) => member !== newMembers[index])
    ) {
      errors.push(`${contract}: persisted enum ${name} member order changed.`);
    }
  }

  for (const [namespaceId, oldNamespace] of Object.entries(
    previous.namespaces,
  )) {
    const newNamespace = current.namespaces[namespaceId];
    if (!newNamespace || oldNamespace.root !== newNamespace.root) {
      errors.push(
        `${contract}: storage namespace ${namespaceId} was removed or renamed.`,
      );
      continue;
    }
    for (const [name, oldDefinition] of Object.entries(oldNamespace.types)) {
      const newDefinition = newNamespace.types[name];
      if (!newDefinition) {
        errors.push(
          `${contract}: storage namespace ${namespaceId} type ${name} was removed.`,
        );
        continue;
      }
      compareMemberDefinitions(
        contract,
        `storage namespace ${namespaceId} type ${name}`,
        oldDefinition,
        newDefinition,
        name === oldNamespace.root && oldDefinition.kind === "struct",
        errors,
      );
    }
  }

  return errors;
}

function gapEnd(layout: StorageLayout, gap: StorageVar): bigint {
  const bytes = BigInt(layout.types[gap.type].numberOfBytes);
  return BigInt(gap.slot) + bytes / 32n;
}

export function diffLayouts(
  contract: string,
  previous: StorageLayout,
  current: StorageLayout,
  previousMetadata: StorageMetadata = { enums: {}, namespaces: {} },
  currentMetadata: StorageMetadata = { enums: {}, namespaces: {} },
): string[] {
  const errors = compareMetadata(contract, previousMetadata, currentMetadata);
  const previousGap = previous.storage.find((entry) => entry.label === "__gap");
  const currentGap = current.storage.find((entry) => entry.label === "__gap");

  for (const oldEntry of previous.storage) {
    if (oldEntry.label === "__gap") continue;
    const newEntry = current.storage.find(
      (candidate) => candidate.label === oldEntry.label,
    );
    if (!newEntry) {
      errors.push(
        `${contract}: state variable \`${oldEntry.label}\` was removed or renamed.`,
      );
      continue;
    }
    if (
      oldEntry.slot !== newEntry.slot ||
      oldEntry.offset !== newEntry.offset
    ) {
      errors.push(
        `${contract}: \`${oldEntry.label}\` moved from ${oldEntry.slot}+${oldEntry.offset} ` +
          `to ${newEntry.slot}+${newEntry.offset}.`,
      );
    }
    compareType(
      contract,
      oldEntry.label,
      previous,
      oldEntry.type,
      current,
      newEntry.type,
      errors,
      new Set(),
    );
  }

  if (previousGap) {
    if (!currentGap) {
      errors.push(`${contract}: reserved __gap was removed.`);
      return errors;
    }
    if (gapEnd(previous, previousGap) !== gapEnd(current, currentGap)) {
      errors.push(
        `${contract}: reserved __gap must shrink from the front without changing its end slot.`,
      );
    }
    const oldGapStart = BigInt(previousGap.slot);
    const newGapStart = BigInt(currentGap.slot);
    if (newGapStart < oldGapStart) {
      errors.push(`${contract}: reserved __gap moved backward.`);
    }
    const previousLabels = new Set(
      previous.storage.map((entry) => entry.label),
    );
    for (const entry of current.storage) {
      if (previousLabels.has(entry.label) || entry.label === "__gap") continue;
      const slot = BigInt(entry.slot);
      if (slot < oldGapStart || slot >= newGapStart) {
        errors.push(
          `${contract}: new variable \`${entry.label}\` at slot ${entry.slot} ` +
            `does not consume the front of the reserved gap.`,
        );
      }
    }
  }

  return errors;
}
