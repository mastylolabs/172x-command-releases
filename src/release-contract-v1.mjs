import { createHash } from 'node:crypto'
import { lstat, readFile, readdir } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'

const SHA256 = /^[a-f0-9]{64}$/u
const GIT_SHA1 = /^[a-f0-9]{40}$/u
const CANONICAL_RC = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-rc\.(0|[1-9]\d*)$/u
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/u
const SAFE_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/u
const EXPECTED_REPOSITORY = 'mastylolabs/172x-command-releases'
const EXPECTED_SOURCE_REPOSITORY = 'mastylolabs/172x-command'
const EXPECTED_MARKETPLACE_REPOSITORY = 'mastylolabs/172x-command-marketplace'
const EXPECTED_VERSION = '0.2.0-rc.1'
const EXPECTED_TAG = `command-v${EXPECTED_VERSION}`
const EXPECTED_TARGET = 'universal-apple-darwin'
const EXPECTED_NAMES = Object.freeze({
  download: `172X-Command_${EXPECTED_VERSION}_universal.dmg`,
  provenance: `172X-Command_${EXPECTED_VERSION}_provenance.intoto.json`,
  sbom: `172X-Command_${EXPECTED_VERSION}_sbom.cdx.json`,
})
const CYCLONEDX_COMPONENT_TYPES = new Set([
  'application', 'container', 'cryptographic-asset', 'data', 'device', 'device-driver', 'file',
  'firmware', 'framework', 'library', 'machine-learning-model', 'operating-system', 'platform',
])

function object(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value, keys, label) {
  if (!object(value) || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    throw new Error(`${label}: unexpected or missing fields`)
  }
}

function string(value, label, maximum = 1000) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new Error(`${label}: expected a non-empty bounded string`)
  }
  return value
}

function timestamp(value, label) {
  if (typeof value !== 'string') throw new Error(`${label}: expected a canonical RFC3339 UTC timestamp`)
  const match = RFC3339.exec(value)
  if (!match) throw new Error(`${label}: expected a canonical RFC3339 UTC timestamp`)
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction] = match
  const year = Number(yearText)
  const month = Number(monthText)
  const day = Number(dayText)
  const hour = Number(hourText)
  const minute = Number(minuteText)
  const second = Number(secondText)
  const millisecond = Number(fraction ?? '000')
  if (year === 0 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) {
    throw new Error(`${label}: expected a real RFC3339 calendar timestamp`)
  }
  const parsed = new Date(0)
  parsed.setUTCFullYear(year, month - 1, day)
  parsed.setUTCHours(hour, minute, second, millisecond)
  const canonical = `${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondText}.${fraction ?? '000'}Z`
  if (parsed.toISOString() !== canonical) throw new Error(`${label}: expected a real RFC3339 calendar timestamp`)
}

function sha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new Error(`${label}: expected lowercase SHA-256`)
}

function gitSha(value, label) {
  if (typeof value !== 'string' || !GIT_SHA1.test(value)) throw new Error(`${label}: expected a full Git SHA-1`)
}

function validateArtifact(value, label, expectedContentType, expectedFileName) {
  exact(value, ['fileName', 'byteLength', 'sha256', 'contentType'], label)
  if (typeof value.fileName !== 'string' || !SAFE_FILE.test(value.fileName) || value.fileName !== expectedFileName) {
    throw new Error(`${label}.fileName: does not match the canonical RC artifact name`)
  }
  if (!Number.isSafeInteger(value.byteLength) || value.byteLength <= 0) throw new Error(`${label}.byteLength: expected a positive safe integer`)
  sha256(value.sha256, `${label}.sha256`)
  if (value.contentType !== expectedContentType) throw new Error(`${label}.contentType: unexpected media type`)
  return value
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted)
  if (!object(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]))
}

function same(value, expected, label) {
  if (JSON.stringify(sorted(value)) !== JSON.stringify(sorted(expected))) {
    throw new Error(`${label}: shape or release identity differs from the approved contract`)
  }
}

export function canonicalJson(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`
}

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function validateReleaseRecord(value) {
  exact(value, [
    'schemaVersion', 'recordType', 'createdAt', 'distribution', 'product', 'source', 'marketplace',
    'build', 'apple', 'download', 'provenance', 'sbom', 'hostInventory', 'recovery',
  ], 'release record')
  if (value.schemaVersion !== 1 || value.recordType !== '172x-command-release') throw new Error('release record: unsupported schema or type')
  timestamp(value.createdAt, 'createdAt')

  exact(value.distribution, ['repository', 'tag', 'recordAssetName', 'contractCommitSha'], 'distribution')
  if (
    value.distribution.repository !== EXPECTED_REPOSITORY || value.distribution.tag !== EXPECTED_TAG ||
    value.distribution.recordAssetName !== 'release-record-v1.json'
  ) throw new Error('distribution: unexpected repository, tag, or record asset')
  gitSha(value.distribution.contractCommitSha, 'distribution.contractCommitSha')

  exact(value.product, ['name', 'version', 'channel', 'bundleIdentifier', 'minimumMacOS', 'architectures', 'packageFormat'], 'product')
  if (
    value.product.name !== '172X Command' || value.product.version !== EXPECTED_VERSION ||
    !CANONICAL_RC.test(value.product.version) || value.product.channel !== 'rc' ||
    value.product.bundleIdentifier !== 'ai.172x.command' || value.product.minimumMacOS !== '13.0' ||
    JSON.stringify(value.product.architectures) !== JSON.stringify(['arm64', 'x86_64']) ||
    value.product.packageFormat !== 'universal-dmg'
  ) throw new Error('product: identity differs from the exact approved macOS RC version')

  exact(value.source, ['repository', 'commitSha', 'treeSha', 'tag', 'dirty', 'signedTag'], 'source')
  if (
    value.source.repository !== EXPECTED_SOURCE_REPOSITORY || value.source.tag !== EXPECTED_TAG ||
    value.source.dirty !== false || value.source.signedTag !== true
  ) throw new Error('source: repository, exact signed tag, or clean-tree evidence is invalid')
  gitSha(value.source.commitSha, 'source.commitSha')
  gitSha(value.source.treeSha, 'source.treeSha')

  exact(value.marketplace, ['repository', 'commitSha', 'contractVersion', 'catalogRevision', 'catalogSha256'], 'marketplace')
  if (value.marketplace.repository !== EXPECTED_MARKETPLACE_REPOSITORY || value.marketplace.contractVersion !== 'v1'
    || value.marketplace.commitSha !== '7a1faa24d291db69f2c6fb4ab2669ba0811ad83a'
    || value.marketplace.catalogRevision !== 'w1-private-2026.08.27.1'
    || value.marketplace.catalogSha256 !== '0bd9ca38ac2e37be8b3b86affb1eebc386e7a2c7ef4ee884f54787d4429fc344') {
    throw new Error('marketplace: repository or contract is unsupported')
  }
  gitSha(value.marketplace.commitSha, 'marketplace.commitSha')
  string(value.marketplace.catalogRevision, 'marketplace.catalogRevision')
  sha256(value.marketplace.catalogSha256, 'marketplace.catalogSha256')

  exact(value.build, ['workflowRepository', 'workflowPath', 'workflowCommitSha', 'runId', 'runAttempt', 'runnerImage', 'tools'], 'build')
  if (value.build.workflowRepository !== EXPECTED_SOURCE_REPOSITORY || value.build.workflowPath !== '.github/workflows/release-candidate.yml') {
    throw new Error('build: unexpected workflow identity')
  }
  gitSha(value.build.workflowCommitSha, 'build.workflowCommitSha')
  if (value.build.workflowCommitSha !== value.source.commitSha) throw new Error('build: workflow commit differs from signed source commit')
  string(value.build.runId, 'build.runId', 32)
  if (!/^\d+$/u.test(value.build.runId)) throw new Error('build.runId: expected a numeric GitHub Actions run identifier')
  if (!Number.isSafeInteger(value.build.runAttempt) || value.build.runAttempt < 1) throw new Error('build.runAttempt: invalid')
  if (value.build.runnerImage !== 'macos-15') throw new Error('build.runnerImage: unsupported')
  exact(value.build.tools, ['rustc', 'cargo', 'node', 'npm', 'tauri'], 'build.tools')
  for (const [key, tool] of Object.entries(value.build.tools)) string(tool, `build.tools.${key}`, 100)

  exact(value.apple, ['teamId', 'signingIdentity', 'certificateSha256', 'notarizationStatus', 'ticketStapled', 'notarizationSubmissions', 'gatekeeper'], 'apple')
  string(value.apple.teamId, 'apple.teamId', 20)
  string(value.apple.signingIdentity, 'apple.signingIdentity')
  sha256(value.apple.certificateSha256, 'apple.certificateSha256')
  if (value.apple.notarizationStatus !== 'accepted' || value.apple.ticketStapled !== true) throw new Error('apple: notarization or stapling evidence is incomplete')
  if (!Array.isArray(value.apple.notarizationSubmissions) || value.apple.notarizationSubmissions.length !== 2) throw new Error('apple.notarizationSubmissions: application and installer evidence required')
  const roles = []
  for (const [index, submission] of value.apple.notarizationSubmissions.entries()) {
    exact(submission, ['artifactRole', 'submissionId', 'status'], `apple.notarizationSubmissions[${index}]`)
    if (!['application', 'installer'].includes(submission.artifactRole) || submission.status !== 'accepted') throw new Error('apple.notarizationSubmissions: invalid role or status')
    string(submission.submissionId, `apple.notarizationSubmissions[${index}].submissionId`)
    roles.push(submission.artifactRole)
  }
  if (new Set(roles).size !== 2) throw new Error('apple.notarizationSubmissions: duplicate role')
  exact(value.apple.gatekeeper, ['application', 'installer'], 'apple.gatekeeper')
  if (value.apple.gatekeeper.application !== 'accepted' || value.apple.gatekeeper.installer !== 'accepted') throw new Error('apple.gatekeeper: both assessments must pass')

  validateArtifact(value.download, 'download', 'application/x-apple-diskimage', EXPECTED_NAMES.download)
  validateArtifact(value.provenance, 'provenance', 'application/vnd.in-toto+json', EXPECTED_NAMES.provenance)
  validateArtifact(value.sbom, 'sbom', 'application/vnd.cyclonedx+json', EXPECTED_NAMES.sbom)

  exact(value.hostInventory, ['schemaVersion', 'records'], 'hostInventory')
  if (value.hostInventory.schemaVersion !== 1 || !Array.isArray(value.hostInventory.records) || value.hostInventory.records.length > 500) throw new Error('hostInventory: invalid')
  for (const [index, item] of value.hostInventory.records.entries()) {
    exact(item, ['packageId', 'packageVersion', 'deliveryMode', 'manifestSha256', 'sourceTreeSha256', 'hostBinding'], `hostInventory.records[${index}]`)
    string(item.packageId, `hostInventory.records[${index}].packageId`)
    string(item.packageVersion, `hostInventory.records[${index}].packageVersion`)
    if (item.deliveryMode !== 'host-bundled-source') throw new Error('hostInventory: downloaded executable delivery is forbidden')
    sha256(item.manifestSha256, `hostInventory.records[${index}].manifestSha256`)
    sha256(item.sourceTreeSha256, `hostInventory.records[${index}].sourceTreeSha256`)
    string(item.hostBinding, `hostInventory.records[${index}].hostBinding`)
  }

  exact(value.recovery, ['draftOnly', 'publicPromotion', 'rollback', 'artifactPolicy'], 'recovery')
  if (
    value.recovery.draftOnly !== true || value.recovery.publicPromotion !== 'separate-manual-action' ||
    value.recovery.rollback !== 'publish-prior-verified-release' || value.recovery.artifactPolicy !== 'replace-draft-as-complete-verified-set'
  ) throw new Error('recovery: unsafe publication or rollback policy')

  const artifacts = [value.download, value.provenance, value.sbom]
  if (new Set(artifacts.map((artifact) => artifact.fileName)).size !== artifacts.length) throw new Error('artifacts: duplicate file names')
  return value
}

function expectedSlsaProvenance(record) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    predicate: {
      buildDefinition: {
        buildType: `https://github.com/${record.build.workflowRepository}/${record.build.workflowPath}@${record.build.workflowCommitSha}`,
        externalParameters: {
          artifactName: record.download.fileName,
          channel: 'rc',
          contractCommitSha: record.distribution.contractCommitSha,
          runnerImage: record.build.runnerImage,
          sourceCommitSha: record.source.commitSha,
          sourceRepository: record.source.repository,
          sourceTag: record.source.tag,
          target: EXPECTED_TARGET,
          version: EXPECTED_VERSION,
          workflowCommitSha: record.build.workflowCommitSha,
          workflowPath: record.build.workflowPath,
          workflowRepository: record.build.workflowRepository,
        },
        internalParameters: {},
        resolvedDependencies: [
          {
            digest: { gitCommit: record.source.commitSha, gitTree: record.source.treeSha },
            uri: `git+https://github.com/${record.source.repository}@refs/tags/${record.source.tag}`,
          },
          {
            digest: { gitCommit: record.build.workflowCommitSha },
            uri: `git+https://github.com/${record.build.workflowRepository}@${record.build.workflowCommitSha}#path=${record.build.workflowPath}`,
          },
          {
            digest: { gitCommit: record.distribution.contractCommitSha },
            uri: `git+https://github.com/${record.distribution.repository}@${record.distribution.contractCommitSha}#path=${record.distribution.recordAssetName}`,
          },
          {
            digest: { gitCommit: record.marketplace.commitSha, sha256: record.marketplace.catalogSha256 },
            uri: `git+https://github.com/${record.marketplace.repository}@${record.marketplace.commitSha}#catalog=${record.marketplace.catalogRevision}`,
          },
        ],
      },
      runDetails: {
        builder: {
          id: 'https://github.com/actions/runner',
        },
        byproducts: [],
        metadata: {
          invocationId: `https://github.com/${record.build.workflowRepository}/actions/runs/${record.build.runId}/attempts/${record.build.runAttempt}`,
        },
      },
    },
    predicateType: 'https://slsa.dev/provenance/v1',
    subject: [
      { digest: { sha256: record.download.sha256 }, name: record.download.fileName },
      { digest: { sha256: record.sbom.sha256 }, name: record.sbom.fileName },
    ],
  }
}

export function validateSlsaProvenance(provenance, record) {
  same(provenance, expectedSlsaProvenance(record), 'SLSA provenance v1')
}

export function validateCycloneDxSbom(sbom, record) {
  exact(sbom, ['bomFormat', 'specVersion', 'version', 'metadata', 'components', 'dependencies'], 'CycloneDX SBOM')
  if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.6' || sbom.version !== 1) {
    throw new Error('CycloneDX SBOM: unsupported format or version')
  }
  exact(sbom.metadata, ['component'], 'CycloneDX SBOM metadata')
  const rootRef = `pkg:generic/172x-command@${EXPECTED_VERSION}`
  same(sbom.metadata.component, {
    'bom-ref': rootRef,
    name: '172X Command',
    type: 'application',
    version: record.product.version,
  }, 'CycloneDX SBOM root component')

  if (!Array.isArray(sbom.components) || sbom.components.length === 0 || sbom.components.length > 500) {
    throw new Error('CycloneDX SBOM components: expected a bounded non-empty component inventory')
  }
  const componentRefs = []
  for (const [index, component] of sbom.components.entries()) {
    exact(component, ['bom-ref', 'name', 'type', 'version'], `CycloneDX SBOM components[${index}]`)
    const ref = string(component['bom-ref'], `CycloneDX SBOM components[${index}].bom-ref`, 500)
    string(component.name, `CycloneDX SBOM components[${index}].name`)
    string(component.version, `CycloneDX SBOM components[${index}].version`)
    if (!CYCLONEDX_COMPONENT_TYPES.has(component.type)) throw new Error(`CycloneDX SBOM components[${index}].type: unsupported`)
    if (ref === rootRef) throw new Error('CycloneDX SBOM components: root component must not be duplicated')
    componentRefs.push(ref)
  }
  if (new Set(componentRefs).size !== componentRefs.length) throw new Error('CycloneDX SBOM components: duplicate bom-ref')

  if (!Array.isArray(sbom.dependencies) || sbom.dependencies.length !== componentRefs.length + 1) {
    throw new Error('CycloneDX SBOM dependencies: each component and root needs one dependency entry')
  }
  const allRefs = new Set([rootRef, ...componentRefs])
  const edges = new Map()
  for (const [index, dependency] of sbom.dependencies.entries()) {
    exact(dependency, ['ref', 'dependsOn'], `CycloneDX SBOM dependencies[${index}]`)
    const ref = string(dependency.ref, `CycloneDX SBOM dependencies[${index}].ref`, 500)
    if (!allRefs.has(ref) || edges.has(ref) || !Array.isArray(dependency.dependsOn)) {
      throw new Error('CycloneDX SBOM dependencies: duplicate, unknown, or malformed ref')
    }
    if (new Set(dependency.dependsOn).size !== dependency.dependsOn.length) {
      throw new Error('CycloneDX SBOM dependencies: duplicate dependsOn ref')
    }
    for (const target of dependency.dependsOn) {
      if (typeof target !== 'string' || !allRefs.has(target) || target === rootRef || target === ref) {
        throw new Error('CycloneDX SBOM dependencies: dangling, root, or self dependency')
      }
    }
    edges.set(ref, dependency.dependsOn)
  }
  if (edges.size !== allRefs.size || [...allRefs].some((ref) => !edges.has(ref))) {
    throw new Error('CycloneDX SBOM dependencies: dependency refs are incomplete')
  }
  const reachable = new Set([rootRef])
  const pending = [rootRef]
  while (pending.length > 0) {
    const ref = pending.pop()
    for (const target of edges.get(ref) ?? []) {
      if (!reachable.has(target)) {
        reachable.add(target)
        pending.push(target)
      }
    }
  }
  if (reachable.size !== allRefs.size) throw new Error('CycloneDX SBOM dependencies: every component must be reachable from the root')
}

export async function validateReleaseDirectory(directory) {
  const root = resolve(directory)
  const actualNames = (await readdir(root)).sort()
  const metadataByName = new Map()
  for (const name of actualNames) {
    const metadata = await lstat(join(root, name))
    if (!metadata.isFile()) throw new Error(`release directory: top-level entry must be a regular file: ${name}`)
    metadataByName.set(name, metadata)
  }

  const recordPath = join(root, 'release-record-v1.json')
  const recordBytes = await readFile(recordPath)
  let record
  try {
    record = validateReleaseRecord(JSON.parse(recordBytes.toString('utf8')))
  } catch (error) {
    throw new Error(`release-record-v1.json: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (recordBytes.toString('utf8') !== canonicalJson(record)) throw new Error('release-record-v1.json: JSON is not canonical')

  const references = [record.download, record.provenance, record.sbom]
  const expectedNames = ['SHA256SUMS', 'release-record-v1.json', ...references.map((artifact) => artifact.fileName)].sort()
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) throw new Error('release directory: expected one complete five-file artifact set with no extra or missing files')

  for (const artifact of references) {
    if (basename(artifact.fileName) !== artifact.fileName) throw new Error(`artifact path is not a safe base name: ${artifact.fileName}`)
    const bytes = await readFile(join(root, artifact.fileName))
    const metadata = metadataByName.get(artifact.fileName)
    if (!metadata?.isFile() || metadata.size !== artifact.byteLength || digest(bytes) !== artifact.sha256) {
      throw new Error(`artifact bytes differ from release record: ${artifact.fileName}`)
    }
  }

  let provenance
  let sbom
  try {
    provenance = JSON.parse(await readFile(join(root, record.provenance.fileName), 'utf8'))
    sbom = JSON.parse(await readFile(join(root, record.sbom.fileName), 'utf8'))
  } catch {
    throw new Error('provenance or SBOM is not valid JSON')
  }
  validateSlsaProvenance(provenance, record)
  validateCycloneDxSbom(sbom, record)

  const checksumNames = ['release-record-v1.json', ...references.map((artifact) => artifact.fileName)].sort()
  const expectedChecksums = `${(await Promise.all(checksumNames.map(async (name) => `${digest(await readFile(join(root, name)))}  ${name}`))).join('\n')}\n`
  const checksums = await readFile(join(root, 'SHA256SUMS'), 'utf8')
  if (checksums !== expectedChecksums) throw new Error('SHA256SUMS: content is incomplete, unsorted, or mismatched')

  return { tag: record.distribution.tag, version: record.product.version, files: expectedNames }
}
