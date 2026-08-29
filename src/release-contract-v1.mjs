import { createHash } from 'node:crypto'
import { readFile, readdir, stat } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'

const SHA256 = /^[a-f0-9]{64}$/u
const GIT_SHA1 = /^[a-f0-9]{40}$/u
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u
const SAFE_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/u
const EXPECTED_REPOSITORY = 'mastylolabs/172x-command-releases'
const EXPECTED_SOURCE_REPOSITORY = 'mastylolabs/172x-command'
const EXPECTED_MARKETPLACE_REPOSITORY = 'mastylolabs/172x-command-marketplace'

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
  if (typeof value !== 'string' || !RFC3339.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label}: expected an RFC3339 UTC timestamp`)
  }
}

function sha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new Error(`${label}: expected lowercase SHA-256`)
}

function gitSha(value, label) {
  if (typeof value !== 'string' || !GIT_SHA1.test(value)) throw new Error(`${label}: expected a full Git SHA-1`)
}

function validateArtifact(value, label, expectedContentType) {
  exact(value, ['fileName', 'byteLength', 'sha256', 'contentType'], label)
  if (typeof value.fileName !== 'string' || !SAFE_FILE.test(value.fileName)) throw new Error(`${label}.fileName: unsafe name`)
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

export function canonicalJson(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`
}

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function validateReleaseRecord(value) {
  exact(value, [
    'schemaVersion', 'recordType', 'createdAt', 'distribution', 'product', 'source', 'marketplace',
    'build', 'apple', 'download', 'updater', 'provenance', 'sbom', 'hostInventory', 'recovery',
  ], 'release record')
  if (value.schemaVersion !== 1 || value.recordType !== '172x-command-release') throw new Error('release record: unsupported schema or type')
  timestamp(value.createdAt, 'createdAt')

  exact(value.distribution, ['repository', 'tag', 'recordAssetName', 'contractCommitSha'], 'distribution')
  if (value.distribution.repository !== EXPECTED_REPOSITORY || value.distribution.recordAssetName !== 'release-record-v1.json') {
    throw new Error('distribution: unexpected repository or record asset')
  }
  gitSha(value.distribution.contractCommitSha, 'distribution.contractCommitSha')

  exact(value.product, ['name', 'version', 'channel', 'bundleIdentifier', 'minimumMacOS', 'architectures', 'packageFormat'], 'product')
  if (
    value.product.name !== '172X Command' || typeof value.product.version !== 'string' || !SEMVER.test(value.product.version) ||
    value.product.channel !== 'rc' || value.product.bundleIdentifier !== 'ai.172x.command' || value.product.minimumMacOS !== '13.0' ||
    JSON.stringify(value.product.architectures) !== JSON.stringify(['arm64', 'x86_64']) || value.product.packageFormat !== 'universal-dmg'
  ) throw new Error('product: identity differs from the approved macOS RC contract')
  const expectedTag = `command-v${value.product.version}`
  if (value.distribution.tag !== expectedTag) throw new Error('distribution.tag: does not match product version')

  exact(value.source, ['repository', 'commitSha', 'treeSha', 'tag', 'dirty', 'signedTag'], 'source')
  if (value.source.repository !== EXPECTED_SOURCE_REPOSITORY || value.source.tag !== expectedTag || value.source.dirty !== false || value.source.signedTag !== true) {
    throw new Error('source: repository, exact signed tag, or clean-tree evidence is invalid')
  }
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

  validateArtifact(value.download, 'download', 'application/x-apple-diskimage')
  exact(value.updater, ['target', 'architectures', 'version', 'publicationDate', 'notes', 'artifact', 'signatureAsset', 'tauriSignature'], 'updater')
  if (
    value.updater.target !== 'darwin' || JSON.stringify(value.updater.architectures) !== JSON.stringify(['aarch64', 'x86_64']) ||
    value.updater.version !== value.product.version
  ) throw new Error('updater: target, architectures, or version is invalid')
  timestamp(value.updater.publicationDate, 'updater.publicationDate')
  if (value.updater.publicationDate !== value.createdAt) throw new Error('updater.publicationDate: differs from release creation identity')
  string(value.updater.notes, 'updater.notes', 10_000)
  string(value.updater.tauriSignature, 'updater.tauriSignature', 4096)
  if (/\s/u.test(value.updater.tauriSignature)) throw new Error('updater.tauriSignature: whitespace is forbidden')
  validateArtifact(value.updater.artifact, 'updater.artifact', 'application/gzip')
  validateArtifact(value.updater.signatureAsset, 'updater.signatureAsset', 'application/octet-stream')
  validateArtifact(value.provenance, 'provenance', 'application/vnd.in-toto+json')
  validateArtifact(value.sbom, 'sbom', 'application/vnd.cyclonedx+json')

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

  const artifacts = [value.download, value.updater.artifact, value.updater.signatureAsset, value.provenance, value.sbom]
  if (new Set(artifacts.map((artifact) => artifact.fileName)).size !== artifacts.length) throw new Error('artifacts: duplicate file names')
  return value
}

export async function validateReleaseDirectory(directory) {
  const root = resolve(directory)
  const recordPath = join(root, 'release-record-v1.json')
  const recordBytes = await readFile(recordPath)
  let record
  try {
    record = validateReleaseRecord(JSON.parse(recordBytes.toString('utf8')))
  } catch (error) {
    throw new Error(`release-record-v1.json: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (recordBytes.toString('utf8') !== canonicalJson(record)) throw new Error('release-record-v1.json: JSON is not canonical')

  const references = [record.download, record.updater.artifact, record.updater.signatureAsset, record.provenance, record.sbom]
  const expectedNames = ['SHA256SUMS', 'release-record-v1.json', ...references.map((artifact) => artifact.fileName)].sort()
  const actualNames = (await readdir(root)).sort()
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) throw new Error('release directory: expected one complete artifact set with no extra or missing files')

  for (const artifact of references) {
    if (basename(artifact.fileName) !== artifact.fileName) throw new Error(`artifact path is not a safe base name: ${artifact.fileName}`)
    const path = join(root, artifact.fileName)
    const metadata = await stat(path)
    const bytes = await readFile(path)
    if (!metadata.isFile() || metadata.size !== artifact.byteLength || digest(bytes) !== artifact.sha256) {
      throw new Error(`artifact bytes differ from release record: ${artifact.fileName}`)
    }
  }

  const signatureBytes = await readFile(join(root, record.updater.signatureAsset.fileName), 'utf8')
  if (signatureBytes.trim() !== record.updater.tauriSignature) throw new Error('updater signature asset differs from the release record signature')

  let provenance
  let sbom
  try {
    provenance = JSON.parse(await readFile(join(root, record.provenance.fileName), 'utf8'))
    sbom = JSON.parse(await readFile(join(root, record.sbom.fileName), 'utf8'))
  } catch {
    throw new Error('provenance or SBOM is not valid JSON')
  }
  const provenanceSubjects = new Map((Array.isArray(provenance.subject) ? provenance.subject : []).map((subject) => [subject?.name, subject?.digest?.sha256]))
  const expectedSubjects = [record.download, record.updater.artifact, record.updater.signatureAsset, record.sbom]
  if (provenance._type !== 'https://in-toto.io/Statement/v1' || provenance.predicateType !== 'https://slsa.dev/provenance/v1'
    || provenanceSubjects.size !== expectedSubjects.length
    || expectedSubjects.some((artifact) => provenanceSubjects.get(artifact.fileName) !== artifact.sha256)) {
    throw new Error('provenance does not bind the complete binary and SBOM subject set')
  }
  if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.6' || !Array.isArray(sbom.components)
    || sbom.components.length === 0 || !sbom.metadata?.component || !Array.isArray(sbom.dependencies)) {
    throw new Error('SBOM is not a meaningful CycloneDX 1.6 component inventory')
  }

  const checksumNames = ['release-record-v1.json', ...references.map((artifact) => artifact.fileName)].sort()
  const expectedChecksums = `${(await Promise.all(checksumNames.map(async (name) => `${digest(await readFile(join(root, name)))}  ${name}`))).join('\n')}\n`
  const checksums = await readFile(join(root, 'SHA256SUMS'), 'utf8')
  if (checksums !== expectedChecksums) throw new Error('SHA256SUMS: content is incomplete, unsorted, or mismatched')

  return { tag: record.distribution.tag, version: record.product.version, files: expectedNames }
}
