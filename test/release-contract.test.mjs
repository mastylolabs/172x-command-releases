import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  validateCycloneDxSbom,
  validateReleaseDirectory,
  validateReleaseRecord,
  validateSlsaProvenance,
} from '../src/release-contract-v1.mjs'

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const fixture = join(repositoryRoot, 'fixtures', 'valid')
const negativeFixture = join(repositoryRoot, 'fixtures', 'invalid-hidden-extra')

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

async function releaseRecord() {
  return json(join(fixture, 'release-record-v1.json'))
}

async function copiedFixture(t, prefix = '172x-release-contract-') {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await cp(fixture, directory, { recursive: true })
  return directory
}

test('assigns the confirmed write-enabled administrator as the exact repository owner', async () => {
  const codeowners = await readFile(join(repositoryRoot, '.github', 'CODEOWNERS'), 'utf8')
  assert.equal(codeowners, '* @zmastylo\n')
  assert.match(codeowners, /^\* @[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\n$/u)
})

test('accepts the exact five-file command-v0.2.0-rc.1 release set', async () => {
  const result = await validateReleaseDirectory(fixture)
  assert.equal(result.tag, 'command-v0.2.0-rc.1')
  assert.equal(result.version, '0.2.0-rc.1')
  assert.deepEqual(result.files, [
    '172X-Command_0.2.0-rc.1_provenance.intoto.json',
    '172X-Command_0.2.0-rc.1_sbom.cdx.json',
    '172X-Command_0.2.0-rc.1_universal.dmg',
    'SHA256SUMS',
    'release-record-v1.json',
  ])
})

test('rejects updater metadata and updater artifacts from the private RC', async (t) => {
  const record = await releaseRecord()
  record.updater = { artifact: 'forbidden' }
  assert.throws(() => validateReleaseRecord(record), /unexpected or missing fields/u)

  const directory = await copiedFixture(t)
  await writeFile(join(directory, '172X-Command_0.2.0-rc.1_universal.app.tar.gz'), 'forbidden updater\n')
  await assert.rejects(validateReleaseDirectory(directory), /five-file artifact set/u)
})

test('rejects hidden extras and non-regular top-level directories', async (t) => {
  const hiddenFileDirectory = await copiedFixture(t, '172x-release-hidden-file-')
  await cp(join(negativeFixture, '.unexpected'), join(hiddenFileDirectory, '.unexpected'))
  await assert.rejects(validateReleaseDirectory(hiddenFileDirectory), /five-file artifact set/u)

  const hiddenDirectory = await copiedFixture(t, '172x-release-hidden-directory-')
  await mkdir(join(hiddenDirectory, '.hidden-directory'))
  await assert.rejects(validateReleaseDirectory(hiddenDirectory), /top-level entry must be a regular file/u)
})

test('rejects symlinked top-level artifacts before reading them', async (t) => {
  const directory = await copiedFixture(t, '172x-release-symlink-')
  const name = '172X-Command_0.2.0-rc.1_universal.dmg'
  await unlink(join(directory, name))
  await symlink(join(fixture, name), join(directory, name))
  await assert.rejects(validateReleaseDirectory(directory), /top-level entry must be a regular file/u)
})

test('rejects artifact tampering', async (t) => {
  const directory = await copiedFixture(t)
  await writeFile(join(directory, '172X-Command_0.2.0-rc.1_universal.dmg'), 'tampered fixture\n')
  await assert.rejects(validateReleaseDirectory(directory), /artifact bytes differ/u)
})

test('rejects absent Apple evidence and executable Marketplace delivery', async () => {
  const record = await releaseRecord()
  record.apple.ticketStapled = false
  assert.throws(() => validateReleaseRecord(record), /notarization or stapling evidence/u)
  record.apple.ticketStapled = true
  record.hostInventory.records[0].deliveryMode = 'downloaded-native-plugin'
  assert.throws(() => validateReleaseRecord(record), /downloaded executable delivery is forbidden/u)
})

test('strictly binds the complete SLSA v1 predicate to record and workflow identity', async () => {
  const record = await releaseRecord()
  const provenance = await json(join(fixture, record.provenance.fileName))
  const mutations = [
    (value) => { delete value.predicate },
    (value) => { value.predicate.buildDefinition.buildType = 'https://example.invalid/build' },
    (value) => { value.predicate.buildDefinition.externalParameters.target = 'other-target' },
    (value) => { value.predicate.buildDefinition.externalParameters.sourceCommitSha = 'e'.repeat(40) },
    (value) => { value.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'e'.repeat(40) },
    (value) => { value.predicate.buildDefinition.resolvedDependencies[1].uri = 'git+https://example.invalid/workflow' },
    (value) => { value.predicate.buildDefinition.resolvedDependencies[2].digest.gitCommit = 'e'.repeat(40) },
    (value) => { value.predicate.buildDefinition.resolvedDependencies[3].digest.gitCommit = 'e'.repeat(40) },
    (value) => { value.predicate.runDetails.builder.id = 'https://example.invalid/builder' },
    (value) => { value.predicate.runDetails.metadata.invocationId = 'https://example.invalid/run' },
    (value) => { value.subject[0].digest.sha256 = '0'.repeat(64) },
  ]
  for (const mutate of mutations) {
    const candidate = structuredClone(provenance)
    mutate(candidate)
    assert.throws(() => validateSlsaProvenance(candidate, record), /SLSA provenance v1/u)
  }
})

test('strictly validates CycloneDX root, components, dependency refs, and reachability', async () => {
  const record = await releaseRecord()
  const sbom = await json(join(fixture, record.sbom.fileName))
  const mutations = [
    (value) => { value.metadata.component = 'not-an-object' },
    (value) => { value.metadata.component.version = '0.2.0' },
    (value) => { value.components[0] = null },
    (value) => { delete value.components[0].name },
    (value) => { value.components[0]['bom-ref'] = value.metadata.component['bom-ref'] },
    (value) => { value.dependencies.pop() },
    (value) => { value.dependencies[0].dependsOn = ['pkg:generic/missing@1.0.0'] },
    (value) => { value.dependencies[0].dependsOn = [] },
    (value) => { value.dependencies[1].ref = 'pkg:generic/missing@1.0.0' },
  ]
  for (const mutate of mutations) {
    const candidate = structuredClone(sbom)
    mutate(candidate)
    assert.throws(() => validateCycloneDxSbom(candidate, record), /CycloneDX SBOM/u)
  }
})

test('rejects stable, non-canonical, and non-approved RC versions and filenames', async () => {
  for (const version of ['0.2.0', '0.2.0-beta.1', '0.2.0-rc.01', '0.2.0-rc.2']) {
    const record = await releaseRecord()
    record.product.version = version
    assert.throws(() => validateReleaseRecord(record), /exact approved macOS RC version/u)
  }
  for (const role of ['download', 'provenance', 'sbom']) {
    const record = await releaseRecord()
    record[role].fileName = `unexpected-${role}`
    assert.throws(() => validateReleaseRecord(record), /canonical RC artifact name/u)
  }
})

test('rejects normalized impossible dates and accepts a canonical leap-day timestamp', async () => {
  for (const createdAt of [
    '2026-02-31T12:00:00Z',
    '2025-02-29T12:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-01-01T12:00:00.1Z',
  ]) {
    const record = await releaseRecord()
    record.createdAt = createdAt
    assert.throws(() => validateReleaseRecord(record), /RFC3339/u)
  }
  const leapDay = await releaseRecord()
  leapDay.createdAt = '2024-02-29T12:00:00.123Z'
  assert.doesNotThrow(() => validateReleaseRecord(leapDay))
})

test('rejects mismatched distribution, source, workflow, and Marketplace identity', async () => {
  const mutations = [
    (record) => { record.distribution.tag = 'command-v0.2.0' },
    (record) => { record.source.repository = 'example/other' },
    (record) => { record.source.tag = 'command-v0.2.0' },
    (record) => { record.build.workflowPath = '.github/workflows/other.yml' },
    (record) => { record.build.workflowCommitSha = 'e'.repeat(40) },
    (record) => { record.marketplace.commitSha = '0'.repeat(40) },
    (record) => { record.marketplace.catalogRevision = 'main' },
  ]
  for (const mutate of mutations) {
    const record = await releaseRecord()
    mutate(record)
    assert.throws(() => validateReleaseRecord(record))
  }
})

test('rejects non-draft release and coupled publication policy', async () => {
  const record = await releaseRecord()
  record.recovery.draftOnly = false
  assert.throws(() => validateReleaseRecord(record), /unsafe publication/u)
  record.recovery.draftOnly = true
  record.recovery.publicPromotion = 'automatic'
  assert.throws(() => validateReleaseRecord(record), /unsafe publication/u)
})
