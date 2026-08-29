import assert from 'node:assert/strict'
import { cp, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { validateReleaseDirectory, validateReleaseRecord } from '../src/release-contract-v1.mjs'

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const fixture = join(repositoryRoot, 'fixtures', 'valid')

test('assigns the confirmed write-enabled administrator as the exact repository owner', async () => {
  const codeowners = await readFile(join(repositoryRoot, '.github', 'CODEOWNERS'), 'utf8')
  assert.equal(codeowners, '* @zmastylo\n')
  assert.match(codeowners, /^\* @[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\n$/u)
})

test('accepts the representative complete release set', async () => {
  const result = await validateReleaseDirectory(fixture)
  assert.equal(result.tag, 'command-v0.2.0-rc.1')
  assert.equal(result.files.length, 7)
})

test('rejects hidden extra files and directories from the negative fixture', async () => {
  const directory = await mkdtemp(join(tmpdir(), '172x-release-contract-hidden-'))
  await cp(fixture, directory, { recursive: true })
  await cp(join(repositoryRoot, 'fixtures', 'invalid-hidden-extra'), directory, { recursive: true })
  await assert.rejects(validateReleaseDirectory(directory), /no extra or missing files/u)
})

test('rejects artifact tampering', async () => {
  const directory = await mkdtemp(join(tmpdir(), '172x-release-contract-'))
  await cp(fixture, directory, { recursive: true })
  await writeFile(join(directory, '172X-Command_0.2.0-rc.1_universal.dmg'), 'tampered fixture\n')
  await assert.rejects(validateReleaseDirectory(directory), /artifact bytes differ/u)
})

test('rejects absent Apple evidence and executable Marketplace delivery', async () => {
  const record = JSON.parse(await readFile(join(fixture, 'release-record-v1.json'), 'utf8'))
  record.apple.ticketStapled = false
  assert.throws(() => validateReleaseRecord(record), /notarization or stapling evidence/u)
  record.apple.ticketStapled = true
  record.hostInventory.records[0].deliveryMode = 'downloaded-native-plugin'
  assert.throws(() => validateReleaseRecord(record), /downloaded executable delivery is forbidden/u)
})

test('rejects a mismatched distribution tag', async () => {
  const record = JSON.parse(await readFile(join(fixture, 'release-record-v1.json'), 'utf8'))
  record.distribution.tag = 'command-v0.2.0'
  assert.throws(() => validateReleaseRecord(record), /does not match product version/u)
})

test('rejects a different Marketplace or source-workflow identity', async () => {
  const record = JSON.parse(await readFile(join(fixture, 'release-record-v1.json'), 'utf8'))
  record.marketplace.commitSha = '0'.repeat(40)
  assert.throws(() => validateReleaseRecord(record), /marketplace/u)
  record.marketplace.commitSha = '7a1faa24d291db69f2c6fb4ab2669ba0811ad83a'
  record.build.workflowCommitSha = 'e'.repeat(40)
  assert.throws(() => validateReleaseRecord(record), /workflow commit differs/u)
})
