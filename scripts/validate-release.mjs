#!/usr/bin/env node
import { validateReleaseDirectory } from '../src/release-contract-v1.mjs'

const directory = process.argv[2]
if (!directory || process.argv.length !== 3) {
  console.error('usage: validate-release.mjs RELEASE_DIRECTORY')
  process.exit(2)
}

try {
  const result = await validateReleaseDirectory(directory)
  console.log(JSON.stringify({ status: 'valid', ...result }))
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
