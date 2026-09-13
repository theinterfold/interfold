// r130 (b)-leg unit check: isLibOnly/isWorkspaceOnly classification
const { readFileSync } = require('fs')
function isWorkspaceOnly(nargoPath) {
  const content = readFileSync(nargoPath, 'utf-8')
  return /^\s*\[workspace\]/m.test(content) && !/^\s*\[package\]/m.test(content)
}
function isLibOnly(nargoPath) {
  const content = readFileSync(nargoPath, 'utf-8')
  const pkgStart = content.indexOf('[package]')
  if (pkgStart < 0) return false
  const pkgEndMatch = content.search(/\n\s*\[/)
  const pkgEnd = pkgEndMatch < 0 ? content.length : pkgEndMatch
  const pkgBlock = content.slice(pkgStart, pkgEnd)
  return /^\s*type\s*=\s*"lib"\s*$/m.test(pkgBlock)
}
const ROOT='/home/dev/interfold-research/interfold'
const cases=[
  ['circuits/bin/recursive_aggregation/c3_fold_batch_lib/Nargo.toml', 'LIB', true],
  ['circuits/bin/recursive_aggregation/c3_fold/Nargo.toml', 'PKG', false],
]