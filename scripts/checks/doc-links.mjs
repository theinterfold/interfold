// SPDX-License-Identifier: LGPL-3.0-only

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { dirname, isAbsolute, relative, resolve } from 'node:path'

const root = realpathSync(process.cwd())
const documents = new Map()
const directories = new Map()
const markdown = (file) => /\.mdx?$/i.test(file)
const inside = (file) => {
  const path = relative(root, file)
  return path !== '..' && !path.startsWith('../') && !isAbsolute(path)
}
const mask = (text) => text.replace(/[^\n]/g, ' ')

function prose(text) {
  let fence
  return text
    .replace(/^---\r?\n[\s\S]*?\r?\n---\s*\r?\n/, mask)
    .replace(/<!--[\s\S]*?-->/g, mask)
    .split('\n')
    .map((line) => {
      const delimiter = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line)
      if (fence) {
        if (delimiter && delimiter[1][0] === fence[0] && delimiter[1].length >= fence.length && !delimiter[2].trim()) fence = undefined
        return mask(line)
      }
      if (delimiter) {
        fence = delimiter[1]
        return mask(line)
      }
      return line
    })
    .join('\n')
}

function entities(text) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }
  return text.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (whole, name) => {
    if (!name.startsWith('#')) return named[name.toLowerCase()]
    const value = name.toLowerCase().startsWith('#x') ? parseInt(name.slice(2), 16) : Number(name.slice(1))
    return value <= 0x10ffff ? String.fromCodePoint(value) : whole
  })
}

function readDocument(file) {
  if (documents.has(file)) return documents.get(file)
  if (!inside(file) || !inside(realpathSync(file))) throw new Error('path is outside the repository')
  const text = prose(readFileSync(file, 'utf8'))
  const html = text.replace(/(`+)([^`\n]*?)\1/g, mask)
  const anchors = new Set([...html.matchAll(/<[A-Za-z][^<>]*?\s(?:id|name)\s*=\s*["']([^"']+)["']/g)].map((match) => match[1]))
  const headings = new Set()
  for (const match of text.matchAll(/^ {0,3}#{1,6}\s+(.+)$/gm)) {
    const label = entities(
      match[1]
        .replace(/\s+#+\s*$/, '')
        .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
        .replace(/<[^>]*>/g, ''),
    )
    const base = label
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{M}\p{N}_ -]/gu, '')
      .replace(/ /g, '-')
    let anchor = base
    for (let suffix = 1; headings.has(anchor); suffix++) anchor = `${base}-${suffix}`
    headings.add(anchor)
    anchors.add(anchor)
  }
  const result = { text, anchors }
  documents.set(file, result)
  return result
}

function destination(text, start) {
  let cursor = start
  while (/\s/.test(text[cursor] ?? '') && cursor < text.length) cursor++
  if (text[cursor] === '<') {
    const end = text.indexOf('>', cursor + 1)
    return end < 0 ? '' : text.slice(cursor + 1, end)
  }
  let value = '',
    depth = 0
  for (; cursor < text.length; cursor++) {
    const char = text[cursor]
    if (char === '\\' && /[\\() ]/.test(text[cursor + 1] ?? '')) {
      value += text[++cursor]
      continue
    }
    if (/\s/.test(char) || (char === ')' && depth === 0)) break
    if (char === '(') depth++
    if (char === ')') depth--
    value += char
  }
  return value
}

function links(text) {
  const body = text.replace(/(`+)([^`\n]*?)\1/g, mask)
  const found = []
  const definitions = new Map()
  const label = (value) => value.trim().toLowerCase().replace(/\s+/g, ' ')
  for (const match of body.matchAll(/^ {0,3}\[(?!\^)([^\]\n]+)\]:[ \t]*/gm)) {
    const url = destination(body, match.index + match[0].length)
    definitions.set(label(match[1]), url)
    found.push({ url, index: match.index })
  }
  for (const match of body.matchAll(/!?\[(?!\^)([^\]\n]*)\](?:\[([^\]\n]*)\])?/g)) {
    const end = match.index + match[0].length
    const url = body[end] === '(' ? destination(body, end + 1) : definitions.get(label(match[2] || match[1]))
    if (url) found.push({ url, index: match.index })
  }
  return found
}

function exactCase(file) {
  let parent = root
  for (const name of relative(root, file).split('/').filter(Boolean)) {
    if (!directories.has(parent)) directories.set(parent, new Set(readdirSync(parent)))
    if (!directories.get(parent).has(name)) throw new Error('missing target or incorrect file-name case')
    parent = resolve(parent, name)
  }
}

function check(source, url) {
  if (/^(?:[a-z][a-z\d+.-]*:|\/)/i.test(url)) return false
  let path, anchor
  try {
    const split = url.indexOf('#')
    path = decodeURIComponent((split < 0 ? url : url.slice(0, split)).split('?')[0])
    anchor = split < 0 ? '' : decodeURIComponent(url.slice(split + 1))
  } catch {
    throw new Error('invalid URL escape')
  }
  const target = path ? resolve(dirname(source), path) : source
  if (!inside(target)) throw new Error('path is outside the repository')
  if (!existsSync(target)) throw new Error('missing target')
  exactCase(target)
  if (!inside(realpathSync(target))) throw new Error('path is outside the repository')
  if (anchor && markdown(target) && !readDocument(target).anchors.has(anchor)) throw new Error(`missing anchor #${anchor}`)
  return true
}

try {
  const requested = process.argv.slice(2)
  const files = requested.length
    ? requested
    : execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
        cwd: root,
        encoding: 'utf8',
      })
        .split('\0')
        .filter((path) => markdown(path) && existsSync(resolve(root, path)))
  let count = 0,
    failures = 0
  for (const path of [...new Set(files)].sort()) {
    const file = resolve(root, path)
    try {
      if (!markdown(file)) throw new Error('expected a Markdown or MDX source')
      const { text } = readDocument(file)
      for (const { url, index } of links(text)) {
        try {
          if (check(file, url)) count++
        } catch (error) {
          console.error(`${path}:${text.slice(0, index).split('\n').length}: ${url}: ${error.message}`)
          failures++
        }
      }
    } catch (error) {
      console.error(`${path}:1: ${error.message}`)
      failures++
    }
  }
  console.log(`Checked ${count} relative documentation links in ${new Set(files).size} files; ${failures} errors.`)
  if (failures) process.exitCode = 1
} catch (error) {
  console.error(`check:links: ${error.message}`)
  process.exitCode = 1
}
