// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useRef, useState } from 'react'
import { useHydrated, useInView, useReducedMotion } from './hooks'
import classes from './ui.module.css'

type TerminalProps = {
  /** Lines that start with `$ ` are commands. Lines that start with `# ` are comments. Other lines are output. */
  lines: string[]
  title?: string
}

const isCommand = (line: string) => line.startsWith('$ ')

/**
 * Terminal window that types its commands when it enters the view. The full text is in the server
 * render, so it is readable without JavaScript. Copy puts only the commands on the clipboard.
 */
export function Terminal({ lines, title = 'terminal' }: TerminalProps) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref)
  const reduced = useReducedMotion()
  const mounted = useHydrated()
  const [typed, setTyped] = useState<{ line: number; char: number } | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (typed !== null || !mounted || reduced || !inView) return
    const timer = window.setTimeout(() => setTyped({ line: 0, char: 0 }), 150)
    return () => window.clearTimeout(timer)
  }, [mounted, reduced, inView, typed])

  useEffect(() => {
    if (typed === null || typed.line >= lines.length) return
    const line = lines[typed.line]
    const body = isCommand(line) ? line.slice(2) : line
    if (isCommand(line) && typed.char < body.length) {
      const timer = window.setTimeout(() => setTyped({ line: typed.line, char: typed.char + 1 }), 28)
      return () => window.clearTimeout(timer)
    }
    const timer = window.setTimeout(() => setTyped({ line: typed.line + 1, char: 0 }), isCommand(line) ? 380 : 120)
    return () => window.clearTimeout(timer)
  }, [typed, lines])

  const copy = async () => {
    const commands = lines.filter(isCommand).map((line) => line.slice(2))
    try {
      await navigator.clipboard.writeText(commands.join('\n'))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  const animating = typed !== null && typed.line < lines.length

  return (
    <div ref={ref} className={classes.terminal}>
      <div className={classes.terminalBar}>
        <span className={classes.terminalDot} />
        <span className={classes.terminalDot} />
        <span className={classes.terminalDot} />
        <span className={classes.terminalTitle}>{title}</span>
        <button type='button' className={classes.terminalCopy} onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className={classes.terminalBody}>
        {lines.map((line, i) => {
          const command = isCommand(line)
          const comment = line.startsWith('# ')
          const body = command ? line.slice(2) : line
          let visible = body
          let cursor = false
          if (animating && typed) {
            if (i > typed.line) visible = ''
            if (i === typed.line) {
              visible = command ? body.slice(0, typed.char) : ''
              cursor = command
            }
          }
          const hidden = animating && typed !== null && i > typed.line
          return (
            <span key={i} className={classes.terminalLine} style={hidden ? { visibility: 'hidden' } : undefined}>
              {command ? <span className={classes.terminalPrompt}>$ </span> : null}
              <span className={command ? undefined : comment ? classes.terminalComment : classes.terminalOutput}>{visible}</span>
              {cursor ? <span className={classes.terminalCursor} /> : null}
            </span>
          )
        })}
      </pre>
    </div>
  )
}
