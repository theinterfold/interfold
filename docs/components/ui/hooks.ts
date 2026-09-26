// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { RefObject, useEffect, useState, useSyncExternalStore } from 'react'

const REDUCED_MOTION = '(prefers-reduced-motion: reduce)'

const subscribeReducedMotion = (onChange: () => void) => {
  const query = window.matchMedia(REDUCED_MOTION)
  query.addEventListener('change', onChange)
  return () => query.removeEventListener('change', onChange)
}

/** Returns true when the reader asks the operating system for reduced motion. The server render reports false. */
export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeReducedMotion,
    () => window.matchMedia(REDUCED_MOTION).matches,
    () => false,
  )
}

const subscribeNothing = () => () => {}

/** Returns false during the server render and hydration, and true after the component is live in the browser. */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    subscribeNothing,
    () => true,
    () => false,
  )
}

/**
 * Returns true after the element enters the viewport for the first time.
 * The server render and a browser without IntersectionObserver both report `true`, so content is
 * never hidden when JavaScript does not run.
 */
export function useInView<T extends Element>(ref: RefObject<T>, rootMargin = '0px 0px -10% 0px'): boolean {
  const [state, setState] = useState<'unknown' | 'hidden' | 'visible'>('unknown')
  useEffect(() => {
    const el = ref.current
    if (!el || typeof IntersectionObserver === 'undefined') return
    // The observer reports the current state once after observe(), and then on every change.
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setState('visible')
          observer.disconnect()
        } else {
          setState('hidden')
        }
      },
      { rootMargin },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [ref, rootMargin])
  return state !== 'hidden'
}
