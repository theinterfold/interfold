// SPDX-License-Identifier: LGPL-3.0-only

import { useReducedMotion, type MotionProps } from 'framer-motion'

export function useRevealMotion(delay = 0): MotionProps {
  const reducedMotion = useReducedMotion()
  if (reducedMotion) return {}
  return {
    initial: { opacity: 0, y: 18 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: '-90px' },
    transition: { duration: 0.36, delay, ease: 'easeOut' },
  }
}

export function useLiftMotion(): MotionProps {
  const reducedMotion = useReducedMotion()
  if (reducedMotion) return {}
  return {
    whileHover: { y: -2 },
    transition: { duration: 0.16, ease: 'easeOut' },
  }
}
