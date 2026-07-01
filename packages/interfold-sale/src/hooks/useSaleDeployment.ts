// SPDX-License-Identifier: LGPL-3.0-only

import { useEffect, useState } from 'react'
import { readableError } from '../lib/format'
import { fetchJson } from '../lib/storage'
import type { SaleDeployment } from '../types'

export function useSaleDeployment() {
  const [deployment, setDeployment] = useState<SaleDeployment>()
  const [error, setError] = useState<string>()

  useEffect(() => {
    let alive = true
    fetchJson<SaleDeployment>('/sale/deployment.json')
      .then((value) => {
        if (!alive) return
        setDeployment(value)
        setError(undefined)
      })
      .catch((err: unknown) => {
        if (!alive) return
        setError(readableError(err))
      })
    return () => {
      alive = false
    }
  }, [])

  return { deployment, error }
}
