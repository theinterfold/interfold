// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import axios, { AxiosRequestConfig, Method } from 'axios'
import { handleGenericError } from '@/utils/handle-generic-error'

type FetchConfig = AxiosRequestConfig & {
  suppressNotFound?: boolean
}

export const useApi = () => {
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const pending = useRef(0)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const fetchData = useCallback(
    async <T, U = undefined>(url: string, method: Method = 'get', data?: U, config?: FetchConfig): Promise<T | undefined> => {
      pending.current += 1
      if (mounted.current) setIsLoading(true)
      const { suppressNotFound = false, ...axiosConfig } = config ?? {}
      try {
        const response = await axios.request<T>({ ...axiosConfig, url, method, data })
        return response.data
      } catch (error) {
        if (suppressNotFound && axios.isAxiosError(error) && error.response?.status === 404) return undefined
        handleGenericError(`API Error - ${url}`, error as Error)
        throw error
      } finally {
        pending.current -= 1
        if (mounted.current) setIsLoading(pending.current > 0)
      }
    },
    [],
  )

  return { fetchData, isLoading }
}
