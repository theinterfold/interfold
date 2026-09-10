// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import axios, { AxiosRequestConfig, Method } from 'axios'
import { handleGenericError } from '@/utils/handle-generic-error'

type FetchConfig = AxiosRequestConfig & {
  suppressNotFound?: boolean
}

export const useApi = () => {
  const [isLoading, setIsLoading] = useState<boolean>(false)

  const fetchData = async <T, U = undefined>(
    url: string,
    method: Method = 'get',
    data?: U,
    config?: FetchConfig,
  ): Promise<T | undefined> => {
    setIsLoading(true)
    const { suppressNotFound = false, ...axiosConfig } = config ?? {}
    try {
      const response = method === 'get' ? await axios.get<T>(`${url}`, axiosConfig) : await axios.post<T>(`${url}`, data, axiosConfig)
      return response.data
    } catch (error) {
      if (suppressNotFound && axios.isAxiosError(error) && error.response?.status === 404) return undefined
      handleGenericError(`API Error - ${url}`, error as Error)
    } finally {
      setIsLoading(false)
    }
    return undefined
  }

  return { fetchData, isLoading }
}
