// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { SurveyApi } from '@interfold/ckks-salary-sdk'
import { SURVEY_API, ADMIN_KEY } from '@/utils/constants'

interface SurveyContextValue {
  api: SurveyApi
}

const SurveyContext = createContext<SurveyContextValue | null>(null)

export const SurveyProvider = ({ children }: { children: ReactNode }) => {
  const value = useMemo(() => ({ api: new SurveyApi(SURVEY_API, ADMIN_KEY) }), [])
  return <SurveyContext.Provider value={value}>{children}</SurveyContext.Provider>
}

export const useSurvey = (): SurveyContextValue => {
  const ctx = useContext(SurveyContext)
  if (!ctx) throw new Error('useSurvey must be used within SurveyProvider')
  return ctx
}
