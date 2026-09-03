// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useQuery } from '@tanstack/react-query'
import { useSurvey } from '@/context/SurveyContext'

export const useRounds = () => {
  const { api } = useSurvey()
  return useQuery({ queryKey: ['rounds'], queryFn: () => api.rounds(), refetchInterval: 4000 })
}

export const useRound = (e3Id: string | undefined) => {
  const { api } = useSurvey()
  return useQuery({
    queryKey: ['round', e3Id],
    queryFn: () => api.round(e3Id!),
    enabled: !!e3Id,
    refetchInterval: 3000,
  })
}

export const useHealth = () => {
  const { api } = useSurvey()
  return useQuery({ queryKey: ['health'], queryFn: () => api.health(), refetchInterval: 10000 })
}
