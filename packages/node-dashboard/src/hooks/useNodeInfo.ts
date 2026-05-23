// SPDX-License-Identifier: LGPL-3.0-only
import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'

export interface NodeInfo {
  name: string
  address: string
  peer: string
  quicPort: string
  ctrlPort: string
}

export interface NodeStatus {
  status: string
  wallet: string
  noir: string
}

export interface UseNodeInfoResult {
  info: NodeInfo | null
  status: NodeStatus | null
  loadInfo: () => Promise<void>
  loadStatus: () => Promise<void>
}

export function useNodeInfo(): UseNodeInfoResult {
  const [info, setInfo] = useState<NodeInfo | null>(null)
  const [status, setStatus] = useState<NodeStatus | null>(null)

  const loadInfo = useCallback(async () => {
    if (info) return
    try {
      const [name, address, peer, quic, ctrl] = await Promise.all([
        api('/api/config?param=name'),
        api('/api/config?param=address'),
        api('/api/peer-id'),
        api('/api/config?param=quic_port'),
        api('/api/config?param=ctrl_port'),
      ])
      setInfo({
        name: name.trim(),
        address: address.trim(),
        peer: peer.trim(),
        quicPort: quic.trim(),
        ctrlPort: ctrl.trim(),
      })
    } catch {
      // ignore
    }
  }, [info])

  const loadStatus = useCallback(async () => {
    try {
      const [st, wa, no] = await Promise.all([api('/api/status'), api('/api/wallet'), api('/api/noir')])
      setStatus({ status: st.trim(), wallet: wa.trim(), noir: no.trim() })
    } catch {
      // ignore
    }
  }, [])

  // Refresh status every 30 s
  useEffect(() => {
    const id = setInterval(loadStatus, 30_000)
    return () => clearInterval(id)
  }, [loadStatus])

  return { info, status, loadInfo, loadStatus }
}
