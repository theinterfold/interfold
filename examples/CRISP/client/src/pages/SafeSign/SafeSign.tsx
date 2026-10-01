// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useAccount, useBytecode, useChainId, useSignTypedData } from 'wagmi'
import { useModal } from 'connectkit'
import { BaseError, recoverAddress } from 'viem'
import type { Hex } from 'viem'
import { EditorialShell } from '@/design/Editorial'
import { parseSignRequest, safeBallotTypedData, signsWithKey } from '@/utils/safeBallot'
import type { SafeSignRequest } from '@/utils/safeBallot'

/**
 * The page a Safe owner opens from the coordinator's link, to sign one ballot for the Safe.
 *
 * It reads the request from the URL fragment and rebuilds the digest locally. It sends nothing to
 * the CRISP server. Its only network read is the code of the connected account, which names no
 * round and no ballot.
 */
const SafeSign: React.FC = () => {
  const { request: encoded } = useParams()
  const { address } = useAccount()
  const chainId = useChainId()
  const { setOpen } = useModal()
  const { signTypedDataAsync } = useSignTypedData()
  const [signature, setSignature] = useState<Hex | null>(null)
  const [signing, setSigning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const parsed = useMemo((): { request: SafeSignRequest } | { error: string } => {
    try {
      return { request: parseSignRequest(encoded ?? '') }
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) }
    }
  }, [encoded])

  const linked = 'request' in parsed ? parsed.request : undefined
  const connected = address && linked?.owners.includes(address) ? address : undefined
  const wrongChain = chainId !== linked?.chainId
  // Only an owner that signs with a key is asked. A contract owner, such as a nested Safe connected
  // through WalletConnect, signs in its own app, which can publish the message. The link can name
  // any owner as a key owner, so the page reads the code of the connected account itself.
  const code = useBytecode({ address: connected, query: { enabled: Boolean(connected) && !wrongChain } })
  const owner = connected && code.isSuccess && signsWithKey(code.data) ? connected : undefined

  if ('error' in parsed) {
    return (
      <EditorialShell className='flex w-full flex-1 flex-col'>
        <section className='pad-section col' style={{ gap: 12 }}>
          <h1 className='h1'>Sign a Safe ballot</h1>
          <div className='cap error'>{parsed.error}</div>
        </section>
      </EditorialShell>
    )
  }

  const { request } = parsed
  const { typedData, digest } = safeBallotTypedData(request)

  const sign = async () => {
    setSigning(true)
    setError(null)
    try {
      if (!owner) throw new Error('The connected wallet is not an owner of this Safe.')
      const signed = await signTypedDataAsync(typedData)
      if ((await recoverAddress({ hash: digest, signature: signed })) !== owner) {
        throw new Error('The wallet signed something other than this ballot.')
      }
      setSignature(signed)
    } catch (e) {
      setError(e instanceof BaseError ? e.shortMessage : e instanceof Error ? e.message : String(e))
    } finally {
      setSigning(false)
    }
  }

  const copy = async () => {
    if (!signature) return
    await navigator.clipboard.writeText(signature)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section col' style={{ gap: 20, maxWidth: 760 }}>
        <div className='col' style={{ gap: 8 }}>
          <div className='mono muted'>Round #{request.e3Id}</div>
          <h1 className='h1'>Sign a Safe ballot</h1>
          <p className='lede'>
            The coordinator says this ballot votes for <strong>{request.choice}</strong>. The ballot is encrypted, so you cannot check this
            here. Sign only if you trust the coordinator.
          </p>
        </div>

        <div className='card col' style={{ gap: 10 }}>
          <div className='cap muted'>Safe</div>
          <div className='hex'>{request.safe}</div>
          <div className='cap muted'>
            {request.threshold} of {request.owners.length} owners must sign
          </div>
          <div className='cap muted'>CRISP program (chain {request.chainId})</div>
          <div className='hex'>{request.crispProgram}</div>
          <div className='cap muted'>Message you sign (SafeMessage hash)</div>
          <div className='hex'>{digest}</div>
        </div>

        <div className='cap'>
          Your signature goes only to the coordinator. Send it back through the same private channel. Do not sign this in the Safe app: it
          publishes the message, and anyone could then tell this vote from a mask.
        </div>
        <div className='cap'>
          Your signature authorises this ballot until the round ends. Whoever holds the signatures and the encrypted ballot can submit the
          ballot one time. If the ballot was not submitted before, they can also submit it after a later vote of the Safe, and it then
          replaces that vote. Sign only for a coordinator that you trust.
        </div>

        {!address && (
          <div>
            <button className='btn lg' onClick={() => setOpen(true)}>
              Connect your owner wallet
            </button>
          </div>
        )}
        {address && !connected && <div className='cap error'>The connected wallet {address} is not an owner of this Safe.</div>}
        {connected && wrongChain && <div className='cap error'>Switch the wallet to chain {request.chainId}.</div>}
        {connected && !wrongChain && code.isError && (
          <div className='cap error'>Could not read the connected account. Reload the page to try again.</div>
        )}
        {connected && !wrongChain && code.isSuccess && !owner && (
          <div className='cap error'>
            The connected owner {connected} is a contract, so it cannot sign a ballot. Do not sign this in its own app.
          </div>
        )}
        {owner && !wrongChain && !signature && (
          <div>
            <button className='btn lg' disabled={signing} onClick={sign}>
              {signing ? 'Waiting for the wallet…' : 'Sign the ballot →'}
            </button>
          </div>
        )}

        {signature && (
          <div className='col' style={{ gap: 8 }}>
            <div className='cap'>Your signature. Copy it and send it to the coordinator.</div>
            <div className='row' style={{ gap: 8 }}>
              <input className='field' readOnly value={signature} onFocus={(e) => e.target.select()} />
              <button className='btn' onClick={copy}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        )}
        {error && <div className='cap error'>{error}</div>}
      </section>
    </EditorialShell>
  )
}

/** Mount a new page for each request and each account, so that no state of one reaches another. */
const SafeSignPage: React.FC = () => {
  const { request } = useParams()
  const { address } = useAccount()
  return <SafeSign key={`${request ?? ''}:${address ?? ''}`} />
}

export default SafeSignPage
