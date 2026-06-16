// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { WalletIcon } from '@phosphor-icons/react'
import CardContent from '../components/CardContent'

/**
 * ConnectWallet component - First step in the Interfold wizard flow
 *
 * This component introduces users to the Interfold protocol and provides the initial
 * wallet connection interface. It explains the E3 (Encrypted Execution Environment)
 * concept and guides users through the secure computation workflow using FHE,
 * zero-knowledge proofs, and distributed key cryptography.
 */
const ConnectWallet: React.FC = () => {
  return (
    <CardContent>
      <div className='space-y-6 text-center'>
        <div className='flex justify-center'>
          <WalletIcon size={48} className='text-interfold-500' />
        </div>
        <p className='text-base font-extrabold uppercase text-slate-600/50'>Step 1: Connect Your Wallet</p>
        <div className='space-y-4'>
          <h3 className='text-lg font-semibold text-slate-700'>Welcome to Interfold</h3>
          <p className='leading-relaxed text-slate-600'>
            Interfold is a protocol for Encrypted Execution Environments (E3) that enables secure computations on private data using fully
            homomorphic encryption (FHE), zero-knowledge proofs, and distributed key cryptography. Connect your wallet to experience
            privacy-preserving computation.
          </p>
          <div className='rounded-lg border border-interfold-200 bg-interfold-50 p-4'>
            <p className='text-sm text-slate-600'>
              <strong>How it works:</strong> You'll request an E3 computation → Ciphernode committee is selected → Committee publishes
              shared public key → You encrypt and submit inputs → Secure computation executes → Only verified outputs are decrypted by the
              committee.
            </p>
          </div>
        </div>
      </div>
    </CardContent>
  )
}

export default ConnectWallet
