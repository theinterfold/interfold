// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import GnosisGuildLogo from '@/assets/icons/gg.svg'
import { CastleTurret, GithubLogo, TelegramLogo, TwitterLogo } from '@phosphor-icons/react'

const Footer: React.FC = () => {
  return (
    <div className='crisp-editorial' data-palette='interfold' data-mode='light' data-density='comfortable'>
      <footer className='footer'>
        <span>© 2026 — Crisp Protocol</span>
        <span className='muted'>Secret-ballot voting with FHE + threshold MPC</span>
        <div className='links' style={{ alignItems: 'center' }}>
          <a href='https://github.com/gnosisguild/interfold' target='_blank' rel='noopener noreferrer' aria-label='GitHub'>
            <GithubLogo size={18} />
          </a>
          <a href='https://x.com/InterfoldE3' target='_blank' rel='noopener noreferrer' aria-label='X'>
            <TwitterLogo size={18} />
          </a>
          <a href='https://t.me/interfold_e3' target='_blank' rel='noopener noreferrer' aria-label='Telegram'>
            <TelegramLogo size={18} />
          </a>
          <a href='https://warpcast.com/interfolde3' target='_blank' rel='noopener noreferrer' aria-label='Farcaster'>
            <CastleTurret size={18} />
          </a>
          <a href='https://theinterfold.com' target='_blank' rel='noopener noreferrer'>
            Secured with The Interfold
          </a>
          <a
            href='https://www.gnosisguild.org/'
            target='_blank'
            rel='noopener noreferrer'
            style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}
          >
            Gnosis Guild
            <img src={GnosisGuildLogo} className='h-4 w-4' alt='Gnosis Guild' />
          </a>
        </div>
      </footer>
    </div>
  )
}

export default Footer
