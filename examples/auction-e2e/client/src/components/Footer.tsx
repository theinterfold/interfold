// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { GithubLogoIcon } from '@phosphor-icons/react'

export const GITHUB_URL = 'https://github.com/theinterfold/interfold'
export const INTERFOLD_URL = 'https://theinterfold.com'

const Footer: React.FC = () => (
  <footer className='site-footer'>
    <div className='site-footer-grid'>
      <div className='site-footer-brand'>
        <p className='site-footer-wordmark'>
          <span>Sealed-bid</span>
          <span>auctions</span>
        </p>
      </div>
      <div className='site-footer-group site-footer-legal'>
        <p className='site-footer-label'>Elsewhere</p>
        <div className='site-footer-links flex flex-col gap-2'>
          <a href={INTERFOLD_URL} target='_blank' rel='noreferrer'>
            Secured with The Interfold
          </a>
          <a href={GITHUB_URL} target='_blank' rel='noreferrer'>
            <GithubLogoIcon size={16} /> GitHub
          </a>
        </div>
      </div>
      <p className='site-footer-copyright'>Demo on insecure parameters</p>
    </div>
  </footer>
)

export default Footer
