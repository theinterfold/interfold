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
  <footer className='footer'>
    <span>Sealed-Bid Auctions</span>
    <span>Demo on insecure parameters</span>
    <div className='links'>
      <a href={INTERFOLD_URL} target='_blank' rel='noreferrer'>
        Secured with The Interfold
      </a>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='inline-flex items-center gap-2'>
        <GithubLogoIcon size={16} /> GitHub
      </a>
    </div>
  </footer>
)

export default Footer
