// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { socialLinks } from '../SocialLinks'
import Link from 'next/link'
import classes from './Footer.module.css'

const Footer = () => {
  return (
    <footer style={{ padding: '3rem', textAlign: 'center', color: '#B8B8B8' }}>
      {/* <img
        src='/interfold-mark-glow.svg'
        style={{
          opacity: 0.3,
          margin: '0 auto',
          maxWidth: '200px',
          marginBottom: '1rem',
        }}
      /> */}
      <p>{new Date().getFullYear()} © The Interfold</p>
      <ul className={classes.socialLinks}>
        {socialLinks.map(({ name, icon, url }, i) => {
          return (
            <li key={i}>
              <Link href={url} id={name} target='_blank'>
                {icon}
              </Link>
            </li>
          )
        })}
      </ul>
    </footer>
  )
}

export default Footer
