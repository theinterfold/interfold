// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect } from 'react'
import type { AppProps } from 'next/app'
import 'katex/dist/katex.min.css'
import '../styles/globals.css'

// When a sidebar folder is expanded, scroll its submenu into view so the
// newly revealed sub-pages are visible (Nextra doesn't do this by default,
// which hides children of folders sitting at the bottom of the sidebar).
function useSidebarAutoScroll() {
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null
      const btn = target?.closest('.nextra-sidebar-container button')
      if (!btn) return
      const li = btn.closest('li')
      if (!li) return
      // Wait for the expand/collapse animation to settle, then, if the folder
      // is now open, bring its last child into view.
      window.setTimeout(() => {
        const submenu = li.querySelector('ul')
        if (submenu && submenu.getBoundingClientRect().height > 0) {
          const last = (submenu.lastElementChild as HTMLElement | null) ?? submenu
          last.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        }
      }, 220)
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [])
}

function App({ Component, pageProps }: AppProps) {
  useSidebarAutoScroll()
  return (
    <>
      <Component {...pageProps} />
    </>
  )
}

export default App
