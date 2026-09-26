// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect } from 'react'
import type { AppProps } from 'next/app'
import Router from 'next/router'
import 'katex/dist/katex.min.css'
import '../styles/globals.css'

const SIDEBAR_SCROLL_KEY = 'nextra-sidebar-scroll'

function getSidebarScrollEl(): HTMLElement | null {
  return document.querySelector('.nextra-sidebar-container .nextra-scrollbar')
}

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

// Nextra auto-scrolls the sidebar to center the active item on every page
// mount. For items near the bottom of a long sidebar (e.g. FOLD Token),
// this pushes them off-screen whenever the active page is near the top.
// Fix: save the scroll position before navigation and restore it after
// Nextra's scroll has run.
function useSidebarScrollMemory() {
  useEffect(() => {
    // Restore saved position after Nextra's scrollIntoView settles (2 rAF frames)
    const saved = sessionStorage.getItem(SIDEBAR_SCROLL_KEY)
    if (saved !== null) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          const el = getSidebarScrollEl()
          if (el) el.scrollTop = parseInt(saved, 10)
        })
      })
    }

    // Save position when the user clicks a sidebar page link
    const onLinkClick = (e: MouseEvent) => {
      const anchor = (e.target as HTMLElement)?.closest('a')
      if (!anchor?.closest('.nextra-sidebar-container')) return
      const el = getSidebarScrollEl()
      if (el) sessionStorage.setItem(SIDEBAR_SCROLL_KEY, String(el.scrollTop))
    }
    document.addEventListener('click', onLinkClick, true)
    return () => document.removeEventListener('click', onLinkClick, true)
  }, [])
}

// Pages keep every tab panel in the DOM (`<Tabs.Tab unmount={false}>`), so the table of contents
// can link to a heading inside a tab that is not selected. When the URL hash or an in-page link
// points to such a heading, select its tab first and then scroll to the heading.
function useOpenTabForHash() {
  useEffect(() => {
    const open = (hash: string) => {
      if (hash.length < 2) return
      const target = document.getElementById(decodeURIComponent(hash.slice(1)))
      const panel = target?.closest<HTMLElement>('[role="tabpanel"]')
      if (!target || !panel || getComputedStyle(panel).display !== 'none') return
      const tabId = panel.getAttribute('aria-labelledby')
      const tab = tabId ? document.getElementById(tabId) : null
      if (!tab) return
      tab.click()
      requestAnimationFrame(() => requestAnimationFrame(() => target.scrollIntoView({ block: 'start' })))
    }
    // Headless UI sets the default tab while the page hydrates. Wait for that before selecting.
    const onHashChange = () => window.setTimeout(() => open(window.location.hash), 200)
    const onClick = (event: MouseEvent) => {
      const anchor = (event.target as HTMLElement | null)?.closest('a')
      const href = anchor?.getAttribute('href')
      if (href?.startsWith('#')) window.setTimeout(() => open(href), 0)
    }
    onHashChange()
    window.addEventListener('hashchange', onHashChange)
    document.addEventListener('click', onClick)
    Router.events.on('routeChangeComplete', onHashChange)
    return () => {
      window.removeEventListener('hashchange', onHashChange)
      document.removeEventListener('click', onClick)
      Router.events.off('routeChangeComplete', onHashChange)
    }
  }, [])
}

function App({ Component, pageProps }: AppProps) {
  useSidebarAutoScroll()
  useSidebarScrollMemory()
  useOpenTabForHash()
  return (
    <>
      <Component {...pageProps} />
    </>
  )
}

export default App
