// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { CompareTable } from './components/CompareTable'
import { Overview } from './components/Overview'
import { Playground } from './components/Playground'
import { defaultParams, toScenario, updateParams, type Params } from './lib/params'

export function App() {
  const [params, setParams] = useState<Params>(defaultParams)
  const [design, setDesign] = useState('vickrey')

  const change = (patch: Partial<Params>) => setParams((old) => updateParams(old, patch))
  const open = (name: string) => {
    setDesign(name)
    document.getElementById('playground')?.scrollIntoView()
  }

  return (
    <>
      <header className='topbar'>
        <span className='brand'>
          <span className='glyph' />
          Interfold · Auction designs
        </span>
        <nav className='topnav'>
          <a href='#overview'>Overview</a>
          <a href='#playground'>Playground</a>
          <a href='#compare'>Compare</a>
        </nav>
      </header>

      <main className='page flex flex-col gap-16'>
        <div className='flex flex-col gap-5'>
          <span className='mono text-accent'>Sealed-bid auctions · l-BFV</span>
          <h1 className='display'>
            Ten ways to <em>count bids</em> in the dark
          </h1>
          <p className='lede m-0'>Plaintext simulation: nothing is encrypted. See what each design sends, computes, and reveals.</p>
        </div>

        <Overview profile={params.profile} bidders={params.bidders} levels={params.levels} selected={design} onOpen={open} />
        <Playground params={params} design={design} onChange={change} onDesign={setDesign} />
        <CompareTable scenario={toScenario(params)} selected={design} onOpen={open} />
      </main>

      <footer className='footer'>
        <span>Values are simulated slots in the clear. The parameters are toy parameters. This is not secure.</span>
      </footer>
    </>
  )
}
