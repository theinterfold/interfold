// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Network pulse — small, low-emphasis footer strip.

export default function Pulse({ data }: { data: { activeNow: number; ballots24h: number; pollsAllTime: number } }) {
  return (
    <section className='pulse' aria-label='Network activity'>
      <div className='pulse__inner'>
        <div className='pulse__brand'>
          <span className='pulse__brand-mark' aria-hidden='true' />
          <span>Interfold network</span>
        </div>
        <div className='pulse__metrics'>
          <div className='pulse__metric'>
            <span className='pulse__metric-num mono'>{data.activeNow}</span>
            <span className='pulse__metric-label'>active E3{data.activeNow === 1 ? '' : 's'} right now</span>
          </div>
          <div className='pulse__metric'>
            <span className='pulse__metric-num mono'>{data.ballots24h.toLocaleString()}</span>
            <span className='pulse__metric-label'>encrypted ballots, last 24h</span>
          </div>
          <div className='pulse__metric'>
            <span className='pulse__metric-num mono'>{data.pollsAllTime.toLocaleString()}</span>
            <span className='pulse__metric-label'>CRISP polls, all-time</span>
          </div>
        </div>
        <div className='pulse__status'>
          <span className='pulse__status-dot' />
          <span>All systems nominal</span>
        </div>
      </div>
    </section>
  )
}
