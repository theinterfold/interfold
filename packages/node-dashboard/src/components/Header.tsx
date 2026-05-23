// SPDX-License-Identifier: LGPL-3.0-only

interface HeaderProps {
  nodeName: string
  e3Count: number
  eventCount: number
  connected: boolean | null
}

export default function Header({ nodeName, e3Count, eventCount, connected }: HeaderProps) {
  const pillCls = `conn-pill${connected === true ? ' on' : ''}`
  const label = connected === null ? 'Connecting' : connected ? 'Live' : 'Disconnected'

  return (
    <header className='hdr'>
      <div className='wordmark'>
        <div className='wordmark-icon'>
          <svg viewBox='0 0 16 16' stroke='#fff' strokeWidth='1.6' strokeLinejoin='round' fill='none'>
            <polygon points='8,1.5 13.5,4.75 13.5,11.25 8,14.5 2.5,11.25 2.5,4.75' />
          </svg>
        </div>
        Enclave
      </div>
      <div className='hdr-sep' />
      <div className='hdr-node'>{nodeName}</div>
      <div className='hdr-right'>
        <span className='hdr-stat'>
          <b>{e3Count}</b> E3s
        </span>
        <span className='hdr-stat'>
          <b>{eventCount}</b> events
        </span>
        <div className={pillCls}>
          <div className='live-dot' />
          <span>{label}</span>
        </div>
      </div>
    </header>
  )
}
