// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round } from '@interfold/ckks-salary-sdk'
import { SectionHeader } from '@interfold/ckks-editorial'
import { short, EXPLORER_TX } from '@/utils/constants'

export const SubmissionsTable = ({ round }: { round: Round }) => (
  <section className="pad-section">
    <SectionHeader
      num="03"
      kicker="LEDGER"
      title={
        <>
          Verified submissions{' '}
          <span className="tag" data-testid="submission-count">
            {round.submissions.length}
          </span>
        </>
      }
      meta={`${round.submissions.length} verified on-chain`}
    />
    {round.submissions.length === 0 ? (
      <p className="muted" style={{ marginTop: 20 }}>
        None yet.
      </p>
    ) : (
      <table className="ledger" style={{ marginTop: 20 }} data-testid="submissions">
        <thead>
          <tr>
            <th>#</th>
            <th>u_commitment</th>
            <th>tx</th>
            <th>gas</th>
            <th>verified</th>
          </tr>
        </thead>
        <tbody>
          {round.submissions.map((s) => (
            <tr key={s.u_commitment}>
              <td className="mono">{s.index}</td>
              <td className="mono">{short(s.u_commitment, 12)}</td>
              <td className="mono">
                {EXPLORER_TX ? (
                  <a href={`${EXPLORER_TX}${s.tx_hash}`} target="_blank" rel="noreferrer">
                    {short(s.tx_hash, 10)}
                  </a>
                ) : (
                  short(s.tx_hash, 10)
                )}
              </td>
              <td className="mono">{s.gas_used?.toLocaleString() ?? '—'}</td>
              <td>{s.verified ? <span className="tag live">verified on-chain</span> : <span className="tag pending">pending</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )}
  </section>
)
