// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round } from '@interfold/ckks-salary-sdk'
import { short, EXPLORER_TX } from '@/utils/constants'

export const SubmissionsTable = ({ round }: { round: Round }) => (
  <section className="card">
    <h3>
      Verified submissions <span className="badge" data-testid="submission-count">{round.submissions.length}</span>
    </h3>
    {round.submissions.length === 0 ? (
      <p className="muted">None yet.</p>
    ) : (
      <table className="subs" data-testid="submissions">
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
              <td>{s.index}</td>
              <td>
                <code>{short(s.u_commitment, 12)}</code>
              </td>
              <td>
                {EXPLORER_TX ? (
                  <a href={`${EXPLORER_TX}${s.tx_hash}`} target="_blank" rel="noreferrer">
                    {short(s.tx_hash, 10)}
                  </a>
                ) : (
                  <code>{short(s.tx_hash, 10)}</code>
                )}
              </td>
              <td>{s.gas_used?.toLocaleString() ?? '—'}</td>
              <td>{s.verified ? '✓ on-chain' : '…'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )}
  </section>
)
