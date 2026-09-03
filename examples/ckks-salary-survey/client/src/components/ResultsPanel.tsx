// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round } from '@interfold/ckks-salary-sdk'
import { fmtMoney, EXPLORER_TX } from '@/utils/constants'

export const ResultsPanel = ({ round }: { round: Round }) => {
  const r = round.results
  if (!r) return null
  return (
    <section className="card results" data-testid="results">
      <h3>Results</h3>
      <div className="stats">
        <div>
          <div className="label">participants</div>
          <div className="value" data-testid="result-count">{r.count}</div>
        </div>
        <div>
          <div className="label">mean</div>
          <div className="value" data-testid="result-mean">{fmtMoney(r.mean)}</div>
        </div>
        <div>
          <div className="label">variance</div>
          <div className="value" data-testid="result-variance">{fmtMoney(r.variance)}</div>
        </div>
        <div>
          <div className="label">std. deviation</div>
          <div className="value" data-testid="result-stddev">{fmtMoney(r.stddev)}</div>
        </div>
      </div>
      <p className="muted">
        The committee opened exactly <b>two numbers</b>: slot 0 = S·Σ(salary/cap) = {r.opened_slots[0]} and slot 1 =
        S·Σ(salary/cap)² = {r.opened_slots[1]}. <b>Individual salaries were never decrypted.</b> Mean, variance and
        standard deviation are derived from those two aggregates and the public count.
      </p>
      {round.evaluation?.publish_tx_hash && (
        <div className="muted">
          ciphertext output tx{' '}
          {EXPLORER_TX ? (
            <a href={`${EXPLORER_TX}${round.evaluation.publish_tx_hash}`} target="_blank" rel="noreferrer">
              {round.evaluation.publish_tx_hash}
            </a>
          ) : (
            <code>{round.evaluation.publish_tx_hash}</code>
          )}{' '}
          · evaluated in {round.evaluation.eval_millis} ms
        </div>
      )}
      <div className="muted">
        on-chain plaintext <code>{r.plaintext_hex}</code>
      </div>
    </section>
  )
}
