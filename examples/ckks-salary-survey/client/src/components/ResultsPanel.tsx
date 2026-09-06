// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Round } from '@interfold/ckks-salary-sdk'
import { HonestScope, ResultCard, SectionHeader } from '@interfold/ckks-editorial'
import { fmtMoney, EXPLORER_TX } from '@/utils/constants'

export const ResultsPanel = ({ round }: { round: Round }) => {
  const r = round.results
  if (!r) return null
  return (
    <section className="pad-section" data-testid="results">
      <SectionHeader
        num="04"
        kicker="OPENED"
        title="One ciphertext, threshold-decrypted"
        meta={
          <>
            <span data-testid="result-count">{r.count}</span> participants · slot 0 + slot 1
          </>
        }
      />
      <div className="grid-3" style={{ marginTop: 24 }}>
        <ResultCard
          label="Mean salary"
          value={<span data-testid="result-mean">{fmtMoney(r.mean)}</span>}
          caption={<>cap · S·Σ(salary/cap) / n — from slot 0 = {r.opened_slots[0]}</>}
          reveals="The average over every participant."
          hides="Any individual salary."
        />
        <ResultCard
          label="Variance"
          value={<span data-testid="result-variance">{fmtMoney(r.variance)}</span>}
          caption={<>Σx²/n − mean² — from slot 1 = {r.opened_slots[1]} (relinearised ct×ct)</>}
          reveals="The spread of the population."
          hides="Who sits where in it."
        />
        <ResultCard
          label="Std. deviation"
          value={<span data-testid="result-stddev">{fmtMoney(r.stddev)}</span>}
          caption="√variance — derived locally from the two opened aggregates."
          reveals="A second-moment summary."
          hides="Every ciphertext the committee received."
        />
      </div>
      <div className="grid-2" style={{ marginTop: 24 }}>
        <HonestScope
          items={[
            <>
              The committee opened exactly <b>two numbers</b>: slot 0 = S·Σ(salary/cap) = {r.opened_slots[0]} and slot 1 = S·Σ(salary/cap)² ={' '}
              {r.opened_slots[1]}. <b>Individual salaries were never decrypted.</b>
            </>,
            'Mean, variance and standard deviation are derived from those two aggregates and the public count.',
            'The smudging noise in the opened aggregates is truncated to 2 decimals so the on-chain bytes are reproducible.',
          ]}
        />
        <div className="card col" style={{ gap: 10 }}>
          <div className="mono muted">On-chain record</div>
          {round.evaluation?.publish_tx_hash && (
            <div className="mono-sm" style={{ wordBreak: 'break-all' }}>
              ciphertext output tx{' '}
              {EXPLORER_TX ? (
                <a href={`${EXPLORER_TX}${round.evaluation.publish_tx_hash}`} target="_blank" rel="noreferrer">
                  {round.evaluation.publish_tx_hash}
                </a>
              ) : (
                <span className="mono">{round.evaluation.publish_tx_hash}</span>
              )}{' '}
              · evaluated in {round.evaluation.eval_millis} ms
            </div>
          )}
          <div className="mono-sm" style={{ wordBreak: 'break-all' }}>
            on-chain plaintext <span className="mono">{r.plaintext_hex}</span>
          </div>
        </div>
      </div>
    </section>
  )
}
