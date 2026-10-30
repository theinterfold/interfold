// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { type AuctionType, MAX_BIDDERS, MIN_BIDDERS } from '@interfold/auction-core'
import { designOf } from '@/utils/designs'

export const Mono: React.FC<{ children: React.ReactNode }> = ({ children }) => <span className='font-mono'>{children}</span>

/**
 * The headings of every explainer, in this order. A heading that does not apply to a type is left out,
 * but the order never changes.
 */
export const EXPLAINER_HEADINGS = {
  sends: 'Who sends what',
  computes: 'What the program computes',
  example: 'A worked example',
  reading: 'How the result is read',
  cannotFail: 'Why it cannot fail',
  leaks: 'What it leaks',
  trust: 'Whom you must trust',
} as const

/** One section of an explainer. */
export const Part: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className='space-y-3'>
    <h3 className='h3'>{title}</h3>
    {children}
  </div>
)

export const Prose: React.FC<{ children: React.ReactNode }> = ({ children }) => <p className='prose-ed max-w-3xl'>{children}</p>

export const Bullets: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <ul className='prose-ed max-w-3xl list-disc space-y-1 pl-6'>{children}</ul>
)

/** The first block of every explainer: one sentence on how the winner is found, then what the design reveals and whom it trusts. */
export const AtAGlance: React.FC<{ type: AuctionType; children: React.ReactNode }> = ({ type, children }) => {
  const design = designOf(type)
  return (
    <div className='card flat space-y-3'>
      <p className='mono muted'>{design.label} · at a glance</p>
      <Prose>{children}</Prose>
      <dl className='grid gap-4 text-sm sm:grid-cols-2'>
        <div>
          <dt className='meta muted'>What it reveals</dt>
          <dd className='mt-1'>{design.reveals}</dd>
        </div>
        <div>
          <dt className='meta muted'>Whom you must trust</dt>
          <dd className='mt-1'>{design.trust}</dd>
        </div>
      </dl>
    </div>
  )
}

/** The two rows of a bid, defined once for the three explainers. */
export const BidRows: React.FC = () => (
  <>
    <Mono>ge</Mono> and <Mono>gt</Mono> are rows of the bid. Each row has one slot for each price step. In <Mono>ge</Mono>, every step up to
    and including the bid is 1. In <Mono>gt</Mono>, every step below the bid is 1. All other slots are 0.
  </>
)

/** The sentence on the size of the auction. */
export const BidderLimit: React.FC = () => (
  <>
    The auction takes {MIN_BIDDERS} to {MAX_BIDDERS} bidders.
  </>
)

/** The sentence that says what "cannot fail" covers. */
export const FailureScope: React.FC = () => (
  <Prose>
    This covers the numbers only. The committee, the program and the chain can still fail. The progress list of an auction shows such a
    failure.
  </Prose>
)
