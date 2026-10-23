// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { SetupError, type Profile } from '@designs'
import { MAX_BIDDERS, MIN_BIDDERS, maxBidders } from '../lib/simulate'

interface ErrorNoteProps {
  error: Error
  design: string
  profile: Profile
  levels: number
}

/** A setup that the profile cannot hold, with the largest bidder count that it can hold. */
export function ErrorNote({ error, design, profile, levels }: ErrorNoteProps) {
  const limit = error instanceof SetupError ? maxBidders(design, profile, levels) : null
  return (
    <div className='note bad flex flex-col gap-2' role='alert'>
      <div className='flex flex-wrap items-center gap-2'>
        <span className='tag bad'>{error instanceof SetupError ? error.kind : 'error'}</span>
        <strong>{design} cannot run this auction.</strong>
      </div>
      <div>{error.message}</div>
      {error instanceof SetupError && (
        <div className='text-[13px]'>
          {limit === null
            ? `With ${levels} levels on the ${profile} profile, this design cannot run for any bidder count from ${MIN_BIDDERS} to ${MAX_BIDDERS}.`
            : `With ${levels} levels on the ${profile} profile, this design runs for up to ${limit} bidders.`}
        </div>
      )}
    </div>
  )
}
