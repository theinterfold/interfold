// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { WarningIcon } from '@phosphor-icons/react'
import { LEVELS_MAX, MAX_BIDDERS, MAX_BUDGET_UNITS, MAX_TIERS, MIN_LEVELS } from '@interfold/token-launch'
import { GITHUB_URL } from '@/components/Footer'

const LIFECYCLE = [
  [
    'Create',
    `The creator picks a sale token, a supply, a payment token, ${MIN_LEVELS} to ${LEVELS_MAX} price steps, a budget unit and up to ${MAX_TIERS} escrow tiers. The creator requests two E3 runs (round 1 and round 2) and pays two Interfold fees.`,
  ],
  [
    'Committee keys',
    'A committee of ciphernodes makes one public key for each round. No node holds a whole secret key. Bids open when both keys exist.',
  ],
  [
    'Bid',
    'The bidder picks an escrow tier, a private budget and a private max price step. The browser encrypts the bid twice, once for each round, and proves in one proof that both ciphertexts are valid. The bidder saves a secret file. The contract locks the tier amount.',
  ],
  [
    'Round 1',
    'The bidding window closes. The program adds all round 1 ciphertexts. It never decrypts a single bid. The committee decrypts the sums of budgets at a few price steps. The sums also show which bids counted.',
  ],
  [
    'Probing',
    'The contract reads the round 1 sums. It finds the range where the clearing price must be. It then asks for a few more price steps inside that range.',
  ],
  [
    'Round 2',
    'The program adds all round 2 ciphertexts and the committee decrypts the sums at the new price steps. These sums fix the clearing price.',
  ],
  ['Clear', 'The contract sets one clearing price for all bidders and stores the root of the claim tree.'],
  [
    'Claim',
    'Each bidder opens the claim page and picks a fresh address. The browser proves that the bidder has a counted bid in the tree. The relayer sends the claim. The fresh address gets the tokens and the refund. Nothing links the fresh address to the bid. A bid at the clearing step of a capped sale takes the extra steps in the next section.',
  ],
] as const

const PARTIES = [
  [
    'Everyone on the chain',
    [
      'The address, the escrow tier and the time of each bid',
      'Two ciphertexts per bid (not readable)',
      'The budget sums at the probe price steps, not the full demand curve',
      'The clearing price, the clearing step and the total sold',
      'Which bids counted',
      'For each claim: the escrow tier, the class (below, at or above the clearing step), the nullifier, the fresh address and the amounts',
      'For a winning claim: the budget of the winner, but not its bid address or max price',
      'For a claim at the clearing step (a capped sale): the bid index, the budget and the recipient. See the limits below',
    ],
  ],
  [
    'The committee',
    [
      'Only what is public: the masked sums and the counted bitmap',
      'No single bid. A threshold of nodes must work together to decrypt, and a node that is alone learns nothing',
    ],
  ],
  ['The creator', ['The same as everyone on the chain. The creator does not see any budget or max price before the end.']],
  [
    'The relayer',
    [
      'The IP address of the browser and the data of the bid or the claim',
      'It cannot change a bid or a claim: the signature and the proof fix every field',
      'It cannot link a claim to a bid',
    ],
  ],
  ['The bidder', ['Its own secret: the salt, the budget, the max price step and the index. Keep it safe. It is the only way to claim.']],
] as const

const HIDDEN = [
  'The max price step of each bid. Winners and losers never reveal it.',
  'The budget of each bid until a claim of a winner. A loser never reveals its budget.',
  'Which claim belongs to which bid.',
  'The demand at the price steps that the search does not probe.',
]

const Block: React.FC<{ eyebrow: string; title: string; children: React.ReactNode }> = ({ eyebrow, title, children }) => (
  <section className='space-y-5'>
    <div className='space-y-2'>
      <p className='mono muted'>{eyebrow}</p>
      <h2 className='h2'>{title}</h2>
      <div className='hr' />
    </div>
    {children}
  </section>
)

const About: React.FC = () => (
  <div className='page space-y-14'>
    <header className='max-w-3xl space-y-5'>
      <p className='mono muted'>How it works</p>
      <h1 className='h1'>A private token launch: what each party learns</h1>
      <p className='lede'>
        A bidder gives a budget and a max price. Both stay private. The sale clears at one price. A claim goes to a fresh address, and
        nobody can link it to the bid.
      </p>
    </header>

    <Block eyebrow='Nº 01' title='The privacy model'>
      <div className='grid gap-5 md:grid-cols-2'>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Private bids</p>
          <p className='text-sm text-ink-2'>
            A bid has a budget (1 to {MAX_BUDGET_UNITS} budget units) and a max price step. The browser encrypts both. The program only adds
            ciphertexts. It does not multiply them.
          </p>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Probe search</p>
          <p className='text-sm text-ink-2'>
            The clearing price needs the sum of budgets at a few price steps. The sale finds them in two rounds. Round 1 reveals a few sums.
            Round 2 reveals a few more, only inside the range that remains. The committee never reveals the full demand curve.
          </p>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono muted'>One price</p>
          <p className='text-sm text-ink-2'>
            Every winner pays the same clearing price. No bidder pays more than its budget. No bidder pays more per token than its max
            price. The contract refunds the rest of the escrow.
          </p>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Unlinkable claims</p>
          <p className='text-sm text-ink-2'>
            A claim proof shows that a counted bid exists in the claim tree and that its nullifier is new. It does not show which bid. The
            payout goes to the address in the proof.
          </p>
        </div>
      </div>
    </Block>

    <Block eyebrow='Nº 02' title='What each party learns'>
      <div className='space-y-4'>
        {PARTIES.map(([party, items]) => (
          <div key={party} className='card flat space-y-2'>
            <p className='mono-sm muted'>{party}</p>
            <ul className='list-disc space-y-1 pl-5 text-sm'>
              {items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className='card space-y-2'>
        <p className='mono-sm text-accent'>What stays hidden</p>
        <ul className='list-disc space-y-1 pl-5 text-sm'>
          {HIDDEN.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
      <p className='prose-ed max-w-3xl'>
        <strong>Limits.</strong> The claim shows the escrow tier. A winning claim also shows the budget. A claim at the clearing step also
        shows the bid index and the recipient. If only one bidder has that tier and budget, an observer can guess the bid. Pick a common
        tier. Claim in a separate session, with a fresh address and no wallet link. The relayer hides the gas payer, not your network
        address.
      </p>
    </Block>

    <Block eyebrow='Nº 03' title='Life of a sale'>
      <ol className='steps'>
        {LIFECYCLE.map(([title, body], index) => (
          <li key={title} className='step done'>
            <span className='pin'>{index + 1}</span>
            <div>
              <p className='font-semibold'>{title}</p>
              <p className='text-sm text-ink-2'>{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </Block>

    <Block eyebrow='Nº 04' title='Bids at the clearing step'>
      <p className='prose-ed max-w-3xl'>
        In a capped sale, bids above the clearing step get their full tokens. Bids below it get nothing. Bids at the clearing step share the
        tokens that are left, and the supply may not cover all of them. The sale fills these bids in bid order: the earliest bid fills
        first, and later bids get a refund when the tokens run out.
      </p>
      <p className='prose-ed max-w-3xl'>
        Bid order is public, so a bidder at the clearing step must register its claim. A registration shows the bid index, the budget and
        the recipient. It links the bid address to the recipient. The registration window lasts three days from the clearing. After it,
        anyone can pay the registered claims, and the keeper does it too. A bid at the clearing step that does not register in time gets its
        escrow back and no tokens. Bids above and below the step stay unlinkable.
      </p>
    </Block>

    <Block eyebrow='Nº 05' title='Failed and dropped bids'>
      <p className='prose-ed max-w-3xl'>
        A bid counts only if its ciphertext opens its commitment in both rounds. If a bid does not count, anyone can refund its escrow to
        the bidder after the sale clears. If either E3 run fails, or the probe search finds a bad output, the sale stops. Each bidder then
        gets its escrow back and the creator gets the supply back.
      </p>
    </Block>

    <div role='note' className='note warn flex gap-3'>
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warm' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app uses the development preset of the encryption scheme. The ring is small (N = 128). It is fast enough to prove in a
          browser. It is not secure. Never use it for bids that matter. A sale takes at most {MAX_BIDDERS} bids.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn lg'>
        Create a sale
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
