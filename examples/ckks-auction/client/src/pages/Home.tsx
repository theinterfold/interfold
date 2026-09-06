// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'
import { Keyhole, Function, ShieldCheck } from '@phosphor-icons/react'
import { Cipher, HonestScope, MarkerUnderline, SectionHeader, ThresholdRow } from '@interfold/ckks-editorial'

const PRINCIPLES = [
  {
    icon: Keyhole,
    label: 'Sealed',
    body: 'Your bid is CKKS-encrypted and proven in this browser. The server, the chain and the committee only ever see ciphertext and proofs — the plaintext never leaves this page.',
  },
  {
    icon: Function,
    label: 'Ranked, not revealed',
    body: 'The network ranks ciphertexts: every i<j difference is driven through 12 cubic sign-extraction iterations, relinearised under ONE hybrid ceremony key. No intermediate is ever opened.',
  },
  {
    icon: ShieldCheck,
    label: 'Only the signs open',
    body: 'The committee threshold-decrypts a matrix of saturated ±1 comparison signs. The winner follows from it; no bid amount and no gap between bids ever does.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'Balance snapshot',
    body: 'The round opener publishes ONE Poseidon Merkle root of (address, balance) leaves — a balance attestation (CRISP’s token-holder model). Bidders fetch their own leaf + path from the server.',
  },
  {
    num: '02',
    title: 'Encrypt + prove — in your browser',
    body: 'The bid is CKKS-encrypted here (WASM, ParamSet 2: N=512, 38 limbs, Δ=2⁴⁰) and three UltraHonk proofs are generated locally. The plaintext never leaves this page.',
  },
  {
    num: '03',
    title: 'Submit from your wallet',
    body: 'publishInput is sent from the bidder’s own key: the circuit’s public address must equal msg.sender. The contract verifies all three proofs on-chain (~3 M gas) and rejects replays by u_commitment.',
  },
  {
    num: '04',
    title: 'Evaluate + open',
    body: 'All i<j differences are packed into one ciphertext and driven through 12 iterations of f(y)=(1.5−0.5y²)y using the committee’s ONE hybrid relin key (one ceremony serves all 24 multiplication levels). One threshold opening reveals only saturated ±1 signs.',
  },
]

export const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Sealed-bid auction on a threshold-CKKS committee</div>
            <h1 className="display headline">
              The network ranks <MarkerUnderline>ciphertexts</MarkerUnderline>.
              <br />
              Only the winner opens.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              Sealed bids, encrypted and proven in the browser. A five-node committee that runs no app logic ranks them with 12 cubic
              sign-extraction iterations relinearised under ONE hybrid ceremony key — depth 37 — and threshold-decrypts only the ±1 signs,
              never a bid amount.
            </p>
          </div>
          <ul className="col" style={{ gap: 18, listStyle: 'none', margin: 0, padding: 0 }}>
            {PRINCIPLES.map(({ icon: Icon, label, body }) => (
              <li key={label} className="row" style={{ alignItems: 'flex-start', gap: 16 }}>
                <Icon size={28} weight="light" style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <span className="accent" style={{ fontWeight: 600, marginRight: 8 }}>
                    {label}.
                  </span>
                  <span className="muted">{body}</span>
                </div>
              </li>
            ))}
          </ul>
          <div>
            <Link to="/rounds" className="btn lg" data-testid="go-rounds">
              Browse rounds →
            </Link>
          </div>
        </div>

        <div className="split-visual">
          <div className="card col" style={{ gap: 18 }}>
            <div className="between">
              <span className="mono muted">Your bid, encrypted</span>
              <span className="tag">ParamSet 2 · N=512 · 38 limbs</span>
            </div>
            <Cipher seed={2} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">Sign matrix, opened</span>
              <span className="tag">±1 only · depth 37</span>
            </div>
            <Cipher seed={37} length={96} blockSize={4} />
            <div className="hr-soft" />
            <div className="col" style={{ gap: 8 }}>
              <span className="mono muted">Threshold committee · n=5, t=1 · one hybrid relin ceremony</span>
              <ThresholdRow signed={5} total={5} />
            </div>
          </div>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <SectionHeader num="01" kicker="PROTOCOL" title="Four steps, one opening" meta="depth 37 · 1 hybrid ceremony" />
      <div className="grid-2" style={{ marginTop: 28 }}>
        {STEPS.map((s) => (
          <div key={s.num} className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Nº {s.num}</div>
            <div className="h3">{s.title}</div>
            <p className="muted" style={{ margin: 0 }}>
              {s.body}
            </p>
          </div>
        ))}
      </div>
    </section>

    <section className="pad-section">
      <SectionHeader num="02" kicker="PROOFS" title="What the three proofs establish" meta="Greco ×2 + validity" />
      <div className="col" style={{ gap: 16, marginTop: 28 }}>
        <div className="card">
          <b>Well-formed encryption (Greco, 2 legs).</b>{' '}
          <span className="muted">
            ct0 = pk0·u + e0 + Δm and ct1 = pk1·u + e1 per RNS limb, with u/e bounded — the ciphertext really encrypts the committed message,
            with fresh randomness (u_commitment shared across both legs).
          </span>
        </div>
        <div className="card">
          <b>Slot replication.</b>{' '}
          <span className="muted">
            The message polynomial is a constant in every one of the N/2 slots (its tail coefficients are ≤ 64), which the one-hot pair
            packing requires — a non-replicated ciphertext is rejected by the proof.
          </span>
        </div>
        <div className="card">
          <b>bid ≤ balance.</b>{' '}
          <span className="muted">
            The same message (bound by m_commitment) encodes bid/cap with bid ≤ balance, where poseidon(address, balance) opens to the
            round’s published root.
          </span>
        </div>
        <div className="card">
          <b>Sender binding.</b>{' '}
          <span className="muted">
            address is a public input; the contract requires it to equal msg.sender, so a proof cannot be reused by anyone else.
          </span>
        </div>
        <div className="card">
          <b>What is and is not hidden.</b>{' '}
          <span className="muted">
            Not hidden: who bid (publisher address), how many bids, and the full comparison order among bidders. Hidden: every bid value and
            every gap between bids — slots that would carry magnitude are binarised to exactly ±1.
          </span>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Insecure demo parameters (N=512); a depth-37 circuit fits only N=65536 at 128-bit security — this stack is a sizing input, not a security claim.',
          'C-5 flooding gap: the decryption-share smudging noise is far below what the calculator requires for this depth.',
          'The published plaintext bytes are not yet bound to the proof’s reconstructed ring element (decode gap).',
          'RISC0 program-correctness is out of scope; the ranking policy runs natively in program/.',
        ]}
      />
    </section>
  </>
)
