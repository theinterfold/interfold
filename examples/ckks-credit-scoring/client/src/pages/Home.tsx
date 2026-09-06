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
    label: 'Private',
    body: 'Your issuer-attested features, the logit and your output mask are encrypted and proven in this browser. The server and the chain only ever see ciphertext and proofs.',
  },
  {
    icon: Function,
    label: 'Computed, not revealed',
    body: 'The network evaluates the sigmoid on the ENCRYPTED logit — two ciphertext × ciphertext products under jointly generated relinearization keys. No intermediate is ever opened.',
  },
  {
    icon: ShieldCheck,
    label: 'Only you can read it',
    body: 'The committee threshold-decrypts a masked probability σ(z) + m. Without your mask, kept in this browser, that number says nothing to anyone.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'Issuer snapshot, public model, applicant list',
    body: 'The round opener registers one Poseidon Merkle root of (address, x₀..x₇) leaves — the issuer’s attestation of each applicant’s 8 features — the public logistic model (w, b) in ×2¹⁶ fixed point, and the applicant list. Your slot is your position.',
  },
  {
    num: '02',
    title: 'Encrypt logit + mask, prove — in your browser',
    body: 'You compute z = ⟨w, x⟩/cap + b locally and pick a secret mask m ∈ [0, 1024). Both are CKKS slot-encoded at your slot and encrypted here (WASM, ParamSet 4: N=512, 5 limbs, Δ=2⁴⁰); five UltraHonk proofs are generated locally.',
  },
  {
    num: '03',
    title: 'Submit from your wallet',
    body: 'publishInput is sent from your own key: the proof’s public address must equal msg.sender, its index your registered slot, its model words the registered model. The contract verifies all five proofs on-chain.',
  },
  {
    num: '04',
    title: 'Evaluate + open',
    body: 'The program computes σ(z) ≈ 0.5 + 0.197z − 0.004z³ homomorphically, slot-wise, and adds your mask. Slot i of ONE ciphertext opens as σ(zᵢ) + mᵢ. You subtract m and read σ(z).',
  },
]

export const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Private credit scoring on a threshold-CKKS committee</div>
            <h1 className="display headline">
              The network computes <MarkerUnderline>σ</MarkerUnderline>.
              <br />
              Only you can read it.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              A logistic score over your attested features, evaluated on ciphertext by a five-node committee that runs no app logic: one
              DKG, two relinearization-key ceremonies, one threshold decryption of a masked result.
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
              Open the rounds →
            </Link>
          </div>
        </div>

        <div className="split-visual">
          <div className="card col" style={{ gap: 18 }}>
            <div className="between">
              <span className="mono muted">Your logit, encrypted</span>
              <span className="tag">ParamSet 4 · N=512</span>
            </div>
            <Cipher seed={4} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">Your mask, encrypted</span>
              <span className="tag">m ∈ [0, 1024)</span>
            </div>
            <Cipher seed={1024} length={96} blockSize={4} />
            <div className="hr-soft" />
            <div className="col" style={{ gap: 8 }}>
              <span className="mono muted">Threshold committee · n=5, t=1</span>
              <ThresholdRow signed={5} total={5} />
            </div>
          </div>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <SectionHeader num="01" kicker="PROTOCOL" title="Four steps, one opening" meta="depth 2 · 2 ceremonies" />
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
      <SectionHeader num="02" kicker="PROOFS" title="What the five proofs establish" meta="Greco ×4 + validity" />
      <div className="col" style={{ gap: 16, marginTop: 28 }}>
        <div className="card">
          <b>Well-formed encryptions (Greco, 2 × 2 legs).</b>{' '}
          <span className="muted">
            ct0 = pk0·u + e0 + m and ct1 = pk1·u + e1 per RNS limb for both ciphertexts, with u/e bounded — each ciphertext really encrypts its
            committed message with fresh randomness.
          </span>
        </div>
        <div className="card">
          <b>Slot encoding (credit leg).</b>{' '}
          <span className="muted">
            The logit message is the slot-index encoding of (Σ Wⱼxⱼ + B·cap) / (2¹⁶·cap) under the registered model, the mask message the encoding
            of mask/2¹⁰ &lt; 1024 — checked on every coefficient within a slack that forces every other slot to 0.
          </span>
        </div>
        <div className="card">
          <b>Attested features.</b>{' '}
          <span className="muted">
            poseidon(address, x₀..x₇) opens to the round’s issuer root with xⱼ ≤ cap; the address is bound to msg.sender on-chain. Nobody can score
            a fabricated vector or a model of their choosing.
          </span>
        </div>
        <div className="card">
          <b>Why CKKS with a ceremony.</b>{' '}
          <span className="muted">
            The sigmoid runs on the encrypted logit, so what opens is a probability — not a linear score anyone could invert. That needs ct × ct
            products and therefore a relinearization key the committee generates jointly.
          </span>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Insecure demo parameters (N=512); the calculator requires ~112 smudging bits at λ=50 for this depth, the demo uses 20.',
          'The published plaintext bytes are not yet bound to the C7 proof’s reconstructed ring element (decode gap).',
          'RISC0 program-correctness is out of scope; the policy runs natively in program/.',
          'Only RISC0 and the fee token are mocked; every other proof on this page is real and verified on-chain.',
        ]}
      />
    </section>
  </>
)
