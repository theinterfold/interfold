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
    body: 'Your model update g ∈ [−1, 1]^d AND your private sample count nᵢ are encrypted and proven in this browser. The server and the chain only ever see ciphertext and proofs — neither the update nor the dataset size is revealed.',
  },
  {
    icon: Function,
    label: 'Weighted, not revealed',
    body: 'The network weights by the private counts HOMOMORPHICALLY — one ciphertext × ciphertext product per client, relinearized under the committee’s level-0 ceremony key, then summed. No intermediate is ever opened.',
  },
  {
    icon: ShieldCheck,
    label: 'Bounded by the circuit',
    body: 'The validity leg enforces the poisoning bound ‖g‖² ≤ B and 1 ≤ n < 1024 in exact fixed-point arithmetic. A poisoned update cannot dominate the mean, and a fake giant count cannot either.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'Client list, norm bound, minimum clients',
    body: 'The round opener registers the client list (your slot = your position), the public squared-norm bound ‖g‖² ≤ B every update must prove against (the poisoning bound) and the public minimum number of clients the server requires before it evaluates.',
  },
  {
    num: '02',
    title: 'Encrypt update + count, prove — in your browser',
    body: 'Your update g ∈ [−1, 1]^d is CKKS coefficient-encoded as gradient_block(g) (g_j at coefficient j+1, the constant 1 at d+1) and your sample count as constant(n) (coefficient 0), both encrypted here (WASM, ParamSet 5: N=512, 3 limbs, Δ=2⁴⁰); five UltraHonk proofs are generated locally. Update and count never leave this page.',
  },
  {
    num: '03',
    title: 'Submit from your wallet',
    body: 'publishInput is sent from your own key: the circuit’s public address must equal msg.sender, its index your registered slot, and its norm_bound the round’s. The contract verifies all five proofs on-chain (~5 M gas), one update per sender.',
  },
  {
    num: '04',
    title: 'Evaluate + open',
    body: 'Once at least the minimum number of clients has submitted, the program computes Σᵢ constant(nᵢ) × gradient_block(gᵢ) homomorphically — one ct × ct product per client under the level-0 key, one rescale — so coefficient j+1 opens as Σᵢ nᵢ·g_ij and coefficient d+1 as Σᵢ nᵢ. The weighted mean is their ratio.',
  },
]

export const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Private federated averaging on a threshold-CKKS committee</div>
            <h1 className="display headline">
              The network weights by <MarkerUnderline>dataset size</MarkerUnderline>
              <br />
              it never sees.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              True FedAvg where neither any client's update nor its dataset size is revealed. Each update and its private sample count are
              encrypted under a threshold CKKS key held by a five-node committee that runs no app logic: one DKG, one level-0
              relinearization-key ceremony, one threshold decryption of the sample-weighted aggregate.
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
              <span className="mono muted">Your update g, encrypted</span>
              <span className="tag">ParamSet 5 · N=512</span>
            </div>
            <Cipher seed={5} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">Your sample count nᵢ, encrypted</span>
              <span className="tag">1 ≤ n &lt; 1024</span>
            </div>
            <Cipher seed={1023} length={96} blockSize={4} />
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
      <SectionHeader num="01" kicker="PROTOCOL" title="Four steps, one opening" meta="1 ct×ct per client · level-0 key" />
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
            ct0 = pk0·u + e0 + m and ct1 = pk1·u + e1 per RNS limb for BOTH ciphertexts, with u/e bounded — each ciphertext really encrypts its
            committed message with fresh randomness (u_commitment shared across its two legs).
          </span>
        </div>
        <div className="card">
          <b>Coefficient layout (validity leg).</b>{' '}
          <span className="muted">
            The gradient message is exactly gradient_block(g) at Δ=2⁴⁰ (within the encoder's rounding slack, every other coefficient 0 — no
            hidden coordinate, no cross-term) and the count message is exactly constant(n) with 1 ≤ n &lt; 1024.
          </span>
        </div>
        <div className="card">
          <b>Bounded update.</b>{' '}
          <span className="muted">
            |g_j| ≤ 1 and Σ_j g_j² ≤ B in exact fixed-point integer arithmetic — a poisoned update cannot dominate the mean, and a fake giant
            count cannot either.
          </span>
        </div>
        <div className="card">
          <b>Why CKKS with a ceremony.</b>{' '}
          <span className="muted">
            Weighting by a PRIVATE count means multiplying two ciphertexts — constant(nᵢ) × gradient_block(gᵢ) — and therefore a
            relinearization key the committee generates jointly. What opens is the aggregate, never a client's share of it.
          </span>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Insecure demo parameters (N=512); 20 smudging bits vs the ~78 the calculator requires at λ=50.',
          'Cross-term mask hiding ratio is 2^10 (DEMO), not statistical.',
          'The published plaintext bytes are not bound to the C7 proof’s u_global (decode gap).',
          'RISC0 program-correctness is out of scope; the policy runs natively in program/.',
          'The aggregate (weighted sum + total count) is public once opened; with few clients this is the usual FedAvg leakage — with two clients one could subtract its own contribution. The server enforces the round’s minimum client count before evaluating; it is a public policy knob, not a differential-privacy guarantee.',
        ]}
      />
    </section>
  </>
)
