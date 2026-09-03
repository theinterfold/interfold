// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'

export const Home = () => (
  <>
    <h1>Sealed-bid auction with a leak-free winner</h1>
    <p className="muted">
      Bids are encrypted under a threshold CKKS key held by a 5-node Interfold committee. The committee never learns a
      bid: the only value it ever decrypts is a matrix of <b>±1 comparison signs</b>.
    </p>

    <div className="grid">
      <div className="panel">
        <h3>1 · Snapshot</h3>
        <p>
          The round opener publishes ONE Poseidon Merkle root of <span className="mono">(address, balance)</span> leaves — a
          balance attestation (CRISP's token-holder model). Bidders fetch their own leaf + path from the server.
        </p>
      </div>
      <div className="panel">
        <h3>2 · Encrypt + prove — in your browser</h3>
        <p>
          The bid is CKKS-encrypted here (WASM, ParamSet 2: N=512, 38 limbs, Δ=2⁴⁰) and three UltraHonk proofs are generated
          locally. The plaintext never leaves this page.
        </p>
      </div>
      <div className="panel">
        <h3>3 · Submit from your wallet</h3>
        <p>
          <span className="mono">publishInput</span> is sent from the bidder's own key: the circuit's public{' '}
          <span className="mono">address</span> must equal <span className="mono">msg.sender</span>. The contract verifies all
          three proofs on-chain (~3 M gas) and rejects replays by <span className="mono">u_commitment</span>.
        </p>
      </div>
      <div className="panel">
        <h3>4 · Evaluate + open</h3>
        <p>
          All i&lt;j differences are packed into one ciphertext and driven through 12 iterations of{' '}
          <span className="mono">f(y)=(1.5−0.5y²)y</span> using the committee's ONE hybrid relin key (one ceremony serves all 24 multiplication levels). One threshold opening
          reveals only saturated ±1 signs.
        </p>
      </div>
    </div>

    <h2>What the proof proves</h2>
    <div className="panel">
      <ul>
        <li>
          <b>Well-formed encryption (Greco, 2 legs)</b>: <span className="mono">ct0 = pk0·u + e0 + Δm</span> and{' '}
          <span className="mono">ct1 = pk1·u + e1</span> per RNS limb, with u/e bounded — the ciphertext really encrypts the
          committed message, with fresh randomness (<span className="mono">u_commitment</span> shared across both legs).
        </li>
        <li>
          <b>Slot replication</b>: the message polynomial is a constant in every one of the N/2 slots (its tail coefficients
          are ≤ 64), which the one-hot pair packing requires — a non-replicated ciphertext is rejected by the proof.
        </li>
        <li>
          <b>bid ≤ balance</b>: the same message (bound by <span className="mono">m_commitment</span>) encodes{' '}
          <span className="mono">bid/cap</span> with <span className="mono">bid ≤ balance</span>, where{' '}
          <span className="mono">poseidon(address, balance)</span> opens to the round's published root.
        </li>
        <li>
          <b>Sender binding</b>: <span className="mono">address</span> is a public input; the contract requires it to equal{' '}
          <span className="mono">msg.sender</span>, so a proof cannot be reused by anyone else.
        </li>
      </ul>
      <p className="muted">
        What is NOT hidden: who bid (publisher address), how many bids, and the full comparison order among bidders. What is
        hidden: every bid value and every gap between bids — slots that would carry magnitude are binarised to exactly ±1.
      </p>
    </div>

    <p>
      <Link to="/rounds">
        <button>Browse rounds →</button>
      </Link>
    </p>
  </>
)
