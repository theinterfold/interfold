// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { add, mulCipher, mulPlain, neg, sub, type Ring, type Slots } from './field'

/**
 * A simulated ciphertext: the N plaintext slots in the clear, and the multiplicative depth.
 * A fresh input has depth 0. Sums and ct×pt products keep the depth of the ciphertext. A ct×ct
 * product has the depth of the deeper input plus 1.
 *
 * Only `Evaluator.mul` and `Evaluator.mulPlain` are counted. Sums and differences, with a
 * ciphertext or with a plaintext, are free, as in the Rust crate.
 */
export class Ciphertext {
  constructor(
    readonly ring: Ring,
    readonly slots: Slots,
    readonly depth = 0,
  ) {}

  /** ct + ct. */
  add(other: Ciphertext): Ciphertext {
    return new Ciphertext(this.ring, add(this.slots, other.slots, this.ring.t), Math.max(this.depth, other.depth))
  }

  /** ct - ct. */
  sub(other: Ciphertext): Ciphertext {
    return new Ciphertext(this.ring, sub(this.slots, other.slots, this.ring.t), Math.max(this.depth, other.depth))
  }

  /** -ct. */
  neg(): Ciphertext {
    return new Ciphertext(this.ring, neg(this.slots, this.ring.t), this.depth)
  }

  /** ct + pt. Not counted. */
  addPlain(plaintext: Slots): Ciphertext {
    return new Ciphertext(this.ring, add(this.slots, plaintext, this.ring.t), this.depth)
  }

  /** ct - pt. Not counted. */
  subPlain(plaintext: Slots): Ciphertext {
    return new Ciphertext(this.ring, sub(this.slots, plaintext, this.ring.t), this.depth)
  }
}

/** The intermediate value that a design shows with `Evaluator.show`. */
export interface TraceStep {
  label: string
  slots: Slots
  depth: number
}

/** The operation counts of one run. */
export interface OpCounts {
  /** ct×ct products. */
  ciphertextProducts: number
  /** ct×pt products. */
  plaintextProducts: number
}

/**
 * Homomorphic products for the program, counted so that the designs can be compared. In the
 * real program `mul` also relinearizes back to two components. This simulation has no such step.
 */
export class Evaluator {
  private ciphertextProductCount = 0
  private plaintextProductCount = 0
  /** The steps shown with `show`, in order. `undefined` when the run is not traced. */
  readonly trace: TraceStep[] | undefined

  constructor(
    readonly ring: Ring,
    trace = false,
  ) {
    this.trace = trace ? [] : undefined
  }

  /** ct×ct. Each call adds one level of depth. */
  mul(a: Ciphertext, b: Ciphertext): Ciphertext {
    this.ciphertextProductCount++
    const slots = mulCipher(a.slots, b.slots, this.ring.t)
    return new Ciphertext(this.ring, slots, Math.max(a.depth, b.depth) + 1)
  }

  /** ct×pt. The depth does not change. */
  mulPlain(a: Ciphertext, plaintext: Slots): Ciphertext {
    this.plaintextProductCount++
    return new Ciphertext(this.ring, mulPlain(a.slots, plaintext, this.ring.t), a.depth)
  }

  /** `∏ cts` with a balanced tree: `n - 1` products at depth `⌈log2 n⌉`. */
  product(cts: Ciphertext[]): Ciphertext {
    if (cts.length === 0) throw new Error('the product of no ciphertexts is not defined')
    if (cts.length === 1) return cts[0]
    const middle = Math.floor(cts.length / 2)
    return this.mul(this.product(cts.slice(0, middle)), this.product(cts.slice(middle)))
  }

  /**
   * `(∏ u_i, Σ_i x_i · ∏_{j≠i} u_j)`: `3(n - 1)` products at depth `⌈log2 n⌉`.
   *
   * Merges pairs with `(P1, E1) · (P2, E2) = (P1·P2, E1·P2 + P1·E2)`. With `u = 1 - x` on 0/1
   * slots, the second value is 1 exactly in the slots where one `x_i` is 1.
   */
  productAndExactlyOne(u: Ciphertext[], x: Ciphertext[]): [Ciphertext, Ciphertext] {
    if (u.length !== x.length) throw new Error('u and x need the same length')
    if (u.length === 0) throw new Error('the product of no ciphertexts is not defined')
    if (u.length === 1) return [u[0], x[0]]
    const middle = Math.floor(u.length / 2)
    const [p1, e1] = this.productAndExactlyOne(u.slice(0, middle), x.slice(0, middle))
    const [p2, e2] = this.productAndExactlyOne(u.slice(middle), x.slice(middle))
    const exactlyOne = this.mul(e1, p2).add(this.mul(p1, e2))
    return [this.mul(p1, p2), exactlyOne]
  }

  /**
   * Records `ciphertext` under `label` when the run is traced, and returns it unchanged. A design
   * wraps the values that a reader wants to see.
   */
  show(label: string, ciphertext: Ciphertext): Ciphertext {
    this.trace?.push({ label, slots: ciphertext.slots, depth: ciphertext.depth })
    return ciphertext
  }

  get counts(): OpCounts {
    return {
      ciphertextProducts: this.ciphertextProductCount,
      plaintextProducts: this.plaintextProductCount,
    }
  }
}
