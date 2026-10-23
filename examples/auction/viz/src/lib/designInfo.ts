// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** Text and colours for each design. The facts come from `examples/auction/README.md` and `ts/README.md`. */

import type { PriceRule } from '@designs'

export const priceRuleLabels: Record<PriceRule, string> = {
  none: 'No price',
  first: 'Winning bid',
  second: 'Second-highest bid',
}

export const tieRuleLabels = {
  index: 'The higher index wins',
  random: 'Random priority, drawn after the bids close',
  lane: 'The random lane (the sum of the masks) picks a bidder of the tie set',
}

/** A short explanation of each design. */
export const explanations: Record<string, string> = {
  rank:
    'Each bidder puts its bid in an exponent: X^b. The program multiplies these polynomials and publishes a blinded score for each bidder. ' +
    'The score of the winner is 0. The score of a loser is a random non-zero value, and only that bidder can unblind it. ' +
    'The design computes no price: the winner opens a bid commitment outside the program.',
  'rank-batched':
    'This design computes the same scores as rank, with 2 ct×ct products for all bidders. ' +
    'Each bidder puts its bid in its own window of 3B coefficients. One product gives the score of each bidder at the center of its window. ' +
    'A second product applies each blinding to one score only. The cost is 3·n²·B coefficients, and a tie for the highest bid shows a zero for each tied bidder.',
  'first-price':
    'Each bidder encrypts a thermometer of bid · n + index. This folded value is different for each bidder. ' +
    'The program computes the OR of all thermometers: 1 - ∏(1 - T_i), in a product tree of depth ⌈log2 n⌉. ' +
    'The output is a function of the winner and the winning bid only. The reader takes both from coefficient 0.',
  'first-price-blind':
    'This design adds the thermometers instead of multiplying them. Slot p then holds c[p], the number of bids above p. ' +
    'One product with the sum of the bidder masks makes each slot 0 or a random non-zero value. ' +
    'Only the length of the non-zero prefix is visible: the largest bid · n + index.',
  'second-price':
    'This design adds a second thermometer region for the plain bids. The program keeps the slots where two or more bids are above the slot. ' +
    'Coefficient 0 of the output holds n · second_price + winner. The masks of the bidders hide all other coefficients.',
  'second-price-blind':
    'The program computes c · (c - 1) in the plain-bid region and c · c in the folded region. Then it blinds both with the masks. ' +
    'The plain-bid region is non-zero where two or more bids are above the slot. ' +
    'The folded region shows the winner, and it also shows the winning bid.',
  vickrey:
    'The slots hold one region of B slots for each candidate winner. Slot p of a region is 0 only when that bidder beats all other bidders at level p. ' +
    'The output is 0 above the second-highest bid in every region. At the second-highest bid, only the winner region is 0. ' +
    'The price is the last level with a non-zero slot. The winner is the region that is 0 at that level. The program has 4 ct×ct products at depth 3, for any number of bidders.',
  'vickrey-compact':
    'This design has the same program as vickrey, with 2 ciphertexts for each bidder instead of 3. ' +
    'The bid ciphertext holds [b >= p] + [b = p], with values 0, 1, and 2. The program squares it to get both thermometers: [b >= p] = v(3 - v)/2 and [b > p] = v(2 - v). ' +
    'The squares cost n more ct×ct products and one more level of depth. They save one encryption proof for each bidder.',
  'rl-first-price':
    'A weight group holds W = ⌊log2 t⌋ bidders (13 on the toy profile, 16 on the demo profile), and bidder k has the weight 2^(k mod W). ' +
    'The ring holds one block of B slots for each group. Slot p of a block is Z + m·A: Z is the weighted count of bids at or above p, A is the count of bids above p, and m is the sum of the masks. ' +
    'Above the highest bid the slot is 0. At the highest bid A is 0, so the slot is the sum of the weights of the tied bidders, with no mask and no error. Below it the slot is uniform. ' +
    'One more slot holds m: this random value picks the winner of a tie. The program has 1 ct×ct product for any number of bidders.',
  'rl-second-price':
    'The lanes of one copy are y and one z lane for each weight group. Both are 0 above the second-highest bid s and uniform below it. ' +
    'At s, y = R·c and z = R·c·L, where R is the sum of the pair masks, c = C(C - 1) counts the bids at or above s, and L is the sum of the weights of the winner set in that group. ' +
    'The reader takes the ratio z / y, and the bits of the ratio name the winner set. A pair mask has the same value in the y lane and the z lane, and a proof of this shape is part of each submission. ' +
    'If R is 0 at s, the copy reads s too low, with probability 1/t. The ring holds many copies, and the reader takes the highest s. ' +
    'A random lane, as in rl-first-price, picks the winner of the set. The program has 6 ct×ct products at depth 3.',
}

/** The colour and dash of the line of each design in the cost charts. */
export const designStyles: Record<string, { color: string; dash?: string }> = {
  rank: { color: '#1f5a3a' },
  'rank-batched': { color: '#1f5a3a', dash: '5 3' },
  'first-price': { color: '#a8651a' },
  'first-price-blind': { color: '#a8651a', dash: '5 3' },
  'second-price': { color: '#8b2a14' },
  'second-price-blind': { color: '#8b2a14', dash: '5 3' },
  vickrey: { color: '#12150f' },
  'vickrey-compact': { color: '#12150f', dash: '5 3' },
  'rl-first-price': { color: '#2b5f8a' },
  'rl-second-price': { color: '#2b5f8a', dash: '5 3' },
}
