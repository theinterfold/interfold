# Sealed-bid auctions

This example is a standalone sealed-bid auction application on Interfold. Anyone connects a wallet
and creates an auction. Other users connect a wallet and bid. No one sees a bid. The committee
decrypts one result.

The creator selects the auction type:

| Id  | Type                         | Bidders | Winner                                                   | Price                  | The result shows      |
| --- | ---------------------------- | ------- | -------------------------------------------------------- | ---------------------- | --------------------- |
| 0   | First-price                  | 2 to 8  | the highest bid; on a tie, the tied bidder who bid first | the highest bid        | the winner, the price |
| 1   | Second-price, mask providers | 2 to 8  | the highest bid; on a tie, the tied bidder who bid first | the second-highest bid | the winner, the price |
| 2   | Second-price, no providers   | 2 to 8  | the highest bid; on a tie, the tied bidder who bid first | the second-highest bid | the winner, the price |

For a second-price auction, the winning bid stays secret. For a first-price auction, the price is
the winning bid, so that bid is public. A tie at the top always goes to the tied bidder whose
counted bid was submitted first (see "Bid updates"). All three types resolve a tie inside the
computation and do not show it. The computation of all three types cannot fail by chance.

The first-price type is a priority-expanded first-price auction. The result has one lane of 16 slots
for each bidder. Above the price, every slot is 0. At the price, the lane of the winner is exactly 1
and every lane before it is exactly 0. The program multiplies a random mask only into the slots that
the reader does not need, so the mask can never hide the result. Each bidder sends three ciphertexts
(`ge`, `gt` and a random `mask` that the bidder draws). Privacy needs one bidder that draws its mask
at random (see "The program: the first-price type").

The mask-provider type gives the second-price result. The random mask does not come from the
bidders. The creator names 1 to 4 mask providers, and each provider sends one random mask. A bid has
two ciphertexts only. Privacy needs one honest provider. The auction needs every provider to send
its mask (see "Send a mask").

The no-providers type also gives the second-price result. It needs no mask provider and no trusted
party. Each bidder sends two random shares with the bid, and the program makes the random factor
from the sum of the shares of all bidders. A bid has four ciphertexts. Privacy needs one bidder that
draws its shares at random. The price: the random factor is not exactly uniform, so the numbers that
are not 0 in the result leak a small statistical hint about the losing bids. The hint is larger on
the small parameters of this demo than on secure parameters (see "The program: the no-providers
type").

| Step           | What happens                                                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create         | The creator pays the E3 fee and requests an E3. The request carries the type, the title, the price of each bid level and, for the mask-provider type, the mask providers. |
| Key generation | The ciphernodes run a distributed key generation. It makes the l-BFV public key and the threshold relinearization key.                                                    |
| Masks          | Mask-provider type only. Each mask provider proves and sends one mask. Bidding opens when all masks are in.                                                               |
| Bid            | Each bidder encrypts a bid in the browser, proves with one proof that the bid is valid, and sends it. A bidder can update a bid, and a relayer can send it.               |
| Computation    | The FHE program multiplies ciphertexts. It uses the threshold relinearization key.                                                                                        |
| Decryption     | The committee decrypts one ciphertext. It holds the winner and the price only.                                                                                            |
| Result         | The web app decodes the result and shows the winner and the price.                                                                                                        |

This example runs on the **insecure SIMD parameters (parameter set 5: N = 128, t = 257)**. They are
for development and give no security.

The lane layout comes from the design study in [`../auction`](../auction): the designs in Rust, a
plaintext simulation, a design visualizer (`../auction/viz`) and the report for review
(`../auction/REPORT.md`). The first-price type uses one random mask from the bidders (see "The
program: the first-price type"). The mask-provider type replaces it with masks from providers (see
"The program: the mask-provider type"). The no-providers type replaces it with shares that the
bidders send (see "The program: the no-providers type").

## How a bid works

A bid is a whole number `b` from 0 to 15. The 128 slots of the SIMD plaintext hold 8 groups of 16
slots. Slot `i` has level `i % 16`. A first-price bid has three ciphertexts. A bid of the
mask-provider type has two. A bid of the no-providers type has four:

| Role | Name    | Slot `i` holds                                                                                                              | Types            |
| ---- | ------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| 0    | `ge`    | `1` if `b >= i % 16`, else `0`                                                                                              | all              |
| 1    | `gt`    | `1` if `b > i % 16`, else `0`                                                                                               | all              |
| 2    | `mask`  | a uniform random value in 0 to 256                                                                                          | 0 (first-price)  |
| 2, 3 | `share` | a uniform random value in 0 to 256 (the `mask` distribution). A bid has two shares, `s1` and `s2`. Role number 3 in the SDK | 2 (no providers) |

These ciphertexts do not depend on the number of bidders or on the position of the bidder.

A mask provider of the mask-provider type sends one more kind of ciphertext: a provider mask. Its
128 slots hold a uniform random value in 1 to 256. No slot is 0. It is not a role of a bid, and a
bidder never sends it.

### Create an auction

`AuctionProgram.validate` reads
`customParams = abi.encode(uint8 auctionType, uint8 levels, uint256[16] prices, string title, address gate, bytes gateConfig, address[] providers)`.
`levels` is the number of price steps, from 2 to 16 (`InvalidLevels` otherwise). It stores the
auction and emits `AuctionCreated`, which carries `gate` and `gateConfig`. It inserts leaf 0: the
configuration leaf, `keccak256(configInput(auctionType, providers))` in the BN254 field. The
configuration input is
`"interfold-auction-config-v1" || uint8 auctionType || provider_1 || ... || provider_k`. Each
provider is 20 raw bytes. The first-price type (0) and the no-providers type (2) have no provider,
so their configuration input has no provider bytes. If `gate` is not the zero address, it calls
`IBidderGate(gate).configure(e3Id, gateConfig)` (see "The bidder gate"). `prices[b]` is the price of
step `b`. The first `levels` prices must increase strictly, and the other prices must be zero
(`InvalidPrices` otherwise); the steps can be uneven. Read them with `auctionPrices(e3Id)`, and the
number of steps with `auctions(e3Id)`, which returns `(auctionType, levels, creator, title, gate)`.
The program and the circuits see only steps, so the prices do not change the computation. The
coordination server gives the program the configuration bytes as input 0. The program reads the type
and the providers from them, so the compute proof binds both through the input root.

`providers` is the list of mask providers. The mask-provider type (1) needs 1 to `MAX_PROVIDERS` = 4
providers. No provider is the zero address, and no address is in the list twice. The first-price
type and the no-providers type need an empty list. The contract reverts with `InvalidProviders` for
any other list. For the mask-provider type, `validate` also emits
`MaskProvidersSet(e3Id, providers)` after `AuctionCreated`. Read the list with
`auctionProviders(e3Id)`, and test an address with `isProvider(e3Id, address)`.
`configInput(auctionType, providers)` and `configLeaf(auctionType, providers)` give the bytes and
the leaf.

### Send a bid

One `publishInput(e3Id, data)` call sends one complete bid. The bidder does not send the ciphertexts
one by one.

```text
data = abi.encode(address bidder, bytes[] ciphertexts, bytes32[] commitments,
                  bytes proof, bytes gateProof, bytes signature)
```

`ciphertexts` and `commitments` have `roleCount(type)` entries (3 for type 0, 2 for type 1, 4 for
type 2), in role order. `commitments[r]` is the ciphertext commitment of `ciphertexts[r]`. The
contract does these steps:

1. It rejects the call after the input window (`InputDeadlineReached`).
2. It rejects a wrong number of ciphertexts or commitments, an empty ciphertext and a zero bidder
   (`InvalidBidShape`, `EmptyInputData`, `BidderIsZero`).
3. It gives the bid the version `bidCount(e3Id, bidder) + 1`. A fourth bid of one address fails
   (`TooManyBids`). The first bid of an address takes one of the places: `maxBidders(type)` is 8 for
   every type (`TooManyBidders`).
4. It checks the sender. A direct bid comes from `bidder` (`SenderNotBidder`). A relayed bid carries
   the signature of `bidder` (see "Relayed bids").
5. If the auction has a gate, it asks the gate if `bidder` can bid (`BidderNotEligible`).
6. It verifies the bid proof (`InvalidBidProof`) with `bidVerifier2` (2 roles), `bidVerifier3` (3
   roles) or `bidVerifier4` (4 roles). The public inputs are the commitments, the bidder, `levels`,
   the committee key commitment of the E3 and the VK anchor. The anchor must be the anchor of the
   type: `vkAnchor3` (first-price), `vkAnchor2` (mask providers) or `vkAnchorQnr` (no providers).
7. It inserts one leaf for each ciphertext as consecutive leaves, in role order, and emits
   `BidSubmitted(e3Id, bidder, version, firstIndex, ciphertexts, commitments)`. `firstIndex` is the
   leaf index of the first ciphertext.

The leaf of a bid ciphertext is
`sha256(keccak256(ciphertext) || commitment || bidder || uint40 version)` in the BN254 field
(`inputLeaf`). It binds four things: the published bytes, the commitment, the bidder and the
version. The contract cannot check that the bytes open the commitment. It binds both in the leaf,
and the program checks them (see "The program: which bids count").

`bidCount(e3Id, bidder)` gives the number of bids of an address. `bidderCount(e3Id)` gives the
number of addresses that bid. The ciphertexts are in the calldata and in the `BidSubmitted` event.
The server and the web app read them from the event.

### Send a mask

A mask-provider auction names its mask providers at creation. Each provider sends one mask with
`publishInput(e3Id, data)`. `data` has the encoding of a bid, with these values:

- `bidder` is the provider.
- `ciphertexts` and `commitments` have one entry each: the mask and its commitment.
- `proof` is the mask proof (`auction_mask`).
- `gateProof` and `signature` are empty.

The contract treats the call as a mask when `isProvider(e3Id, bidder)` is true. It does these steps:

1. It rejects the call after the input window (`InputDeadlineReached`).
2. It rejects a wrong shape (`InvalidBidShape`) and an empty ciphertext (`EmptyInputData`).
3. It rejects a sender that is not the provider (`SenderNotBidder`). A mask has no relayed form.
4. It rejects a second mask of the same provider (`MaskAlreadySubmitted`).
5. It verifies the mask proof (`InvalidMaskProof`) with `maskVerifier`. The public inputs are the
   commitment, the provider, the committee key commitment of the E3 and `vkAnchorMask`.
6. It inserts one leaf, `inputLeaf(keccak256(ciphertext), commitment, provider, MASK_VERSION)`, and
   emits `MaskSubmitted(e3Id, provider, index, ciphertext, commitment)`.

No gate applies to a provider. `MASK_VERSION` is `0xFFFFFFFF`. A bid has a version from 1 to 3, so a
bid never has the version of a mask. The metadata of a mask leaf is `provider || MASK_VERSION`.

The leaves of a mask-provider auction have this order, and the contract enforces it:

1. Leaf 0: the configuration, with the providers.
2. Leaves 1 to `k`: the `k` masks, in the order of submission.
3. The bids, two leaves each (`ge`, then `gt`).

The contract rejects every bid with `MasksPending` until `maskCount(e3Id)` is equal to the number of
providers. A provider cannot bid. `maskSubmitted(e3Id, provider)` tells if a provider has sent its
mask.

The contract cannot check that the mask bytes open the commitment. The program checks them, as it
does for a bid. A mask that does not open its commitment stops the auction: the program needs every
mask (see "The program: the masks").

### Bid updates

A bidder is an address. It can send up to `MAX_BIDS_PER_BIDDER` = 3 bids: the first bid and two
updates. Each bid has its own ciphertexts, its own proof and the next version. An update does not
remove the earlier bid: all leaves stay in the tree and in the input root.

The program counts one bid for each bidder: the latest bid whose ciphertexts all open their
commitments. If the latest bid does not open, an earlier version counts. If no bid of a bidder
opens, the program drops the bidder whole. The program never counts part of a bid.

The place of a bid in the queue is the leaf index of its first ciphertext. The bidder position in
the computation is the order of the counted bids by that index. A bidder that updates gets the place
of its update, so an update loses the place of the earlier bid: a bidder that bids first and updates
last counts after every bidder that bid in between. If the update does not open its commitments, the
earlier bid counts and keeps its own place. On a tie at the top, the tied bidder with the lowest
position wins, which is the tied bidder whose counted bid was published first. The order of the bids
is the order of the transactions on chain, so no bidder can change it by encrypting again.

### Relayed bids

A bidder can sign a bid, and any account can send it. The relayer pays the gas. The bidder address
stays the bidder of the proof, the gate check and the leaves.

The signature is EIP-712 with the domain name `AuctionProgram` and the domain version `1`, and the
type `Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)`:

- `version` is the version the bid will get: `bidCount + 1`. An old signature is useless after the
  bidder bids again.
- `inputsHash` is `keccak256(abi.encode(commitments, ciphertextHashes))`, with
  `ciphertextHashes[r] = keccak256(ciphertexts[r])`. A relayer cannot swap the bytes of a signed
  bid.

`bidDigest(e3Id, bidder, version, inputsHash)` returns the digest to sign. The contract checks the
signature with OpenZeppelin `SignatureChecker`, so it accepts an EOA and an ERC-1271 wallet. With an
empty `signature`, the bid is direct.

The coordination server has a relayer: `POST /relay` sends `publishInput` from the account of
`RELAYER_PRIVATE_KEY`. On the local chain this key is Anvil account 9 by default. No bidder and no
ciphernode uses it. The web app signs with the wallet when you select **Send through relayer**. See
"Run the server" for the endpoint.

A mask is never relayed. The provider sends it from its own account, because the contract checks
`msg.sender`.

### The bidder gate

An auction can name a gate contract. The gate decides which addresses can bid. A gate implements
`IBidderGate`:

```solidity
function configure(uint256 e3Id, bytes calldata config) external;
function isEligible(
  uint256 e3Id,
  address bidder,
  bytes calldata proof
) external view returns (bool);
```

`validate` calls `configure` once for each auction, with `gateConfig`. Each bid calls `isEligible`
with `gateProof`. The gate keys its state by `(msg.sender, e3Id)`, and `msg.sender` is the program.
If `gate` is the zero address, anyone can bid and `gateConfig` must be empty
(`GateConfigWithoutGate`). A non-zero `gate` must be a contract (`InvalidGate`).

`contracts/gates/MerkleAllowlistGate.sol` is an example gate. Its `gateConfig` is
`abi.encode(address[] members)`: 1 to 256 addresses in strictly increasing order. The gate builds
the Merkle root on chain, stores it and emits `AllowlistSet(program, e3Id, root, members)`. The leaf
of a member is `keccak256(member)`. The inner nodes use the sorted-pair `keccak256`, and an odd node
moves up unchanged. The `gateProof` of a bidder is `abi.encode(bytes32[] path)`.
`sdk/src/allowlist.ts` (`allowlistRoot`, `allowlistProof`) builds the same root and path. The web
app sorts and deduplicates the addresses that the creator enters. It builds the proof of a bidder
from the `AllowlistSet` event. The web app finds the gate through `VITE_ALLOWLIST_GATE_ADDRESS`.

### The program: which bids count

The server sends the runner every published input, not only the bids that count. For each input it
sends the commitment (`input_commitments`), the bidder (`input_slots`) and the bid version
(`input_parents`). The program reads the 5-byte field `input_parents` as the bid version, not as a
parent. Input 0 (the configuration) has a zero commitment, a zero slot and the parent 0. The input
policy of the program (`policy()` in `program/src/lib.rs`) has two parts:

- **Leaf.** The leaf of input 0 is the configuration leaf. For every other input, the program needs
  a commitment and 25 bytes of metadata (`bidder || uint40 version`). It computes the same leaf as
  `inputLeaf`. A ciphertext that does not open its commitment still gets a leaf, because every
  published input needs one.
- **Select.** The program always selects input 0. It groups the other inputs into bids: a bid is a
  maximal run of consecutive inputs with identical metadata, because the contract inserts one bid as
  one run. For each bidder it keeps the run with the highest version in which every input opens its
  commitment. A bidder with no such run is dropped whole. A run with malformed metadata is never
  selected. The bidder position in the computation is the order of the selected runs by leaf index.

`sdk/src/selection.ts` (`selectBids`) is the same rule in TypeScript. The server, the web app and
the integration test use it. The server starts no computation with fewer than 2 selected bidders.

### The program: the masks

The mask-provider type has `k` mask inputs after input 0, one for each provider. Each of them has
`input_slots` = the provider and `input_parents` = `MASK_VERSION`. The policy reads the leading run
of inputs with the version `MASK_VERSION` after input 0 as the masks. It does this:

- If one mask has no commitment, or its bytes do not open its commitment, the policy selects input 0
  only. The processor then stops: the auction cannot run without every mask.
- Otherwise it selects every mask, and then the bids with the rule above. An input with the version
  `MASK_VERSION` after a bid is not a mask, and the policy ignores it. The contract never makes such
  an input.

`selectBids` skips the masks. `checkMasks(masks, providers, opens)` in `sdk/src/selection.ts` checks
them. It returns `complete` (every provider has a mask that opens), `missing` (the providers with no
mask) and `invalid` (the providers whose mask does not open). The server and the web app use it. The
server starts no computation until `complete` is true.

### The program: lanes

With `n` bidders (2 to 8), the 128 slots hold `n` lanes of 16 slots. Lane `j` is the slots `16 j` to
`16 j + 15`, and it belongs to the bidder at position `j`. Level `p` of lane `j` is the slot
`16 j + p`. The program makes one copy of the lanes. It multiplies the result by `used`, which is 1
in the slots `0` to `16 n - 1` and 0 in the other slots, so the slots of the lanes that do not exist
are 0 in every output.

On a tie at the top, the lane of the lowest bidder position wins. The ciphertext bytes play no part
in the tie, so a bidder cannot change it by encrypting again. `sdk/src/layout.ts` decodes the result
of all three types, and the decoder returns the same shape for them.

### The program: the first-price type

The first-price type is priority-expanded first price (PE-FP). A bid has three ciphertexts: `ge`,
`gt` and `mask`. Let `G[p]` be the sum of `gt_j[p]` over all bidders: the number of bids above `p`.
It is the same in every lane. Let `E_j[p]` be the sum of `ge_k[p] - gt_k[p]` over the bidders `k`
before `j`: the number of earlier bidders that bid exactly `p`. Let `m` be the sum of the masks,
times `used`. Lane `j` holds:

```text
out_j[p] = ge_j[p] + m[p] * (G[p] + E_j[p])
```

This is one ciphertext product, at depth 1, and `3 n` products of a ciphertext and a plaintext. With
`h` the highest bid and `w` the first bidder that bid `h`:

- At a level above `h`, every lane is 0, because `ge`, `G` and `E` are 0.
- At level `h`, a lane before `w` is 0, because `ge = 0` and `G + E = 0`. Lane `w` is exactly 1,
  because `ge = 1` and `G + E = 0`. A lane after `w` is `1 + m * E` or `m * E`, and it means
  nothing.
- At a level below `h`, `G` is 1 or more, so the mask hides the slot.

**Example.** The bids are 2, 3 and 3. At level 3, the lanes are `0`, `1` and a random value. Lane 0
has `ge = 0`. Lane 1 has `ge = 1` and `G + E = 0`. Lane 2 has `ge = 1` and `E = 1`, because bidder 1
bid 3 before it. Level 3 is the highest level with a non-zero slot, so the price is 3. The first
non-zero lane is lane 1, so bidder 1 wins. The tie with bidder 2 does not show.

The decoder reads the price as the highest level where some lane is not 0. It reads the winner as
the first lane that is not 0 at that level. That lane must be exactly 1, and every lane before it
must be exactly 0. Any other pattern is invalid, and the web app says so.

**Why it cannot fail.** The mask touches only the slots where `G + E` is 1 or more. The decoder
never needs these slots. So the result reads whatever the masks hold, also when the sum of the masks
is 0 in a slot. A bidder that sends a bad mask on purpose cannot change the winner or the price.

**What it leaks.** The output shows the winner and the highest bid, which is the price. If at least
one bidder draws its mask at random and keeps it secret, `m` is uniform in every slot. `G + E` is a
whole number from 1 to `2 n`, which is below 257, and 257 is prime. So each masked slot is uniform,
and it shows nothing about the other bids or about a tie. If all bidders share their masks, they can
read `G + E`, which shows more than the winner and the price.

### The program: the second-price tests

The two second-price types use the same test vector. Slot `p` of lane `k` tests whether bidder `k`
beats every other bidder at level `p`:

```text
g_k[p]     = #{j != k : b_j > p} + [b_k < p] + [b_k = p] * #{j < k : b_j = p}
c[p]       = #{j : b_j >= p}
tests_k[p] = g_k[p] * c[p] * (c[p] - 1)
```

`g_k[p]` is 0 exactly when no other bid is above `p`, `b_k >= p` and no earlier bidder ties with `k`
at `p`. With `s` the second-highest bid:

- At a level below `s`, two or more bids are above the level, so the slot is not 0.
- At level `s`, the slot is 0 in the lane of the winner (a tie goes to the lowest position) and not
  0 in every other lane.
- At a level above `s`, at most one bid is at or above the level, so the slot is 0.

Every non-zero `g` is a whole number from 1 to `n`, and every non-zero `c (c - 1)` is a whole number
from 2 to `n (n - 1)`. Both are below 257, and 257 is prime. So `tests` is not 0 mod 257 exactly
where it is not 0 as a whole number. The program multiplies `tests` by a factor `r` that is 0 in no
slot of a lane that exists. So the output is 0 exactly where `tests` is 0, and the result always
reads. The result is a function of the winner and `s` only. It does not show the winning bid, the
other bids, a count or a tie. The three ciphertext products of `tests` are at depth 2. The types
differ in how they make `r`.

### The program: the mask-provider type

The mask-provider type has no mask from the bidders. A bid has the roles 0 and 1 only (`ge` and
`gt`). The program has `k` masks `M_1` to `M_k`, one from each provider (1 to 4). It computes:

```text
out = tests * r        r = (M_1 * used) * M_2 * ... * M_k
```

The product tree of `r` has depth 2 at most, and the output has depth 3. There are `k + 3`
ciphertext products.

**Why it cannot fail.** The proof `auction_mask` shows that every slot of every `M_i` is not 0
mod 257. The number 257 is prime, so a product of numbers that are not 0 is not 0. A slot of `out`
thus is 0 only where `tests` is 0.

**Why it stays private.** Each `M_i` is uniform in 1 to 256 when its provider is honest. A product
of a uniform value that is not 0 and fixed values that are not 0 is uniform in 1 to 256. If one
provider is honest, every slot of `out` that is not 0 is thus uniform. Only the zero pattern shows,
and the zero pattern is a function of the winner and the price. If all providers share their masks,
they can divide `out` by `r` and read the numbers in `tests`. These numbers show more than the
winner and the price. A provider never sees a bid, and a provider cannot bid.

### The program: the no-providers type

The no-providers type gives the same result as the mask-provider type and does not fail by chance,
like it. It needs no mask provider. The creation has no provider list (`providers` must be empty,
and the configuration input is `"interfold-auction-config-v1" || uint8(2)`). The program selects
bids with the rule of "The program: which bids count", and there are no mask inputs. A bid has four
ciphertexts: `ge`, `gt` and the two shares `s1` and `s2`. The program computes:

```text
S1  = the sum of s1 over the selected bids
S2  = the sum of s2 over the selected bids
r   = ((S1 * S1 - 3) * used) * (S2 * S2 - 3)
out = tests * r
```

The depth is 3: the squares have depth 1, `r` has depth 2, `tests` has depth 2 and `out` has
depth 3. There are 7 ciphertext products. The constant 3 is the plaintext with the value 3 in every
slot. `sdk/src/layout.ts` decodes the result with the same decoder as the other second-price type.

**Why it cannot fail.** The number 3 is not a square modulo 257 (a check of all 257 values, also
done for 65537). So `S^2 - 3` is not 0 for any `S`, and `r` is not 0 in any slot, whatever the
bidders send. A slot of `out` is thus 0 only where `tests` is 0, for any shares. A bidder that sends
bad shares on purpose cannot change the winner or the price. It can only change the random numbers
in the slots that are not 0. Because of this, a share needs no proof other than the normal
encryption proof.

**What it leaks.** If at least one bidder draws its shares at random and keeps them secret, `S1` and
`S2` are uniform and unknown to everyone else, even if all the other bidders agree on their shares.
No trusted party is needed. But `S^2 - 3` takes only 129 of the 257 values, so `r` is close to
uniform, and not uniform. A slot of `out` that is not 0 is `tests * r`, and its distribution depends
a little on the number in `tests`. The numbers that are not 0 thus leak a small statistical hint
about the counts in `tests`, which are a function of the losing bids. The zero pattern shows the
winner and the price, as in the mask-provider type. The hint is larger on the small modulus of this
demo than on a secure parameter set, which has a much larger modulus. The mask-provider type has no
such hint: its mask is exactly uniform and not 0.

## What is proven

Each bidder publishes one bid proof. It is `auction_bid3` for the first-price type (3 roles),
`auction_bid2` for the mask-provider type (2 roles) and `auction_bid4` for the no-providers type (4
roles). Each mask provider publishes one mask proof, `auction_mask`. A proof runs in a browser or in
Node, and a browser can prove at most 2^21 gates (the WASM heap is 4 GiB; a 2^22 circuit runs out of
memory after it loads the SRS). One circuit that verifies all `K` encryption proofs has more gates
than that, so the bid is a tree of circuits. Every one has fewer than 2^21 gates and pads to 2^21,
except the two smaller circuits of the mask-provider type, which pad to 2^20. The shared rules are
in the Noir library `circuits/bid` (`auction_bid`). The six circuits are thin packages around it:

- `auction_bid_pair` (`circuits/pair`) verifies the encryption proofs of the roles 0 and 1. It holds
  the bid.
- `auction_bid_shares` (`circuits/shares`, no-providers type only) verifies the encryption proofs of
  the roles 2 and 3, which are the shares.
- `auction_bid3` (`circuits/bid3`, first-price type) verifies the pair proof and the encryption
  proof of role 2, which is the mask.
- `auction_bid4` (`circuits/bid4`, no-providers type) verifies the pair proof and the shares proof.
- `auction_bid2` (`circuits/bid2`, mask-provider type) verifies the pair proof only.
- `auction_mask` (`circuits/mask`, mask-provider type) verifies one encryption proof, and proves
  that every slot of the plaintext is not 0 mod 257. It is the proof of a provider mask.

Only `auction_bid2`, `auction_bid3`, `auction_bid4` and `auction_mask` have an EVM verifier. The two
inner circuits make recursive proofs. Together, the circuits check these facts:

- **The encryption.** Every ciphertext has an Interfold user-data encryption proof. It shows that
  the ciphertext encrypts a plaintext `k1` under this E3 committee key. All proofs use the same
  verification key, and they carry the same `ct0` and `ct1` verification-key chains. The inner
  proofs publish the key row commitment, the key hash and the chains, and the outer circuit checks
  that they are the same in every proof of the tree.
- **The bid.** `auction_bid_pair` has one private bid `b`. The public input `levels` is the number
  of price steps that the creator chose. The circuit proves that `levels` is in 2 to 16, that
  `b < levels` and that `b` has a one-hot vector. The contract gives the `levels` of the auction, so
  no valid proof exists for a bid at a step that the auction does not have.
- **The plaintexts.** The `k1` of role 0 is the row `b` of the table for `ge`. The `k1` of role 1 is
  the row `b` of the table for `gt`. Both roles use the same `b` inside `auction_bid_pair`, so
  nothing links them afterwards. A mask has a free `k1`, and so has a share. The tables come from
  `program/examples/bid_table.rs` and fhe.rs.
- **The binding.** Each ciphertext commitment is the commitment of its encryption proof. The bidder
  is not zero.
- **The mask.** `auction_mask` has a private list of 128 slot values. It proves that every value
  minus 1 is below 2^8, so every value is in 1 to 256 and no slot is 0. It proves that the `k1` of
  the ciphertext is the SIMD encoding of the slot values. The values stay private. The provider is a
  public input and is not zero.
- **The shares.** `auction_bid_shares` checks the two encryption proofs of the roles 2 and 3 and
  their binding, and no other rule. A share is any plaintext, because the program does not need a
  property of it: no value of `S` makes `S^2 - 3` zero (see "The program: the no-providers type").
  The mask of the first-price type has no rule either: the program reads the result whatever the
  mask holds (see "The program: the first-price type").

The public inputs of the bid proof, in order, are: the `K` ciphertext commitments, `bidder`,
`levels`, the committee key commitment and the VK anchor. That is `K + 4` values. The contract
supplies `bidder`, `levels`, the committee key commitment of the E3 and the anchor of the
deployment. The public inputs of the mask proof, in order, are: the ciphertext commitment, the
provider, the committee key commitment and the VK anchor. The contract supplies the provider (the
sender), the committee key commitment and the anchor. The VK anchor covers the user-data encryption
circuits and the inner circuits of the tree. It is `vkAnchor3` for the first-price type (it contains
`auction_bid_pair`). `vkAnchorQnr` is the anchor of the no-providers type (it contains
`auction_bid_pair` and `auction_bid_shares`). The final circuit takes the inner key as a witness and
binds it into the anchor, so each type has its own anchor, and a bid proof of one type fails the
anchor check of the other type. `vkAnchor2` is the anchor of `auction_bid2`: it covers the same
circuits as `vkAnchor3`. `vkAnchorMask` covers the encryption circuits only, because `auction_mask`
has no inner circuit. The contract chooses the verifier and the anchor by the type and by the call
(a bid or a mask).

| Circuit              | Proof                                    | Types  | Gates (`bb gates`) | Padded size |
| -------------------- | ---------------------------------------- | ------ | ------------------ | ----------- |
| `auction_bid_pair`   | recursive, roles 0 and 1                 | 0 to 2 | 1,427,574          | 2^21        |
| `auction_bid_shares` | recursive, roles 2 and 3 (no pair check) | 2      | 1,424,795          | 2^21        |
| `auction_bid3`       | EVM, the pair proof and role 2           | 0      | 1,426,850          | 2^21        |
| `auction_bid4`       | EVM, the pair proof and the shares       | 2      | 1,426,857          | 2^21        |
| `auction_bid2`       | EVM, the pair proof only                 | 1      | 681,650            | 2^20        |
| `auction_mask`       | EVM, a provider mask                     | 1      | 688,062            | 2^20        |

The gate count of `auction_bid_shares` is from a later run of `bb` 6.0.0 than the other counts. In
that run `auction_bid4` has 1,425,260 gates. Compare the counts of one run only.

Only the bid proof (or the mask proof) leaves the machine of the bidder (or of the provider). The
encryption proofs stay on that machine.

The proof has `bidder` as a public input. For a direct bid, `bidder` is `msg.sender`. For a relayed
bid, it is the signer. A proof that another address copies fails, because the bidder is part of the
proof. Without this, a copy of the thermometers of the highest bidder would make a tie at that bid,
and the price would show the bid.

The mask proof has `provider` as a public input in the same way. The contract sets it to
`msg.sender`, so a mask proof that another address copies fails. A provider cannot send the mask of
another provider.

The `ge` and `gt` ciphertexts of one bid come from one `b`, because the circuit has only one `b`.
The limit of bidders is `maxBidders(type)`: 8 for every type. One copy of the lanes has `16 n`
slots, and they must fit in the 128 slots of the ring.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-rc.3, `bb` 6.0.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout. `pnpm dev:setup` installs it.

Proof aggregation stays on everywhere, tests included. The l-BFV key aggregator has no skip path.
The deploy uses the real DKG and decryption verifiers (`ENABLE_ZK_VERIFICATION=true` in
`scripts/lib/dev_config.sh`).

## Run it

Run these commands in this order.

1. Build the Noir circuits for the insecure SIMD preset. Run it in the repository root:

   ```sh
   pnpm build:circuits --preset insecure-simd --committee minimum
   ```

2. Build the SDK. It bundles the user-data encryption circuits. Run it after the last circuit build:
   a later circuit build cleans `circuits/bin/threshold/target`, and the SDK reads a circuit from
   that directory.

   ```sh
   pnpm sdk:build
   ```

   The SDK build selects `insecure/minimum` at its end. Step 3 selects `insecure-simd/minimum`
   again.

3. Set up the example. This step runs `scripts/compile_circuits.sh`, which compiles the bid circuits
   and the mask circuit. It writes the verifiers of `auction_bid2`, `auction_bid3`, `auction_bid4`
   and `auction_mask` (`contracts/verifiers/AuctionVerifier2.sol`, `AuctionVerifier3.sol`,
   `AuctionVerifier4.sol` and `AuctionMaskVerifier.sol`) and the four VK anchors. It builds
   `program/examples/vk_hash.rs` to hash the verification keys:

   ```sh
   pnpm install
   pnpm dev:setup
   ```

   `pnpm dev:setup` also builds `@interfold/auction` (`sdk/`, `pnpm build:sdk`). The client, the
   server and the tests import it from `sdk/dist`, so run `pnpm build:sdk` again after you change
   `sdk/src` or recompile the circuits. The package copies the compiled bid circuits and
   `vk_anchor.json` from `circuits/` into `sdk/circuits`. `@interfold/auction` has the layout, the
   selection and the allowlist; `@interfold/auction/prover` has `BidProver` and loads
   `@aztec-foundation/bb.js`.

4. Start the stack: anvil, the ciphernodes, the program server, the coordination server and the web
   app:

   ```sh
   pnpm dev:all
   ```

If `interfold noir setup` (the last step of `dev:setup`) fails with
`checksum missing for circuits-<version>.tar.gz`, the CLI `versions.json` has no checksum for that
version. Pack the build of this repository instead:

```sh
STAGE=$(mktemp -d) && mkdir -p "$STAGE/circuits/insecure-simd"
cp -R ../../dist/circuits/insecure-simd/minimum "$STAGE/circuits/insecure-simd/"
jq '.files |= with_entries(select(.key | startswith("insecure-simd/minimum/")))' \
  ../../dist/circuits/checksums.json > "$STAGE/circuits/checksums.json"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf /tmp/auction-circuits.tar.gz circuits
interfold noir setup --circuits-archive /tmp/auction-circuits.tar.gz \
  --circuits-configuration insecure-simd/minimum --allow-unpinned-archive
```

`COPYFILE_DISABLE=1` stops macOS `tar` from adding `._*` entries. The installer refuses those
entries.

### Use the web app

Open <http://localhost:3000>. The app has three pages: **Auctions** (the list), **Create** and **How
it works**.

1. **Connect a wallet.** Add the anvil network to a browser wallet (chain ID 31337, RPC
   `http://localhost:8545`). Import some of the well-known anvil keys. Do not use accounts 1 to 5:
   they are the ciphernodes. Do not use account 9: it is the relayer of the server. Use these keys
   on a local chain only.
2. **Get test tokens.** A request pays a fee in the fee token. On anvil, select **Get test tokens**
   to mint some.
3. **Create an auction.** Enter a title (1 to 80 bytes), select the type, the price steps and the
   bidding duration. The page offers three types: first-price (the default), second-price with mask
   providers and second-price with no providers. Each card shows the bidder limit of the type (2 to
   8 bidders) and the number of ciphertexts of each bid (3, 2 and 4). A top tie always goes to the
   tied bidder who bid first, and the result never shows the tie. The first-price type has no
   providers field. The page explains that it never fails, that it needs no trusted party and that
   the winning bid is the price, so it is public. The no-providers type has no providers field
   either. The page explains that this type needs no trusted party and never fails, and that the
   numbers in the result that are not 0 leak a small statistical hint about the losing bids, larger
   on the demo parameters than on secure ones. For the mask-provider type, the page shows the list
   **Mask providers**. Name 1 to 4 addresses. The list starts with your wallet and the server
   provider, if the server has one (**Add the server provider** adds it again). Each provider sends
   one mask before bidding opens. Privacy needs one honest provider, and the auction needs every
   provider to send its mask. The page checks the list with the rules of the contract. For the price
   steps, first set **Number of steps** (2 to 16, 8 by default). Then select **Even steps** (a start
   price and a step) or **Custom list** (one price for each step, increasing, for example a 1-2-5
   scale). Under **Who can bid**, select **Anyone** or **Allowlist**. For an allowlist, enter the
   addresses. The page sorts them and removes duplicates. The **Allowlist** choice needs
   `VITE_ALLOWLIST_GATE_ADDRESS`. Optionally, select **Choose a picture** (PNG, JPEG or WebP). The
   page shrinks it, and the wallet signs the upload after the request is mined. Key generation takes
   some minutes. Bidding opens when the committee publishes the key (and, for the mask-provider
   type, when all masks are in), and it closes at the end of the duration. The masks and the bids
   use the same window.
4. **Send a mask** (mask-provider type). The auction page shows **Mask providers**: each provider,
   and if its mask is in. A connected provider selects **Submit mask**. The browser draws 128 random
   values in 1 to 256, encrypts them and proves the encryption, then makes the mask proof. The page
   shows each step. The wallet sends one transaction. A provider that the server runs (see "Run the
   server") sends its mask by itself. The page shows an alert if a mask on chain does not open its
   commitment: the auction cannot run then.
5. **Bid.** Open the auction page from another account. Select one of the prices that the creator
   set (the steps 0 to `levels - 1`). Select **Submit bid**. A first-price bid is 3 ciphertexts: the
   bid thermometer "at least", the bid thermometer "above" and a random mask (the browser draws 128
   random values in 0 to 256). A no-providers bid has 4 ciphertexts: the two thermometers and two
   random shares (the browser draws 128 random values in 0 to 256 for each share). A mask-provider
   bid has the two thermometers only. In a mask-provider auction the page shows **Waiting for mask
   providers (x/k)** until all masks are in, and an account that is a provider cannot bid. The
   browser encrypts each ciphertext and proves its encryption, then makes the bid proof. The page
   shows each step. A no-providers bid has the step **Prove the shares in the last two
   ciphertexts**. Each proof takes some minutes. The wallet then sends one transaction. With **Send
   through relayer**, the wallet signs the bid and the server sends the transaction. The bid counts
   when the transaction is mined. On an allowlist auction, the page shows if the account is on the
   list. After a bid, the page shows the version of the bid and **Update bid (n left)**: an address
   can send 3 bids. An update has a new proof. The latest bid whose bytes open counts, and it counts
   from the time of the update: an update loses the place of the earlier bid in a tie. The auction
   is full when `bidderCount` reaches 8. The page keeps the level and the transaction hash of each
   version in the browser storage.
6. **Result.** When the window closes, the server computes the result, and the committee decrypts
   it. The page decodes the published plaintext in the browser. It uses `selectBids` to find the
   bids that counted. It shows the bidders that it dropped because their bytes did not open, and the
   version of each bid that counted. Every type shows the winner, the price, your outcome and a grid
   with one lane for each bidder and one column for each level. For the mask-provider type and the
   no-providers type, the grid shows that the lane of the winner is the only zero lane at the price
   level. For the first-price type, the grid shows that the lane of the winner is exactly 1 at the
   price level, every lane before it is 0 and every slot above the price is 0. The page shows an
   error when the output does not have the pattern of a result. This does not happen for any bids
   and any masks (first-price type), when every mask is valid (mask-provider type) and for any
   shares (no-providers type).

An auction needs 2 bidders at least, and 8 at most. A bidder counts only if one of its bids opens
its commitments. With fewer than 2 such bidders, the server computes nothing, and the E3 fails at
its compute deadline. A mask-provider auction also needs a mask from every provider that opens its
commitment. If one provider does not send its mask, bidding stays closed, and the E3 fails at its
compute deadline. The other two types need nothing more.

## Test

```sh
cargo test --release -p e3-user-program   # the FHE program and its input policy, all three types, against a local l-BFV key
(cd circuits/bid && nargo test)           # the bid validity rules (the shared library)
hardhat test                              # the contract and the allowlist gate (with a mock bid verifier)
pnpm test:server                          # the server and the @interfold/auction package
pnpm test:integration                     # DKG -> 9 bid proofs and 1 mask proof -> FHE -> threshold decryption, the types 0 to 2
```

`pnpm test` runs `hardhat test`. `pnpm test:integration` runs `pnpm test:server` first.

The integration test runs three auctions at the same time. They need 26 encryptions, 9 bid proofs
and 1 mask proof.

| Type                         | Bids (bidder: step)              | What else it covers                                                                                                                                                                                                      | Result checked                       |
| ---------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| First-price                  | `0: 9`, `1: 9`, `2: 11`          | A top tie on step 9. An allowlist of bidders 0 to 2, and the creator account is rejected. Bidder 1 signs, and the relayer of the server sends the bid. The bytes of bidder 2 do not open, so the program drops bidder 2. | bidder 0 wins at price 9 (bid first) |
| Second-price, mask providers | `0: 14`, `1: 12`, `2: 9`, `0: 5` | The creator is the only provider and sends its mask. The update counts: bidder 0 bids the highest step and then updates. The test sends the update again as version 3, and a fourth bid is rejected.                     | bidder 1 wins at price 9             |
| Second-price, no providers   | `0: 5`, `1: 5`                   | A top tie on step 5 of a 6-step auction.                                                                                                                                                                                 | bidder 0 wins at price 5 (bid first) |

The test also checks that the contract rejects these bids:

- a 3-ciphertext bid for an auction with 4 roles (`InvalidBidShape`);
- a proof whose commitments are swapped (the verifier fails);
- a proof that another bidder copies with its own address (the verifier fails);
- a direct bid from an account that is not the bidder (`SenderNotBidder`);
- a bid from an account that is not on the allowlist (`BidderNotEligible`);
- a signed bid with two ciphertexts swapped, a bid with the signature of another account, and the
  same signed bid after it was sent (`InvalidSignature`);
- a bid for a mask-provider auction before its mask is in (`MasksPending`), and a second mask of the
  same provider (`MaskAlreadySubmitted`);
- a fourth bid of one address (`TooManyBids`).

It checks `bidCount`, `bidderCount`, the `firstIndex` and the `version` of each `BidSubmitted` event
and the number of leaves. It then selects the bids with `selectBids` and compares them with the
expected bids. `cargo test` covers a tie at the top for each type (the earliest position wins), 8
bidders, the output of the first-price type under any mask, the zero slots of the output, and the
leaf and the selection of the input policy. The latest valid version wins. An earlier version counts
if the latest does not open. A bidder with no bid that opens is dropped whole. A leaf vector is
shared with the Solidity `inputLeaf`. `hardhat test` covers the contract (bids, updates, relayed
bids, the verifiers, the allowlist and the gate configuration) and the Merkle root of the allowlist
gate on chain and in TypeScript. `pnpm test:server` runs the unit tests of the server and of `sdk/`,
including the input assembly for 2, 3 and 4 roles, the relay and the bid selection.

The tests of the first-price type are these. `hardhat test` covers the creation (providers are
rejected), the role count (3), the bidder limit (8) and the anchor rule: a bid of this type must
carry `vkAnchor3`. `cargo test` covers the result for 2 to 8 bidders, all bid patterns with the top
ties, and masks that are the worst case (a mask sum of 0 in every slot included): the result is
always exact. `pnpm test:server` covers the layout and the decoder, which reads the lanes and
rejects a pattern that no honest result has.

The tests of the mask-provider type are these. `hardhat test` covers the provider list, the order of
the leaves (the configuration, the masks, then the bids), the mask rules (shape, sender, a second
mask, a bad proof) and `MasksPending`. `cargo test` covers the policy of the masks and the result of
the type for 2 to 8 bidders and 1 to 4 providers, including masks that are the worst case for the
noise. `pnpm test:server` covers the input assembly with masks, the rule that starts a computation
(all masks and 2 bidders) and the mask provider of the server.

The tests of the no-providers type are these. `hardhat test` covers the creation (providers are
rejected), the role count (4) and the bidder limit (8), and the anchor rule: a bid of this type must
carry `vkAnchorQnr`. `cargo test` covers the result for 2 to 8 bidders, all bid patterns with the
top ties, and shares that the bidders choose against the program (so that `S` takes every value from
0 to 256): the result is always exact. It runs the FHE computation for a set of bidder counts.
`pnpm test:server` covers the layout, the decoder and the rule for providers, and the input assembly
and the rule that starts a computation for 4 ciphertexts and no masks.

## Deploy to Sepolia

The app can run on Sepolia. This checkout has made no Sepolia deployment. The steps below prepare
one. The local flow does not change: on chain 31337 the deploy uses the mock data-availability
verifier, and the server uses `mock_http`.

Read "Limits on Sepolia" at the end of this section first. The parameters are insecure, and the
compute proof is a mock.

### 1. Choose the Interfold protocol

| Target            | What you need                                                                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your own protocol | Deploy the protocol from this branch (`pnpm protocol:deploy` in `packages/interfold-contracts`). Your account owns it, so the deploy wires the program itself. |
| The official one  | The addresses are in `packages/interfold-contracts/deploy/protocol/sepolia-protocol.deployment.json`. The owner is a Safe.                                     |

The official Sepolia deployment cannot run this app yet:

- It has no route for parameter set 5 (insecure SIMD, l-BFV). Its routes cover the parameter sets 0
  and 2. The owner must add the route for set 5.
- Interfold keeps one ciphertext verifier for each encryption scheme (`fhe.rs:BFV`).
  `setCiphertextVerifier` replaces the verifier that other programs, such as CRISP, use for new E3s.
  With the mock compute verifier, this change also stops the proof check for those programs. Use
  your own protocol, or agree the change with the owner.
- The deploy script cannot call `setCiphertextVerifier` or `registerE3Program`. It prints the calls
  for the Safe (step 4).

Your protocol and the official one need these as well:

- Ciphernodes that run the insecure SIMD l-BFV circuits (`BFV_PRESET=insecure-simd`). Register and
  bond them in the registry. The `minimum` committee has 3 nodes. Enable the `sepolia` chain in
  `interfold.config.yaml` (`enabled: true`) and start each node with `interfold start`.
- The built circuits of this example: `pnpm dev:setup` writes `circuits/target/vk_anchor.json`
  (`vkAnchor2`, `vkAnchor3`, `vkAnchorMask` and `vkAnchorQnr`) and the bid and mask verifiers. The
  deploy reads them.
- Sepolia ETH for the deploy account and for the server key. The auction creators need the fee token
  of the protocol.

### 2. Set up Avail

The server publishes each ciphertext output to Avail. The `AvailVectorXDataAvailabilityVerifier`
checks the VectorX proof on Ethereum. Only the output uses Avail. The bids are calldata of
`publishInput`.

1. Create an Avail application ID on the Avail testnet (Turing). Sepolia uses the Turing VectorX
   bridge.
2. Create an Avail account and fund it with testnet tokens. Its secret URI is `AVAIL_SEED`.
3. Build the helper that the server runs:

   ```sh
   cargo build --release -p auction-da
   ```

`auction-da` has two commands. Each prints one JSON document.

```sh
# Environment: AVAIL_RPC_URL, AVAIL_APP_ID, AVAIL_SEED, AVAIL_BRIDGE_API_URL, DESTINATION_CHAIN_ID
auction-da submit --file ciphertext.bin     # waits for Avail finality; prints the publication
auction-da proof --pending '<publication>'  # prints {"status":"pending"} or {"status":"ready", ...}
```

The timing matters:

- Avail finalizes the data in minutes. `auction-da submit` waits for it, for up to 5 minutes.
- The VectorX proof can take up to about 3 hours. CRISP reserves 10 800 seconds for it.
- The compute window starts when the input window closes. The compute, the Avail finalization, the
  proof and the publication transaction must all fit in it. The official Sepolia value is 604 800
  seconds (7 days). For your own protocol, set `interfold.timeoutConfig.computeWindow` to at least
  14 400 seconds (4 hours).
- The input window needs no Avail time, because the bids do not use Avail.

### 3. Deploy the program

Compile first (`pnpm compile`). Then deploy:

```sh
export SEPOLIA_RPC_URL=https://...        # an HTTP RPC endpoint
export PRIVATE_KEY=0x...                  # the deploy key. Never commit it.
export INTERFOLD_ADDRESS=0x...            # the protocol; the script does not need a record of it
export TEMPLATE_UNPROVED_TEST=1           # the mock compute verifier
export ALLOW_SEPOLIA_UNPROVED_COMPUTE=true  # the explicit acknowledgment that Sepolia requires
pnpm deploy:sepolia
```

| Variable                                 | Effect                                                                                                                                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SEPOLIA_RPC_URL`                        | The RPC endpoint of the `sepolia` network. It falls back to `RPC_URL`.                                                                                                                                                                                       |
| `PRIVATE_KEY`                            | The deploy key. The `sepolia` network has no other account.                                                                                                                                                                                                  |
| `INTERFOLD_ADDRESS`                      | The Interfold address. Without it the script reads `deployed_contracts.json`.                                                                                                                                                                                |
| `POSEIDON_T3_ADDRESS`                    | The `PoseidonT3` library. Without it the script uses the record, then the canonical address, then deploys it.                                                                                                                                                |
| `TEMPLATE_UNPROVED_TEST=1`               | Deploy `MockOpenVmReceiptVerifier`. It accepts every compute receipt. Chain 31337 allows it. Sepolia also needs the next variable.                                                                                                                           |
| `ALLOW_SEPOLIA_UNPROVED_COMPUTE`         | `true` acknowledges the mock compute verifier on Sepolia. Every other chain refuses it.                                                                                                                                                                      |
| `MOCK_DATA_AVAILABILITY=true`            | Deploy `MockDataAvailabilityVerifier` on a public testnet. Mainnet refuses it. The server needs `DATA_AVAILABILITY_MODE=mock_http`, and the `sepolia` chain of `interfold.config.yaml` needs `data_availability.mode: mock_http` with the URL of the server. |
| `DEFER_PROTOCOL_WIRING=true`             | Skip `setCiphertextVerifier` and `registerE3Program` even when the key is the owner.                                                                                                                                                                         |
| `ALLOW_REPLACE_CIPHERTEXT_VERIFIER=true` | Replace a ciphertext verifier that the protocol already has. Without it, the script prints the calls instead.                                                                                                                                                |

Without `TEMPLATE_UNPROVED_TEST`, the script deploys the real `OpenVmReceiptVerifier` with the
identity that `interfold program compile` wrote. Real proofs on Sepolia are not tested. Without
`MOCK_DATA_AVAILABILITY`, the data-availability verifier is `AvailVectorXDataAvailabilityVerifier`
with the Sepolia bridge and VectorX addresses of `@interfold/contracts`.

The program constructor takes, in this order, the Interfold address, the compute verifier and the
image ID, then the bid verifiers `bidVerifier2`, `bidVerifier3` and `bidVerifier4`, the mask
verifier `maskVerifier`, the anchors `vkAnchor2`, `vkAnchor3`, `vkAnchorMask` and `vkAnchorQnr`, and
the data-availability verifier. The deploy script deploys the four verifiers, reads the four anchors
from `circuits/target/vk_anchor.json` and records all of them in `deployed_contracts.json`.

The script records every address in `deployed_contracts.json` and writes `e3_program` and its
`deploy_block` to the `sepolia` entry of `interfold.config.yaml`. Write down the `deploy_block`. The
server needs it as `DEPLOY_BLOCK`.

### 4. Wire the protocol

If the deploy key is the Interfold owner, the script sends `setCiphertextVerifier` and
`registerE3Program` and checks `e3Programs`. Otherwise it prints both calls as JSON with `to`,
`function`, `args` and `data`. Send them in that order from the owner (for example a Safe batch).
The program is not usable until both calls are executed.

### 5. Run the server

Copy `server/.env.example` and fill the Sepolia block. The server refuses a bad configuration at
start.

```sh
set -a && source server/.env && set +a
pnpm tsx ./server/index.ts
```

Or run the Docker image. Build it from the repository root, after the host builds that the
`Dockerfile` header lists:

```sh
docker build -f examples/auction-e2e/server/Dockerfile -t auction-server .
docker run -p 8080:8080 -v auction-data:/data --env-file examples/auction-e2e/server/.env auction-server
```

| Variable                                                                           | Use                                                                                                                                                                            |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `RPC_URL`, `WS_RPC_URL`, `CHAIN_ID`, `PRIVATE_KEY`                                 | The chain (31337 or 11155111), the HTTP endpoint, an optional WebSocket endpoint for the live listener, and the operator key.                                                  |
| `INTERFOLD_ADDRESS`, `REGISTRY_ADDRESS`, `FEE_TOKEN_ADDRESS`, `E3_PROGRAM_ADDRESS` | The contracts.                                                                                                                                                                 |
| `DEPLOY_BLOCK`, `LOG_CHUNK_SIZE`                                                   | The first block to scan, and the largest log range of one request (default 10 000). `DEPLOY_BLOCK` is required on Sepolia.                                                     |
| `PORT`, `PROGRAM_RUNNER_URL`, `CALLBACK_URL`                                       | The listen port, the program runner and the base URL of this server that the runner calls back. In Docker, use service names, not `127.0.0.1`.                                 |
| `DATA_AVAILABILITY_MODE`                                                           | `mock_http` (default) or `avail`.                                                                                                                                              |
| `AVAIL_RPC_URL`, `AVAIL_APP_ID`, `AVAIL_SEED`, `AVAIL_BRIDGE_API_URL`              | The Avail settings of `avail` mode. `DESTINATION_CHAIN_ID` is `CHAIN_ID`.                                                                                                      |
| `AVAIL_PROOF_POLL_INTERVAL_SECONDS`, `AUCTION_DA_BIN`                              | The proof poll interval (default 60) and the path of `auction-da`.                                                                                                             |
| `DATA_DIRECTORY`                                                                   | The directory of the published objects, the Avail records and the pictures (`images/`). Keep it on a volume.                                                                   |
| `RELAYER_PRIVATE_KEY`                                                              | The account that pays the gas of `POST /relay`. On the local chain it defaults to Anvil account 9, which no bidder or ciphernode uses. On Sepolia the relay is off without it. |
| `MASK_PROVIDER_PRIVATE_KEY`                                                        | Optional. The key of the mask provider of the server (see below). On both networks it is off without it. The account needs gas, and no ciphernode or bidder uses it.           |

The server does this:

- At start it lists the `AuctionCreated` events from `DEPLOY_BLOCK`. For each auction that has a
  committee key and no output, it rebuilds the key from the historical events, checks the key
  commitment and schedules the compute.
- In `avail` mode it stores each output in `DATA_DIRECTORY/e3-<id>/`, publishes it to Avail, polls
  the proof and then calls `publishCiphertextOutput` with the ABI proof as the availability proof.
  After a restart it resumes each unfinished output. It checks the E3 stage before it publishes, so
  it never publishes an output twice.
- It gives each run a random token and sends the runner `CALLBACK_URL/callback/<e3Id>/<token>`. The
  callback accepts only that token. A failed run is tried again with backoff until the E3 leaves
  `KeyPublished` or chain time passes the compute deadline.
- In `avail` mode it calls `verify` on the program before it spends Avail funds on an output.
- `GET /health` returns 200 when the process is up.
- It reads every `BidSubmitted` event of the auction and sends the runner all the inputs: the
  configuration and each ciphertext of each bid, with its commitment, its bidder and its bid version
  (`input_commitments`, `input_slots`, `input_parents`). The input root covers all of them. The
  program then counts, for each bidder, its latest bid whose ciphertexts open their commitments. The
  server applies the same rule (`sdk/src/selection.ts`) and does not start a run with fewer than two
  such bidders.
- For a mask-provider auction it also reads the providers (the `auctionProviders` view) and every
  `MaskSubmitted` event. It sends the runner the inputs in leaf order: the configuration with the
  providers, then the masks (`input_slots` is the provider and `input_parents` is `MASK_VERSION`),
  then the bids. It starts no run until every provider has a mask that opens its commitment
  (`checkMasks`) and at least 2 bidders count. The other two types have no mask input: the server
  sends the configuration and the bids, and the ciphertexts of each bid are 3 or 4 consecutive
  leaves.
- If `MASK_PROVIDER_PRIVATE_KEY` is set, the server is a mask provider. For each mask-provider
  auction that lists its address, it waits for the committee key and for the input window. It then
  draws a mask, proves it with `BidProver.proveMask` in Node and sends `publishInput` from that key.
  It proves one mask at a time. It reads `maskSubmitted` first, so a restart sends no second mask. A
  failed send is tried again with backoff and the same proof. If the contract rejects the proof, the
  server proves again. The server skips an auction of another type, or an auction that does not list
  its address. The mask is secret only while the server keeps it, so a public server key counts as
  one provider only.
- `GET /provider` returns `{ "address": "0x..." }`, the address of the mask provider, or status 404
  without `MASK_PROVIDER_PRIVATE_KEY`. The web app uses it to offer the server provider in the
  creation form. CORS is open.
- `POST /relay` with `{ "e3Id": "<decimal>", "data": "0x..." }` sends `publishInput(e3Id, data)`
  from the relayer account, after a simulation, and answers `{ "txHash": "0x..." }` once it is
  mined, or `{ "error": "<revert reason>" }` with status 422. It makes no other check: the program
  verifies the EIP-712 signature, the gate and the proof, and a relayed bid cannot change after it
  is signed. Any page may call it (CORS is open). It spends the gas of `RELAYER_PRIVATE_KEY`, so a
  public server needs its own funded key and a rate limit in front.

Run `pnpm test:server` for the unit tests of the configuration, the log chunks, the publication
steps, the input metadata, the relay, the pictures, the bid selection and the mask provider.

### The auction picture

An auction can have one picture. The creator adds it, and every visitor sees it in the list and on
the auction page. The picture is not on chain. The server stores it in `DATA_DIRECTORY/images/`.
This directory needs no new setting, and it is on the same volume as the other server data. A
reverse proxy such as Caddy must pass the `PUT` and `OPTIONS` methods, the header
`x-auction-image-signature` and a request body of 1 MiB. Caddy does this by default.

`PUT /auctions/:e3Id/image` stores the picture. The body is the image bytes. The request header
`x-auction-image-signature` holds the signature of the creator (`personal_sign`, hex). The signed
text has five lines:

```text
Interfold auction image
chain: <chain id>
program: <AuctionProgram address, checksum form>
e3Id: <decimal>
sha256: 0x<hex SHA-256 of the exact body bytes>
```

The server answers with these statuses:

| Status | Cause                                                                                 |
| ------ | ------------------------------------------------------------------------------------- |
| 400    | `e3Id` is not a decimal number, the body is empty, or the signature is missing or bad |
| 413    | The body is larger than 1 MiB (1 048 576 bytes)                                       |
| 415    | The first bytes are not PNG, JPEG or WebP. SVG is refused.                            |
| 404    | `auctions(e3Id)` on chain has the zero address as creator                             |
| 403    | The signer is not the creator, or the signature covers other bytes                    |
| 204    | The server stored the picture. It replaced an earlier picture of this auction.        |

The server reads the type from the first bytes and ignores the content type of the request. It
writes the file to a temporary name and then renames it, so a reader never gets half a file. The
size limit of 1 MiB applies to this route only.

`GET /auctions/:e3Id/image` returns the bytes. It sets `Content-Type` to the type that it found,
`X-Content-Type-Options: nosniff`, `Cache-Control: public, max-age=60` and `ETag` (the SHA-256 of
the file). It answers 304 when `If-None-Match` matches. It answers 404 when the auction has no
picture. Any page can call both routes (CORS is open, as for `POST /relay`). The response also sets
`Cross-Origin-Resource-Policy: cross-origin`, because the web app is cross-origin isolated.

The web app shrinks the picture before it uploads it. It scales the picture to 1280 pixels on the
long side, and encodes WebP (JPEG if the browser cannot encode WebP). This removes the metadata and
transparency. After the create transaction is mined, the wallet asks for the signature. If the
upload fails, the auction stays and the page shows the error. The creator can then select **Add
picture** (or **Replace picture**) on the auction page. The web app reads the server URL from
`VITE_SERVER_URL`, as for the relay.

### 6. Run the program runner

Run it where the ciphernodes can reach it, and put its URL in `PROGRAM_RUNNER_URL`. The server must
be reachable from the runner at `CALLBACK_URL`.

```sh
E3_PROGRAM__DEV=true interfold program start   # the unproved runner that matches the mock compute verifier
```

### 7. Deploy the web app

The web app is a static Vite build. Vercel cannot build it from git: the build needs the compiled
circuits, `types/` and the built SDK and wasm package, and none of them is committed. Build it on a
prepared host and upload the output.

1. Prepare the host. Run `pnpm dev:setup` and `pnpm compile` in this directory, and build the
   workspace packages the client imports (`@interfold/sdk`, `@interfold/contracts` and
   `@interfold/auction`).
2. Link the client to a Vercel project: `cd client && vercel link`.
3. Pull the project settings: `vercel pull --yes --environment=production`. Set the `VITE_*`
   variables of `client/.env.example` on the project first. Every value is public in the bundle: put
   no secret in them. For Sepolia: `VITE_CHAIN_ID=11155111`, `VITE_RPC_URL`, `VITE_DEPLOY_BLOCK`
   (the program `deploy_block`), `VITE_LOG_CHUNK_SIZE`, the four contract addresses and, if you want
   them, `VITE_FAUCET_ADDRESS` and `VITE_WALLETCONNECT_PROJECT_ID`.
4. Build locally: `vercel build --prod`. This runs `pnpm run build` and writes
   `client/.vercel/output`.
5. Upload the output: `vercel deploy --prebuilt --prod`.

`client/vercel.json` turns off git deployments and the install step, and keeps the cross-origin
isolation headers and the single-page rewrite. Prover threads need those headers.

### Limits on Sepolia

- The parameters are insecure (N = 128, t = 257). They give no security. Do not use the app for
  anything of value.
- The compute proof is a mock. The on-chain verifier accepts every compute receipt. Nothing proves
  that the output follows from the bids. Trust the operator of the server and of the program runner.
- Data availability is real: the VectorX proof is checked on Ethereum. The server key and the Avail
  account are single points of trust and of availability.
- The VectorX proof takes hours. A result appears after the compute, the Avail finalization, the
  proof and the decryption.
- The official Sepolia deployment needs the owner to add the route for parameter set 5, and a change
  of the shared ciphertext verifier (step 1).
- No Sepolia deployment of this app was run from this checkout. Test each step on your own before
  you rely on it.

## Timings

These figures come from one run of `pnpm test:integration` (Node, 11 prover threads) on an Apple
Silicon laptop. They are estimates.

| Step                                                | Time                                                                                              |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Key generation (request to published key, real DKG) | 6 to 13 minutes for one auction; about 26 minutes when four ran at the same time (an earlier run) |
| Threshold decryption (ciphertext output to result)  | about 20 seconds                                                                                  |

The time of a bidder (encryptions, encryption proofs and the bid proof, in Node and in the browser)
and the time of the integration test have not been measured again for the flow of one bid proof. The
older figures were for a proof of each ciphertext, and they do not apply.

## Layout

| Path                            | What                                                                                                                                                                |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sdk/`                          | `@interfold/auction` (private): the four files below. `pnpm build:sdk` builds `sdk/dist` and `sdk/circuits`                                                         |
| `sdk/src/layout.ts`             | the slot encoding, the roles and limits of each type and the result decoders                                                                                        |
| `sdk/src/prover.ts`             | `BidProver`: encrypt, the encryption proofs, the pair, shares and bid proofs, and `proveMask` (a provider mask)                                                     |
| `sdk/src/selection.ts`          | `selectBids` and `checkMasks`: the TypeScript form of the input policy (which bids and which masks count)                                                           |
| `sdk/src/allowlist.ts`          | `allowlistRoot` and `allowlistProof`: the allowlist tree of `MerkleAllowlistGate`                                                                                   |
| `circuits/bid/`                 | `auction_bid`: the library with the bid rules shared by the circuits, and the tables of the honest bids                                                             |
| `circuits/pair/`, `shares/`     | `auction_bid_pair` (roles 0 and 1, the bid) and `auction_bid_shares` (roles 2 and 3, the shares): recursive                                                         |
| `circuits/bid3/`, `bid4/`       | `auction_bid3` and `auction_bid4`: the proofs the contract verifies; `scripts/compile_circuits.sh` builds all                                                       |
| `circuits/bid2/`, `mask/`       | `auction_bid2` (the bid proof of type 1) and `auction_mask` (the mask proof of a provider): the proofs the contract verifies                                        |
| `contracts/AuctionProgram.sol`  | auction config and providers, bids, masks and updates, relayed-bid signatures, gate check, proof checks, leaves, DA check                                           |
| `contracts/interfaces/`         | `IBidderGate` and `IBidVerifier`                                                                                                                                    |
| `contracts/gates/`              | `MerkleAllowlistGate`: the example gate                                                                                                                             |
| `contracts/verifiers/`          | `AuctionVerifier2.sol`, `AuctionVerifier3.sol`, `AuctionVerifier4.sol` and `AuctionMaskVerifier.sol`: generated by `scripts/compile_circuits.sh`. Do not edit them. |
| `program/src/lib.rs`            | the FHE processor and the input policy (the leaf and the selection; all three auction types)                                                                        |
| `program/examples/bid_table.rs` | the generator of `circuits/bid/src/constants.nr`                                                                                                                    |
| `program/examples/vk_hash.rs`   | the hash of ordered VK hashes, for the VK anchor                                                                                                                    |
| `runner/`                       | the program server (`program-runner`) that serves `program/`                                                                                                        |
| `guest/`                        | the OpenVM guest that proves the program                                                                                                                            |
| `server/`                       | the coordination server: events, compute, relay (`POST /relay`), mask provider (`GET /provider`), pictures (`/auctions/:e3Id/image`), output publication, `/health` |
| `da/`                           | `auction-da`: the Avail helper of the server (Rust)                                                                                                                 |
| `deploy/default.ts`             | the deployment of the program and of the allowlist gate, for the local chain and Sepolia                                                                            |
| `client/`                       | the web app                                                                                                                                                         |
| `test/`                         | the Hardhat tests of the contract and the gate                                                                                                                      |
| `tests/`                        | the integration test and its input helper                                                                                                                           |

## Limits

- The parameters are insecure. They give no security.
- An auction has 2 to 8 bidders, for every type. `maxBidders(type)` and `MAX_BIDDERS_BY_TYPE` in
  `sdk/src/layout.ts` set the limit. The slot layout has one copy of the lanes, so `16 n` slots must
  fit in 128.
- An auction has 2 to 16 price steps, chosen by its creator. The slot layout always has 16 levels (0
  to 15). The steps `levels` to 15 stay empty, because every thermometer is 0 there. Thus the price
  never decodes to a step that the auction does not have.
- Anyone can bid, unless the auction has a gate. The first bid of an address takes one of the places
  (8), even if its bytes do not open. When the places are full, the contract rejects the first bid
  of every new address. One party with that many addresses can fill all places. A gate limits who
  can bid, but the example allowlist does not limit one party that holds several listed addresses.
- An address can send 3 bids at most: the first bid and 2 updates.
- The proof binds the ciphertext commitment, not the published bytes. A bidder that publishes bytes
  that do not open the commitment does not count: the program uses an earlier version, or drops the
  bidder whole. This does not stall the E3. The auction needs 2 bidders that count.
- A bidder can withdraw by publishing bytes that do not open the commitments. The bidder learns
  nothing from this.
- The ciphertexts are still on chain as calldata. This example has no data-availability input path
  yet. The leaf already binds the content hash of each ciphertext, so a later data-availability path
  can supply the bytes.
- A relayed bid shows the bidder address on chain, as a direct bid does. `POST /relay` has no
  authentication and no rate limit.
- The server stores the picture of an auction without a rate limit. A creator can upload 1 MiB for
  each auction that the creator owns, and the file stays on the disk of the server. The picture is
  public. An EOA wallet must sign the upload: the server does not check ERC-1271 signatures.
- A tie at the top goes to the tied bidder whose counted bid was published first. This favours early
  bidders: a bidder that bids late cannot win a tie, and an update gives up the place of the earlier
  bid. The order is the order of the transactions on chain, so whoever orders them (the block
  builder, or a relayer for relayed bids) chooses the winner of a tie between bids that arrive at
  the same time. A bidder cannot change the tie by encrypting again, and the ciphertext bytes play
  no part in it. A bidder can still use more than one address to hold more than one place.
- The result of every type does not show that a tie happened. It shows the winner and the price
  only. For the first-price type, the price is the winning bid, so that bid is public.
- A first-price bid has a third ciphertext, the mask, so a bid makes two proofs after the
  encryptions (the pair proof and the bid proof), as a mask-provider bid does. A no-providers bid
  makes three: the pair proof, the shares proof and the bid proof.
- The first-price type and the two second-price types cannot read a slot as zero by error. In the
  first-price type, the mask touches only the slots that the reader does not need. In the
  second-price types, the factor `r` is never zero in a slot that exists.
- Privacy of the first-price type needs one bidder that draws its mask at random and keeps it
  secret. If all the bidders share their masks, they can read the numbers `G + E`, which show more
  than the winner and the price (for example, how many bidders bid above a level). The result alone
  is never enough to read a bid.
- A mask-provider auction has `k` mask providers (1 to 4), and the creator names them. A provider is
  not a bidder: the contract never counts its address as a bidder, and it rejects its bids.
- Privacy of the mask-provider type needs one honest provider that keeps its mask secret and draws
  it at random. If all providers share their masks, they can read the numbers in `tests`: for each
  lane and level, a product of counts. These numbers show more than the winner and the price. The
  result alone is never enough to read a bid.
- The mask-provider auction needs every provider. If one provider does not send its mask, the
  contract keeps bidding closed, and the E3 fails at its compute deadline. A provider cannot be
  replaced after the creation of the auction. The creator should name providers that are online, and
  should name the server provider, if there is one.
- A mask that does not open its commitment stops the mask-provider auction too: the program needs
  every mask. The contract cannot see this, because it does not see the plaintext. Only the provider
  can send its mask, so only a provider can cause it. The web app shows an alert.
- A mask-provider bid proves only `ge` and `gt`. The mask providers add 1 to 4 encryptions and
  proofs to the whole auction, one for each provider, and the bidders do no mask work.
- A no-providers bid has four ciphertexts: the two thermometers and two shares. The shares need no
  provider and no proof other than the encryption proof, and a bid makes three proofs after the
  encryptions (the pair proof, the shares proof and the bid proof).
- The no-providers type needs no trusted party and cannot fail by chance, whatever the bidders send.
  The price is a small statistical hint. `S^2 - 3` takes only 129 of the 257 values, so the factor
  `r` is not exactly uniform, and the numbers of the result that are not 0 leak a little about the
  counts in `tests`, which depend on the losing bids. The hint is larger on the small modulus of
  this demo than on a secure parameter set. The result alone does not show a bid, but this type is
  not the choice if the losing bids must stay completely hidden. Privacy needs one bidder that draws
  its shares at random and keeps them secret. If all the bidders share their shares, they can
  compute `r`.
- The committee publishes 128 coefficients (the whole ring) for this preset. Other presets
  publish 50.
