# Auction designs viewer

A small static web app that shows the sealed-bid auction designs of `../ts`. It runs the plaintext
simulation in the browser. Nothing is encrypted, and nothing leaves the page: there is no wallet, no
chain, and no network call (except the web fonts).

The app has three sections:

- **Overview:** one card for each of the 10 designs (the 8 region designs and the 2 ratio-lane
  designs `rl-first-price` and `rl-second-price`), with what the output reveals, the price rule, the
  tie rule, the own-rank property, and the measured ct×ct, ct×pt, and depth. A chart shows ct×ct and
  depth for 2 to 16 bidders.
- **Playground:** set the bidders, the price levels, each bid, the seed, the tie priority, and the
  profile. For the selected design the app shows the bidder inputs, each step of the program trace,
  and the output with its readout. A zero slot is a filled cell. The decoded result is compared with
  the plain rule on the bids. For a ratio-lane design, a lane view shows each lane for each price
  level as zero, uniform, or result. Under it are the weight groups (the bidders that the value of a
  group names), the tie set, the random lane, and the tie resolution: the winner is
  `tie set[random mod size]`. With more than 13 bidders on the toy profile (16 on the demo profile),
  the lanes of more than one weight group show.
- **All designs on these bids:** one table row for each design, with the tie set of the ratio-lane
  designs.

The app imports the simulation from `../ts/src` with the Vite alias `@designs`. It does not copy or
change that code. Read `../ts/README.md` for the encodings.

## Run

You need Node 18 or later. The directory is a separate pnpm root (see `pnpm-workspace.yaml`), so
`pnpm install` does not touch the root workspace.

```sh
pnpm install
pnpm dev        # http://localhost:5173
pnpm build      # type check, then a static build in dist/
pnpm typecheck  # tsc --noEmit
```

The toy profile (N = 1024) is the default. The demo profile (N = 16384) is slower. The cost chart
waits for a click on that profile.
