# RWA Guard

**One call that answers: is this token safe to act on, right now?**

Tokenised real-world assets carry risks that an ERC-20 balance cannot express. A
position can be globally frozen. A holder can be individually blocked. The
implementation can be replaced underneath every holder. The display-to-underlying
ratio can change on a timer. The price feed can stop updating when the stock
market closes.

Today there is no on-chain primitive that answers the question *"is this token
safe to act on, right now?"* `RWA Guard` makes that question a single call.

```solidity
(bool ok, uint256 reasonBits) = guard.isSafeToTrade(token, ctx);
```

`RWA Guard` is a stateless `view` contract. It holds no funds, has no owner, and
has no upgrade path.

## Deny-by-default

Each row below is a reason bit. **A signal the guard cannot read is a `BLOCK`,
not a pass** -- an unreadable condition is not a satisfied condition.

| Bit | Gate | Condition |
|----:|------|-----------|
| 0 | G0 | Token identity |
| 1 | G1 | Global pause |
| 2 | G2 | Token pause |
| 3 | G3 | Counterparty block |
| 4 | G4 | Implementation drift |
| 5 | G5 | Ratio transition |
| 6 | G6 | Feed staleness |
| 7 | G7 | Withdrawn 2026-09-04. The bit stays permanently reserved. |
| 8 | G8 | Feed coherence (rejects 56 of 146 live feeds) |
| 16-24 | U | Per-gate unreadable plane |
| 255 | U | Aggregate: set if and only if any bit on the unreadable plane is set |

`ok` is defined as `reasonBits == 0` and is never re-derived from a subset of the
bits. The decoding contract a reader must implement -- including what to do with
a bit it does not recognise -- is stated in full at the top of
`contracts/src/GuardBits.sol`. Bits 7 and 23 are permanently reserved; a payload
that sets either one did not come from this version.

Two properties the tests are there to prove: **each gate is load-bearing**, and
**unknown is not allow** -- there is no code path from "could not determine" to
`ok = true`.

## Known limitations

The guard reports the absence of eight named conditions, plus an unreadable bit when it could not check one. It does not check the integrator's own accounting.

Once a ratio transition has completed, the ratio condition reads clean; with every other condition clear, reasonBits is exactly 0 and the guard lets a redeem through. Both demo vaults pay one token per share and never use the multiplier in that payout, so after the transition both pay the wrong amount. In the tested case the ratio halves: each vault pays twice the fair amount, and the first redeem empties the guarded vault, so the next holder's redeem reverts. This exposure is declared, not fixed: test/Integration.t.sol measures it (AS-29d).

An off-chain `eth_call` answer is advisory and carries a time-of-check to
time-of-use window; it can be stale as soon as the next block. Only
in-transaction evaluation through the integration library, reverting on failure,
is atomic.

Both chains receive the same build artifact, deployed with a plain `CREATE`,
never `CREATE2`. The two deployments below share one address only because the
same deployer used nonce 0 on both chains; nothing depends on that.
On a chain where the token and the control plane do not exist, every call returns
`ok == false` with at least the unreadable bits of G0 through G5 and the
aggregate bit set. That is the designed consequence, not a failure. G1 through G5
read contracts that exist only on Robinhood Chain; on Arbitrum Sepolia only G0,
G6 and G8 have anything to read.

## This is not an audit

This code has not been audited. It is a hackathon entry: read it, run the tests,
and form your own view before relying on any part of it. Nothing here is a
warranty, and the gate table above is the complete list of what the guard looks
at.

## AI disclosure

This entry was built with AI coding assistance. Contract code, tests, the
tooling scripts and this document all had AI involvement at some stage. Every
file was reviewed before it was committed, and the test suite and the mutation
battery under `contracts/` exist so that review is not the only thing standing
behind the claims made here. The threat model, the scope limits and the decision
to declare the exposure above rather than paper over it are ours.

## Identifiers

Identifiers appear throughout the code, the tests and the comments. `AS-`, `SG-`
and `TM-` number acceptance criteria, security gaps and threat model entries, and
they are defined inside this repository. `FD-`, `TS-`, `KG-`, `RD-` and `BR-` are
design-review trace numbers: a reader will find the identifier here but not the
note it points at, because those notes are not part of this repository.

## Build and test

Foundry is the only toolchain. `contracts/forge.sh` is a thin wrapper that keeps
every build artifact outside the repository, so a checkout stays clean.

```
cd contracts
./forge.sh build
./forge.sh test -vv
./forge.sh fmt
./forge.sh battery [--only <id>]     # mutation battery
./forge.sh parity [--self-test]      # cross-checks between the scripts
./forge.sh coverage --report lcov
```

Current state of `./forge.sh test`:

```
Ran 15 test suites: 235 tests passed, 0 failed, 2 skipped (237 total tests)
```

## Deploy

`script/Deploy.s.sol` reads no keys and no RPC endpoint from inside Solidity. The
operator supplies all three through the forge CLI: a wallet (a keystore account
is preferred over a raw private key), a sender address, and an RPC endpoint.

```
forge script script/Deploy.s.sol:Deploy \
  --rpc-url <endpoint> --account <keystore-account> --sender <address> --broadcast
```

Without `--broadcast` the same command only simulates. The contracts-local
`.gitignore` excludes `.env` and `broadcast/`, so neither a key file nor a
broadcast record can end up committed.

## Deployments

| Network | Address | Contract |
|---|---|---|
| Robinhood Chain testnet (chain id 46630) | `0x44C8B6c094a20e17Cc5A7D9C8227dFD631260a2e` | `RWAGuardView` |
| Arbitrum Sepolia (chain id 421614) | [`0x44C8B6c094a20e17Cc5A7D9C8227dFD631260a2e`](https://sepolia.arbiscan.io/address/0x44C8B6c094a20e17Cc5A7D9C8227dFD631260a2e) | `RWAGuardView` |

On both chains the deployed runtime bytecode equals the build artifact's
`deployedBytecode` byte for byte.

Observed with one `eth_call` each (no price feed passed, so G6 and G8 are
unreadable in both):

- Robinhood Chain testnet, TSLA token, the control plane's current
  implementation as `expectedImpl`: `reasonBits == 0x8000…01480000` -- G0, G1,
  G2, G4 and G5 were read and none fired; G3, G6 and G8 were unreadable.
  Passing a different `expectedImpl` sets the G4 bit (`…01480010`).
- Arbitrum Sepolia, where the token and the control plane do not exist:
  `reasonBits == 0x8000…017f0000` -- the unreadable bits of G0 through G6 and
  G8, plus the aggregate bit, the designed consequence described above.

## Timeline

This repository is a fresh export of a private workspace. Its first commit is a
snapshot dated when the export was made, not a replay of earlier history; the
work after that lands as ordinary commits. The Buildathon ran from 2026-09-14.

Written before 2026-09-14 (work began 2026-09-08; the organisers confirmed in
writing that prior code is allowed):

- `contracts/src/GuardBits.sol`, `contracts/src/GuardCore.sol` -- both revised since
- `contracts/test/Base.sol`, `contracts/forge.sh`, `contracts/foundry.toml`,
  `contracts/test/fixtures/README.md` -- revised since
- `contracts/test/GuardBits.t.sol`,
  `contracts/test/fixtures/equity-token-proxy.runtime.hex` -- unchanged since

Written from 2026-09-14 on:

- `contracts/src/RWAGuard.sol`, `contracts/src/RWAGuardView.sol`,
  `contracts/src/demo/`
- every other file under `contracts/test/` (ten of the eleven `.t.sol` files)
- `contracts/script/Deploy.s.sol`, `contracts/mutation_battery.sh`,
  `contracts/build_parity.sh`, `contracts/tools/`, `contracts/.gitignore`
- `web/` and this README
- both deployments (2026-09-16)

## Web page

`web/` is a dependency-free page: three files, no build step, no CDN, no package
manager. Open `web/index.html` directly. It hand-builds the `eth_call`, decodes
the two-word return under the full decoding contract, and keeps an `eth_chainId`
control arm in every run -- because a rejected endpoint makes every call fail
identically, which reads exactly like "the contract has none of these functions".
It also decodes a pasted `reasonBits` value with no network at all.

## Layout

```
contracts/src/          the guard, the gate implementations, the integration library
contracts/test/         the test suite
contracts/script/       deployment
contracts/forge.sh      toolchain wrapper; keeps artifacts out of the tree
web/                    dependency-free page that calls the guard
```

## License

MIT (`SPDX-License-Identifier: MIT`), `pragma solidity 0.8.24`.
