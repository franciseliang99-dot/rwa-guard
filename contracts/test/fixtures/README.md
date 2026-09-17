# Bytecode fixtures

## `equity-token-proxy.runtime.hex`

The 283-byte **runtime** bytecode of a deployed equity-token proxy on Robinhood Chain
testnet (chain id 46630), captured 2026-09-08 by `eth_getCode`.

**How it was obtained** — re-run this to reproduce it byte for byte:

```sh
RPC=https://rpc.testnet.chain.robinhood.com
EQUITY_ADDR=0xc9f9c86933092bbbfff3ccb4b105a4a94bf3bd4e   # TSLA equity token
# (the shell variable is deliberately not called TOKEN: secret scanners flag that
#  name when it is followed by a long value, and they are right to — "ERC-20 token"
#  and "credential token" are the same word. A check that carries a known-benign
#  finding is how checks get ignored.)

# control arm, same endpoint, same run — proves a zero or a failure below
# would be a value and not a transport symptom
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# => {"jsonrpc":"2.0","id":1,"result":"0xb626"}      # 0xb626 == 46630

curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getCode\",\"params\":[\"$EQUITY_ADDR\",\"latest\"]}"
```

**It is fetched, never hand-typed.** That is the whole point: the guard's two compile-time
constants are supposed to be *derived from this code*, not transcribed from a note someone
took once. A hand-typed fixture would make the derivation test pass by construction.

### The two assertions the tests must make against it

Both verified 2026-09-08 at the time of capture:

1. **`keccak256(runtime) == KNOWN_PROXY_CODEHASH`**
   → `0x2f367e6a678e7b30ab613d5963e541e6f4d3ca586de76e2f441fbfeb1a27c440` ✅
   Identical for all five equity tokens (TSLA · AMZN · PLTR · NFLX · AMD).
2. **Byte at offset 28 is `PUSH32` (`0x7f`), its 32-byte immediate has a zero high 12 bytes,
   and its low 20 bytes are the control-plane address** ✅
   → `0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca5`

The derivation is unambiguous, and that was measured rather than assumed: **the whole 283 bytes
contain exactly one `PUSH32`**, and the control-plane address occurs at exactly one byte offset
(41, i.e. 28 + 1 opcode + 12 zero bytes). There is no second candidate to pick wrongly.

⚠ The tool was calibrated in the same run rather than trusted: `cast keccak 0x` returns the
known keccak of the empty input, and `cast keccak "abc"` equals `cast keccak 0x616263`, so it
hashes decoded bytes rather than the ASCII of the hex string. Without that arm, a tool that
hashed the string would have produced a wrong-but-plausible constant.

### What a full disassembly of it shows

Walking the instruction stream from offset 0 and respecting PUSH immediates consumes **exactly
283 bytes with nothing left over** — so these counts are over real opcodes, not over bytes that
merely happen to have those values:

| opcode | count | why it matters |
|---|---|---|
| `SLOAD` | **0** | the proxy never reads storage — the beacon is a `PUSH32` immediate, not an EIP-1967 slot read. The slot is populated but the runtime does not consult it |
| `PUSH32` | **1** | the control-plane address; the only one, hence unambiguous |
| `DELEGATECALL` | 1 | the forwarding call |
| `STATICCALL` | 1 | |
| `EXTCODEHASH` | 1 | |
| `PUSH0` | **19** | see below |
| `TLOAD` / `TSTORE` / `MCOPY` | 0 | |

🔬 **The 19 `PUSH0`s are evidence about the chain, not just about this contract.** This bytecode
is deployed, mined, and executed by real transactions today. `PUSH0` was introduced in Shanghai,
so a chain that rejected it could not be running this contract at all. That is **consensus-level**
evidence, one level stronger than probing an opcode through `eth_call` — and it was sitting in
bytecode already captured days earlier, unread, because nobody disassembled it.

⚠ **State it exactly as narrowly as it is.** It corroborates `PUSH0` **only**. `MCOPY`, `TSTORE`
and `TLOAD` appear zero times here, so this contract says nothing about them; those rest on the
`eth_call` measurement alone. And it is evidence about **chain 46630 only** — the fallback chain
has no code at this address at all.
