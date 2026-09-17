// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

/// @title RWAGuard -- thin shell over GuardCore.evaluate
/// @notice For the same valid input tuple, this library returns identical verdicts to the deployed view form; the bit layout is defined only in GuardBits.sol, and this file restates no bit numbers.
/// @dev This library holds no storage, no immutable, and no constant of its own; it never reads msg.sender, and there is no overload that defaults the actor from it.
/// @dev This guard provides no reentrancy guard; the obligation is transferred by contract to the integrator. The integrator must add nonReentrant on the outer function that wraps this call, before any external interaction executes.
/// @dev A dependency that reverts, returns a short answer, or a feed stuck in a degraded mode is structurally unavailable to this library and is read as a violation bit, never skipped.
/// @dev This library performs zero SSTORE and zero transient storage: TLOAD and TSTORE are both absent, so no lock can live here; that obligation stays with the integrator's own CEI order.
/// @dev The read-only reentrancy surface is real: GuardCore issues a staticcall to the caller-supplied ctx.priceFeed, and that contract can observe but not write the integrator's mid-transaction state.
/// @dev Integrator order, verbatim: 1. checks -- call RWAGuard.enforce(token, ctx); as the very first statement, before any state read executes.
/// @dev 2. effects -- update the integrator's own storage only after enforce has not reverted.
/// @dev 3. interactions -- place any external call last, after checks and effects.
/// @dev CEI makes the observed state consistent, it does not remove observation: the read-only surface noted above still exists inside the checks step.
/// @dev D1. ok == (reasonBits == 0); never re-derive ok from a subset of the bits.
/// @dev D2. reasonBits & ~GuardBits.KNOWN_MASK != 0 signals a bit from a newer version; treat it as BLOCK, never as pass.
/// @dev D3. reasonBits & GuardBits.RESERVED_MASK must be zero: bits 7 and 23 are permanently reserved, and a nonzero value means this payload was not produced by this version.
/// @dev D4. bit 255 is an aggregate, not a ninth gate: it is set exactly when GuardBits.UNREADABLE_MASK has at least one bit set.
/// @dev D5. per gate, the violated bit and its own unreadable bit are mutually exclusive, though different gates combine freely: bits 8 and 22 set together is not an invariant violation.
/// @dev D6. when bit 0 is set, bits 1, 3 and 4 are true statements about the canonical control plane, not necessarily about this token's own controller.
/// @dev D7. match the GuardBlocked selector first, then decode reasonBits: an empty revert or a Panic(uint256) is not a verdict, it is a decode failure or an out-of-gas condition.
/// @dev C1. ctx.priceFeed and ctx.expectedImpl must be immutable values set in the constructor of the integrator, never recomputed per call.
/// @dev C2. ctx.maxFeedAge must be chosen explicitly: 0 is the strictest setting, not a default.
/// @dev C3. fill ctx.actor from msg.sender at the boundary of the integrator; when there is no counterparty, set ctx.counterparty = ctx.actor explicitly.
/// @dev C4. Never use try/catch to swallow an enforce revert; this does not forbid keeping governance and migration paths outside the contract, which is a separate design choice.
/// @dev L1. no reentrancy guard can exist inside this library by construction; the obligation sits entirely with the integrator's own CEI order described above.
/// @dev L2. a clone with byte-identical runtime pointing at the same beacon passes G0 exactly like the original, because the codehash check does not distinguish deployment addresses.
/// @dev L3. does not know which price feed is the right one for a given token; that judgement belongs to the integrator that sets ctx.priceFeed, not to this library.
/// @dev L4. no TWAP, no multi-source cross-check, no deviation cap is implemented here; flash-loan price skew is not defended by this unit.
/// @dev L5. does not remove the time-of-check to time-of-use window between a view read of GuardCore.evaluate and the integrator's own subsequent state change.
/// @dev L6. no path to exchange the guard once it is inlined into an integrator's bytecode; CONTROL_PLANE and KNOWN_PROXY_CODEHASH are constants inlined at compile time.
/// @dev If the control plane's implementation ever changes shape without a coordinated redeploy, enforce reverts on every call for every integrator built against the old codehash: the guard becomes permanently closed rather than silently wrong.
/// @dev This is a scope boundary, not a defect: the integrator MUST keep a migration path outside the contract, because an inlined library gives none; without one, that closure is a permanent freeze of user funds.
/// @dev The read-only reentrancy surface described above is orthogonal to this migration limit; they are two separate boundary conditions, not the same one restated.
/// @dev The staticcall to ctx.priceFeed inside GuardCore.evaluate is the only external call made before the integrator acts on the returned verdict.
/// @dev The bit layout lives in exactly one place, GuardBits.sol; an edit to one copy must be made to every copy of this NatSpec, meaning RWAGuardView.sol and this file together.
library RWAGuard {
    error GuardBlocked(address token, uint256 reasonBits);

    function enforce(address token, Ctx memory ctx) internal view {
        (bool ok, uint256 reasonBits) = GuardCore.evaluate(token, ctx);
        if (!ok) {
            revert GuardBlocked(token, reasonBits);
        }
    }

    function check(address token, Ctx memory ctx) internal view returns (bool ok, uint256 reasonBits) {
        return GuardCore.evaluate(token, ctx);
    }
}
