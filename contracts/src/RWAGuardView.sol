// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

/// @title RWAGuardView — the only deployed contract of this system
/// @notice A thin view shell over GuardCore.evaluate: `ok == (reasonBits == 0)`. The bit
///         layout and the seven-clause decoding contract are defined only in GuardBits.sol;
///         this comment restates no bit numbers.
/// @dev N2 Thin shell is load-bearing: no logic besides forwarding and returning. Any extra
///      branch would turn verdict identity with the library form from a structural property
///      into a per-case coincidence. For the same valid input tuple, this contract and the
///      integration library form produce identical verdicts.
/// @dev N3 Storage model: no state variables, no immutables, no constructor, no initializer,
///      no receive, no fallback, no ERC-165 registration, no sweep function. A sweep would add
///      a write path and an owner this contract does not have.
/// @dev N4 Balance: native ETH can be credited without calling this contract (a SELFDESTRUCT
///      beneficiary, a block fee recipient), so the balance is not provably zero. No native or
///      ERC-20 balance is read on any decision path, so the same input returns the same bits
///      no matter what the balance is. Any value sent to this contract is permanently unrecoverable,
///      because no withdrawal path exists.
/// @dev N5 Access control: this contract has no access control, and that is the correct
///      design, not a gap: it holds no state, no assets and no roles, and adding access
///      control would require a storage slot. The observed control plane's admin role is not
///      a role of this contract; this contract only reads that control plane's state.
/// @dev N6 Upgrades: immutable by structure -- no DELEGATECALL, no proxy, no admin storage.
///      Any proposal to make this contract upgradeable overturns a load-bearing design claim.
///      The cost of a wrong constant is a redeploy, not an upgrade path.
/// @dev N7 Deployment: both chains receive the same build artifact, deployed with a plain
///      CREATE, never CREATE2 -- different addresses on each chain are expected, not a defect.
///      On a chain where the token and control plane do not exist, every call returns
///      `ok == false` with at least the unreadable bits of G0 through G5 and the aggregate bit
///      set; that is the designed consequence. A slimmed second build that only runs part of
///      the gates is rejected.
/// @dev N8 Involuntary reverts a caller may see, all fail-closed: an ABI decode failure (an
///      `address` word with non-zero high 12 bytes, a `uint64` word with dirty high bits, or
///      calldata shorter than the encoding) is a compiler decoder revert with empty returndata;
///      `Ctx` is a static tuple so this signature carries no offset word, and
///      trailing bytes beyond the encoding are ignored; an unknown selector, calldata shorter
///      than 4 bytes, or a call carrying value also yields an empty revert; an uncaught
///      out-of-gas call (for example a hostile feed burning forwarded gas) leaves no
///      returndata. An empty revert is a failed judgement, never `reasonBits == 0`; the cost
///      is lost diagnostics, not safety. This decode surface exists only in this deployed
///      form; the two forms return identical verdicts for valid input tuples, and it is not
///      claimed that they behave the same on every calldata.
/// @dev N9 Usage semantics: an off-chain `eth_call` answer from this function is advisory and
///      carries a time-of-check to time-of-use window; it can be stale as soon as the next
///      block. Only in-transaction evaluation through the integration library, reverting on
///      failure, is atomic.
/// @dev N10 The actor is an explicit `ctx` field; `msg.sender` is never read by this contract,
///      and there is no overload that defaults the actor from it.
contract RWAGuardView {
    /// @notice Forwards a trade-safety judgement to GuardCore and returns it unchanged.
    /// @param token Untrusted token address to evaluate.
    /// @param ctx Caller-supplied judgement context.
    /// @return ok True only when reasonBits is zero.
    /// @return reasonBits Bit-encoded judgement reasons; the layout is defined only in GuardBits.sol.
    function isSafeToTrade(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return GuardCore.evaluate(token, ctx);
    }
}
