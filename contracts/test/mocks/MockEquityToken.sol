// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {FixtureMutator} from "./MockControlPlane.sol";

/// 仅供本地测试。绝不部署到任何公链。
/// 本夹具的存储不受判定组那些『零状态』断言的任何约束。
///
/// C6: the equity-token fixture. It must be usable two ways: standalone (`new`-deployed, used by
/// AS-39 to get a clean fan-out count with no proxy in the loop) and as the logic contract behind
/// a real, etched proxy runtime (used by the proxy-forwarding self-check and by every attack arm
/// that needs the guard's codehash gate to actually accept the token). To survive delegatecall:
/// no constructor writes storage, no `immutable`, no assumption that `address(this)` is the
/// address this contract itself was deployed to, and the storage layout below is append-only --
/// new fields must be added after `_mutator`, never inserted before it.
contract MockEquityToken {
    uint256 internal constant WAD = 1e18; // constant: no slot, delegatecall-safe

    bool public pausedFlag;                                                 // slot 0
    mapping(address => bool) internal _retiredBlockedSlot;                  // slot 1 -- RETIRED placeholder, never read or written; kept so slots 2..10 stay aligned behind the proxy
    uint256 public ui;                                                      // slot 2
    uint256 public newUi;                                                   // slot 3
    uint256 public effAt;                                                   // slot 4  (uint256, never uint64)
    mapping(address => uint256) public rawOf;                               // slot 5
    uint256 public rawTotal;                                                // slot 6
    mapping(address => mapping(address => uint256)) public allowanceOf;     // slot 7  (display units)
    address internal _callbackTarget;                                       // slot 8
    bytes internal _callbackData;                                           // slot 9
    mapping(bytes4 => FixtureMutator.Mode) internal _mutator;               // slot 10
    // APPEND-ONLY below this line: host storage behind the proxy is slot-aligned.

    error ZeroMultiplier();
    error InsufficientRaw(address from, uint256 have, uint256 need);
    error InsufficientAllowance(address owner, address spender, uint256 have, uint256 need);
    error UnsupportedSelector(bytes4 selector);

    // Deliberately NOT implemented: implementation(), decimals(), symbol(), isBlocked(address).
    // A real equity-token proxy reverts on implementation() (that selector is emitted by the proxy
    // toward the plane, never dispatched to callers of the token), and the guard makes zero ERC-20
    // metadata reads. isBlocked(address) is absent on the real token too (measured 2026-09-16,
    // chain 46630: empty-data revert; the real implementation asks the control plane instead), and
    // a fixture that answered it is exactly how a guard reading the token stayed green here while
    // it was permanently unreadable on-chain. Declaring any of the four would only invite an
    // implementer to read from them.

    function paused() external view returns (bool) {
        FixtureMutator.respond(_mutator[this.paused.selector], _boolWord(pausedFlag));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function uiMultiplier() external view returns (uint256) {
        FixtureMutator.respond(_mutator[this.uiMultiplier.selector], bytes32(ui));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function newUIMultiplier() external view returns (uint256) {
        FixtureMutator.respond(_mutator[this.newUIMultiplier.selector], bytes32(newUi));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function effectiveAt() external view returns (uint256) {
        FixtureMutator.respond(_mutator[this.effectiveAt.selector], bytes32(effAt));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function setPaused(bool v) external {
        pausedFlag = v;
    }

    function setRatios(uint256 ui_, uint256 newUi_, uint256 effAt_) external {
        ui = ui_;
        newUi = newUi_;
        effAt = effAt_;
    }

    // The fixture's position-building entry point. No access control: this is a fixture.
    function mintRaw(address to, uint256 rawAmount) external {
        rawOf[to] += rawAmount;
        rawTotal += rawAmount;
    }

    // Rule 1: active multiplier m = (effAt != 0 && block.timestamp >= effAt) ? newUi : ui,
    // compared at full uint256 width so effAt values above 2^64 are never silently truncated.
    function _activeMultiplier() private view returns (uint256) {
        return (effAt != 0 && block.timestamp >= effAt) ? newUi : ui;
    }

    // Rule 2: balanceOf = rawOf[who] * m / WAD, floor. Rule 5: m == 0 => 0 (no default-to-1e18).
    function balanceOf(address who) external view returns (uint256) {
        uint256 m = _activeMultiplier();
        if (m == 0) {
            return 0;
        }
        return (rawOf[who] * m) / WAD;
    }

    // Rule 6: same conversion as balanceOf, applied to rawTotal, floor.
    function totalSupply() external view returns (uint256) {
        uint256 m = _activeMultiplier();
        if (m == 0) {
            return 0;
        }
        return (rawTotal * m) / WAD;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return allowanceOf[owner][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowanceOf[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _doTransfer(msg.sender, to, amount);
        return true;
    }

    // No infinite-allowance special case: allowance is decremented by `amount` (display units)
    // regardless of its size.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 have = allowanceOf[from][msg.sender];
        if (have < amount) {
            revert InsufficientAllowance(from, msg.sender, have, amount);
        }
        allowanceOf[from][msg.sender] = have - amount;
        _doTransfer(from, to, amount);
        return true;
    }

    // Rule 3: rawDelta = ceil(amount * WAD / m), raw is conserved (from loses rawDelta, to gains
    // rawDelta). Rule 4: insufficient raw reverts; this is the fixture's normal (non-mutator)
    // failure path. Checked arithmetic gives Panic(0x11) on overflow rather than a silent wrap.
    // The callback fires after the ledger update, so a reentering callback observes post-transfer
    // balances -- this is what makes a vault's reentrancy guard a real, checkable claim.
    function _doTransfer(address from, address to, uint256 amount) private {
        uint256 m = _activeMultiplier();
        if (m == 0) {
            revert ZeroMultiplier();
        }
        uint256 rawDelta = (amount * WAD + m - 1) / m;
        uint256 haveRaw = rawOf[from];
        if (haveRaw < rawDelta) {
            revert InsufficientRaw(from, haveRaw, rawDelta);
        }
        rawOf[from] = haveRaw - rawDelta;
        rawOf[to] += rawDelta;
        _fireCallback();
    }

    function _fireCallback() private {
        address target = _callbackTarget;
        if (target == address(0)) {
            return;
        }
        bytes memory data = _callbackData;
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    // Reentrancy hook: target == address(0) disables the callback.
    function setCallback(address target, bytes calldata data) external {
        _callbackTarget = target;
        _callbackData = data;
    }

    /// Reverts UnsupportedSelector unless selector is one of paused()/uiMultiplier()/
    /// newUIMultiplier()/effectiveAt(). No access control: this is a fixture.
    function setMutator(bytes4 selector, uint8 kind, uint256 arg, bytes32 wordA, bytes32 wordB) external {
        if (
            selector != this.paused.selector &&
            selector != this.uiMultiplier.selector &&
            selector != this.newUIMultiplier.selector &&
            selector != this.effectiveAt.selector
        ) {
            revert UnsupportedSelector(selector);
        }
        FixtureMutator.validate(kind, arg);
        FixtureMutator.Mode storage m = _mutator[selector];
        m.kind = kind;
        m.arg = arg;
        m.wordA = wordA;
        m.wordB = wordB;
    }

    function _boolWord(bool v) private pure returns (bytes32) {
        return v ? bytes32(uint256(1)) : bytes32(uint256(0));
    }
}
