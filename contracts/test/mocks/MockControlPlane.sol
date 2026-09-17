// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// 仅供本地测试。绝不部署到任何公链。
/// 本夹具的存储不受判定组那些『零状态』断言的任何约束。
///
/// This library holds the one mutator implementation shared by MockControlPlane (C5) and
/// MockEquityToken (C6). It never touches src/, never imports the guard, and never gives any
/// fixture a way to make itself easier to pass -- it only shapes what a fixture's read-only
/// surface returns.
library FixtureMutator {
    uint8 internal constant NORMAL   = 0; // 32-byte normal word
    uint8 internal constant REVERT   = 1; // revert(0, 0)
    uint8 internal constant LENGTH   = 2; // return exactly `arg` bytes: normal word prefix, rest explicitly zeroed
    uint8 internal constant RAW_WORD = 3; // return exactly wordA (32 bytes)
    uint8 internal constant BURN     = 4; // consume >= arg gas, then NORMAL; arg == type(uint256).max => runs to OOG
    uint8 internal constant GAS_BAND = 5; // gasleft() (sampled first) >= arg ? wordA : wordB (32 bytes)
    uint256 internal constant MAX_LENGTH = 1024;

    struct Mode {
        uint8 kind;
        uint256 arg;
        bytes32 wordA;
        bytes32 wordB;
    }

    error UnknownMutatorKind(uint8 kind);
    error MutatorLengthTooLarge(uint256 length);

    /// Setter-time domain check. Reverts MutatorLengthTooLarge iff kind == LENGTH && arg > MAX_LENGTH.
    /// Deliberately does NOT reject unknown kinds, so respond()'s default branch stays reachable --
    /// an unrecognized kind number must fail loudly at read time, not be swallowed at setter time.
    function validate(uint8 kind, uint256 arg) internal pure {
        if (kind == LENGTH && arg > MAX_LENGTH) {
            revert MutatorLengthTooLarge(arg);
        }
    }

    /// Never returns normally: every reachable branch ends in an assembly `return` or `revert`.
    /// The final statement is a plain Solidity `revert UnknownMutatorKind(kind)` so that any kind
    /// value outside {NORMAL..GAS_BAND} fails loudly instead of silently falling back to NORMAL.
    ///
    /// gasleft() is sampled as the very first statement, before any storage reads below, so BURN's
    /// target and GAS_BAND's threshold comparison are measured against the gas actually forwarded
    /// to this STATICCALL, not against whatever remains after unrelated dispatch overhead.
    function respond(Mode storage m, bytes32 normalWord) internal view {
        uint256 gasAtEntry = gasleft();
        uint8 kind = m.kind;
        uint256 arg = m.arg;
        bytes32 wordA = m.wordA;
        bytes32 wordB = m.wordB;

        if (kind == NORMAL) {
            assembly {
                let p := mload(0x40)
                mstore(p, normalWord)
                return(p, 32)
            }
        }
        if (kind == REVERT) {
            assembly {
                revert(0, 0)
            }
        }
        if (kind == LENGTH) {
            assembly {
                let p := mload(0x40)
                mstore(p, normalWord)
                let padded := mul(div(add(arg, 31), 32), 32)
                for { let k := 32 } lt(k, padded) { k := add(k, 32) } {
                    mstore(add(p, k), 0)
                }
                return(p, arg)
            }
        }
        if (kind == RAW_WORD) {
            assembly {
                let p := mload(0x40)
                mstore(p, wordA)
                return(p, 32)
            }
        }
        if (kind == BURN) {
            uint256 target = gasAtEntry > arg ? gasAtEntry - arg : 0;
            while (gasleft() > target) { }
            assembly {
                let p := mload(0x40)
                mstore(p, normalWord)
                return(p, 32)
            }
        }
        if (kind == GAS_BAND) {
            bytes32 chosen = gasAtEntry >= arg ? wordA : wordB;
            assembly {
                let p := mload(0x40)
                mstore(p, chosen)
                return(p, 32)
            }
        }
        revert UnknownMutatorKind(kind);
    }
}

/// 仅供本地测试。绝不部署到任何公链。
/// 本夹具的存储不受判定组那些『零状态』断言的任何约束。
///
/// C5: the control-plane fixture. It is etched onto the guard's compile-time CONTROL_PLANE
/// constant address, so it must never write anything in its constructor and must never declare
/// an immutable -- there is none of either here.
contract MockControlPlane {
    bool public pausedFlag;                                     // slot 0
    mapping(address => bool) public blocked;                    // slot 1
    address public impl;                                        // slot 2, offset 0
    bool internal _countingMode;                                // slot 2, offset 20 (packed with impl)
    uint256 internal _readCount;                                // slot 3
    mapping(bytes4 => FixtureMutator.Mode) internal _mutator;   // slot 4

    error UnsupportedSelector(bytes4 selector);

    // NAMED COMMENT (required, do not "fix"): paused() is intentionally NOT `view`. With
    // countingMode on, it SSTOREs a counter. The guard reaches this function through the
    // STATICCALL opcode and never looks at the declared Solidity mutability of the callee --
    // that SSTORE halts the static frame regardless of what this function is declared as.
    // Changing this modifier back to `view` cannot rescue a working call counter; it would only
    // make the deliberate AS-39(c) self-check (setCountingMode(true)) fail to compile the SSTORE
    // that self-check exists to observe.
    function paused() external returns (bool) {
        if (_countingMode) {
            _readCount += 1;
        }
        FixtureMutator.respond(_mutator[this.paused.selector], _boolWord(pausedFlag));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function isBlocked(address who) external view returns (bool) {
        FixtureMutator.respond(_mutator[this.isBlocked.selector], _boolWord(blocked[who]));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function implementation() external view returns (address) {
        FixtureMutator.respond(_mutator[this.implementation.selector], bytes32(uint256(uint160(impl))));
        revert(); // unreachable: respond() always terminates via assembly return/revert above
    }

    function setPaused(bool v) external {
        pausedFlag = v;
    }

    function setBlocked(address who, bool v) external {
        blocked[who] = v;
    }

    function setImplementation(address v) external {
        impl = v;
    }

    // ONLY AS-39(c) may call this with `true`. Every other test must leave countingMode false and
    // must call setCountingMode(false) again after using it, or later tests in the same contract
    // would silently inherit bit 17 in reasonBits.
    function setCountingMode(bool on) external {
        _countingMode = on;
    }

    function readCount() external view returns (uint256) {
        return _readCount;
    }

    /// Reverts UnsupportedSelector unless selector is one of paused()/isBlocked(address)/
    /// implementation(). No access control: this is a fixture, driven only by local tests.
    function setMutator(bytes4 selector, uint8 kind, uint256 arg, bytes32 wordA, bytes32 wordB) external {
        if (
            selector != this.paused.selector &&
            selector != this.isBlocked.selector &&
            selector != this.implementation.selector
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
