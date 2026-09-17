// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// 仅供本地测试。绝不部署到任何公链。
/// 本夹具的存储不受判定组那些『零状态』断言的任何约束。
///
/// C9: the price-feed fixture. Every field is `private` on purpose -- solc's automatic getters
/// always return well-formed 32-byte words, and this fixture's entire reason for existing is to
/// produce malformed shapes (0 bytes, 31 bytes, gas-banded answers, an oversized `description()`
/// length). A `public` field here would be a silent second, well-formed reader of the same data,
/// undermining every hostile shape this contract exists to produce. Field names carry a trailing
/// `W` for the same reason: no field may ever collide with the `latestRoundData` / `description`
/// selectors.
///
/// NAMED COMMENT (structural, not an oversight): this fixture has no call counter. The guard
/// reads both selectors below via the STATICCALL opcode; any SSTORE/TSTORE/LOG inside that frame
/// halts the read and changes the verdict rather than silently incrementing a counter (see
/// AS-39(c) for the general argument, proven there against MockControlPlane's countingMode
/// escape hatch). Instead this fixture offers an assertable invariant: readRoundConfig() and
/// readModes() return identical values before and after a full judgement run.
contract MockPriceFeed {
    uint8 internal constant FEED_CLEAN = 0;
    uint8 internal constant FEED_REVERT = 1;
    uint8 internal constant FEED_SHORT = 2;
    uint8 internal constant FEED_LONG = 3;
    uint8 internal constant FEED_GAS_BAND = 4;
    uint8 internal constant FEED_BURN = 5;

    uint8 internal constant DESC_CLEAN = 0;
    uint8 internal constant DESC_REVERT = 1;
    uint8 internal constant DESC_SHORT = 2;
    uint8 internal constant DESC_BAD_OFFSET = 3;
    uint8 internal constant DESC_HUGE_LEN = 4;
    uint8 internal constant DESC_BOMB = 5;
    uint8 internal constant DESC_TAIL_PAD = 6;

    uint256 internal constant BOMB_MAX = 1 << 32;

    uint256 private _roundIdW;            // slot 0
    int256  private _answerW;             // slot 1
    uint256 private _startedAtW;          // slot 2 -- the guard never reads this, but it must be settable
    uint256 private _updatedAtW;          // slot 3 -- literal value used only when _followNow is false
    uint256 private _answeredInRoundW;    // slot 4
    bool    private _followNow;           // slot 5 -- default true; see setFollowNow
    bytes   private _descW;               // slot 6 -- description() CLEAN payload content
    uint8   private _feedMode;            // slot 7, offset 0
    uint8   private _descMode;            // slot 7, offset 1
    uint256 private _modeArg;             // slot 8  -- shared argument slot (length / offset / bomb size)
    uint256 private _gasBurn;             // slot 9
    uint256 private _gasThreshold;        // slot 10
    uint256 private _roundIdAltW;         // slot 11 -- GAS_BAND alternate round
    uint256 private _answeredInRoundAltW; // slot 12 -- GAS_BAND alternate answeredInRound (< alt round, incoherent on purpose)

    error UnknownFeedMode(uint8 mode);
    error UnknownDescMode(uint8 mode);
    error ModeArgOutOfDomain(uint8 mode, uint256 arg);

    // C9 is only ever `new`-deployed; never etched, never delegatecalled. That is what makes a
    // constructor safe here, unlike C5/C6.
    constructor() {
        _followNow = true;
    }

    /// Both Solidity signatures below describe only the CLEAN-path shape. Every branch is emitted
    /// through inline assembly `return`/`revert` so that lengths and offsets the ABI encoder could
    /// never itself produce (0, 31, 128, 159, 192 bytes; offset != 0x20; length == type(uint256).max;
    /// a ~10MB tail) are all reachable. The declared Solidity return types are therefore never
    /// actually ABI-encoded by solc for any of these functions.
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // gasleft() is sampled first, before any other work, so FEED_GAS_BAND and FEED_BURN
        // measure against the gas actually forwarded to this STATICCALL.
        uint256 gasAtEntry = gasleft();
        uint8 mode = _feedMode;
        uint256 roundIdW_ = _roundIdW;
        uint256 answerW_ = uint256(_answerW);
        uint256 startedAtW_ = _startedAtW;
        uint256 updatedAtW_ = _followNow ? block.timestamp : _updatedAtW;
        uint256 answeredInRoundW_ = _answeredInRoundW;

        if (mode == FEED_CLEAN) {
            assembly {
                let p := mload(0x40)
                mstore(p, roundIdW_)
                mstore(add(p, 32), answerW_)
                mstore(add(p, 64), startedAtW_)
                mstore(add(p, 96), updatedAtW_)
                mstore(add(p, 128), answeredInRoundW_)
                return(p, 160)
            }
        }
        if (mode == FEED_REVERT) {
            assembly {
                revert(0, 0)
            }
        }
        if (mode == FEED_SHORT) {
            uint256 len = _modeArg;
            assembly {
                let p := mload(0x40)
                mstore(p, roundIdW_)
                mstore(add(p, 32), answerW_)
                mstore(add(p, 64), startedAtW_)
                mstore(add(p, 96), updatedAtW_)
                mstore(add(p, 128), answeredInRoundW_)
                return(p, len)
            }
        }
        if (mode == FEED_LONG) {
            assembly {
                let p := mload(0x40)
                mstore(p, roundIdW_)
                mstore(add(p, 32), answerW_)
                mstore(add(p, 64), startedAtW_)
                mstore(add(p, 96), updatedAtW_)
                mstore(add(p, 128), answeredInRoundW_)
                mstore(add(p, 160), 0)
                return(p, 192)
            }
        }
        if (mode == FEED_GAS_BAND) {
            // CLEAN under the sampled gas budget, but round/answeredInRound flip to the
            // (deliberately incoherent) alternate pair once gas drops below the threshold.
            uint256 rid = roundIdW_;
            uint256 air = answeredInRoundW_;
            if (gasAtEntry < _gasThreshold) {
                rid = _roundIdAltW;
                air = _answeredInRoundAltW;
            }
            assembly {
                let p := mload(0x40)
                mstore(p, rid)
                mstore(add(p, 32), answerW_)
                mstore(add(p, 64), startedAtW_)
                mstore(add(p, 96), updatedAtW_)
                mstore(add(p, 128), air)
                return(p, 160)
            }
        }
        if (mode == FEED_BURN) {
            uint256 target = gasAtEntry > _gasBurn ? gasAtEntry - _gasBurn : 0;
            while (gasleft() > target) { }
            assembly {
                let p := mload(0x40)
                mstore(p, roundIdW_)
                mstore(add(p, 32), answerW_)
                mstore(add(p, 64), startedAtW_)
                mstore(add(p, 96), updatedAtW_)
                mstore(add(p, 128), answeredInRoundW_)
                return(p, 160)
            }
        }
        revert UnknownFeedMode(mode);
    }

    function description() external view returns (string memory) {
        uint8 mode = _descMode;

        if (mode == DESC_CLEAN) {
            bytes memory data = _descW;
            uint256 len = data.length;
            uint256 padded = ((len + 31) / 32) * 32;
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 32), len)
                let dataPtr := add(data, 32)
                for { let k := 0 } lt(k, padded) { k := add(k, 32) } {
                    mstore(add(add(p, 64), k), mload(add(dataPtr, k)))
                }
                return(p, add(64, padded))
            }
        }
        if (mode == DESC_REVERT) {
            assembly {
                revert(0, 0)
            }
        }
        if (mode == DESC_SHORT) {
            bytes memory data = _descW;
            uint256 len = data.length;
            uint256 padded = ((len + 31) / 32) * 32;
            uint256 shortLen = _modeArg;
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 32), len)
                let dataPtr := add(data, 32)
                for { let k := 0 } lt(k, padded) { k := add(k, 32) } {
                    mstore(add(add(p, 64), k), mload(add(dataPtr, k)))
                }
                return(p, shortLen)
            }
        }
        if (mode == DESC_BAD_OFFSET) {
            // word1 = 0: the only length that is legal against a 64-byte answer under criterion (4)
            // (length <= returndatasize() - 64), so ONLY criterion (3), offset == 0x20, is violated --
            // independent of any stored description text.
            uint256 badOffset = _modeArg;
            assembly {
                let p := mload(0x40)
                mstore(p, badOffset)
                mstore(add(p, 32), 0)
                return(p, 64)
            }
        }
        if (mode == DESC_HUGE_LEN) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 32), not(0))
                return(p, 64)
            }
        }
        if (mode == DESC_BOMB) {
            // p := mload(0x40): no memory is allocated in description() before this branch, so
            // bytes past the free pointer are untouched (zero in practice, not guaranteed -- we do
            // not rely on any EVM guarantee about memory past the free pointer). No test asserts
            // body content: test 65 copies at most 64 bytes and asserts only returndatasize(),
            // word0, and word1.
            uint256 bombLen = _modeArg;
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 32), bombLen)
                return(p, add(64, bombLen))
            }
        }
        if (mode == DESC_TAIL_PAD) {
            // The CLEAN encoding plus 32 explicitly zeroed trailing bytes: the positive control
            // arm for criterion (4) being `length <= returndatasize() - 64` rather than an exact
            // length match.
            bytes memory data = _descW;
            uint256 len = data.length;
            uint256 padded = ((len + 31) / 32) * 32;
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 32), len)
                let dataPtr := add(data, 32)
                for { let k := 0 } lt(k, padded) { k := add(k, 32) } {
                    mstore(add(add(p, 64), k), mload(add(dataPtr, k)))
                }
                mstore(add(add(p, 64), padded), 0)
                return(p, add(96, padded))
            }
        }
        revert UnknownDescMode(mode);
    }

    function setRound(
        uint256 roundId_,
        int256 answer_,
        uint256 startedAt_,
        uint256 updatedAt_,
        uint256 answeredInRound_
    ) external {
        _roundIdW = roundId_;
        _answerW = answer_;
        _startedAtW = startedAt_;
        _updatedAtW = updatedAt_;
        _answeredInRoundW = answeredInRound_;
    }

    // Default true. When on, latestRoundData() evaluates updatedAt = block.timestamp at read
    // time, so a vm.warp past the transition point never makes the feed look stale on its own.
    function setFollowNow(bool on) external {
        _followNow = on;
    }

    function setDescriptionText(bytes calldata s) external {
        _descW = s;
    }

    // mode == FEED_SHORT && arg >= 160 is out of domain (SHORT must be a strict prefix of the
    // 160-byte CLEAN encoding). Unknown mode numbers are NOT rejected here -- only at read time,
    // in latestRoundData()'s default branch -- so a wrong mode number fails loudly instead of the
    // guard being fed a silently-substituted CLEAN response.
    function setFeedMode(uint8 mode, uint256 arg) external {
        if (mode == FEED_SHORT && arg >= 160) {
            revert ModeArgOutOfDomain(mode, arg);
        }
        _feedMode = mode;
        _modeArg = arg;
    }

    // DESC_SHORT requires arg < 64 (criterion (1) is returndatasize() >= 64); DESC_BAD_OFFSET must
    // not accidentally choose the correct offset 0x20; DESC_BOMB is capped at BOMB_MAX so a test
    // typo can never accidentally request an unbounded allocation. Unknown mode numbers are NOT
    // rejected here, only at read time.
    function setDescMode(uint8 mode, uint256 arg) external {
        if (mode == DESC_SHORT && arg >= 64) {
            revert ModeArgOutOfDomain(mode, arg);
        }
        if (mode == DESC_BAD_OFFSET && arg == 0x20) {
            revert ModeArgOutOfDomain(mode, arg);
        }
        if (mode == DESC_BOMB && arg > BOMB_MAX) {
            revert ModeArgOutOfDomain(mode, arg);
        }
        _descMode = mode;
        _modeArg = arg;
    }

    function setGasBand(uint256 gasThreshold, uint256 altRoundId, uint256 altAnsweredInRound) external {
        _gasThreshold = gasThreshold;
        _roundIdAltW = altRoundId;
        _answeredInRoundAltW = altAnsweredInRound;
    }

    function setGasBurn(uint256 amount) external {
        _gasBurn = amount;
    }

    // Stored values only -- updatedAt is NOT evaluated against block.timestamp here, unlike in
    // latestRoundData(). This is what makes the state-invariance self-check meaningful: this
    // function's return value does not drift merely because time passed between two calls.
    function readRoundConfig()
        external
        view
        returns (
            uint256 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint256 answeredInRound,
            bool followNow
        )
    {
        return (_roundIdW, _answerW, _startedAtW, _updatedAtW, _answeredInRoundW, _followNow);
    }

    function readModes()
        external
        view
        returns (uint8 feedMode, uint8 descMode, uint256 modeArg, uint256 gasBurn, uint256 gasThreshold)
    {
        return (_feedMode, _descMode, _modeArg, _gasBurn, _gasThreshold);
    }
}
