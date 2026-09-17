// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GatesBaseline} from "./Gates.t.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {Ctx} from "../src/GuardBits.sol";
import {RWAGuardView} from "../src/RWAGuardView.sol";

/// Header: TS-2 (test_U3_2) compares the deployed view against GuardCore.evaluate directly and
/// is NOT AS-1 (the dual-form identity claim against U4's library wrapper is owned by U7).
/// Every test in this file is mutation-battery invariant (FD-U3-9) and belongs to no U7 §8b
/// expected-red row. V5 and the INV-9 forced-ETH pin required by U8 §4 are discharged here by
/// test_U3_9_storageSlotsStayZero and test_U3_10_forcedEthDoesNotChangeVerdict respectively; U8
/// must cite them, not re-implement them.
contract RWAGuardViewTest is GatesBaseline {
    address internal constant U3_FEED = address(uint160(uint256(keccak256("rwa-guard.u3.feed"))));
    address internal constant U3_IMPL = address(uint160(uint256(keccak256("rwa-guard.u3.impl"))));
    uint64  internal constant U3_MAX_FEED_AGE = 3600;
    uint256 internal constant U3_FORCED_WEI = 1_000_000 ether;
    uint256 internal constant U3_ENCODED_LEN = 196; // 4 + 6 * 32 (token + 5 static Ctx words)
    uint256 internal constant U3_RETURN_LEN = 64;   // (bool, uint256)
    uint256 internal constant U3_SLOT_COUNT = 19;   // slots 0..15 + 3 derived EIP-1967 slots
    string  internal constant U3_CANONICAL_SIG =
        "isSafeToTrade(address,(address,address,address,address,uint64))";
    string  internal constant U3_WRONG_OVERLOAD_SIG = "isSafeToTrade(address)";

    // ---- helpers ----

    function _u3_deploy() internal returns (RWAGuardView guard) {
        guard = new RWAGuardView();
    }

    function _u3_plainCtx() internal pure returns (Ctx memory ctx) {
        ctx = Ctx({
            priceFeed: U3_FEED,
            actor: ACTOR,
            counterparty: COUNTERPARTY,
            expectedImpl: U3_IMPL,
            maxFeedAge: U3_MAX_FEED_AGE
        });
    }

    // Fresh, independent copy of `src`. Memory-to-memory struct assignment in Solidity copies only a
    // reference, so assigning the baseline ctx to a local and then editing a field would edit the
    // baseline itself and make the TS-2 corpus cumulative.
    function _u3_copyCtx(Ctx memory src) internal pure returns (Ctx memory out) {
        out = Ctx({
            priceFeed: src.priceFeed,
            actor: src.actor,
            counterparty: src.counterparty,
            expectedImpl: src.expectedImpl,
            maxFeedAge: src.maxFeedAge
        });
    }

    function _u3_encode(address token, Ctx memory ctx) internal pure returns (bytes memory data) {
        data = abi.encodeCall(RWAGuardView.isSafeToTrade, (token, ctx));
    }

    // Fresh copy of `data`; ORs `mask` (a 256-bit value read big-endian, like a Solidity word)
    // into the 32-byte word starting at calldata offset 4 + 32*wordIndex.
    function _u3_withWordOr(bytes memory data, uint256 wordIndex, uint256 mask)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(data);
        uint256 base = 4 + 32 * wordIndex;
        for (uint256 k = 0; k < 32; k++) {
            uint8 shiftedByte = uint8(mask >> (8 * (31 - k)));
            if (shiftedByte != 0) {
                out[base + k] = bytes1(uint8(out[base + k]) | shiftedByte);
            }
        }
    }

    // Fresh copy of `data`; XORs `mask` (a 256-bit value read big-endian, like a Solidity word)
    // into the 32-byte word starting at calldata offset 4 + 32*wordIndex.
    function _u3_withWordXor(bytes memory data, uint256 wordIndex, uint256 mask)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(data);
        uint256 base = 4 + 32 * wordIndex;
        for (uint256 k = 0; k < 32; k++) {
            uint8 shiftedByte = uint8(mask >> (8 * (31 - k)));
            if (shiftedByte != 0) {
                out[base + k] = bytes1(uint8(out[base + k]) ^ shiftedByte);
            }
        }
    }

    // Fresh copy of the first `newLen` bytes of `data`.
    function _u3_truncate(bytes memory data, uint256 newLen) internal pure returns (bytes memory out) {
        out = new bytes(newLen);
        for (uint256 i = 0; i < newLen; i++) {
            out[i] = data[i];
        }
    }

    // Fresh copy of `data` with its first 4 bytes replaced by `selector`. Used to build
    // wrong-overload and zero-selector calldata without slicing a `bytes memory` (memory bytes
    // cannot be sliced in Solidity; only calldata bytes can).
    function _u3_withSelector(bytes memory data, bytes4 selector) internal pure returns (bytes memory out) {
        out = bytes.concat(data);
        out[0] = selector[0];
        out[1] = selector[1];
        out[2] = selector[2];
        out[3] = selector[3];
    }

    function _u3_rawStatic(address target, bytes memory data)
        internal
        view
        returns (bool success, bytes memory ret)
    {
        (success, ret) = target.staticcall(data);
    }

    function _u3_rawCall(address target, uint256 value, bytes memory data)
        internal
        returns (bool success, bytes memory ret)
    {
        (success, ret) = target.call{value: value}(data);
    }

    function _u3_assertEmptyRevert(bool success, bytes memory ret, string memory reason) internal pure {
        assertFalse(success, reason);
        assertEq(ret.length, 0, reason);
    }

    function _u3_assertWellFormed(bool success, bytes memory ret, string memory reason)
        internal
        pure
        returns (bool ok, uint256 bits)
    {
        assertTrue(success, reason);
        assertEq(ret.length, U3_RETURN_LEN, reason);
        (ok, bits) = abi.decode(ret, (bool, uint256));
    }

    function _u3_readSlots(address target) internal view returns (bytes32[U3_SLOT_COUNT] memory slots) {
        for (uint256 i = 0; i < 16; i++) {
            slots[i] = vm.load(target, bytes32(i));
        }
        slots[16] = vm.load(target, bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
        slots[17] = vm.load(target, bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1));
        slots[18] = vm.load(target, bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1));
    }

    function _u3_assertSlotsZero(address target, string memory reason) internal view {
        bytes32[U3_SLOT_COUNT] memory slots = _u3_readSlots(target);
        for (uint256 i = 0; i < U3_SLOT_COUNT; i++) {
            assertEq(uint256(slots[i]), 0, reason);
        }
    }

    // One TS-2 corpus case: view-vs-core cross-check plus the raw-static-call decode
    // cross-check, kept in one helper so the calling test's local-variable count stays low
    // under legacy codegen.
    function _u3_assertFidelity(RWAGuardView guard, address token, Ctx memory ctx)
        internal
        returns (uint256 coreBits)
    {
        (bool okV, uint256 bitsV) = guard.isSafeToTrade(token, ctx);
        (bool okC, uint256 bitsC) = GuardCore.evaluate(token, ctx);
        assertEq(bitsV, bitsC, "AS-U3-2: view and core reasonBits match for the same input");
        assertEq(okV, okC, "AS-U3-2: view and core ok match for the same input");
        assertEq(okV, bitsV == 0, "AS-U3-2: view ok equals reasonBits == 0");
        coreBits = bitsC;

        (bool success, bytes memory ret) = _u3_rawStatic(address(guard), _u3_encode(token, ctx));
        (bool okRaw, uint256 bitsRaw) =
            _u3_assertWellFormed(success, ret, "AS-U3-2: raw static call to the view is well-formed");
        assertEq(okRaw, okV, "AS-U3-2: raw decode matches the high-level ok");
        assertEq(bitsRaw, bitsV, "AS-U3-2: raw decode matches the high-level reasonBits");
    }

    // ---- tests (exactly 10) ----

    function test_U3_1_selectorDerivedTwoWays() public pure {
        bytes4 selFromSig = bytes4(keccak256(bytes(U3_CANONICAL_SIG)));
        assertTrue(
            RWAGuardView.isSafeToTrade.selector == selFromSig,
            "AS-U3-1: selector matches the signature-derived value"
        );

        bytes4 wrongSel = bytes4(keccak256(bytes(U3_WRONG_OVERLOAD_SIG)));
        assertTrue(
            wrongSel != RWAGuardView.isSafeToTrade.selector,
            "AS-U3-1: wrong-overload selector differs from the real one"
        );

        Ctx memory ctx = _u3_plainCtx();
        bytes memory viaEncodeCall = abi.encodeCall(RWAGuardView.isSafeToTrade, (NEVER_DEPLOYED, ctx));
        bytes memory viaSelector =
            abi.encodeWithSelector(RWAGuardView.isSafeToTrade.selector, NEVER_DEPLOYED, ctx);
        assertEq(viaEncodeCall.length, U3_ENCODED_LEN, "AS-U3-1: encoded call has the expected length");
        assertEq(
            uint256(keccak256(viaEncodeCall)),
            uint256(keccak256(viaSelector)),
            "AS-U3-1: encodeCall and encodeWithSelector produce the same bytes"
        );
    }

    function test_U3_2_forwardingMatchesCore() public {
        Env memory e = _baseline();
        RWAGuardView guard = _u3_deploy();
        Ctx memory c;

        assertEq(
            _u3_assertFidelity(guard, e.token, e.ctx),
            0,
            "AS-U3-2: k0 baseline core bits are exactly zero"
        );

        c = _u3_copyCtx(e.ctx);
        c.priceFeed = address(0);
        _u3_assertFidelity(guard, e.token, c);

        c = _u3_copyCtx(e.ctx);
        c.actor = address(0);
        _u3_assertFidelity(guard, e.token, c);

        c = _u3_copyCtx(e.ctx);
        c.counterparty = address(0);
        _u3_assertFidelity(guard, e.token, c);

        c = _u3_copyCtx(e.ctx);
        c.expectedImpl = address(0);
        _u3_assertFidelity(guard, e.token, c);

        c = _u3_copyCtx(e.ctx);
        c.expectedImpl = address(e.feed);
        _u3_assertFidelity(guard, e.token, c);

        c = _u3_copyCtx(e.ctx);
        c.maxFeedAge = type(uint64).max;
        _u3_assertFidelity(guard, e.token, c);

        assertTrue(
            _u3_assertFidelity(guard, NEVER_DEPLOYED, e.ctx) != 0,
            "AS-U3-2: k7 never-deployed token core bits are non-zero"
        );

        _u3_assertFidelity(guard, address(0), e.ctx);

        c = _u3_copyCtx(e.ctx);
        c.counterparty = ACTOR;
        _u3_assertFidelity(guard, e.token, c);

        Ctx memory zero;
        _u3_assertFidelity(guard, address(0), zero);

        assertEq(
            _u3_assertFidelity(guard, e.token, e.ctx),
            0,
            "AS-U3-2: baseline ctx is unchanged after the corpus"
        );
    }

    function test_U3_3_unknownSelectorEmptyRevert() public {
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawStatic(address(guard), valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-3: control call with valid selector succeeds");

        bytes4 wrongSel = bytes4(keccak256(bytes(U3_WRONG_OVERLOAD_SIG)));
        assertTrue(
            wrongSel != RWAGuardView.isSafeToTrade.selector,
            "AS-U3-3: wrong-overload selector differs from the real one"
        );
        (bool s1, bytes memory r1) = _u3_rawStatic(address(guard), _u3_withSelector(valid, wrongSel));
        _u3_assertEmptyRevert(s1, r1, "AS-U3-3: wrong-overload selector yields empty revert");

        (bool s2, bytes memory r2) = _u3_rawStatic(address(guard), "");
        _u3_assertEmptyRevert(s2, r2, "AS-U3-3: empty calldata yields empty revert");

        (bool s3, bytes memory r3) = _u3_rawStatic(address(guard), _u3_truncate(valid, 3));
        _u3_assertEmptyRevert(s3, r3, "AS-U3-3: 3-byte calldata yields empty revert");

        (bool s4, bytes memory r4) = _u3_rawStatic(address(guard), _u3_withSelector(valid, bytes4(0)));
        _u3_assertEmptyRevert(s4, r4, "AS-U3-3: zero-selector calldata yields empty revert");
    }

    function test_U3_4_valueBearingCallsEmptyRevert() public {
        vm.deal(address(this), 10 ether);
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawCall(address(guard), 0, valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-4: zero-value control call succeeds");

        (bool s1, bytes memory r1) = _u3_rawCall(address(guard), 1, valid);
        _u3_assertEmptyRevert(s1, r1, "AS-U3-4: value-bearing call with valid data yields empty revert");

        (bool s2, bytes memory r2) = _u3_rawCall(address(guard), 1, "");
        _u3_assertEmptyRevert(s2, r2, "AS-U3-4: value-bearing call with empty data yields empty revert");

        assertEq(address(guard).balance, 0, "AS-U3-4: guard balance stays zero after rejected value-bearing calls");

        vm.deal(address(guard), 5);
        assertEq(address(guard).balance, 5, "AS-U3-4: balance probe reads a non-zero dealt value");
    }

    function test_U3_5_dirtyAddressWordEmptyRevert() public {
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawStatic(address(guard), valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-5: control call with clean addresses succeeds");

        for (uint256 i = 0; i < 5; i++) {
            bytes memory dirtyHigh = _u3_withWordOr(valid, i, uint256(1) << 160);
            assertTrue(
                keccak256(dirtyHigh) != keccak256(valid),
                "AS-U3-5: dirty-bit-160 mutation actually changed the bytes"
            );
            (bool sh, bytes memory rh) = _u3_rawStatic(address(guard), dirtyHigh);
            _u3_assertEmptyRevert(sh, rh, "AS-U3-5: address word with dirty bit 160 yields empty revert");

            bytes memory dirtyTop = _u3_withWordOr(valid, i, uint256(1) << 255);
            assertTrue(
                keccak256(dirtyTop) != keccak256(valid),
                "AS-U3-5: dirty-bit-255 mutation actually changed the bytes"
            );
            (bool st, bytes memory rt) = _u3_rawStatic(address(guard), dirtyTop);
            _u3_assertEmptyRevert(st, rt, "AS-U3-5: address word with dirty bit 255 yields empty revert");

            bytes memory twin = _u3_withWordXor(valid, i, 1);
            assertTrue(
                keccak256(twin) != keccak256(valid),
                "AS-U3-5: in-range twin mutation actually changed the bytes"
            );
            (bool sw, bytes memory rw) = _u3_rawStatic(address(guard), twin);
            _u3_assertWellFormed(sw, rw, "AS-U3-5: in-range twin still succeeds");
        }
    }

    function test_U3_6_dirtyUint64WordEmptyRevert() public {
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawStatic(address(guard), valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-6: control call with clean maxFeedAge succeeds");

        bytes memory dirtyLow = _u3_withWordOr(valid, 5, uint256(1) << 64);
        assertTrue(
            keccak256(dirtyLow) != keccak256(valid),
            "AS-U3-6: dirty-bit-64 mutation actually changed the bytes"
        );
        (bool s1, bytes memory r1) = _u3_rawStatic(address(guard), dirtyLow);
        _u3_assertEmptyRevert(s1, r1, "AS-U3-6: uint64 word with dirty bit 64 yields empty revert");

        bytes memory dirtyTop = _u3_withWordOr(valid, 5, uint256(1) << 255);
        assertTrue(
            keccak256(dirtyTop) != keccak256(valid),
            "AS-U3-6: dirty-bit-255 mutation actually changed the bytes"
        );
        (bool s2, bytes memory r2) = _u3_rawStatic(address(guard), dirtyTop);
        _u3_assertEmptyRevert(s2, r2, "AS-U3-6: uint64 word with dirty bit 255 yields empty revert");

        bytes memory twin = _u3_withWordOr(valid, 5, uint256(1) << 63);
        assertTrue(
            keccak256(twin) != keccak256(valid),
            "AS-U3-6: in-range twin mutation actually changed the bytes"
        );
        (bool s3, bytes memory r3) = _u3_rawStatic(address(guard), twin);
        _u3_assertWellFormed(s3, r3, "AS-U3-6: in-range twin still succeeds");
    }

    function test_U3_7_shortCalldataEmptyRevert() public {
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawStatic(address(guard), valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-7: full-length control call succeeds");

        uint256[3] memory lens = [uint256(195), uint256(164), uint256(4)];
        for (uint256 i = 0; i < 3; i++) {
            (bool s, bytes memory r) = _u3_rawStatic(address(guard), _u3_truncate(valid, lens[i]));
            _u3_assertEmptyRevert(s, r, "AS-U3-7: calldata shorter than the encoding yields empty revert");
        }
    }

    function test_U3_8_trailingCalldataIgnored() public {
        RWAGuardView guard = _u3_deploy();
        bytes memory valid = _u3_encode(NEVER_DEPLOYED, _u3_plainCtx());

        (bool s0, bytes memory r0) = _u3_rawStatic(address(guard), valid);
        _u3_assertWellFormed(s0, r0, "AS-U3-8: clean control call succeeds");

        bytes memory withByte = bytes.concat(valid, hex"ff");
        (bool s1, bytes memory r1) = _u3_rawStatic(address(guard), withByte);
        _u3_assertWellFormed(s1, r1, "AS-U3-8: one trailing byte is ignored");
        assertEq(uint256(keccak256(r1)), uint256(keccak256(r0)), "AS-U3-8: return data is unchanged by one trailing byte");

        bytes memory withWord = bytes.concat(valid, bytes32(type(uint256).max));
        (bool s2, bytes memory r2) = _u3_rawStatic(address(guard), withWord);
        _u3_assertWellFormed(s2, r2, "AS-U3-8: one trailing word is ignored");
        assertEq(uint256(keccak256(r2)), uint256(keccak256(r0)), "AS-U3-8: return data is unchanged by one trailing word");
    }

    function test_U3_9_storageSlotsStayZero() public {
        Env memory e = _baseline();
        RWAGuardView guard = _u3_deploy();

        assertEq(uint256(_u3_readSlots(address(e.feed))[0]), 7, "AS-U3-9: fresh feed slot 0 is 7");
        e.feed.setRound(9, 1e8, T0, T0, 9);
        assertEq(uint256(_u3_readSlots(address(e.feed))[0]), 9, "AS-U3-9: feed slot 0 tracks setRound");

        _u3_assertSlotsZero(address(guard), "AS-U3-9: all 19 slots start zero");

        guard.isSafeToTrade(e.token, e.ctx);
        guard.isSafeToTrade(NEVER_DEPLOYED, e.ctx);

        (bool sc, bytes memory rc) = _u3_rawCall(address(guard), 0, _u3_encode(e.token, e.ctx));
        _u3_assertWellFormed(sc, rc, "AS-U3-9: non-static call still succeeds");

        (bool sd, bytes memory rd) =
            _u3_rawCall(address(guard), 0, _u3_withWordOr(_u3_encode(e.token, e.ctx), 0, uint256(1) << 160));
        _u3_assertEmptyRevert(sd, rd, "AS-U3-9: dirty-word raw call yields empty revert");

        (bool su, bytes memory ru) =
            _u3_rawCall(address(guard), 0, _u3_withSelector(_u3_encode(e.token, e.ctx), bytes4(0)));
        _u3_assertEmptyRevert(su, ru, "AS-U3-9: unknown-selector raw call yields empty revert");

        vm.deal(address(guard), 1 ether);

        _u3_assertSlotsZero(address(guard), "AS-U3-9: all 19 slots stay zero after activity");
    }

    function test_U3_10_forcedEthDoesNotChangeVerdict() public {
        Env memory e = _baseline();
        RWAGuardView guard = _u3_deploy();

        (bool ok0, uint256 b0) = guard.isSafeToTrade(e.token, e.ctx);
        (bool ok7, uint256 b7) = guard.isSafeToTrade(NEVER_DEPLOYED, e.ctx);

        vm.deal(address(guard), U3_FORCED_WEI);
        assertEq(address(guard).balance, U3_FORCED_WEI, "AS-U3-10: forced balance lands on the guard");

        (bool ok0After, uint256 b0After) = guard.isSafeToTrade(e.token, e.ctx);
        (bool ok7After, uint256 b7After) = guard.isSafeToTrade(NEVER_DEPLOYED, e.ctx);
        assertEq(b0After, b0, "AS-U3-10: forced ETH does not change the baseline reasonBits");
        assertEq(ok0After, ok0, "AS-U3-10: forced ETH does not change the baseline ok");
        assertEq(b7After, b7, "AS-U3-10: forced ETH does not change the never-deployed reasonBits");
        assertEq(ok7After, ok7, "AS-U3-10: forced ETH does not change the never-deployed ok");

        assertEq(b0, 0, "AS-U3-10: baseline reasonBits starts at zero");

        vm.etch(e.token, "");
        (, uint256 bChanged) = guard.isSafeToTrade(e.token, e.ctx);
        assertTrue(bChanged != b0, "AS-U3-10: erasing the token's code changes the reasonBits");

        uint8[8] memory gatePositions = [uint8(0), 1, 2, 3, 4, 5, 6, 8];
        uint256 changedSpan = 0;
        for (uint256 i = 0; i < 8; i++) {
            uint256 pos = gatePositions[i];
            uint256 mask = (uint256(1) << pos) | (uint256(1) << (pos + 16));
            if ((bChanged & mask) != 0) {
                changedSpan++;
            }
        }
        assertTrue(changedSpan >= 3, "AS-U3-10: the change-control arm spans at least 3 gates");
    }
}
