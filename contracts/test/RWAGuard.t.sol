// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Vm} from "./Base.sol";
import {GatesBaseline} from "./Gates.t.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {Ctx} from "../src/GuardBits.sol";
import {RWAGuard} from "../src/RWAGuard.sol";
import {MockControlPlane, FixtureMutator} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

contract RWAGuardHost {
    function enforce(address token, Ctx calldata ctx) external view { RWAGuard.enforce(token, ctx); }
    function check(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return RWAGuard.check(token, ctx);
    }
}

contract RWAGuardTest is GatesBaseline {
    string internal constant U4_ERROR_SIG = "GuardBlocked(address,uint256)";
    string internal constant U4_WRONG_SIG_ARITY = "GuardBlocked(address)";
    string internal constant U4_WRONG_SIG_ORDER = "GuardBlocked(uint256,address)";
    uint256 internal constant U4_REVERT_LEN = 68;
    uint256 internal constant U4_CHECK_RETURN_LEN = 64;
    uint256 internal constant U4_SLOT_COUNT = 19;
    uint256 internal constant U4_MIN_REVERTED = 7;

    function _u4_deployHost() internal returns (RWAGuardHost host) {
        host = new RWAGuardHost();
    }

    function _u4_copyCtx(Ctx memory c) internal pure returns (Ctx memory out) {
        out = Ctx({
            priceFeed: c.priceFeed,
            actor: c.actor,
            counterparty: c.counterparty,
            expectedImpl: c.expectedImpl,
            maxFeedAge: c.maxFeedAge
        });
    }

    function _u4_ctxHash(Ctx memory c) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(c)));
    }

    function _u4_localSelector() internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(U4_ERROR_SIG)));
    }

    function _u4_dropSelector(bytes memory ret) internal pure returns (bytes memory out) {
        out = new bytes(ret.length - 4);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = ret[i + 4];
        }
    }

    function _u4_rawEnforce(RWAGuardHost h, address token, Ctx memory ctx)
        internal
        returns (bool success, bytes memory ret)
    {
        (success, ret) = address(h).call(abi.encodeCall(RWAGuardHost.enforce, (token, ctx)));
    }

    function _u4_rawCheck(
        RWAGuardHost h,
        address token,
        Ctx memory ctx,
        bool ok,
        uint256 bits,
        string memory tag
    ) internal {
        (bool success, bytes memory ret) =
            address(h).staticcall(abi.encodeCall(RWAGuardHost.check, (token, ctx)));
        assertTrue(success, string.concat(tag, "raw staticcall to check must succeed"));
        assertEq(ret.length, U4_CHECK_RETURN_LEN, string.concat(tag, "check return length is 64"));
        (bool decodedOk, uint256 decodedBits) = abi.decode(ret, (bool, uint256));
        assertEq(decodedOk, ok, string.concat(tag, "check decoded ok matches expected"));
        assertEq(decodedBits, bits, string.concat(tag, "check decoded reasonBits matches expected"));
    }

    function _u4_checkAgainstCore(RWAGuardHost h, address token, Ctx memory ctx, string memory tag)
        internal
        returns (bool ok, uint256 bits)
    {
        (bool okK, uint256 bitsK) = h.check(token, ctx);
        (bool okC, uint256 bitsC) = GuardCore.evaluate(token, ctx);
        assertEq(bitsC, bitsK, string.concat(tag, "host check reasonBits matches core"));
        assertEq(okC, okK, string.concat(tag, "host check ok matches core"));
        assertEq(okC, bitsC == 0, string.concat(tag, "core ok equals reasonBits == 0"));
        ok = okK;
        bits = bitsK;
    }

    function _u4_assertGuardBlockedPayload(bytes memory ret, address token, uint256 bits, string memory tag)
        internal
        pure
    {
        assertEq(ret.length, U4_REVERT_LEN, string.concat(tag, "revert payload length is 68"));
        assertEq(
            uint256(uint32(bytes4(ret))),
            uint256(uint32(_u4_localSelector())),
            string.concat(tag, "revert payload selector matches GuardBlocked")
        );
        (address t, uint256 b) = abi.decode(_u4_dropSelector(ret), (address, uint256));
        assertEq(t, token, string.concat(tag, "revert payload token matches"));
        assertEq(b, bits, string.concat(tag, "revert payload reasonBits matches"));
        assertEq(
            uint256(keccak256(ret)),
            uint256(keccak256(abi.encodeWithSelector(_u4_localSelector(), token, bits))),
            string.concat(tag, "revert payload whole bytes match the expected encoding")
        );
    }

    function _u4_assertForms(RWAGuardHost h, address token, Ctx memory ctx, string memory tag)
        internal
        returns (bool reverted, uint256 bits)
    {
        bool ok;
        (ok, bits) = _u4_checkAgainstCore(h, token, ctx, tag);
        _u4_rawCheck(h, token, ctx, ok, bits, tag);
        (bool s, bytes memory r) = _u4_rawEnforce(h, token, ctx);
        if (ok) {
            assertTrue(s, string.concat(tag, "enforce succeeds when check is clean"));
            assertEq(r.length, 0, string.concat(tag, "enforce returns empty data when check is clean"));
        } else {
            assertFalse(s, string.concat(tag, "enforce reverts when check is not clean"));
            _u4_assertGuardBlockedPayload(r, token, bits, tag);
        }
        reverted = !ok;
    }

    function _u4_assertClean(RWAGuardHost h, address token, Ctx memory ctx, string memory tag) internal {
        (bool reverted, uint256 bits) = _u4_assertForms(h, token, ctx, tag);
        assertFalse(reverted, string.concat(tag, "clean arm must not revert"));
        assertEq(bits, 0, string.concat(tag, "clean arm reasonBits is exactly zero"));
    }

    function _u4_gateSpan(uint256 bits) internal pure returns (uint256 span) {
        uint8[8] memory positions = [uint8(0), 1, 2, 3, 4, 5, 6, 8];
        for (uint256 i = 0; i < 8; i++) {
            uint256 p = positions[i];
            uint256 mask = (uint256(1) << p) | (uint256(1) << (p + 16));
            if ((bits & mask) != 0) {
                span++;
            }
        }
    }

    function _u4_readSlots(address a) internal view returns (uint256[19] memory slots) {
        for (uint256 i = 0; i < 16; i++) {
            slots[i] = uint256(vm.load(a, bytes32(i)));
        }
        slots[16] = uint256(vm.load(a, bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)));
        slots[17] = uint256(vm.load(a, bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)));
        slots[18] = uint256(vm.load(a, bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)));
    }

    function _u4_assertSlotsZero(address a, string memory tag) internal view {
        uint256[19] memory slots = _u4_readSlots(a);
        for (uint256 i = 0; i < U4_SLOT_COUNT; i++) {
            assertEq(slots[i], 0, string.concat(tag, "host storage slot is zero"));
        }
    }

    function _u4_countWrites(Vm.AccountAccess[] memory d) internal pure returns (uint256 count) {
        for (uint256 i = 0; i < d.length; i++) {
            for (uint256 j = 0; j < d[i].storageAccesses.length; j++) {
                if (d[i].storageAccesses[j].isWrite) {
                    count++;
                }
            }
        }
    }

    function _u4_hasWrite(Vm.AccountAccess[] memory d, address account, uint256 slot, uint256 newValue)
        internal
        pure
        returns (bool found)
    {
        for (uint256 i = 0; i < d.length; i++) {
            for (uint256 j = 0; j < d[i].storageAccesses.length; j++) {
                Vm.StorageAccess memory sa = d[i].storageAccesses[j];
                if (
                    sa.isWrite && sa.account == account && sa.slot == bytes32(slot)
                        && sa.newValue == bytes32(newValue)
                ) {
                    return true;
                }
            }
        }
        return false;
    }

    function _u4_countKind(Vm.AccountAccess[] memory d, Vm.AccountAccessKind kind, address account)
        internal
        pure
        returns (uint256 count)
    {
        for (uint256 i = 0; i < d.length; i++) {
            if (d[i].kind == kind && d[i].account == account) {
                count++;
            }
        }
    }

    function _u4_accessorOf(Vm.AccountAccess[] memory d, Vm.AccountAccessKind kind, address account)
        internal
        pure
        returns (address accessor)
    {
        for (uint256 i = 0; i < d.length; i++) {
            if (d[i].kind == kind && d[i].account == account) {
                return d[i].accessor;
            }
        }
        return address(0);
    }

    function test_U4_1_selectorDerivedFromSignature() public {
        bytes4 localSelector = _u4_localSelector();
        bytes4 aritySelector = bytes4(keccak256(bytes(U4_WRONG_SIG_ARITY)));
        bytes4 orderSelector = bytes4(keccak256(bytes(U4_WRONG_SIG_ORDER)));

        assertEq(
            uint256(uint32(RWAGuard.GuardBlocked.selector)),
            uint256(uint32(localSelector)),
            "AS-U4-1: GuardBlocked selector matches the compile-time signature keccak"
        );
        assertTrue(aritySelector != localSelector, "AS-U4-1: wrong-arity signature yields a different selector");
        assertTrue(orderSelector != localSelector, "AS-U4-1: wrong-order signature yields a different selector");

        bytes memory p1 = abi.encodeWithSelector(RWAGuard.GuardBlocked.selector, TOKEN, uint256(1) << 3);
        bytes memory p2 = abi.encodeWithSignature(U4_ERROR_SIG, TOKEN, uint256(1) << 3);
        assertEq(p1.length, U4_REVERT_LEN, "AS-U4-1: selector-encoded payload length is 68");
        assertEq(p2.length, U4_REVERT_LEN, "AS-U4-1: signature-encoded payload length is 68");
        assertEq(
            uint256(keccak256(p1)),
            uint256(keccak256(p2)),
            "AS-U4-1: selector-encoded and signature-encoded payloads are byte-identical"
        );

        bytes memory p3 = abi.encodeWithSignature(U4_WRONG_SIG_ORDER, uint256(1) << 3, TOKEN);
        assertTrue(
            uint256(keccak256(p3)) != uint256(keccak256(p1)),
            "AS-U4-1: wrong-order payload keccak differs from the correct payload"
        );
    }

    function test_U4_2_checkMatchesCoreOnCorpus() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-2: ";
        uint256 baseHash = _u4_ctxHash(e.ctx);

        assertEq(
            _u4_ctxHash(_u4_copyCtx(e.ctx)),
            baseHash,
            "AS-U4-2: a fresh copy of the baseline ctx hashes the same as the baseline"
        );

        _u4_assertClean(host, TOKEN, e.ctx, tag);
        _u4_rawCheck(host, TOKEN, e.ctx, true, 0, tag);

        Ctx memory t = _u4_copyCtx(e.ctx);
        t.priceFeed = address(0);
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.actor = address(0);
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.counterparty = address(0);
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.expectedImpl = address(0);
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.expectedImpl = address(e.feed);
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.maxFeedAge = type(uint64).max;
        _u4_case2_twin(host, t, baseHash, tag);

        t = _u4_copyCtx(e.ctx);
        t.counterparty = ACTOR;
        _u4_case2_twin(host, t, baseHash, tag);

        (bool k7Reverted, uint256 k7Bits) = _u4_assertForms(host, NEVER_DEPLOYED, e.ctx, tag);
        assertTrue(k7Reverted, "AS-U4-2: k7 NEVER_DEPLOYED must revert");
        // G3CP: no-code tokens now span {G0,G2,G5} (G3 reads only the plane), so the floor is 2 to stay >= 1 gate under any single-gate mutation.
        assertTrue(_u4_gateSpan(k7Bits) >= 2, "AS-U4-2: k7 gate span is at least 2");
        _u4_rawCheck(host, NEVER_DEPLOYED, e.ctx, false, k7Bits, tag);

        (bool k8Reverted, ) = _u4_assertForms(host, address(0), e.ctx, tag);
        assertTrue(k8Reverted, "AS-U4-2: k8 zero-address token must revert");

        Ctx memory zeroCtx;
        (bool k10Reverted, uint256 k10Bits) = _u4_assertForms(host, TOKEN, zeroCtx, tag);
        assertTrue(k10Reverted, "AS-U4-2: k10 zero ctx must revert");
        assertTrue(_u4_gateSpan(k10Bits) >= 3, "AS-U4-2: k10 gate span is at least 3");

        assertEq(_u4_ctxHash(e.ctx), baseHash, "AS-U4-2: baseline ctx is unchanged after the corpus");
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case2_twin(RWAGuardHost host, Ctx memory t, uint256 baseHash, string memory tag) internal {
        assertTrue(_u4_ctxHash(t) != baseHash, "AS-U4-2: corpus twin ctxHash differs from the baseline");
        _u4_assertForms(host, TOKEN, t, tag);
    }

    function test_U4_3_enforceRevertPayloadMultiGate() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-3: ";

        (bool sControl, bytes memory rControl) = _u4_rawEnforce(host, TOKEN, e.ctx);
        assertTrue(sControl, string.concat(tag, "clean control enforce must succeed"));
        assertEq(rControl.length, 0, string.concat(tag, "clean control enforce returns empty data"));

        assertTrue(NEVER_DEPLOYED != EOA, string.concat(tag, "precondition NEVER_DEPLOYED differs from EOA"));

        Ctx memory zeroCtx;
        (uint256 bitsA, bytes memory rA) = _u4_case3_gate(host, NEVER_DEPLOYED, e.ctx, tag);
        _u4_case3_gate(host, address(0), zeroCtx, tag);
        (uint256 bitsC, bytes memory rC) = _u4_case3_gate(host, EOA, e.ctx, tag);

        assertEq(bitsC, bitsA, string.concat(tag, "case C reasonBits equal case A reasonBits"));
        assertTrue(
            uint256(keccak256(rA)) != uint256(keccak256(rC)),
            string.concat(tag, "case A and case C revert payloads differ by token word")
        );
    }

    function _u4_case3_gate(RWAGuardHost host, address token, Ctx memory ctx, string memory tag)
        internal
        returns (uint256 bits, bytes memory ret)
    {
        bool ok;
        (ok, bits) = host.check(token, ctx);
        assertFalse(ok, string.concat(tag, "gate case must not be clean"));
        bool s;
        (s, ret) = _u4_rawEnforce(host, token, ctx);
        assertFalse(s, string.concat(tag, "gate case enforce must revert"));
        _u4_assertGuardBlockedPayload(ret, token, bits, tag);
        // G3CP: no-code tokens now span {G0,G2,G5} (G3 reads only the plane), so the floor is 2 to stay >= 1 gate under any single-gate mutation.
        assertTrue(_u4_gateSpan(bits) >= 2, string.concat(tag, "gate case span is at least 2"));
    }

    function test_U4_4_enforceMatchesCheckEachGateViolated() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-4: ";
        uint256 reverted;

        if (_u4_case4_g1(e, host, tag)) { reverted++; }
        if (_u4_case4_g2(e, host, tag)) { reverted++; }
        if (_u4_case4_g3(e, host, tag)) { reverted++; }
        if (_u4_case4_g4(e, host, tag)) { reverted++; }
        if (_u4_case4_g5(e, host, tag)) { reverted++; }
        if (_u4_case4_g6(e, host, tag)) { reverted++; }
        if (_u4_case4_g8(e, host, tag)) { reverted++; }
        if (_u4_case4_g0(e, host, tag)) { reverted++; }

        assertTrue(reverted >= U4_MIN_REVERTED, "AS-U4-4: at least U4_MIN_REVERTED of eight cases revert");
    }

    function _u4_case4_g1(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.plane.setPaused(true);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.plane.setPaused(false);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g2(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        MockEquityToken(e.token).setPaused(true);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        MockEquityToken(e.token).setPaused(false);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g3(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.plane.setBlocked(ACTOR, true);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.plane.setBlocked(ACTOR, false);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g4(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.plane.setImplementation(address(new MockEquityToken()));
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.plane.setImplementation(address(e.logic));
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g5(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0 + 100);
        vm.warp(T0 + 99);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        MockEquityToken(e.token).setRatios(1e18, 1e18, 0);
        vm.warp(T0);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g6(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.feed.setFollowNow(true);
        e.feed.setRound(7, 1e8, T0, T0, 7);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g8(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.feed.setRound(7, 1e8, T0, T0, 6);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.feed.setRound(7, 1e8, T0, T0, 7);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case4_g0(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        _nonProxyToken(e);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        vm.etch(e.token, _loadProxyRuntime());
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function test_U4_5_enforceMatchesCheckEachGateUnreadable() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-5: ";
        uint256 reverted;

        if (_u4_case5_g1u(e, host, tag)) { reverted++; }
        if (_u4_case5_g2u(e, host, tag)) { reverted++; }
        if (_u4_case5_g3u(e, host, tag)) { reverted++; }
        if (_u4_case5_g4u(e, host, tag)) { reverted++; }
        if (_u4_case5_g5u(e, host, tag)) { reverted++; }
        if (_u4_case5_g6u(e, host, tag)) { reverted++; }
        if (_u4_case5_g8u(e, host, tag)) { reverted++; }
        if (_u4_case5_g0u(e, host, tag)) { reverted++; }

        assertTrue(reverted >= U4_MIN_REVERTED, "AS-U4-5: at least U4_MIN_REVERTED of eight cases revert");
    }

    function _u4_case5_g1u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.plane.setMutator(MockControlPlane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.plane.setMutator(MockControlPlane.paused.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g2u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0)
        );
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0)
        );
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g3u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        Ctx memory t = _u4_copyCtx(e.ctx);
        t.actor = address(0);
        (reverted, ) = _u4_assertForms(host, TOKEN, t, tag);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g4u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        Ctx memory t = _u4_copyCtx(e.ctx);
        t.expectedImpl = address(0);
        (reverted, ) = _u4_assertForms(host, TOKEN, t, tag);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g5u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        MockEquityToken(e.token).setMutator(
            MockEquityToken.uiMultiplier.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        MockEquityToken(e.token).setMutator(
            MockEquityToken.uiMultiplier.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0)
        );
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g6u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        e.feed.setFeedMode(1, 0);
        (reverted, ) = _u4_assertForms(host, TOKEN, e.ctx, tag);
        e.feed.setFeedMode(0, 0);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g8u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        Ctx memory t = _u4_copyCtx(e.ctx);
        t.priceFeed = address(0);
        (reverted, ) = _u4_assertForms(host, TOKEN, t, tag);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function _u4_case5_g0u(Env memory e, RWAGuardHost host, string memory tag) internal returns (bool reverted) {
        (reverted, ) = _u4_assertForms(host, NEVER_DEPLOYED, e.ctx, tag);
        _u4_assertClean(host, TOKEN, e.ctx, tag);
    }

    function test_U4_6_enforcePassWritesNoState() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-6: ";

        _u4_assertSlotsZero(address(host), tag);

        vm.startStateDiffRecording();
        (bool s, bytes memory r) = address(host).call(abi.encodeCall(RWAGuardHost.enforce, (TOKEN, e.ctx)));
        Vm.AccountAccess[] memory d = vm.stopAndReturnStateDiff();

        assertTrue(s, string.concat(tag, "clean enforce call must succeed"));
        assertEq(r.length, 0, string.concat(tag, "clean enforce call returns empty data"));
        assertEq(_u4_countWrites(d), 0, string.concat(tag, "clean enforce performs zero storage writes"));
        assertEq(
            _u4_countKind(d, Vm.AccountAccessKind.Call, address(host)),
            1,
            string.concat(tag, "host is called exactly once")
        );
        assertTrue(_countStaticAll(d) >= 1, string.concat(tag, "at least one staticcall is made"));

        assertEq(
            uint256(vm.load(address(e.feed), bytes32(uint256(0)))),
            7,
            string.concat(tag, "control baseline feed slot 0 holds 7 before the write")
        );

        vm.startStateDiffRecording();
        e.feed.setRound(9, 1e8, T0, T0, 9);
        Vm.AccountAccess[] memory d2 = vm.stopAndReturnStateDiff();

        assertTrue(
            _u4_hasWrite(d2, address(e.feed), 0, 9),
            string.concat(tag, "control write to feed slot 0 is recorded")
        );
        assertTrue(_u4_countWrites(d2) >= 1, string.concat(tag, "control write count is at least one"));
        assertEq(
            uint256(vm.load(address(e.feed), bytes32(uint256(0)))),
            9,
            string.concat(tag, "control write is observable via vm.load")
        );

        _u4_assertSlotsZero(address(host), tag);
    }

    function test_U4_7_verdictIndependentOfCaller() public {
        Env memory e = _baseline();
        RWAGuardHost host = _u4_deployHost();
        string memory tag = "AS-U4-7: ";

        e.plane.setBlocked(BLOCKED_ACTOR, true);
        assertTrue(
            e.plane.isBlocked(BLOCKED_ACTOR),
            string.concat(tag, "fixture check: blocked actor reads back blocked")
        );

        vm.prank(ACTOR);
        (bool ok1, uint256 b1) = host.check(TOKEN, e.ctx);

        vm.startStateDiffRecording();
        vm.prank(BLOCKED_ACTOR);
        (bool ok2, uint256 b2) = host.check(TOKEN, e.ctx);
        Vm.AccountAccess[] memory d = vm.stopAndReturnStateDiff();

        assertEq(
            _u4_accessorOf(d, Vm.AccountAccessKind.StaticCall, address(host)),
            BLOCKED_ACTOR,
            string.concat(tag, "prank actually reached the host as BLOCKED_ACTOR")
        );
        assertEq(b1, b2, string.concat(tag, "reasonBits is independent of caller"));
        assertEq(ok1, ok2, string.concat(tag, "ok is independent of caller"));
        assertEq(b1, 0, string.concat(tag, "clean ctx yields zero reasonBits regardless of caller"));

        bytes memory rActor = _u4_case7_enforceReverts(host, ACTOR, NEVER_DEPLOYED, e.ctx, tag);
        bytes memory rEoa = _u4_case7_enforceReverts(host, EOA, NEVER_DEPLOYED, e.ctx, tag);
        assertEq(
            uint256(keccak256(rActor)),
            uint256(keccak256(rEoa)),
            string.concat(tag, "revert payload is identical regardless of caller")
        );

        (bool okND, uint256 bitsND) = host.check(NEVER_DEPLOYED, e.ctx);
        assertFalse(okND, string.concat(tag, "NEVER_DEPLOYED must not be clean, for the change control"));
        assertTrue(bitsND != b1, string.concat(tag, "NEVER_DEPLOYED reasonBits differ from the clean baseline"));
        // G3CP: no-code tokens now span {G0,G2,G5} (G3 reads only the plane), so the floor is 2 to stay >= 1 gate under any single-gate mutation.
        assertTrue(_u4_gateSpan(bitsND) >= 2, string.concat(tag, "NEVER_DEPLOYED gate span is at least 2"));
    }

    function _u4_case7_enforceReverts(
        RWAGuardHost host,
        address caller,
        address token,
        Ctx memory ctx,
        string memory tag
    ) internal returns (bytes memory ret) {
        bool s;
        vm.startStateDiffRecording();
        vm.prank(caller);
        (s, ret) = _u4_rawEnforce(host, token, ctx);
        Vm.AccountAccess[] memory d = vm.stopAndReturnStateDiff();
        assertFalse(s, string.concat(tag, "enforce from caller must revert"));
        assertEq(
            _u4_accessorOf(d, Vm.AccountAccessKind.Call, address(host)),
            caller,
            string.concat(tag, "prank reached the host as the given caller")
        );
    }
}
