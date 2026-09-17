// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// ============================================================================
// DualForm.t.sol -- U7 AS-1 (dual-form verdict agreement) and AS-1a (Ctx layout)
// ----------------------------------------------------------------------------
// Scope. This file asserts verdict agreement between the two delivery forms, not
// identical behaviour. The deployed form has one extra revert surface: ABI decoding
// of Ctx. In the library form the integrator builds Ctx in Solidity, so its types
// are already clean. Malformed calldata is not a legal decision input tuple and is
// outside the reach of these assertions (that surface is covered by
// test_U3_5_dirtyAddressWordEmptyRevert, test_U3_6_dirtyUint64WordEmptyRevert and
// test_U3_7_shortCalldataEmptyRevert).
//
// Already proven elsewhere (cited, not re-implemented):
//  - test_U3_2_forwardingMatchesCore (test/RWAGuardView.t.sol): the deployed view
//    returns the same reasonBits and ok as the shared judgement core on its corpus,
//    and a raw-calldata decode of the view matches the high-level call.
//  - test_U4_2_checkMatchesCoreOnCorpus (test/RWAGuard.t.sol): the library check,
//    reached through the RWAGuardHost external wrapper, returns the same reasonBits
//    and ok as the shared core on its corpus, and enforce agrees with check.
//  - test_U4_4_enforceMatchesCheckEachGateViolated (test/RWAGuard.t.sol): with one
//    violated setup per gate, enforce reverts with the check verdict exactly when
//    check is not clean.
//  - test_U4_5_enforceMatchesCheckEachGateUnreadable (test/RWAGuard.t.sol): the same,
//    with one unreadable setup per gate.
// Those four reach view-versus-library agreement only transitively, through the core.
// What this file adds: inside one test function and one chain state, the same tuple is
// evaluated by RWAGuardView.isSafeToTrade (external call to a deployed instance) and by
// RWAGuard.check (internal call inlined into this contract), and the two verdicts are
// compared directly: all 256 bits of reasonBits, and ok. This file never calls the
// shared core itself.
//
// Mutation battery (U7 section 8b). No function in this file belongs to any
// expected-red row; every function must stay green under M-G0..M-G8 and M-LOCK.
// Therefore no function here asserts a gate's exact value. Corpus functions assert
// only relations a removed accumulation cannot break: form agreement, ok equals
// (reasonBits == 0), reasonBits stay inside the entry's declared value, and
// fixture-side preconditions observed without the guard. The exact value of each
// entry is asserted by the landed function named in its comment, where one exists.
// Excluded from the corpus: every gas-dependent fixture mode, because the two forms
// run with different gas.
// ============================================================================

import {Vm} from "./Base.sol";
import {GatesBaseline} from "./Gates.t.sol";
import {GuardCore} from "../src/GuardCore.sol";          // only CONTROL_PLANE / KNOWN_PROXY_CODEHASH
import {Ctx} from "../src/GuardBits.sol";
import {RWAGuard} from "../src/RWAGuard.sol";
import {RWAGuardView} from "../src/RWAGuardView.sol";
import {MockControlPlane, FixtureMutator} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

abstract contract DualFormBase is GatesBaseline {
    string  internal constant D_SIG = "isSafeToTrade(address,(address,address,address,address,uint64))";
    address internal constant D_S_FEED         = address(uint160(uint256(keccak256("rwa-guard.u7d.priceFeed"))));
    address internal constant D_S_ACTOR        = address(uint160(uint256(keccak256("rwa-guard.u7d.actor"))));
    address internal constant D_S_COUNTERPARTY = address(uint160(uint256(keccak256("rwa-guard.u7d.counterparty"))));
    address internal constant D_S_IMPL         = address(uint160(uint256(keccak256("rwa-guard.u7d.expectedImpl"))));
    uint64  internal constant D_AGE            = 9_223_372_036_854_775_809; // 2**63 + 1: > type(uint32).max, < type(uint64).max

    // Deploys a fresh RWAGuardView after _baseline(). The library form is inlined
    // via RWAGuard.check, called directly from the test contract.
    function _d_deploy() internal returns (RWAGuardView guard) {
        guard = new RWAGuardView();
    }

    // V1 = view, L = check (internal), V2 = view. Asserts the six FD-U7D-1 relations
    // and returns bitsL. Calls _d_view twice rather than destructuring two external
    // calls inline, to keep this function's own stack shallow under legacy codegen.
    function _d_dual(RWAGuardView guard, address token, Ctx memory ctx) internal view returns (uint256 bits) {
        (bool okV1, uint256 bitsV1) = _d_view(guard, token, ctx);
        (bool okL, uint256 bitsL) = RWAGuard.check(token, ctx);
        (bool okV2, uint256 bitsV2) = _d_view(guard, token, ctx);

        assertEq(bitsV1, bitsL, "AS-1: view and check reasonBits are equal on the same tuple");
        assertEq(okV1, okL, "AS-1: view and check ok are equal on the same tuple");
        assertEq(okV1, (bitsV1 == 0), "AS-1: view ok equals reasonBits == 0");
        assertEq(okL, (bitsL == 0), "AS-1: check ok equals reasonBits == 0");
        assertEq(bitsV2, bitsL, "AS-1: a second view call after check returns the same reasonBits");
        assertEq(okV2, okL, "AS-1: a second view call after check returns the same ok");

        bits = bitsL;
    }

    // One external view call to the deployed form; used by _d_dual (stack) and by
    // the cross-tuple / intervening-write arms.
    function _d_view(RWAGuardView guard, address token, Ctx memory ctx) internal view returns (bool ok, uint256 bits) {
        (ok, bits) = guard.isSafeToTrade(token, ctx);
    }

    // assertEq(bits & ~declared, 0, "AS-1: reasonBits stay inside the entry's declared value")
    function _d_within(uint256 bits, uint256 declared) internal pure {
        assertEq(bits & ~declared, 0, "AS-1: reasonBits stay inside the entry's declared value");
    }

    // Raw staticcall; len = returndata length; word0 = first 32 bytes when len >= 32,
    // else 0. Never asserts. Built without inline assembly: the first 32 bytes are
    // copied into a fixed-size scratch array, then abi.decode'd as a single bytes32.
    function _d_rawRead(address target, bytes memory callData)
        internal
        view
        returns (bool success, uint256 len, bytes32 word0)
    {
        bytes memory ret;
        (success, ret) = target.staticcall(callData);
        len = ret.length;
        if (len >= 32) {
            bytes memory head = new bytes(32);
            for (uint256 i = 0; i < 32; i++) {
                head[i] = ret[i];
            }
            word0 = abi.decode(head, (bytes32));
        }
    }

    // Raw staticcall to the view; asserts success and a 64-byte return; decodes (bool, uint256).
    function _d_rawView(RWAGuardView guard, bytes memory data) internal view returns (bool ok, uint256 bits) {
        (bool success, bytes memory ret) = address(guard).staticcall(data);
        assertTrue(success, "AS-1: raw static call to the view succeeds");
        assertEq(ret.length, 64, "AS-1: raw view return is 64 bytes");
        (ok, bits) = abi.decode(ret, (bool, uint256));
    }

    // Fresh copy built BY NAME: a plain memory-struct assignment would alias src's
    // memory instead of copying it.
    function _d_copyCtx(Ctx memory src) internal pure returns (Ctx memory out) {
        out = Ctx({
            priceFeed: src.priceFeed,
            actor: src.actor,
            counterparty: src.counterparty,
            expectedImpl: src.expectedImpl,
            maxFeedAge: src.maxFeedAge
        });
    }

    // Asserts enc.length == 160, then abi.decode's into five uint256 words.
    function _d_words(bytes memory enc)
        internal
        pure
        returns (uint256 w0, uint256 w1, uint256 w2, uint256 w3, uint256 w4)
    {
        assertEq(enc.length, 160, "AS-1: abi.encode of Ctx is exactly 160 bytes");
        (w0, w1, w2, w3, w4) = abi.decode(enc, (uint256, uint256, uint256, uint256, uint256));
    }

    // Sum over d[i].storageAccesses[j].isWrite.
    function _d_writeCount(Vm.AccountAccess[] memory d) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < d.length; i++) {
            for (uint256 j = 0; j < d[i].storageAccesses.length; j++) {
                if (d[i].storageAccesses[j].isWrite) {
                    n++;
                }
            }
        }
    }
}

contract DualFormLayoutTest is DualFormBase {
    // TS-28: byte layout by name. Named read-back (TS-29) pins constructor position
    // to name; this pins name to wire position, which is what off-chain encoders and
    // the deployed calldata see.
    function test_AS1a_encodeLength160AndSpecOrder() public pure {
        Ctx memory n = Ctx({
            priceFeed: D_S_FEED,
            actor: D_S_ACTOR,
            counterparty: D_S_COUNTERPARTY,
            expectedImpl: D_S_IMPL,
            maxFeedAge: D_AGE
        });
        bytes memory enc = abi.encode(n);
        assertEq(enc.length, 160, "AS-1: abi.encode of the named Ctx is exactly 160 bytes");
        bytes32 named = keccak256(enc);
        bytes32 spec = keccak256(abi.encode(D_S_FEED, D_S_ACTOR, D_S_COUNTERPARTY, D_S_IMPL, D_AGE));
        assertTrue(named == spec, "AS-1: byte layout matches the spec-order scalar encoding");

        // Control: length is blind to order (KG-12's premise), the byte check is not.
        bytes memory feedImplSwap = abi.encode(D_S_IMPL, D_S_ACTOR, D_S_COUNTERPARTY, D_S_FEED, D_AGE);
        assertEq(feedImplSwap.length, 160, "AS-1: control: a swapped scalar encoding is still 160 bytes");
        assertTrue(
            keccak256(feedImplSwap) != named,
            "AS-1: control: swapping feed and expectedImpl changes the byte layout"
        );

        bytes memory actorCounterpartySwap = abi.encode(D_S_FEED, D_S_COUNTERPARTY, D_S_ACTOR, D_S_IMPL, D_AGE);
        assertEq(actorCounterpartySwap.length, 160, "AS-1: control: a swapped scalar encoding is still 160 bytes");
        assertTrue(
            keccak256(actorCounterpartySwap) != named,
            "AS-1: control: swapping actor and counterparty changes the byte layout"
        );

        bytes memory counterpartyImplSwap = abi.encode(D_S_FEED, D_S_ACTOR, D_S_IMPL, D_S_COUNTERPARTY, D_AGE);
        assertEq(counterpartyImplSwap.length, 160, "AS-1: control: a swapped scalar encoding is still 160 bytes");
        assertTrue(
            keccak256(counterpartyImplSwap) != named,
            "AS-1: control: swapping counterparty and expectedImpl changes the byte layout"
        );
    }

    // TS-29: count and types at compile time (positional arity, typed read-back
    // locals), order by named read-back.
    function test_AS1a_positionalConstructionNamedReadBack() public pure {
        Ctx memory p = Ctx(D_S_FEED, D_S_ACTOR, D_S_COUNTERPARTY, D_S_IMPL, D_AGE);
        address f = p.priceFeed;
        address a = p.actor;
        address c = p.counterparty;
        address i = p.expectedImpl;
        uint64 m = p.maxFeedAge;
        assertEq(f, D_S_FEED, "AS-1: positional construction lands priceFeed in its own field");
        assertEq(a, D_S_ACTOR, "AS-1: positional construction lands actor in its own field");
        assertEq(c, D_S_COUNTERPARTY, "AS-1: positional construction lands counterparty in its own field");
        assertEq(i, D_S_IMPL, "AS-1: positional construction lands expectedImpl in its own field");
        assertTrue(m == D_AGE, "AS-1: positional construction lands maxFeedAge in its own field");

        Ctx memory n = Ctx({
            priceFeed: D_S_FEED,
            actor: D_S_ACTOR,
            counterparty: D_S_COUNTERPARTY,
            expectedImpl: D_S_IMPL,
            maxFeedAge: D_AGE
        });
        assertTrue(
            keccak256(abi.encode(p)) == keccak256(abi.encode(n)),
            "AS-1: positional and named construction encode identically"
        );

        Ctx memory swapped = Ctx(D_S_IMPL, D_S_ACTOR, D_S_COUNTERPARTY, D_S_FEED, D_AGE);
        assertTrue(
            swapped.priceFeed != D_S_FEED,
            "AS-1: control: a scrambled positional order no longer lands feed in its own field"
        );
    }

    // Sentinel-encoding half of TS-30: word 4 equals the boundary value, its high
    // bits are clean, and the typed read-back matches.
    function _p1_maxFeedAgeSentinel(uint64 age) private pure returns (uint256 word) {
        Ctx memory c = Ctx({
            priceFeed: D_S_FEED,
            actor: D_S_ACTOR,
            counterparty: D_S_COUNTERPARTY,
            expectedImpl: D_S_IMPL,
            maxFeedAge: age
        });
        (, , , , word) = _d_words(abi.encode(c));
        assertEq(word, uint256(age), "AS-1: the maxFeedAge word equals the sentinel value");
        assertTrue(word >> 64 == 0, "AS-1: the maxFeedAge word leaves its high bits clean");
        assertTrue(c.maxFeedAge == age, "AS-1: the maxFeedAge typed read-back matches the sentinel value");
    }

    // TS-30: maxFeedAge boundaries (0 and type(uint64).max), plus the environment arm.
    function test_AS1a_maxFeedAgeBoundaries() public {
        _p1_maxFeedAgeSentinel(0);
        _p1_maxFeedAgeSentinel(type(uint64).max);

        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);

        Ctx memory ageZeroCopy = _d_copyCtx(e.ctx);
        ageZeroCopy.maxFeedAge = 0;
        assertTrue(ageZeroCopy.maxFeedAge == 0, "AS-1: precondition the age-0 copy keeps its own maxFeedAge");
        _d_within(_d_dual(guard, e.token, ageZeroCopy), (uint256(1) << 6));

        Ctx memory ageMaxCopy = _d_copyCtx(e.ctx);
        ageMaxCopy.maxFeedAge = type(uint64).max;
        assertTrue(
            ageMaxCopy.maxFeedAge == type(uint64).max,
            "AS-1: precondition the max-age copy keeps its own maxFeedAge"
        );
        _d_within(_d_dual(guard, e.token, ageMaxCopy), 0);
    }

    // Sentinel-encoding half of TS-31: the actor and counterparty words for a given
    // counterparty sentinel value.
    function _p1_counterpartyEqualsActorWords(address counterpartyValue)
        private
        pure
        returns (uint256 actorWord, uint256 counterpartyWord)
    {
        Ctx memory c = Ctx({
            priceFeed: D_S_FEED,
            actor: D_S_ACTOR,
            counterparty: counterpartyValue,
            expectedImpl: D_S_IMPL,
            maxFeedAge: D_AGE
        });
        (, actorWord, counterpartyWord, , ) = _d_words(abi.encode(c));
    }

    // TS-31: counterparty == actor encoding, plus the environment arm.
    function test_AS1a_counterpartyEqualsActor() public {
        (uint256 w1, uint256 w2) = _p1_counterpartyEqualsActorWords(D_S_ACTOR);
        assertEq(w1, uint256(uint160(D_S_ACTOR)), "AS-1: counterparty == actor encodes the sentinel into the actor word");
        assertEq(
            w2,
            uint256(uint160(D_S_ACTOR)),
            "AS-1: counterparty == actor encodes the sentinel into the counterparty word"
        );

        (uint256 dw1, uint256 dw2) = _p1_counterpartyEqualsActorWords(D_S_COUNTERPARTY);
        assertTrue(dw1 != dw2, "AS-1: control: a distinct counterparty gives a different word from the actor word");

        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        Ctx memory c = _d_copyCtx(e.ctx);
        c.counterparty = ACTOR;
        assertTrue(c.counterparty == c.actor, "AS-1: precondition the environment copy has counterparty equal to actor");
        _d_within(_d_dual(guard, e.token, c), 0);

        MockEquityToken(e.token).setBlocked(ACTOR, true);
        assertTrue(
            c.counterparty == c.actor,
            "AS-1: precondition the environment copy still has counterparty equal to actor"
        );
        _d_within(_d_dual(guard, e.token, c), (uint256(1) << 3));
    }

    // Spec-order calldata for TS-32, and its priceFeed/expectedImpl-swapped variant.
    function _p1_specOrderCalldata(address token, Ctx memory ctx) private pure returns (bytes memory data) {
        data = bytes.concat(
            bytes4(keccak256(bytes(D_SIG))),
            abi.encode(token, ctx.priceFeed, ctx.actor, ctx.counterparty, ctx.expectedImpl, ctx.maxFeedAge)
        );
    }

    function _p1_swappedFeedImplCalldata(address token, Ctx memory ctx) private pure returns (bytes memory data) {
        data = bytes.concat(
            bytes4(keccak256(bytes(D_SIG))),
            abi.encode(token, ctx.expectedImpl, ctx.actor, ctx.counterparty, ctx.priceFeed, ctx.maxFeedAge)
        );
    }

    // TS-32: the deployed decoder agrees on field order.
    function test_AS1a_viewDecodesSpecOrderCalldata() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        bytes memory data = _p1_specOrderCalldata(e.token, e.ctx);
        assertTrue(
            keccak256(data) == keccak256(abi.encodeCall(RWAGuardView.isSafeToTrade, (e.token, e.ctx))),
            "AS-1: the spec-order argument list matches the canonical encoded call"
        );

        (bool okRaw, uint256 bitsRaw) = _d_rawView(guard, data);
        (bool okL, uint256 bitsL) = RWAGuard.check(e.token, e.ctx);
        assertEq(bitsRaw, bitsL, "AS-1: the raw spec-order call agrees with check on reasonBits");
        assertEq(okRaw, okL, "AS-1: the raw spec-order call agrees with check on ok");
        _d_within(bitsRaw, 0);

        // Swap the priceFeed and expectedImpl words: every swap except actor<->counterparty
        // changes the verdict, because G3 reads both parties symmetrically; that one swap is
        // instead caught by the byte check in this function and in TS-28.
        (, uint256 bitsSwapped) = _d_rawView(guard, _p1_swappedFeedImplCalldata(e.token, e.ctx));
        assertTrue(
            bitsSwapped != bitsL,
            "AS-1: control: swapping the priceFeed and expectedImpl words changes the verdict"
        );
        _d_within(bitsSwapped, (uint256(1) << 4) | (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255));
    }
}

contract DualFormAgreementTest is DualFormBase {
    // Cross-pair half of TS-25: view on one token against check on the other, over
    // the same ctx; both bits and ok must disagree.
    function _p1_crossPair(RWAGuardView guard, address viewToken, address checkToken, Ctx memory ctx)
        private
        view
    {
        (bool okV, uint256 bitsV) = _d_view(guard, viewToken, ctx);
        (bool okC, uint256 bitsC) = RWAGuard.check(checkToken, ctx);
        assertTrue(bitsV != bitsC, "AS-1: view and check on cross-matched tokens disagree on reasonBits");
        assertTrue(okV != okC, "AS-1: view and check on cross-matched tokens disagree on ok");
    }

    // Third half of TS-25: two non-zero tuples whose bits differ but whose ok agrees
    // (both false), showing ok-equality alone cannot discriminate.
    function _p1_crossAgreeOnOk(
        RWAGuardView guard,
        address viewToken,
        address checkToken,
        Ctx memory viewCtx,
        Ctx memory checkCtx
    ) private view {
        (bool okV, uint256 bitsV) = _d_view(guard, viewToken, viewCtx);
        (bool okC, uint256 bitsC) = RWAGuard.check(checkToken, checkCtx);
        assertTrue(bitsV != bitsC, "AS-1: two differing non-zero tuples still disagree on reasonBits");
        assertTrue(okV == okC, "AS-1: control: ok alone cannot discriminate these two non-zero tuples, both false");
    }

    // TS-25 test_AS1_crossTupleDiscrimination: discrimination arm for the comparison
    // itself. Each differing pair differs in at least 2 gates ({G0,G2,G3,G5} against
    // {} and against {G4,G6,G8}), and the battery applies one mutation at a time, so
    // this arm is invariant under M-G0..M-G8.
    function test_AS1_crossTupleDiscrimination() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        uint256 bitsToken = _d_dual(guard, TOKEN, e.ctx);
        _d_within(bitsToken, 0);

        uint256 bitsNeverDeployed = _d_dual(guard, NEVER_DEPLOYED, e.ctx);
        _d_within(
            bitsNeverDeployed,
            (uint256(1) << 16) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 21) | (uint256(1) << 255)
        );

        _p1_crossPair(guard, TOKEN, NEVER_DEPLOYED, e.ctx);
        _p1_crossPair(guard, NEVER_DEPLOYED, TOKEN, e.ctx);

        Ctx memory zero;
        _p1_crossAgreeOnOk(guard, NEVER_DEPLOYED, TOKEN, e.ctx, zero);
    }

    // TS-26 test_AS1_bothFormsWriteNoState: a recorder around both forms counts zero
    // writes; a recorder around a fixture setter, in the same run, counts at least
    // one, proving the zero count is not zero because the channel is broken.
    function test_AS1_bothFormsWriteNoState() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        vm.startStateDiffRecording();
        _d_view(guard, e.token, e.ctx);
        RWAGuard.check(e.token, e.ctx);
        Vm.AccountAccess[] memory diffBoth = vm.stopAndReturnStateDiff();
        assertEq(_d_writeCount(diffBoth), 0, "AS-1: evaluating both forms performs zero storage writes");

        vm.startStateDiffRecording();
        MockEquityToken(e.token).setBlocked(BLOCKED_ACTOR, true);
        Vm.AccountAccess[] memory diffSetter = vm.stopAndReturnStateDiff();
        assertTrue(_d_writeCount(diffSetter) >= 1, "AS-1: control: a fixture setter is recorded as a storage write");

        _d_within(_d_dual(guard, e.token, e.ctx), 0);
    }

    // TS-27 test_AS1_interveningWriteChangesVerdict: control arm for "nothing changed
    // between the calls" -- a two-gate write between view and check does change it.
    function test_AS1_interveningWriteChangesVerdict() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        (bool okBefore, uint256 bitsBefore) = _d_view(guard, TOKEN, e.ctx);

        e.plane.setPaused(true);
        MockEquityToken(e.token).setPaused(true);

        (bool okAfter, uint256 bitsAfter) = RWAGuard.check(TOKEN, e.ctx);
        assertTrue(bitsBefore != bitsAfter, "AS-1: control: an intervening write between view and check changes reasonBits");
        assertTrue(okBefore != okAfter, "AS-1: control: an intervening write between view and check changes ok");

        _d_within(_d_dual(guard, TOKEN, e.ctx), (uint256(1) << 1) | (uint256(1) << 2));
    }

    // mirrors: test_AS0_baselineAllClear (test/Gates.t.sol); value there: 0
    function test_AS1_allClear() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        assertTrue(
            TOKEN.codehash == GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-1: precondition token codehash equals the known proxy codehash"
        );
        assertTrue(
            e.plane.implementation() == e.ctx.expectedImpl,
            "AS-1: precondition control plane implementation equals ctx.expectedImpl"
        );

        {
            (bool okP, uint256 lenP, bytes32 wordP) =
                _d_rawRead(GuardCore.CONTROL_PLANE, abi.encodeWithSelector(MockControlPlane.paused.selector));
            assertTrue(okP, "AS-1: precondition raw paused() on the control plane succeeds");
            assertEq(lenP, 32, "AS-1: precondition raw paused() on the control plane returns 32 bytes");
            assertTrue(wordP == bytes32(0), "AS-1: precondition raw paused() on the control plane returns a zero word");
        }
        {
            (bool okT, uint256 lenT, bytes32 wordT) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.paused.selector));
            assertTrue(okT, "AS-1: precondition raw paused() on the token succeeds");
            assertEq(lenT, 32, "AS-1: precondition raw paused() on the token returns 32 bytes");
            assertTrue(wordT == bytes32(0), "AS-1: precondition raw paused() on the token returns a zero word");
        }
        {
            (bool okF, uint256 lenF, ) =
                _d_rawRead(e.ctx.priceFeed, abi.encodeWithSelector(MockPriceFeed.latestRoundData.selector));
            assertTrue(okF, "AS-1: precondition raw latestRoundData() on the price feed succeeds");
            assertEq(lenF, 160, "AS-1: precondition raw latestRoundData() on the price feed returns 160 bytes");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, 0);
    }

    // mirrors: test_AS3_foreignCodehashIsExactlyBit0 (test/Gates.t.sol); value there: (uint256(1) << 0)
    function test_AS1_g0ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        _nonProxyToken(e);

        assertTrue(
            e.token.code.length != 0,
            "AS-1: precondition the non-proxy token has nonzero code"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 0));
    }

    // mirrors: test_AS5_1_planePaused (test/Gates.t.sol); value there: (uint256(1) << 1)
    function test_AS1_g1ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.plane.setPaused(true);

        {
            (bool ok, uint256 len, bytes32 word0) =
                _d_rawRead(GuardCore.CONTROL_PLANE, abi.encodeWithSelector(MockControlPlane.paused.selector));
            assertTrue(ok, "AS-1: precondition raw paused() on the control plane succeeds");
            assertEq(len, 32, "AS-1: precondition raw paused() on the control plane returns 32 bytes");
            assertTrue(word0 != bytes32(0), "AS-1: precondition raw paused() on the control plane returns a nonzero word");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 1));
    }

    // mirrors: test_AS6_1_tokenPaused (test/Gates.t.sol); value there: (uint256(1) << 2)
    function test_AS1_g2ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setPaused(true);

        {
            (bool ok, uint256 len, bytes32 word0) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.paused.selector));
            assertTrue(ok, "AS-1: precondition raw paused() on the token succeeds");
            assertEq(len, 32, "AS-1: precondition raw paused() on the token returns 32 bytes");
            assertTrue(word0 != bytes32(0), "AS-1: precondition raw paused() on the token returns a nonzero word");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 2));
    }

    // mirrors: test_AS7_1_tokenBlocksActor (test/Gates.t.sol); value there: (uint256(1) << 3)
    function test_AS1_g3ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setBlocked(ACTOR, true);

        {
            (bool ok, uint256 len, bytes32 word0) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.isBlocked.selector, ACTOR));
            assertTrue(ok, "AS-1: precondition raw isBlocked(ACTOR) on the token succeeds");
            assertEq(len, 32, "AS-1: precondition raw isBlocked(ACTOR) on the token returns 32 bytes");
            assertTrue(word0 != bytes32(0), "AS-1: precondition raw isBlocked(ACTOR) on the token returns a nonzero word");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 3));
    }

    // mirrors: test_AS10_implDrift (test/Gates.t.sol), second evaluation; value there: (uint256(1) << 4)
    function test_AS1_g4ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.plane.setImplementation(address(new MockEquityToken()));

        assertTrue(
            e.plane.implementation() != e.ctx.expectedImpl,
            "AS-1: precondition control plane implementation no longer equals ctx.expectedImpl"
        );
        assertTrue(
            e.plane.implementation().code.length != 0,
            "AS-1: precondition the drifted implementation has nonzero code"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 4));
    }

    // mirrors: test_AS12_3_effectiveAtInFuture (test/Gates.t.sol); value there: (uint256(1) << 5)
    function test_AS1_g5ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setRatios(1e18, 1e18, T0 + 1);

        assertTrue(
            MockEquityToken(e.token).effectiveAt() > block.timestamp,
            "AS-1: precondition token effectiveAt is in the future"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 5));
    }

    // mirrors: test_AS13_c_zeroMaxOneSecondStale (test/Gates.t.sol); value there: (uint256(1) << 6)
    function test_AS1_g6ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);

        (, , , uint256 updatedAt, ) = e.feed.latestRoundData();
        assertTrue(
            updatedAt < block.timestamp,
            "AS-1: precondition feed updatedAt is before block.timestamp"
        );
        assertTrue(
            block.timestamp - updatedAt > e.ctx.maxFeedAge,
            "AS-1: precondition feed staleness exceeds ctx.maxFeedAge"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 6));
    }

    // mirrors: test_AS11_bit24_reverse (test/Gates.t.sol), sub-case reverseIncompleteRound; value there: (uint256(1) << 8)
    function test_AS1_g8ViolatedAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockPriceFeed feed = _freshFeed();
        feed.setRound(7, 1e8, T0, T0, 6);
        e.ctx.priceFeed = address(feed);

        (uint80 roundId, , , , uint80 answeredInRound) = feed.latestRoundData();
        assertTrue(
            answeredInRound < roundId,
            "AS-1: precondition feed answeredInRound is less than roundId"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 8));
    }

    // mirrors: test_AS4a_neverDeployedToken (test/Gates.t.sol); value there: (1<<16)|(1<<18)|(1<<19)|(1<<21)|(1<<255)
    function test_AS1_g0UnreadableNotAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        assertTrue(
            NEVER_DEPLOYED.codehash == bytes32(0),
            "AS-1: precondition never-deployed token has empty codehash"
        );

        uint256 bits = _d_dual(guard, NEVER_DEPLOYED, e.ctx);
        _d_within(
            bits,
            (uint256(1) << 16) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 21) | (uint256(1) << 255)
        );
    }

    // derived, asserted nowhere: (1<<17)|(1<<255)
    // setup follows _u4_case5_g1u (test/RWAGuard.t.sol)
    function test_AS1_g1UnreadableAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.plane.setMutator(MockControlPlane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));

        {
            (bool ok, , ) =
                _d_rawRead(GuardCore.CONTROL_PLANE, abi.encodeWithSelector(MockControlPlane.paused.selector));
            assertTrue(!ok, "AS-1: precondition raw paused() on the control plane fails");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 17) | (uint256(1) << 255));
    }

    // mirrors: test_AS6_2_pausedWord31Bytes (test/Gates.t.sol); value there: (1<<18)|(1<<255)
    function test_AS1_g2UnreadableAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setMutator(MockEquityToken.paused.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0));

        {
            (bool ok, uint256 len, ) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.paused.selector));
            assertTrue(ok, "AS-1: precondition raw paused() on the token succeeds");
            assertEq(len, 31, "AS-1: precondition raw paused() on the token returns 31 bytes");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 18) | (uint256(1) << 255));
    }

    // mirrors: test_AS8_zeroActor (test/Gates.t.sol); value there: (1<<19)|(1<<255)
    function test_AS1_g3UnreadableAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setBlocked(address(0), true);
        e.plane.setBlocked(address(0), true);
        e.ctx.actor = address(0);

        assertTrue(
            e.ctx.actor == address(0),
            "AS-1: precondition ctx.actor is the zero address"
        );
        assertTrue(
            e.ctx.counterparty != address(0),
            "AS-1: precondition ctx.counterparty stays nonzero"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 19) | (uint256(1) << 255));
    }

    // derived, asserted nowhere: (1<<20)|(1<<255)
    // setup follows _u4_case5_g4u (test/RWAGuard.t.sol); not reached in Gates (KG-U7G-5)
    function test_AS1_g4UnreadableAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.ctx.expectedImpl = address(0);

        assertTrue(
            e.ctx.expectedImpl == address(0),
            "AS-1: precondition ctx.expectedImpl is the zero address"
        );
        assertTrue(
            e.plane.implementation() != address(0),
            "AS-1: precondition the plane's implementation read stays healthy"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 20) | (uint256(1) << 255));
    }

    // mirrors: test_AS12_4_wrongLength (test/Gates.t.sol), first sub-case; value there: (1<<21)|(1<<255)
    function test_AS1_g5UnreadableAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockEquityToken(e.token).setMutator(MockEquityToken.uiMultiplier.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0));

        {
            (bool ok, uint256 len, ) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.uiMultiplier.selector));
            assertTrue(ok, "AS-1: precondition raw uiMultiplier() on the token succeeds");
            assertEq(len, 31, "AS-1: precondition raw uiMultiplier() on the token returns 31 bytes");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 21) | (uint256(1) << 255));
    }

    // mirrors: test_AS11_bit24_reverse (test/Gates.t.sol), sub-case reverseNoAnswer; value there: (1<<8)|(1<<22)|(1<<255)
    function test_AS1_g6UnreadableNotAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        MockPriceFeed feed = _freshFeed();
        feed.setFeedMode(1, 0); /* FEED_REVERT */
        e.ctx.priceFeed = address(feed);

        {
            (bool ok, , ) =
                _d_rawRead(address(feed), abi.encodeWithSelector(MockPriceFeed.latestRoundData.selector));
            assertTrue(!ok, "AS-1: precondition raw latestRoundData() on the feed fails");
        }

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255));
    }

    // mirrors: test_AS11_bit24_forward (test/Gates.t.sol); value there: (1<<22)|(1<<24)|(1<<255)
    function test_AS1_g8UnreadableNotAlone() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();

        e.ctx.priceFeed = address(0);

        assertTrue(
            e.ctx.priceFeed == address(0),
            "AS-1: precondition ctx.priceFeed is the zero address"
        );

        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 22) | (uint256(1) << 24) | (uint256(1) << 255));
    }

    // byte-for-byte copy of the body of GatesTest._allGatesViolatedSetup (test/Gates.t.sol).
    function _d_combo1Setup(Env memory e) private {
        _nonProxyToken(e);
        e.plane.setPaused(true);
        MockEquityToken(e.token).setPaused(true);
        MockEquityToken(e.token).setBlocked(ACTOR, true);
        e.plane.setImplementation(address(new MockEquityToken()));
        MockEquityToken(e.token).setRatios(1e18, 2e18, 0);
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 6);
    }

    // copy of the setup lines of test_AS18_noShortCircuit_allGatesUnreadable (test/Gates.t.sol),
    // up to (not including) its pre-assertions and its call to the judgement entry point.
    function _d_combo2Setup(Env memory e) private {
        _nonProxyToken(e);
        e.plane.setMutator(
            MockControlPlane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        e.plane.setMutator(
            MockControlPlane.implementation.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.isBlocked.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.uiMultiplier.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        e.feed.setFeedMode(1, 0); // FEED_REVERT
    }

    // mirrors: test_AS18_noShortCircuit_allGatesViolated (test/Gates.t.sol); value there: (1<<0)|(1<<1)|(1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6)|(1<<8)
    function test_AS1_combo1_allGatesViolated() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        _d_combo1Setup(e);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-1: precondition token codehash differs from the proxy baseline"
        );
        assertTrue(e.ctx.actor != address(0), "AS-1: precondition ctx.actor is non-zero");
        assertTrue(e.ctx.counterparty != address(0), "AS-1: precondition ctx.counterparty is non-zero");
        assertTrue(e.ctx.priceFeed != address(0), "AS-1: precondition ctx.priceFeed is non-zero");
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(
            bits,
            (uint256(1) << 0) | (uint256(1) << 1) | (uint256(1) << 2) | (uint256(1) << 3)
                | (uint256(1) << 4) | (uint256(1) << 5) | (uint256(1) << 6) | (uint256(1) << 8)
        );
    }

    // mirrors: test_AS18_noShortCircuit_allGatesUnreadable (test/Gates.t.sol); value there: (1<<0)|(1<<8)|(1<<17)|(1<<18)|(1<<19)|(1<<20)|(1<<21)|(1<<22)|(1<<255)
    function test_AS1_combo2_allReadableGatesUnreadable() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        _d_combo2Setup(e);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-1: precondition token codehash differs from the proxy baseline"
        );
        assertTrue(e.ctx.actor != address(0), "AS-1: precondition ctx.actor is non-zero");
        assertTrue(e.ctx.counterparty != address(0), "AS-1: precondition ctx.counterparty is non-zero");
        assertTrue(e.ctx.priceFeed != address(0), "AS-1: precondition ctx.priceFeed is non-zero");
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(
            bits,
            (uint256(1) << 0) | (uint256(1) << 8) | (uint256(1) << 17) | (uint256(1) << 18)
                | (uint256(1) << 19) | (uint256(1) << 20) | (uint256(1) << 21) | (uint256(1) << 22)
                | (uint256(1) << 255)
        );
    }

    // mirrors: test_AS5_3_planeHasNoCode (test/Gates.t.sol); value there: (1<<17)|(1<<18)|(1<<19)|(1<<20)|(1<<21)|(1<<255)
    function test_AS1_combo3_planeHasNoCode() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        vm.etch(GuardCore.CONTROL_PLANE, new bytes(0));
        assertTrue(GuardCore.CONTROL_PLANE.code.length == 0, "AS-1: precondition control plane has no code");
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(
            bits,
            (uint256(1) << 17) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 20)
                | (uint256(1) << 21) | (uint256(1) << 255)
        );
    }

    // derived, asserted nowhere: (1<<2)|(1<<6)|(1<<19)|(1<<255)
    function test_AS1_combo4_violatedAndUnreadableAcrossGates() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        MockEquityToken(e.token).setPaused(true);
        e.ctx.actor = address(0);
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);
        {
            (bool success, uint256 len, bytes32 word0) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.paused.selector));
            assertTrue(
                success && len == 32 && word0 != bytes32(0),
                "AS-1: precondition token paused() answers a non-zero word"
            );
        }
        assertTrue(e.ctx.actor == address(0), "AS-1: precondition ctx.actor is zero");
        {
            (, , , uint256 updatedAt, ) = e.feed.latestRoundData();
            assertTrue(
                updatedAt < block.timestamp,
                "AS-1: precondition the feed's updatedAt is behind block.timestamp"
            );
        }
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 2) | (uint256(1) << 6) | (uint256(1) << 19) | (uint256(1) << 255));
    }

    // derived, asserted nowhere: (1<<19)|(1<<20)|(1<<22)|(1<<24)|(1<<255)
    function test_AS1_combo5_zeroCtx() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        Ctx memory z;
        assertTrue(
            z.priceFeed == address(0) && z.actor == address(0) && z.counterparty == address(0)
                && z.expectedImpl == address(0) && z.maxFeedAge == 0,
            "AS-1: precondition all five Ctx fields are zero"
        );
        uint256 bits = _d_dual(guard, e.token, z);
        _d_within(
            bits,
            (uint256(1) << 19) | (uint256(1) << 20) | (uint256(1) << 22) | (uint256(1) << 24)
                | (uint256(1) << 255)
        );
    }

    // derived, asserted nowhere: (1<<1)|(1<<19)|(1<<255)
    function test_AS1_combo6_g3AbsorbsBesideG1() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        e.plane.setPaused(true);
        e.plane.setMutator(
            MockControlPlane.isBlocked.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        MockEquityToken(e.token).setBlocked(ACTOR, true);
        {
            (bool success, uint256 len, bytes32 word0) =
                _d_rawRead(e.token, abi.encodeWithSelector(MockEquityToken.isBlocked.selector, ACTOR));
            assertTrue(
                success && len == 32 && word0 != bytes32(0),
                "AS-1: precondition token-side isBlocked(actor) answers a non-zero word"
            );
        }
        {
            (bool success, , ) = _d_rawRead(
                GuardCore.CONTROL_PLANE, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, ACTOR)
            );
            assertFalse(success, "AS-1: precondition plane-side isBlocked(actor) fails to answer");
        }
        {
            (bool success, uint256 len, bytes32 word0) =
                _d_rawRead(GuardCore.CONTROL_PLANE, abi.encodeWithSelector(MockControlPlane.paused.selector));
            assertTrue(
                success && len == 32 && word0 != bytes32(0),
                "AS-1: precondition plane paused() answers a non-zero word"
            );
        }
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 1) | (uint256(1) << 19) | (uint256(1) << 255));
    }

    // derived, asserted nowhere: (1<<4)|(1<<5)|(1<<8)
    function test_AS1_combo7_driftRatioIncompleteRound() public {
        Env memory e = _baseline();
        RWAGuardView guard = _d_deploy();
        e.plane.setImplementation(address(new MockEquityToken()));
        MockEquityToken(e.token).setRatios(1e18, 2e18, 0);
        e.feed.setRound(7, 1e8, T0, T0, 6);
        assertTrue(
            e.plane.implementation() != e.ctx.expectedImpl,
            "AS-1: precondition drifted implementation differs from ctx.expectedImpl"
        );
        assertTrue(
            MockEquityToken(e.token).uiMultiplier() != MockEquityToken(e.token).newUIMultiplier(),
            "AS-1: precondition uiMultiplier differs from newUIMultiplier"
        );
        (uint80 roundId, , , , uint80 answeredInRound) = e.feed.latestRoundData();
        assertTrue(answeredInRound < roundId, "AS-1: precondition answeredInRound is behind roundId");
        uint256 bits = _d_dual(guard, e.token, e.ctx);
        _d_within(bits, (uint256(1) << 4) | (uint256(1) << 5) | (uint256(1) << 8));
    }
}
