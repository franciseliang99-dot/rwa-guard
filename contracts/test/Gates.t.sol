// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TestBase, Vm} from "./Base.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {GuardBits, Ctx} from "../src/GuardBits.sol";
import {MockControlPlane, FixtureMutator} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

// ═══════════════════════════════════════════════════════════════════════
// FD-U7G-3 conflict note
// -----------------------------------------------------------------------
// The bit-layout library's own header comment states that no other
// contract, test, or document may ever define a second copy of the bit
// layout, and a companion rule in U1's own requirements text repeats
// that ban. AV-1 (this unit's own governing rule) requires every
// assertion in this file to compare the FULL 256-bit reasonBits against
// an INDEPENDENT LITERAL SHIFT expression -- never a value derived from
// the bit-layout library's own named constants -- because a test that
// only re-imports those names cannot detect a whole-layout shift; a
// companion self-check file already states that exact consequence for
// its own case. KG-13 names this file's literal shifts as the accepted
// ceiling for that gap. The two texts are in direct conflict: the later,
// more specific rule (AV-1 / KG-13) governs this file, and fixing the
// stale wording is a change that belongs to a different file, not this
// one. The bit-layout library's members therefore appear in this file
// only inside _checkBits and test_AS26_constantPins -- nowhere else, and
// never as the source of an expected value.
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// FD-U7G-5 branch map: each unreadable bit is set only inside its own
// gate's unreadable branch(es) in GuardCore.sol. A passing full-256-bit
// equality that contains bit N therefore proves at least one of that
// gate's unreadable branches executed in this run.
//
//   bit 16 (G0) -> GuardCore.sol:177-180
//   bit 17 (G1) -> GuardCore.sol:199-200
//   bit 18 (G2) -> GuardCore.sol:213-214
//   bit 19 (G3) -> GuardCore.sol:277-278
//   bit 20 (G4) -> GuardCore.sol:302-307
//   bit 21 (G5) -> GuardCore.sol:337-338
//   bit 22 (G6) -> GuardCore.sol:378-384
//   bit 24 (G8) -> GuardCore.sol:412-413
//
// Reached in this file (the unreadable bit is asserted inside a full-value equality):
//   G0 (16): AS4a (codehash 0), AS4b (empty-code hash), AS4c
//   G1 (17): AS5_3, AS18 unreadable
//   G2 (18): AS4a/b/c, AS5_3, AS6_2, AS6_3, AS18 unreadable
//   G3 (19): AS8 zero-party arms (zero-argument cause); AS4a/b/c, AS5_3, AS18 unreadable (read failure)
//   G4 (20): AS5_3, AS18 unreadable -- read-failure cause ONLY. The dirty-word cause and the
//            zero-expectedImpl cause are NOT reached here: deleting either disjunct stays
//            green in this file (KG-U7G-5).
//   G5 (21): AS4a/b/c, AS5_3, AS12_4, AS18 unreadable
//   G6 (22): AS11 forward (feed not set); AS11 reverse (no answer, garbage, future timestamp);
//            AS18 unreadable
//   G8 (24): AS11 forward (the only path)
// The line numbers above describe src/GuardCore.sol as of this slice. Any edit to that file can
// move them, and nothing in this file detects that.
// ═══════════════════════════════════════════════════════════════════════

abstract contract GatesBaseline is TestBase {
    string  internal constant FIXTURE_PATH = "test/fixtures/equity-token-proxy.runtime.hex";
    uint256 internal constant T0 = 1_700_000_000;
    address internal constant TOKEN          = address(uint160(uint256(keccak256("rwa-guard.u7g.token"))));
    address internal constant ACTOR          = address(uint160(uint256(keccak256("rwa-guard.u7g.actor"))));
    address internal constant COUNTERPARTY   = address(uint160(uint256(keccak256("rwa-guard.u7g.counterparty"))));
    address internal constant BLOCKED_ACTOR  = address(uint160(uint256(keccak256("rwa-guard.u7g.blockedActor"))));
    address internal constant NEVER_DEPLOYED = address(uint160(uint256(keccak256("rwa-guard.u7g.neverDeployed"))));
    address internal constant EOA            = address(uint160(uint256(keccak256("rwa-guard.u7g.eoa"))));
    string  internal constant AS25_PREFIX = "AS-25: ";
    string  internal constant AS26_PREFIX = "AS-26: ";

    struct Env { address token; MockControlPlane plane; MockPriceFeed feed; MockEquityToken logic; Ctx ctx; }
    uint256 internal evalCount;

    // §B steps 1-7: every case in this file starts from this assembly. The pre-assertions below
    // prove the premises each step relies on; test_AS0_baselineAllClear proves the assembled
    // baseline evaluates to exactly 0, which every "exactly" value in this file builds on.
    function _baseline() internal returns (Env memory e) {
        // Step 1: pin block.timestamp so every T0 - k subtraction elsewhere in this file is safe.
        vm.warp(T0);

        // Step 2: etch the control-plane fixture onto the guard's compile-time constant address.
        vm.etch(GuardCore.CONTROL_PLANE, address(new MockControlPlane()).code);
        e.plane = MockControlPlane(GuardCore.CONTROL_PLANE);

        // Step 3: deploy the logic contract the proxy delegates into, point the plane at it.
        e.logic = new MockEquityToken();
        e.plane.setImplementation(address(e.logic));
        assertEq(
            e.plane.implementation(),
            address(e.logic),
            "AS-0: control plane answers the logic address it was just given"
        );

        // Step 4: etch the real 283-byte proxy runtime onto TOKEN.
        vm.etch(TOKEN, _loadProxyRuntime());
        e.token = TOKEN;
        assertTrue(
            TOKEN.codehash == GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-0: etched proxy runtime hashes to the known proxy codehash"
        );

        // Step 5: write ratios through the proxy address, read back through both addresses. The
        // second read (through the logic contract's own address) is the control: it proves the
        // write landed in TOKEN's storage via the proxy, not in the logic contract's own storage.
        MockEquityToken(TOKEN).setRatios(1e18, 1e18, 0);
        assertEq(
            MockEquityToken(TOKEN).uiMultiplier(),
            1e18,
            "AS-0: proxy forwards uiMultiplier reads to the logic contract's storage"
        );
        assertEq(
            e.logic.uiMultiplier(),
            0,
            "AS-0: logic contract's own storage is untouched by the proxied write"
        );

        // Step 6: a clean feed -- complete round, description answered, no gas games.
        e.feed = _freshFeed();

        // Step 7: parties non-zero and never blocked; maxFeedAge 0 is the strictest setting, and
        // step 6's followNow default true keeps updatedAt == block.timestamp, so age is 0 too.
        e.ctx = Ctx({
            priceFeed: address(e.feed),
            actor: ACTOR,
            counterparty: COUNTERPARTY,
            expectedImpl: address(e.logic),
            maxFeedAge: 0
        });
    }

    function _freshFeed() internal returns (MockPriceFeed feed) {
        feed = new MockPriceFeed();
        feed.setRound(7, 1e8, T0, T0, 7);
        feed.setDescriptionText("MOCK / USD");
        // followNow stays at its constructor default (true): updatedAt is evaluated at read time
        // as block.timestamp, so it never goes stale merely because vm.warp moved time forward.
    }

    // Re-points e.token at a standalone logic runtime (its own, not the proxy's). Storage at
    // e.token persists through vm.etch, but ratios are rewritten explicitly anyway, as required.
    function _nonProxyToken(Env memory e) internal {
        vm.etch(e.token, address(new MockEquityToken()).code);
        MockEquityToken(e.token).setRatios(1e18, 1e18, 0);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-18: non-proxy token codehash must differ from the known proxy codehash"
        );
    }

    // Second copy of an existing private loader (accepted duplication): readFile -> trim -> parse.
    function _loadProxyRuntime() internal view returns (bytes memory) {
        string memory raw = vm.readFile(FIXTURE_PATH);
        bytes memory rawBytes = bytes(raw);
        uint256 end = rawBytes.length;
        while (end > 0) {
            bytes1 c = rawBytes[end - 1];
            if (c == 0x0a || c == 0x0d || c == 0x20) {
                end--;
            } else {
                break;
            }
        }
        bytes memory trimmed = new bytes(end);
        for (uint256 i = 0; i < end; i++) {
            trimmed[i] = rawBytes[i];
        }
        return vm.parseBytes(string(trimmed));
    }

    function _eval(address token, Ctx memory ctx) internal returns (uint256 bits) {
        (bits, ) = _evalCore(token, ctx, false);
    }

    function _evalRecorded(address token, Ctx memory ctx)
        internal
        returns (uint256 bits, Vm.AccountAccess[] memory diff)
    {
        (bits, diff) = _evalCore(token, ctx, true);
    }

    // The file's only call site for the guard's judgement entry point.
    function _evalCore(address token, Ctx memory ctx, bool record)
        private
        returns (uint256 bits, Vm.AccountAccess[] memory diff)
    {
        if (record) {
            vm.startStateDiffRecording();
        }
        (, bits) = GuardCore.evaluate(token, ctx);
        if (record) {
            diff = vm.stopAndReturnStateDiff();
        }
        _checkBits(bits);
        evalCount += 1;
    }

    // FD-U7G-4 order: AS-25 reserved bits, AS-25 known-mask bits, then both AS-26 directions.
    function _checkBits(uint256 bits) internal pure {
        assertTrue((bits & 0x800080) == 0, "AS-25: bits 7 and 23 are permanently reserved");
        assertTrue((bits & ~GuardBits.KNOWN_MASK) == 0, "AS-25: no unassigned bit may be set");
        assertTrue(
            (bits & (uint256(1) << 255)) == 0 || (bits & 0x17F0000) != 0,
            "AS-26: aggregate bit set implies at least one unreadable bit is set"
        );
        assertTrue(
            (bits & 0x17F0000) == 0 || (bits & (uint256(1) << 255)) != 0,
            "AS-26: an unreadable bit set implies the aggregate bit is set"
        );
    }

    // External self-call target so the checker test below can catch a forged value's revert.
    function checkBitsProbe(uint256 bits) external pure {
        _checkBits(bits);
    }

    function _assertEvalCount(uint256 expected) internal view {
        assertEq(
            evalCount,
            expected,
            "AS-25: evalCount matches the number of evaluations this function performed"
        );
    }

    function _countStatic(Vm.AccountAccess[] memory diff, address account) internal pure returns (uint256 count) {
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && diff[i].account == account) {
                count++;
            }
        }
    }

    function _countStaticAll(Vm.AccountAccess[] memory diff) internal view returns (uint256 count) {
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && diff[i].account != address(vm)) {
                count++;
            }
        }
    }

    function _countStaticCalldata(Vm.AccountAccess[] memory diff, bytes memory callData)
        internal
        pure
        returns (uint256 count)
    {
        bytes32 target = keccak256(callData);
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && keccak256(diff[i].data) == target) {
                count++;
            }
        }
    }
}

contract GatesTest is GatesBaseline {
    function test_AS0_baselineAllClear() public {
        Env memory e = _baseline();
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-0: baseline reasonBits is exactly zero");
        _assertEvalCount(1);
    }

    // FD-U7G-4 C4b: the checker has teeth in both AS-26 directions and both AS-25 clauses.
    function test_AS25_checkerRejectsForgedBits() public {
        // Control: within KNOWN_MASK, aggregate plus one unreadable bit -- must be accepted.
        try this.checkBitsProbe((uint256(1) << 16) | (uint256(1) << 255)) {
            // accepted; nothing further to assert.
        } catch Error(string memory) {
            assertTrue(false, "AS-25: control vector must be accepted, not rejected");
        } catch {
            assertTrue(false, "AS-25: control vector must be accepted without any revert");
        }

        try this.checkBitsProbe(uint256(1) << 7) {
            assertTrue(false, "AS-25: reserved bit 7 must be rejected");
        } catch Error(string memory r) {
            assertTrue(_startsWith(r, AS25_PREFIX), "AS-25: bit 7 rejection has wrong prefix");
        } catch {
            assertTrue(false, "AS-25: bit 7 rejection must surface as Error(string)");
        }

        try this.checkBitsProbe(uint256(1) << 23) {
            assertTrue(false, "AS-25: reserved bit 23 must be rejected");
        } catch Error(string memory r) {
            assertTrue(_startsWith(r, AS25_PREFIX), "AS-25: bit 23 rejection has wrong prefix");
        } catch {
            assertTrue(false, "AS-25: bit 23 rejection must surface as Error(string)");
        }

        try this.checkBitsProbe(uint256(1) << 9) {
            assertTrue(false, "AS-25: unknown bit 9 must be rejected");
        } catch Error(string memory r) {
            assertTrue(_startsWith(r, AS25_PREFIX), "AS-25: bit 9 rejection has wrong prefix");
        } catch {
            assertTrue(false, "AS-25: bit 9 rejection must surface as Error(string)");
        }

        try this.checkBitsProbe(uint256(1) << 255) {
            assertTrue(false, "AS-26: lone aggregate bit must be rejected");
        } catch Error(string memory r) {
            assertTrue(_startsWith(r, AS26_PREFIX), "AS-26: lone aggregate rejection has wrong prefix");
        } catch {
            assertTrue(false, "AS-26: lone aggregate rejection must surface as Error(string)");
        }

        try this.checkBitsProbe(uint256(1) << 16) {
            assertTrue(false, "AS-26: lone unreadable bit must be rejected");
        } catch Error(string memory r) {
            assertTrue(_startsWith(r, AS26_PREFIX), "AS-26: lone unreadable rejection has wrong prefix");
        } catch {
            assertTrue(false, "AS-26: lone unreadable rejection must surface as Error(string)");
        }
    }

    // FD-U7G-3 extra pin, plus the spec's three UNREADABLE_MASK/RESERVED_MASK/KNOWN_MASK pins.
    function test_AS26_constantPins() public {
        assertTrue(
            GuardBits.UNREADABLE_MASK == GuardBits.VIOLATED_MASK << 16,
            "AS-26: UNREADABLE_MASK is VIOLATED_MASK shifted left 16"
        );
        assertTrue(
            GuardBits.RESERVED_MASK == ((uint256(1) << 7) | ((uint256(1) << 7) << 16)),
            "AS-26: RESERVED_MASK is bit 7 and bit 23"
        );
        assertTrue(
            (GuardBits.KNOWN_MASK & GuardBits.RESERVED_MASK) == 0,
            "AS-26: KNOWN_MASK and RESERVED_MASK are disjoint"
        );
        assertTrue(
            GuardBits.KNOWN_MASK == ((uint256(1) << 255) | 0x17F0000 | 0x17F),
            "AS-26: KNOWN_MASK equals the aggregate/unreadable/violated union"
        );
    }

    function _startsWith(string memory s, string memory prefix) private pure returns (bool) {
        bytes memory sb = bytes(s);
        bytes memory pb = bytes(prefix);
        if (sb.length < pb.length) {
            return false;
        }
        for (uint256 i = 0; i < pb.length; i++) {
            if (sb[i] != pb[i]) {
                return false;
            }
        }
        return true;
    }


    function test_AS3_foreignCodehashIsExactlyBit0() public {
        Env memory e = _baseline();
        _nonProxyToken(e);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 0), "AS-3: a foreign codehash yields exactly bit 0");
        _assertEvalCount(1);
    }

    function test_AS4a_neverDeployedToken() public {
        Env memory e = _baseline();
        assertTrue(NEVER_DEPLOYED.codehash == bytes32(0), "AS-4: a never-deployed address must read codehash zero");
        uint256 bits = _eval(NEVER_DEPLOYED, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 16) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 21) | (uint256(1) << 255),
            "AS-4: a never-deployed token yields G0/G2/G3/G5 unreadable"
        );
        _assertEvalCount(1);
    }

    function test_AS4b_eoaToken() public {
        Env memory e = _baseline();
        vm.deal(EOA, 1 ether);
        assertTrue(EOA.codehash == keccak256(new bytes(0)), "AS-4: an EOA address must read the empty-code hash");
        uint256 bits = _eval(EOA, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 16) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 21) | (uint256(1) << 255),
            "AS-4: an EOA token yields G0/G2/G3/G5 unreadable"
        );
        _assertEvalCount(1);
    }

    function test_AS4c_zeroAddressToken() public {
        Env memory e = _baseline();
        uint256 bits = _eval(address(0), e.ctx);
        assertEq(
            bits,
            (uint256(1) << 16) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 21) | (uint256(1) << 255),
            "AS-4: the zero-address token yields G0/G2/G3/G5 unreadable"
        );
        _assertEvalCount(1);
    }

    function test_AS5_1_planePaused() public {
        Env memory e = _baseline();
        e.plane.setPaused(true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 1), "AS-5: control-plane paused yields exactly bit 1");
        _assertEvalCount(1);
    }

    function test_AS5_2_planeNotPaused() public {
        Env memory e = _baseline();
        e.plane.setPaused(false);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-5: control-plane explicitly not paused is a clean arm");
        _assertEvalCount(1);
    }

    function test_AS5_3_planeHasNoCode() public {
        Env memory e = _baseline();
        vm.etch(GuardCore.CONTROL_PLANE, new bytes(0));
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 17) | (uint256(1) << 18) | (uint256(1) << 19) | (uint256(1) << 20) | (uint256(1) << 21)
                | (uint256(1) << 255),
            "AS-5: a codeless control plane yields G1/G2/G3/G4/G5 unreadable"
        );
        _assertEvalCount(1);
    }

    // AS-5: a reverting control-plane paused() read makes the pause gate unreadable rather than
    // giving a false answer, unlike a plane that simply reports itself paused. Every other read
    // on this baseline stays clean, so only the pause gate's unreadable bit (17) and the
    // aggregate bit are set.
    function test_AS5_4_planePausedRevertsUnreadable() public {
        Env memory e = _baseline();
        e.plane.setMutator(MockControlPlane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 17) | (uint256(1) << 255),
            "AS-5: a reverting control-plane paused read yields exactly bit 17 and the aggregate bit"
        );
        _assertEvalCount(1);
    }

    function test_AS6_1_tokenPaused() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setPaused(true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 2), "AS-6: token paused yields exactly bit 2");
        _assertEvalCount(1);
    }

    function test_AS6_2_pausedWord31Bytes() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0)
        );
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 18) | (uint256(1) << 255), "AS-6: a 31-byte paused() reply is unreadable");
        _assertEvalCount(1);
    }

    function test_AS6_3_pausedWord64Bytes() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.LENGTH, 64, bytes32(0), bytes32(0)
        );
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits, (uint256(1) << 18) | (uint256(1) << 255), "AS-6: a 64-byte paused() reply is unreadable too"
        );
        _assertEvalCount(1);
    }

    function test_AS7_1_tokenBlocksActor() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setBlocked(ACTOR, true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 3), "AS-7: a token-side block on the actor yields exactly bit 3");
        _assertEvalCount(1);
    }

    function test_AS7_2_tokenBlocksCounterparty() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setBlocked(COUNTERPARTY, true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 3), "AS-7: a token-side block on the counterparty yields exactly bit 3");
        _assertEvalCount(1);
    }

    function test_AS7_3_planeBlocksActor() public {
        Env memory e = _baseline();
        e.plane.setBlocked(ACTOR, true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 3), "AS-7: a plane-side block on the actor yields exactly bit 3");
        _assertEvalCount(1);
    }

    function test_AS7_4_planeBlocksCounterparty() public {
        Env memory e = _baseline();
        e.plane.setBlocked(COUNTERPARTY, true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 3), "AS-7: a plane-side block on the counterparty yields exactly bit 3");
        _assertEvalCount(1);
    }

    // AS-8 (covers test_AS8_zeroActor, test_AS8_zeroCounterparty, test_AS8_positiveControl).
    // Not a forbidden short-circuit: G3 still sets its bit (bit 19). A zero party field marks G3
    // unreadable before any read is sent, and the two isBlocked reads keyed on that field are
    // never sent; the other field's two reads are still sent. The reason is not "there is nothing
    // to read": isBlocked(address(0)) would return a real answer, but about the wrong subject, so
    // it does not answer the question this bit is about.
    // SD-3: the full-value check alone (bit 19 set, bit 3 clear) cannot show that those reads were
    // not sent. An unreadable G3 discards every word it read, so a mutant that sends isBlocked(0)
    // and gets true still produces the same value. The recorder counts are the real check:
    // isBlocked(0) is sent 0 times, while the non-zero party's isBlocked is sent exactly 2 times
    // (one token read, one plane read) in the same recording, which proves the full-calldata
    // channel works and the zero count is not zero for an unrelated reason.
    function test_AS8_zeroActor() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setBlocked(address(0), true);
        e.plane.setBlocked(address(0), true);
        e.ctx.actor = address(0);
        (uint256 bits, Vm.AccountAccess[] memory diff) = _evalRecorded(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 19) | (uint256(1) << 255),
            "AS-8: a zero actor yields exactly bit 19 plus the aggregate bit 255"
        );
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, address(0))),
            0,
            "AS-8: isBlocked(0) must never be sent"
        );
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, COUNTERPARTY)),
            2,
            "AS-8: isBlocked(counterparty) is sent exactly twice"
        );
        _assertEvalCount(1);
    }

    function test_AS8_zeroCounterparty() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setBlocked(address(0), true);
        e.plane.setBlocked(address(0), true);
        e.ctx.counterparty = address(0);
        (uint256 bits, Vm.AccountAccess[] memory diff) = _evalRecorded(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 19) | (uint256(1) << 255),
            "AS-8: a zero counterparty yields exactly bit 19 plus the aggregate bit 255"
        );
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, address(0))),
            0,
            "AS-8: isBlocked(0) must never be sent"
        );
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, ACTOR)),
            2,
            "AS-8: isBlocked(actor) is sent exactly twice"
        );
        _assertEvalCount(1);
    }

    function test_AS8_positiveControl() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setBlocked(address(0), true);
        e.plane.setBlocked(address(0), true);
        MockEquityToken(e.token).setBlocked(BLOCKED_ACTOR, true);
        e.ctx.actor = BLOCKED_ACTOR;
        (uint256 bits, Vm.AccountAccess[] memory diff) = _evalRecorded(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 3), "AS-8: a real block on a non-zero actor yields exactly bit 3");
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, BLOCKED_ACTOR)),
            2,
            "AS-8: isBlocked(blockedActor) is sent exactly twice"
        );
        assertEq(
            _countStaticCalldata(diff, abi.encodeWithSelector(MockControlPlane.isBlocked.selector, address(0))),
            0,
            "AS-8: isBlocked(0) must never be sent, even with a real block elsewhere"
        );
        _assertEvalCount(1);
    }

    function test_AS9_implEqual() public {
        Env memory e = _baseline();
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-9: implEqual");
        _assertEvalCount(1);
    }

    function test_AS10_implDrift() public {
        // AS-10: the drift target must be a working MockEquityToken logic -- the proxy
        // DELEGATECALLs into it against token storage, so T keeps answering. A codeless
        // drift address would add bits 18/19/21 instead of the single bit 4 this test checks.
        Env memory e = _baseline();
        uint256 b9 = _eval(e.token, e.ctx);
        e.plane.setImplementation(address(new MockEquityToken()));
        uint256 b10 = _eval(e.token, e.ctx);
        assertEq(b9, 0, "AS-10: implEqualBeforeDrift");
        assertEq(b10, (uint256(1) << 4), "AS-10: implDrift");
        assertEq(
            b10 & ~(uint256(1) << 4),
            b9 & ~(uint256(1) << 4),
            "AS-10: onlyBit4Differs"
        );
        _assertEvalCount(2);
    }

    function test_AS11_bit24_forward() public {
        // AS-11: bit 24 has exactly one intentional set path (ctx.priceFeed == address(0));
        // do not "fix" this by touching the feed self-consistency predicate.
        Env memory e = _baseline();
        e.ctx.priceFeed = address(0);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 22) | (uint256(1) << 24) | (uint256(1) << 255),
            "AS-11: bit24Forward"
        );
        _assertEvalCount(1);
    }

    function test_AS11_bit24_reverse() public {
        // Reverse direction: bit 24 must stay 0 in every priceFeed != address(0) corpus below,
        // asserting the converse of test_AS11_bit24_forward.
        Env memory e = _baseline();
        uint256 bits;
        MockPriceFeed feed;

        feed = _freshFeed();
        feed.setFeedMode(1, 0); // FEED_REVERT: the feed never answers
        e.ctx.priceFeed = address(feed);
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255),
            "AS-11: reverseNoAnswer"
        );

        feed = _freshFeed();
        feed.setFeedMode(2, 159); // FEED_SHORT: one byte short of the 160-byte clean encoding
        e.ctx.priceFeed = address(feed);
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255),
            "AS-11: reverseGarbage"
        );

        feed = _freshFeed();
        feed.setFollowNow(false);
        feed.setRound(7, 1e8, T0, T0 + 1, 7);
        e.ctx.priceFeed = address(feed);
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255),
            "AS-11: reverseFutureTimestamp"
        );

        feed = _freshFeed();
        feed.setRound(7, 1e8, T0, T0, 6);
        e.ctx.priceFeed = address(feed);
        bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-11: reverseIncompleteRound");

        _assertEvalCount(4);
    }

    function test_AS12_1_restingStateClean() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setRatios(1e18, 1e18, 0); // explicit: baseline already set this
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-12: restingStateClean");
        _assertEvalCount(1);
    }

    function test_AS12_2_multipliersDiffer() public {
        Env memory e = _baseline();
        uint256 bits;

        MockEquityToken(e.token).setRatios(1e18, 2e18, T0 - 1);
        bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 5), "AS-12: multipliersDifferPastEffective");

        MockEquityToken(e.token).setRatios(1e18, 2e18, T0 + 1);
        bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 5), "AS-12: multipliersDifferFutureEffective");

        _assertEvalCount(2);
    }

    function test_AS12_3_effectiveAtInFuture() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0 + 1);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 5), "AS-12: effectiveAtInFuture");
        _assertEvalCount(1);
    }

    function test_AS12_4_wrongLength() public {
        // Storage at the token address persists across these three sub-cases, so each one
        // resets its selector back to NORMAL before the next is set (§B / §C AS12_4).
        Env memory e = _baseline();
        uint256 bits;

        MockEquityToken(e.token).setMutator(
            MockEquityToken.uiMultiplier.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0)
        );
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 21) | (uint256(1) << 255),
            "AS-12: wrongLengthUiMultiplier"
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.uiMultiplier.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0)
        );

        MockEquityToken(e.token).setMutator(
            MockEquityToken.newUIMultiplier.selector, FixtureMutator.LENGTH, 33, bytes32(0), bytes32(0)
        );
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 21) | (uint256(1) << 255),
            "AS-12: wrongLengthNewUIMultiplier"
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.newUIMultiplier.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0)
        );

        MockEquityToken(e.token).setMutator(
            MockEquityToken.effectiveAt.selector, FixtureMutator.LENGTH, 64, bytes32(0), bytes32(0)
        );
        bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 21) | (uint256(1) << 255),
            "AS-12: wrongLengthEffectiveAt"
        );
        MockEquityToken(e.token).setMutator(
            MockEquityToken.effectiveAt.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0)
        );

        _assertEvalCount(3);
    }

    function test_AS13_a_ageExceedsMax() public {
        Env memory e = _baseline();
        e.ctx.maxFeedAge = 3600;
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 3601, T0 - 3601, 7);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 6), "AS-13: ageExceedsMax");
        _assertEvalCount(1);
    }

    // AS-13 (b) is the §8b "second branch": maxFeedAge == 0 (strictest, not unset) together
    // with updatedAt == block.timestamp (freshest possible reading) must stay clean.
    function test_AS13_b_zeroMaxFreshClean() public {
        Env memory e = _baseline();
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-13: zeroMaxFreshClean");
        _assertEvalCount(1);
    }

    function test_AS13_c_zeroMaxOneSecondStale() public {
        Env memory e = _baseline();
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 6), "AS-13: zeroMaxOneSecondStale");
        _assertEvalCount(1);
    }

    // AS-13b preconditions (shared by (a) below and its sibling (b)), all three required:
    //   (1) block.timestamp (T0) already exceeds maxFeedAge + 1, so the age subtraction never
    //       underflows against either of the two swapped fields;
    //   (2) followNow is off, so updatedAt is the literal stored word rather than a read-time
    //       block.timestamp that would erase the distinction between the two fields;
    //   (3) the round is otherwise complete and non-zero on both arms (G8 stays clean), so the
    //       two arms can only ever disagree on G6.
    function test_AS13b_a_offsetStale() public {
        Env memory e = _baseline();
        e.ctx.maxFeedAge = 3600;
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, /* startedAt */ T0, /* updatedAt */ T0 - 3601, 7);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 6), "AS-13: offsetStale");
        _assertEvalCount(1);
    }

    function test_AS13b_b_offsetSwappedClean() public {
        // The two timestamps swapped relative to (a) above; this is the clean arm, so it is
        // excluded from the AS-37 M-G6 expected-red set even though its sibling (a) is included.
        Env memory e = _baseline();
        e.ctx.maxFeedAge = 3600;
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, /* startedAt */ T0 - 3601, /* updatedAt */ T0, 7);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-13: offsetSwappedClean");
        _assertEvalCount(1);
    }

    function test_AS17_1_oneSecondBeforeEffective() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0 + 100);
        vm.warp(T0 + 99);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 5), "AS-17: oneSecondBeforeEffective");
        _assertEvalCount(1);
    }

    function test_AS17_2_atEffectiveClean() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0 + 100);
        vm.warp(T0 + 100);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-17: atEffectiveClean");
        _assertEvalCount(1);
    }
    function test_AS18_noShortCircuit_allGatesViolated() public {
        Env memory e = _baseline();
        _allGatesViolatedSetup(e);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-18: token must not be the proxy baseline"
        );
        assertTrue(e.ctx.actor != address(0), "AS-18: precondition ctx.actor is non-zero");
        assertTrue(e.ctx.counterparty != address(0), "AS-18: precondition ctx.counterparty is non-zero");
        assertTrue(e.ctx.priceFeed != address(0), "AS-18: precondition ctx.priceFeed is non-zero");
        uint256 bits = _eval(e.token, e.ctx);
        // bit 0 set => bits 1/3/4 are true statements about the canonical control plane, not
        // necessarily about this token's own controller.
        assertEq(
            bits,
            (uint256(1) << 0) | (uint256(1) << 1) | (uint256(1) << 2) | (uint256(1) << 3)
                | (uint256(1) << 4) | (uint256(1) << 5) | (uint256(1) << 6) | (uint256(1) << 8),
            "AS-18: all eight gates violated with no unreadable bit, no short circuit"
        );
        _assertEvalCount(1);
    }

    function test_AS18_noShortCircuit_allGatesUnreadable() public {
        Env memory e = _baseline();
        _nonProxyToken(e);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-18: token must not be the proxy baseline"
        );
        assertTrue(e.ctx.actor != address(0), "AS-18: precondition ctx.actor is non-zero");
        assertTrue(e.ctx.counterparty != address(0), "AS-18: precondition ctx.counterparty is non-zero");
        assertTrue(e.ctx.priceFeed != address(0), "AS-18: precondition ctx.priceFeed is non-zero");
        e.plane.setMutator(
            MockControlPlane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        e.plane.setMutator(
            MockControlPlane.implementation.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0)
        );
        // Non-proxy token, so the plane's implementation() mutator above never touches this token.
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
        uint256 bits = _eval(e.token, e.ctx);
        // G3 unreadable absorbs its violated bit (no bit 3). The feed is non-zero and simply
        // does not answer, so that gives bit 8 (violated), not bit 24 (G8's only unreadable
        // path is a zero feed address).
        assertEq(
            bits,
            (uint256(1) << 0) | (uint256(1) << 8) | (uint256(1) << 17) | (uint256(1) << 18)
                | (uint256(1) << 19) | (uint256(1) << 20) | (uint256(1) << 21) | (uint256(1) << 22)
                | (uint256(1) << 255),
            "AS-18: all readable gates unreadable, aggregate set, bit 24 stays clear"
        );
        _assertEvalCount(1);
    }

    // AS-18: token paused (bit 2) and a stale feed (bit 6) combine with a zero actor; the zero
    // actor field makes the blocked-party gate unreadable (bit 19) rather than violated, so the
    // gate's own violated bit never appears alongside it.
    function test_AS18_combo4_violatedAndUnreadableAcrossGates() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setPaused(true);
        e.ctx.actor = address(0);
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 7);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 2) | (uint256(1) << 6) | (uint256(1) << 19) | (uint256(1) << 255),
            "AS-18: token paused, zero actor and a stale feed yield exactly bits 2, 6, 19 and the aggregate bit"
        );
        _assertEvalCount(1);
    }

    // AS-18: every Ctx field zero at once. The zero actor makes the blocked-party gate unreadable
    // (bit 19), the zero expectedImpl makes the drift gate unreadable with its read still issued
    // (bit 20), and the zero priceFeed answers with no code at all, so both feed-keyed gates come
    // back unreadable too (bit 22 and bit 24).
    function test_AS18_combo5_zeroCtx() public {
        Env memory e = _baseline();
        Ctx memory z;
        uint256 bits = _eval(e.token, z);
        assertEq(
            bits,
            (uint256(1) << 19) | (uint256(1) << 20) | (uint256(1) << 22) | (uint256(1) << 24) | (uint256(1) << 255),
            "AS-18: an all-zero Ctx yields exactly bits 19, 20, 22, 24 and the aggregate bit"
        );
        _assertEvalCount(1);
    }

    // AS-18: the control plane is paused (bit 1) while its blocked-party read separately reverts;
    // the blocked-party gate absorbs that unreadable read rather than reporting a violation, so
    // its violated bit never appears even though the token itself also has a real block set.
    function test_AS18_combo6_g3AbsorbsBesideG1() public {
        Env memory e = _baseline();
        e.plane.setPaused(true);
        e.plane.setMutator(MockControlPlane.isBlocked.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));
        MockEquityToken(e.token).setBlocked(ACTOR, true);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 1) | (uint256(1) << 19) | (uint256(1) << 255),
            "AS-18: plane paused beside an unreadable blocklist yields exactly bits 1, 19 and the aggregate bit"
        );
        _assertEvalCount(1);
    }

    // AS-18: the logic implementation drifts to a fresh contract (bit 4), the multipliers differ
    // with no effectiveAt transition scheduled (bit 5), and the price round is one answer behind
    // its round id (bit 8, an incomplete round) -- three violated bits, no unreadable gate at all.
    function test_AS18_combo7_driftRatioIncompleteRound() public {
        Env memory e = _baseline();
        e.plane.setImplementation(address(new MockEquityToken()));
        MockEquityToken(e.token).setRatios(1e18, 2e18, 0);
        e.feed.setRound(7, 1e8, T0, T0, 6);
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 4) | (uint256(1) << 5) | (uint256(1) << 8),
            "AS-18: implementation drift, a ratio transition and an incomplete round yield exactly bits 4, 5 and 8"
        );
        _assertEvalCount(1);
    }

    function test_AS18b_fanoutCounts() public {
        Env memory e = _baseline();
        _allGatesViolatedSetup(e);
        assertTrue(
            e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-18: token must not be the proxy baseline"
        );
        // Filter (FD-U7G-2): kind == StaticCall && account == X. EXTCODEHASH is excluded
        // structurally by that filter; nothing outside StaticCall is counted. AS-18b must not
        // assert reasonBits.
        (, Vm.AccountAccess[] memory diff) = _evalRecorded(e.token, e.ctx);
        // U2 §6.3 G2 1 + §6.4 G3 2 + §6.6 G5 3
        assertEq(_countStatic(diff, e.token), 6, "AS-18: token fan-out must stay exactly 6");
        // U2 §6.2 G1 1 + §6.4 G3 2 + §6.5 G4 1
        assertEq(
            _countStatic(diff, GuardCore.CONTROL_PLANE),
            4,
            "AS-18: CONTROL_PLANE fan-out must stay exactly 4"
        );
        // U2 §6.7 round 1 + §6.9 description 1
        assertEq(_countStatic(diff, address(e.feed)), 2, "AS-18: feed fan-out must stay exactly 2");
        assertEq(_countStaticAll(diff), 12, "AS-18: total fan-out must stay exactly 12");
        _assertEvalCount(1);
    }

    // Shared setup for AS-18's violated arm and for AS-18b's fan-out count: same assembly,
    // reused per FD-U7G-2 so the two functions cannot silently drift apart.
    function _allGatesViolatedSetup(Env memory e) private {
        _nonProxyToken(e);
        e.plane.setPaused(true);
        MockEquityToken(e.token).setPaused(true);
        MockEquityToken(e.token).setBlocked(ACTOR, true);
        e.plane.setImplementation(address(new MockEquityToken()));
        MockEquityToken(e.token).setRatios(1e18, 2e18, 0);
        e.feed.setFollowNow(false);
        e.feed.setRound(7, 1e8, T0 - 1, T0 - 1, 6);
    }
}
