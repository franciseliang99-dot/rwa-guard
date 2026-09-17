// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Attacks.t.sol -- adversarial test suite for RWA Guard (U7 slice A).
//
// Purpose: this file carries every hostile test case listed in U7 section 7 of the governing
// specification: AS-14, AS-15, AS-16, AS-35, AS-20, AS-21, AS-22, AS-27 (leg one plus its
// positive control, both function names pinned by the design), AS-27b, AS-28(a), AS-28(b),
// AS-28(c), AS-19, AS-24(a), AS-24(b) and AS-34. Each test function pins one attack against the
// deployed and/or library forms of the guard.
//
// Expected-red membership (which of these functions must turn red under which mutation of
// src/GuardCore.sol) lives in the mutation battery script, not in this file.
// Where a comment below names a battery row, the battery script remains authoritative.
//
// Several comments below carry Chinese sentences copied verbatim from the governing
// specification. Those sentences are required to appear exactly as specified, unchanged and
// untranslated, because the specification pins their exact wording as the authoritative
// statement of a structural gap or an invariant; paraphrasing them would silently drop the
// precision the specification requires.

import {Vm} from "./Base.sol";
import {DemoVaultsBaseline} from "./DemoVaults.t.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {Ctx} from "../src/GuardBits.sol";
import {RWAGuard} from "../src/RWAGuard.sol";
import {RWAGuardView} from "../src/RWAGuardView.sol";
import {GuardedVault} from "../src/demo/GuardedVault.sol";
import {MockControlPlane, FixtureMutator} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

interface IAtPlane {
    function paused() external view returns (bool);
    function isBlocked(address who) external view returns (bool);
    function implementation() external view returns (address);
}
interface IAtEquity {
    function uiMultiplier() external view returns (uint256);
    function newUIMultiplier() external view returns (uint256);
    function effectiveAt() external view returns (uint256);
}
interface IAtFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function description() external view returns (string memory);
}
interface IAtErc20 {
    function balanceOf(address who) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract AttacksAlwaysFreshFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, type(int256).max, block.timestamp, block.timestamp, 1);
    }

    function description() external pure returns (string memory) {
        return "ATTACKER / USD";
    }
}

contract AttacksLyingLogic {
    function paused() external pure returns (bool) {
        return false;
    }

    function isBlocked(address) external pure returns (bool) {
        return false;
    }

    function uiMultiplier() external pure returns (uint256) {
        return 1e18;
    }

    function newUIMultiplier() external pure returns (uint256) {
        return 1e18;
    }

    function effectiveAt() external pure returns (uint256) {
        return 0;
    }
}

contract AttacksLengthLiarFeed {
    // 96 bytes declaring a 33-byte string: offset 0x20, length 33, one content word of 0.
    function description() external pure returns (uint256, uint256, uint256) {
        return (0x20, 33, 0);
    }
}

contract AttacksNaiveDescriptionReader {
    // Copies the whole returndata on purpose -- this is the control that shows the metric
    // used elsewhere in this file (guard overhead) actually sees a naive full copy.
    function readAll(address feed) external view returns (uint256 size) {
        (bool ok, bytes memory ret) = feed.staticcall(abi.encodeWithSignature("description()"));
        size = ok ? ret.length : 0;
    }
}

abstract contract AttacksBase is DemoVaultsBaseline {
    address internal constant AT_CLONE = address(uint160(uint256(keccak256("rwa-guard.u7a.clone"))));
    uint256 internal constant AT_GB_BUDGET = 16_000_000;
    uint256 internal constant AT_GB_THRESHOLD = 11_000_000;
    uint256 internal constant AT_GB_BOMB_BYTES = 2_097_152;
    uint256 internal constant AT_GB_BAND_MARGIN = 1_000_000;
    uint256 internal constant AT_GB_ENTRY_SLACK = 50_000;
    uint256 internal constant AT_BOMB_BYTES = 10_000_000;
    uint256 internal constant AT_NAIVE_BOMB_BYTES = 1_048_576;
    uint256 internal constant AT_BOMB_BUDGET = 400_000_000;
    uint256 internal constant AT_BOMB_TEST_GAS_FLOOR = 450_000_000;
    uint256 internal constant AT_BOMB_CALLEE_MIN = 100_000_000;
    uint256 internal constant AT_OVERHEAD_SLACK = 100_000;

    // Builds the exact calldata RWAGuardView.isSafeToTrade expects, from the same encoder the
    // deployed form itself would be called with.
    function _at_viewCalldata(address token, Ctx memory ctx) internal pure returns (bytes memory) {
        return abi.encodeCall(RWAGuardView.isSafeToTrade, (token, ctx));
    }

    // Raw staticcall against the deployed view. Callers must check ret.length == 64 themselves
    // before decoding -- this helper never decodes, so a malformed reply is never interpreted.
    function _at_viewRaw(address view_, bytes memory data, uint256 gasLimit)
        internal
        view
        returns (bool success, bytes memory ret)
    {
        (success, ret) = view_.staticcall{gas: gasLimit}(data);
    }

    // Re-points e.token at a standalone (non-proxy) logic runtime, so a counted address is not
    // shared between the token and the control plane's own implementation. The caller-supplied
    // message lets each call site name the assertion it is standing in for.
    function _at_nonProxyToken(Env memory e, string memory reason) internal {
        vm.etch(e.token, address(new MockEquityToken()).code);
        MockEquityToken(e.token).setRatios(1e18, 1e18, 0);
        assertTrue(e.token.codehash != GuardCore.KNOWN_PROXY_CODEHASH, reason);
    }

    // Swaps the control plane's implementation for a hostile logic contract that answers every
    // read cleanly, regardless of the token's own storage. No assertions here: each call site
    // decides what pausedBefore/pausedAfter mean for its own attack.
    function _at_liarSwap(Env memory e)
        internal
        returns (address liar, bool pausedBefore, bool pausedAfter)
    {
        MockEquityToken(e.token).setPaused(true);
        pausedBefore = MockEquityToken(e.token).paused();
        liar = address(new AttacksLyingLogic());
        e.plane.setImplementation(liar);
        pausedAfter = MockEquityToken(e.token).paused();
    }

    // The one function in this file allowed to use assembly (C2): a bounded-gas staticcall that
    // never copies returndata into memory, so measuring gas against a returndata bomb never
    // itself pays for the bomb's memory expansion.
    function _at_gasUsed(address target, bytes memory data, uint256 budget)
        internal
        view
        returns (bool success, uint256 used)
    {
        assembly ("memory-safe") {
            let g0 := gas()
            success := staticcall(budget, target, add(data, 0x20), mload(data), 0, 0)
            used := sub(g0, gas())
        }
    }

    // Raw read of latestRoundData(), decoded only when the reply is the full five-word (160
    // byte) shape; a short or oversized reply leaves roundId/answeredInRound at 0.
    function _at_rawRound(address feed, uint256 gasLimit)
        internal
        view
        returns (bool success, uint256 roundId, uint256 answeredInRound)
    {
        bytes memory data = abi.encodeWithSelector(IAtFeed.latestRoundData.selector);
        (bool ok, bytes memory ret) = feed.staticcall{gas: gasLimit}(data);
        success = ok;
        if (ret.length == 160) {
            (uint256 w0, , , , uint256 w4) = abi.decode(ret, (uint256, uint256, uint256, uint256, uint256));
            roundId = w0;
            answeredInRound = w4;
        }
    }

    // High-level staticcall that copies the full returndata -- NEVER call this against a bomb
    // description(): the copy cost is exactly the thing this helper does not bound. word0/word1
    // are the raw offset and length words, decoded only when there are at least 64 bytes to read.
    function _at_rawDescriptionHead(address feed)
        internal
        view
        returns (bool success, uint256 size, uint256 word0, uint256 word1)
    {
        (bool ok, bytes memory ret) = feed.staticcall(abi.encodeWithSelector(IAtFeed.description.selector));
        success = ok;
        size = ret.length;
        if (size >= 64) {
            (word0, word1) = abi.decode(ret, (uint256, uint256));
        }
    }

    // External self-call target so a Panic inside GuardCore._answersDescription surfaces as
    // success == false at the caller, instead of unwinding the whole test.
    function atAnswersDescriptionProbe(address feed) external view returns (bool answered) {
        return GuardCore._answersDescription(feed);
    }

    function _at_probeAnswers(address feed) internal view returns (bool callOk, bool answered) {
        (bool ok, bytes memory ret) =
            address(this).staticcall(abi.encodeCall(this.atAnswersDescriptionProbe, (feed)));
        callOk = ok;
        if (ok && ret.length == 32) {
            answered = abi.decode(ret, (bool));
        }
    }

    function _at_countFeedSelector(Vm.AccountAccess[] memory diff, address feed, bytes4 selector)
        internal
        pure
        returns (uint256 count)
    {
        for (uint256 i = 0; i < diff.length; i++) {
            if (
                diff[i].kind == Vm.AccountAccessKind.StaticCall
                    && diff[i].account == feed
                    && diff[i].data.length >= 4
                    && bytes4(diff[i].data) == selector
            ) {
                count++;
            }
        }
    }

    function _at_feedEntriesAreFourBytes(Vm.AccountAccess[] memory diff, address feed)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && diff[i].account == feed) {
                if (diff[i].data.length != 4) {
                    return false;
                }
            }
        }
        return true;
    }
}

contract AttacksExposureTest is AttacksBase {
    // TS-1 (AS-14): the guard gives no protection against a fresh, positive, well-formed
    // attacker feed -- pinning the correct feed address is the integrator's own obligation,
    // not something GuardCore can verify from inside. Control (cited, not called here):
    // test_AS27_roundConsistency_positiveControl shows the guard does catch an inconsistent
    // round on a feed whose own round is incomplete, answeredInRound < roundId
    // (G8 fires on that path).
    function test_AS14_exposure_attackerFreshFeedPasses() public {
        Env memory e = _baseline();
        AttacksAlwaysFreshFeed feed = new AttacksAlwaysFreshFeed();
        e.ctx.priceFeed = address(feed);
        {
            (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) =
                IAtFeed(address(feed)).latestRoundData();
            assertTrue(answer == type(int256).max, "AS-14: the attacker feed answers the maximum int256");
            assertEq(updatedAt, block.timestamp, "AS-14: the attacker feed updatedAt equals block timestamp");
            assertTrue(answeredInRound >= roundId, "AS-14: the attacker feed answeredInRound is not behind roundId");
            assertTrue(
                address(feed).codehash != address(e.feed).codehash,
                "AS-14: the attacker feed code differs from the honest fixture feed code"
            );
        }
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-14: the library form evaluates the attacker feed to zero reasonBits");
        RWAGuardView v = new RWAGuardView();
        (bool ok, uint256 bitsView) = v.isSafeToTrade(e.token, e.ctx);
        assertTrue(ok, "AS-14: the deployed form reports the attacker feed as safe to trade");
        assertEq(bitsView, 0, "AS-14: the deployed form evaluates the attacker feed to zero reasonBits");
        _assertEvalCount(1);
    }

    // TS-2 (AS-15): the lying logic answers every read cleanly, so this test carries no
    // 18/19/21 contamination -- it is the system's only observation of the implementation-
    // drift power (G4) in isolation.
    function test_AS15_implDriftToLyingLogicDetected() public {
        Env memory e = _baseline();
        (address liar, bool pausedBefore, bool pausedAfter) = _at_liarSwap(e);
        assertTrue(pausedBefore, "AS-15: the token reports paused before the implementation is swapped");
        assertFalse(pausedAfter, "AS-15: the lying logic reports not paused after the swap");
        assertEq(e.plane.implementation(), liar, "AS-15: the control plane now points at the lying logic");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 4), "AS-15: implementation drift sets exactly bit 4");
        _assertEvalCount(1);
    }

    // TS-3 (AS-16): exposure, not protection. Pinning expectedImpl to the drifted logic makes
    // G4 pass even though the token's own storage still records paused true -- the two identity
    // inputs fail in opposite directions. Control (cited, not called here):
    // test_AS15_implDriftToLyingLogicDetected pins the opposite outcome: expectedImpl stays the
    // honest logic, so the drift to the lying logic is caught as bit 4.
    function test_AS16_exposure_expectedImplSetToDriftedLogicPasses() public {
        Env memory e = _baseline();
        (address liar, , bool pausedAfter) = _at_liarSwap(e);
        e.ctx.expectedImpl = liar;
        assertTrue(
            vm.load(e.token, bytes32(uint256(0))) != bytes32(0),
            "AS-16: the token's own storage still records paused true"
        );
        assertFalse(pausedAfter, "AS-16: the lying logic itself answers not paused");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, 0, "AS-16: expectedImpl pinned to the drifted logic evaluates to zero reasonBits");
        _assertEvalCount(1);
    }

    // TS-4 (AS-35): this test asserts that a hole is open -- any address etched with the exact
    // proxy runtime passes the codehash gate, whichever address it happens to be.
    // 本系统问的是「这个地址上的代码是不是那份代理」,不是「它是不是那五个之一」;集成方的 `token` 参数本来就该是它自己 `immutable` 钉死的地址,而不是用户输入。
    // Controls (cited, not called here): test_AS21_implWordDirtyHighBytesUnreadable (bit 0,
    // foreign codehash) and test_AS15_implDriftToLyingLogicDetected (bit 4, implementation drift).
    function test_AS35_exposure_cloneOfProxyPasses() public {
        Env memory e = _baseline();
        vm.etch(AT_CLONE, _loadProxyRuntime());
        assertTrue(AT_CLONE != TOKEN, "AS-35: the clone address differs from the baseline proxy address");
        assertTrue(
            AT_CLONE.codehash == GuardCore.KNOWN_PROXY_CODEHASH,
            "AS-35: the etched clone hashes to the known proxy codehash"
        );
        MockEquityToken(AT_CLONE).setRatios(1e18, 1e18, 0);
        assertEq(
            MockEquityToken(AT_CLONE).uiMultiplier(),
            1e18,
            "AS-35: the clone forwards uiMultiplier reads through its own storage"
        );
        uint256 bits = _eval(AT_CLONE, e.ctx);
        assertEq(bits, 0, "AS-35: the clone of the proxy evaluates to zero reasonBits");
        _assertEvalCount(1);
    }

    // TS-5 (AS-20): a raw word equal to two must be read as bit 2 (paused), not misread as a
    // bool-decode failure.
    function test_AS20_pausedWordTwoIsPaused() public {
        Env memory e = _baseline();
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.RAW_WORD, 0, bytes32(uint256(2)), bytes32(0)
        );
        (bool ok, bytes memory ret) = e.token.staticcall(abi.encodeWithSelector(IAtPlane.paused.selector));
        assertTrue(ok, "AS-20: the raw staticcall to the mutated paused selector succeeds");
        assertEq(ret.length, 32, "AS-20: the raw paused reply is exactly one word");
        assertEq(abi.decode(ret, (uint256)), 2, "AS-20: the raw paused reply is exactly the word two");
        uint256 bitsDirty = _eval(e.token, e.ctx);
        assertEq(bitsDirty, (uint256(1) << 2), "AS-20: a paused word of two sets exactly bit 2");
        MockEquityToken(e.token).setMutator(
            MockEquityToken.paused.selector, FixtureMutator.RAW_WORD, 0, bytes32(0), bytes32(0)
        );
        uint256 bitsClean = _eval(e.token, e.ctx);
        assertEq(bitsClean, 0, "AS-20: resetting the paused word to zero clears bit 2");
        _assertEvalCount(2);
    }

    // TS-6 (AS-21): this exercises the non-proxy token, whose six reads are answered by
    // standalone code and never consult the plane. RAW_WORD on implementation() gives a full
    // 32-byte reply, so readable holds and only the dirty high bytes set bit 20.
    function test_AS21_implWordDirtyHighBytesUnreadable() public {
        Env memory e = _baseline();
        _at_nonProxyToken(e, "AS-21: the non-proxy token codehash differs from the known proxy codehash");
        bytes32 dirtyWord =
            bytes32((uint256(1) << 160) | (uint256(1) << 255) | uint256(uint160(address(e.logic))));
        e.plane.setMutator(MockControlPlane.implementation.selector, FixtureMutator.RAW_WORD, 0, dirtyWord, bytes32(0));
        {
            (bool ok, bytes memory ret) =
                GuardCore.CONTROL_PLANE.staticcall(abi.encodeWithSelector(IAtPlane.implementation.selector));
            assertTrue(ok, "AS-21: the raw staticcall to the dirtied implementation selector succeeds");
            assertEq(ret.length, 32, "AS-21: the raw implementation reply is exactly one word");
            uint256 word = abi.decode(ret, (uint256));
            assertTrue(word >> 160 != 0, "AS-21: the raw implementation reply has nonzero high bytes");
            assertEq(
                address(uint160(word)), address(e.logic), "AS-21: the low twenty bytes still equal the honest logic"
            );
        }
        uint256 bitsDirty = _eval(e.token, e.ctx);
        assertEq(
            bitsDirty,
            (uint256(1) << 0) | (uint256(1) << 20) | (uint256(1) << 255),
            "AS-21: dirty high bytes on implementation set bits zero, twenty and two five five"
        );
        e.plane.setMutator(
            MockControlPlane.implementation.selector,
            FixtureMutator.RAW_WORD,
            0,
            bytes32(uint256(uint160(address(e.logic)))),
            bytes32(0)
        );
        uint256 bitsClean = _eval(e.token, e.ctx);
        assertEq(bitsClean, (uint256(1) << 0), "AS-21: a clean implementation word clears bits twenty and two five five");
        _assertEvalCount(2);
    }

    // TS-7 (AS-22): effectiveAt must be compared at full uint256 width; a uint64 downcast would
    // collapse a value above two to the sixty-fourth power back onto T0 and silently call the
    // transition current.
    function test_AS22_effectiveAtAbove2Pow64IsFuture() public {
        Env memory e = _baseline();
        uint256 farFuture = (uint256(1) << 64) + T0;
        MockEquityToken(e.token).setRatios(1e18, 1e18, farFuture);
        assertEq(
            IAtEquity(e.token).effectiveAt(), farFuture, "AS-22: effectiveAt reads back the full value above the bound"
        );
        assertEq(
            uint256(uint64(IAtEquity(e.token).effectiveAt())),
            T0,
            "AS-22: a uint64 downcast of the same value collapses onto T0"
        );
        uint256 bitsFuture = _eval(e.token, e.ctx);
        assertEq(bitsFuture, (uint256(1) << 5), "AS-22: an effectiveAt above the bound sets exactly bit 5");
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0);
        uint256 bitsClean = _eval(e.token, e.ctx);
        assertEq(bitsClean, 0, "AS-22: resetting effectiveAt to T0 clears bit 5");
        _assertEvalCount(2);
    }

    // A far-future effectiveAt whose value sets the top bit (bit 255) must still compare above
    // block.timestamp at full uint256 width: a uint128 downcast collapses it back onto T0, and
    // reading the same word as a signed int256 reports it as negative, so only a full-width
    // unsigned compare correctly keeps this transition in the future.
    function test_AS22_effectiveAtAbove2Pow255IsFuture() public {
        Env memory e = _baseline();
        uint256 eff = (uint256(1) << 255) + T0;
        MockEquityToken(e.token).setRatios(1e18, 1e18, eff);
        assertEq(
            IAtEquity(e.token).effectiveAt(), eff, "AS-22: effectiveAt reads back the full value with the top bit set"
        );
        assertEq(
            uint256(uint128(IAtEquity(e.token).effectiveAt())),
            T0,
            "AS-22: a uint128 downcast of the same value collapses onto T0"
        );
        assertTrue(
            int256(IAtEquity(e.token).effectiveAt()) < 0, "AS-22: the same value read as signed is negative"
        );
        uint256 bitsFuture = _eval(e.token, e.ctx);
        assertEq(bitsFuture, (uint256(1) << 5), "AS-22: an effectiveAt with the top bit set sets exactly bit 5");
        MockEquityToken(e.token).setRatios(1e18, 1e18, T0);
        uint256 bitsClean = _eval(e.token, e.ctx);
        assertEq(bitsClean, 0, "AS-22: resetting effectiveAt to T0 clears bit 5");
        _assertEvalCount(2);
    }

    // TS-8 (AS-34): two independent mechanisms are compared for the eight selectors GuardCore
    // reads -- the compiler-derived interface .selector (computed from the declared name and
    // parameter types) and GuardCore's own hand-typed signature string fed through keccak256.
    // Agreement is not a tautology: the two hand-typed texts (this file's and GuardCore's) could
    // each independently contain a typo. GuardCore.SEL_* is a third, independently hand-typed
    // string and is checked against the same interface value, so both-sides-keccak is avoided.
    // latestRoundData() and description() have no recorded hex literal anywhere in this file;
    // that gap is left open on purpose (KG-U7A-7). KG-U3-10: none of the eight collides with
    // balanceOf/totalSupply, which bounds the ERC-20 half together with AS-18b's fan-out of
    // twelve (KG-U7A-6); no behavioural forced-value ERC-20 test is written here.
    function test_AS34_selectorsTwoMechanisms() public pure {
        bytes4[8] memory sels = _at34_selectors();
        _at34_checkAgreement(sels);
        _at34_checkHex(sels);
        _at34_noErc20Collision(sels, IAtErc20.balanceOf.selector, IAtErc20.totalSupply.selector);
        _at34_pairwiseDistinct(sels);
    }

    function _at34_selectors() private pure returns (bytes4[8] memory sels) {
        sels[0] = IAtPlane.paused.selector;
        sels[1] = IAtPlane.isBlocked.selector;
        sels[2] = IAtPlane.implementation.selector;
        sels[3] = IAtEquity.uiMultiplier.selector;
        sels[4] = IAtEquity.newUIMultiplier.selector;
        sels[5] = IAtEquity.effectiveAt.selector;
        sels[6] = IAtFeed.latestRoundData.selector;
        sels[7] = IAtFeed.description.selector;
    }

    function _at34_checkAgreement(bytes4[8] memory sels) private pure {
        assertEq(
            uint256(uint32(sels[0])),
            uint256(uint32(bytes4(keccak256(bytes("paused()"))))),
            "AS-34: the paused selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[0])),
            uint256(uint32(GuardCore.SEL_PAUSED)),
            "AS-34: the paused selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[1])),
            uint256(uint32(bytes4(keccak256(bytes("isBlocked(address)"))))),
            "AS-34: the isBlocked selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[1])),
            uint256(uint32(GuardCore.SEL_IS_BLOCKED)),
            "AS-34: the isBlocked selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[2])),
            uint256(uint32(bytes4(keccak256(bytes("implementation()"))))),
            "AS-34: the implementation selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[2])),
            uint256(uint32(GuardCore.SEL_IMPLEMENTATION)),
            "AS-34: the implementation selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[3])),
            uint256(uint32(bytes4(keccak256(bytes("uiMultiplier()"))))),
            "AS-34: the uiMultiplier selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[3])),
            uint256(uint32(GuardCore.SEL_UI_MULTIPLIER)),
            "AS-34: the uiMultiplier selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[4])),
            uint256(uint32(bytes4(keccak256(bytes("newUIMultiplier()"))))),
            "AS-34: the newUIMultiplier selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[4])),
            uint256(uint32(GuardCore.SEL_NEW_UI_MULTIPLIER)),
            "AS-34: the newUIMultiplier selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[5])),
            uint256(uint32(bytes4(keccak256(bytes("effectiveAt()"))))),
            "AS-34: the effectiveAt selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[5])),
            uint256(uint32(GuardCore.SEL_EFFECTIVE_AT)),
            "AS-34: the effectiveAt selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[6])),
            uint256(uint32(bytes4(keccak256(bytes("latestRoundData()"))))),
            "AS-34: the latestRoundData selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[6])),
            uint256(uint32(GuardCore.SEL_LATEST_ROUND_DATA)),
            "AS-34: the latestRoundData selector matches GuardCore's own selector constant"
        );
        assertEq(
            uint256(uint32(sels[7])),
            uint256(uint32(bytes4(keccak256(bytes("description()"))))),
            "AS-34: the description selector matches its keccak derivation"
        );
        assertEq(
            uint256(uint32(sels[7])),
            uint256(uint32(GuardCore.SEL_DESCRIPTION)),
            "AS-34: the description selector matches GuardCore's own selector constant"
        );
    }

    function _at34_checkHex(bytes4[8] memory sels) private pure {
        assertEq(
            uint256(uint32(sels[0])),
            uint256(uint32(bytes4(0x5c975abb))),
            "AS-34: the recorded hex literal for paused matches its interface selector"
        );
        assertEq(
            uint256(uint32(sels[1])),
            uint256(uint32(bytes4(0xfbac3951))),
            "AS-34: the recorded hex literal for isBlocked matches its interface selector"
        );
        assertEq(
            uint256(uint32(sels[2])),
            uint256(uint32(bytes4(0x5c60da1b))),
            "AS-34: the recorded hex literal for implementation matches its interface selector"
        );
        assertEq(
            uint256(uint32(sels[3])),
            uint256(uint32(bytes4(0xa60bf13d))),
            "AS-34: the recorded hex literal for uiMultiplier matches its interface selector"
        );
        assertEq(
            uint256(uint32(sels[4])),
            uint256(uint32(bytes4(0xdc767007))),
            "AS-34: the recorded hex literal for newUIMultiplier matches its interface selector"
        );
        assertEq(
            uint256(uint32(sels[5])),
            uint256(uint32(bytes4(0x97a4064f))),
            "AS-34: the recorded hex literal for effectiveAt matches its interface selector"
        );
        // No hex literal is recorded anywhere in this file for latestRoundData() or
        // description(); only the two mechanisms above (interface selector and
        // GuardCore.SEL_*) are compared for those two selectors.
    }

    function _at34_noErc20Collision(bytes4[8] memory sels, bytes4 balanceOfSel, bytes4 totalSupplySel)
        private
        pure
    {
        for (uint256 i = 0; i < sels.length; i++) {
            assertTrue(
                sels[i] != balanceOfSel, "AS-34: none of the eight selectors collides with balanceOf"
            );
            assertTrue(
                sels[i] != totalSupplySel, "AS-34: none of the eight selectors collides with totalSupply"
            );
        }
    }

    function _at34_pairwiseDistinct(bytes4[8] memory sels) private pure {
        for (uint256 i = 0; i < sels.length; i++) {
            for (uint256 j = i + 1; j < sels.length; j++) {
                assertTrue(sels[i] != sels[j], "AS-34: the eight selectors are pairwise distinct");
            }
        }
    }
}

contract AttacksFeedTest is AttacksBase {
    // Feed-read count and consistency, the description adversaries, and the R-19 pin (TS-9..TS-15).

    function test_AS27_roundConsistency_gasBand() public {
        // 它是一条对 bit 8 的否定断言,因此当 G8 的累加被删掉时它恒绿(见 §8b 的 M-G8 行)——「读了两次」与「G8 静默死掉」它一条都分不出。这正是下一条存在的理由,不是冗余。
        // English residual: this leg alone is blind to a re-read placed before description() and
        // to G8's own accumulation dying; test_AS27_roundConsistency_positiveControl below is the
        // positive arm that supplies the discrimination this leg cannot.
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        RWAGuardView v = new RWAGuardView();
        feed.setFeedMode(4, 0); // FEED_GAS_BAND
        feed.setGasBand(AT_GB_THRESHOLD, 8, 7);
        feed.setDescMode(5, AT_GB_BOMB_BYTES); // DESC_BOMB
        {
            (uint8 feedMode, uint8 descMode, uint256 modeArg, , uint256 gasThreshold) = feed.readModes();
            assertEq(uint256(feedMode), 4, "AS-27: the gas-band feed mode reads back as 4");
            assertEq(uint256(descMode), 5, "AS-27: the bomb description mode reads back as 5");
            assertEq(modeArg, AT_GB_BOMB_BYTES, "AS-27: the bomb description length reads back unchanged");
            assertEq(gasThreshold, AT_GB_THRESHOLD, "AS-27: the gas-band threshold reads back unchanged");
        }
        {
            (bool okHi, uint256 ridHi, uint256 airHi) =
                _at_rawRound(address(feed), AT_GB_THRESHOLD + AT_GB_BAND_MARGIN);
            assertTrue(okHi, "AS-27: the above-threshold raw round read succeeds");
            assertEq(ridHi, 7, "AS-27: the above-threshold raw round id is the clean round");
            assertEq(airHi, 7, "AS-27: the above-threshold raw answeredInRound is the clean round");
        }
        {
            (bool okLo, uint256 ridLo, uint256 airLo) =
                _at_rawRound(address(feed), AT_GB_THRESHOLD - AT_GB_BAND_MARGIN);
            assertTrue(okLo, "AS-27: the below-threshold raw round read succeeds");
            assertEq(ridLo, 8, "AS-27: the below-threshold raw round id is the alternate round");
            assertEq(airLo, 7, "AS-27: the below-threshold raw answeredInRound is the alternate answeredInRound");
        }
        {
            (bool okBomb, uint256 dBomb) =
                _at_gasUsed(address(feed), abi.encodeWithSelector(IAtFeed.description.selector), AT_BOMB_BUDGET);
            assertTrue(okBomb, "AS-27: the calibration bomb description call succeeds");
            assertTrue(
                AT_GB_BUDGET + AT_GB_ENTRY_SLACK < AT_GB_THRESHOLD + dBomb,
                "AS-27: the bomb gas gap clears the budget plus entry slack over the threshold"
            );
        }
        {
            Ctx memory ctxZero = Ctx({
                priceFeed: address(0),
                actor: e.ctx.actor,
                counterparty: e.ctx.counterparty,
                expectedImpl: e.ctx.expectedImpl,
                maxFeedAge: e.ctx.maxFeedAge
            });
            (bool okUpper, uint256 oUpper) =
                _at_gasUsed(address(v), _at_viewCalldata(e.token, ctxZero), AT_GB_BUDGET);
            assertTrue(okUpper, "AS-27: the zero-feed calibration judgement succeeds");
            assertTrue(oUpper < AT_GB_BUDGET, "AS-27: the zero-feed judgement overhead is below the budget");
            assertTrue(
                (AT_GB_BUDGET - oUpper) * 63 / 64 >= AT_GB_THRESHOLD + AT_GB_ENTRY_SLACK,
                "AS-27: the forwarded gas after overhead still clears the threshold plus entry slack"
            );
        }
        Ctx memory ctx = Ctx({
            priceFeed: address(feed),
            actor: e.ctx.actor,
            counterparty: e.ctx.counterparty,
            expectedImpl: e.ctx.expectedImpl,
            maxFeedAge: e.ctx.maxFeedAge
        });
        (bool okMain, bytes memory retMain) = _at_viewRaw(address(v), _at_viewCalldata(e.token, ctx), AT_GB_BUDGET);
        assertTrue(okMain, "AS-27: the gas-bounded view call succeeds");
        assertEq(retMain.length, 64, "AS-27: the gas-bounded view reply is exactly 64 bytes");
        (bool ok, uint256 bits) = abi.decode(retMain, (bool, uint256));
        assertTrue(ok, "AS-27: the gas-bounded view judgement passes");
        assertEq(bits, 0, "AS-27: the gas-bounded view reasonBits are 0");
    }

    function test_AS27_roundConsistency_positiveControl() public {
        // This is the positive arm test_AS27_roundConsistency_gasBand needs (FD-U7A-5); it lands
        // in the M-G8 row, not M-G2/M-G3/M-G5.
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setRound(7, 1e8, T0, T0, 6);
        e.ctx.priceFeed = address(feed);
        (uint80 roundId, , , , uint80 answeredInRound) = IAtFeed(address(feed)).latestRoundData();
        assertTrue(answeredInRound < roundId, "AS-27: the direct read shows an incomplete round");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-27: the incomplete round sets bit 8");
        _assertEvalCount(1);
    }

    function test_AS27b_feedReadExactlyTwice() public {
        // AS-39(b) 未通过时,本条按名降级为只断言「恰好 2 次」
        // English residual: the selector-split assertions below stand only while
        // test_AS39b_stateDiffFieldsDecodable (Fixtures) passes; if that test is red this test
        // is degraded by name to the bare "exactly 2" count only (KG-U7A-9), never by editing
        // its expectations.
        Env memory e = _baseline();
        _at_nonProxyToken(e, "AS-27: the non-proxy token codehash must differ from the known proxy codehash");
        (, Vm.AccountAccess[] memory diff) = _evalRecorded(e.token, e.ctx);
        assertEq(_countStatic(diff, address(e.feed)), 2, "AS-27: the feed receives exactly two static reads");
        assertTrue(
            _at_feedEntriesAreFourBytes(diff, address(e.feed)),
            "AS-27: every counted feed entry carries a four-byte selector only"
        );
        assertEq(
            _at_countFeedSelector(diff, address(e.feed), IAtFeed.latestRoundData.selector),
            1,
            "AS-27: latestRoundData is read exactly once"
        );
        assertEq(
            _at_countFeedSelector(diff, address(e.feed), IAtFeed.description.selector),
            1,
            "AS-27: description is read exactly once"
        );
        vm.startStateDiffRecording();
        _eval(e.token, e.ctx);
        e.feed.latestRoundData();
        Vm.AccountAccess[] memory diff2 = vm.stopAndReturnStateDiff();
        assertEq(_countStatic(diff2, address(e.feed)), 3, "AS-27: the control window shows three static reads");
        assertEq(
            _at_countFeedSelector(diff2, address(e.feed), IAtFeed.latestRoundData.selector),
            2,
            "AS-27: the control window reads latestRoundData twice"
        );
        assertEq(
            _at_countFeedSelector(diff2, address(e.feed), IAtFeed.description.selector),
            1,
            "AS-27: the control window still reads description once"
        );
        _assertEvalCount(2);
    }

    function test_AS28_a_hugeDescriptionLengthIsIncoherent() public {
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setDescMode(4, 0); // DESC_HUGE_LEN
        e.ctx.priceFeed = address(feed);
        {
            (bool okRaw, uint256 size, uint256 word0, uint256 word1) = _at_rawDescriptionHead(address(feed));
            assertTrue(okRaw, "AS-28: the raw huge-length description read succeeds");
            assertEq(size, 64, "AS-28: the raw huge-length description reply is exactly 64 bytes");
            assertEq(word0, 0x20, "AS-28: the raw huge-length description offset word is 0x20");
            assertEq(
                word1, type(uint256).max, "AS-28: the raw huge-length description length word is the maximum uint256"
            );
        }
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-28: the huge description length sets bit 8");
        RWAGuardView v = new RWAGuardView();
        {
            (bool okView, bytes memory ret) = _at_viewRaw(address(v), _at_viewCalldata(e.token, e.ctx), GAS_BOUND);
            assertTrue(okView, "AS-28: the deployed-form view call does not revert on the huge description length");
            assertEq(ret.length, 64, "AS-28: the deployed-form view reply is exactly 64 bytes");
            (bool ok, uint256 bitsView) = abi.decode(ret, (bool, uint256));
            assertFalse(ok, "AS-28: the deployed-form view verdict is false for the huge description length");
            assertEq(bitsView, (uint256(1) << 8), "AS-28: the deployed-form view reasonBits match bit 8");
        }
        _assertEvalCount(1);
    }

    function test_AS28_b_futureUpdatedAtSetsBit8AndBit22() public {
        // (b) 那两位属于不同的闸,同时置位完全合法、且是最诚实的描述 —— 「逐闸互斥」说的是「对每道闸 n,它自己的 violated 位与它自己的 unreadable 位互斥」。
        // English residual: GuardBits decoding clause 5 is exactly the future-updatedAt shape
        // this test measures directly -- G8's incoherent round and G6's stale answer are two
        // different gates, and both may legally fire together.
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setFollowNow(false);
        feed.setRound(7, 1e8, T0, T0 + 1, 7);
        e.ctx.priceFeed = address(feed);
        (, , , uint256 updatedAt, ) = IAtFeed(address(feed)).latestRoundData();
        assertTrue(updatedAt > block.timestamp, "AS-28: the direct read shows updatedAt in the future");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(
            bits,
            (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255),
            "AS-28: the future updatedAt sets bit 8 and bit 22 with the aggregate"
        );
        RWAGuardView v = new RWAGuardView();
        (bool okView, bytes memory ret) = _at_viewRaw(address(v), _at_viewCalldata(e.token, e.ctx), GAS_BOUND);
        assertTrue(okView, "AS-28: the deployed-form view call succeeds for the future updatedAt");
        assertEq(ret.length, 64, "AS-28: the deployed-form view reply is exactly 64 bytes");
        (, uint256 bitsView) = abi.decode(ret, (bool, uint256));
        assertEq(
            bitsView,
            (uint256(1) << 8) | (uint256(1) << 22) | (uint256(1) << 255),
            "AS-28: the deployed-form view reasonBits match bit 8 and bit 22 with the aggregate"
        );
        _assertEvalCount(1);
    }

    function test_AS28_c_descriptionBombGasBounded() public {
        assertTrue(gasleft() >= AT_BOMB_TEST_GAS_FLOOR, "AS-28: the test frame gas floor covers the bomb budget");
        Env memory e = _baseline();
        RWAGuardView v = new RWAGuardView();
        AttacksNaiveDescriptionReader naive = new AttacksNaiveDescriptionReader();
        uint256 jC;
        uint256 iC;
        {
            _at_gasUsed(address(v), _at_viewCalldata(e.token, e.ctx), AT_BOMB_BUDGET);
            bool okJC;
            (okJC, jC) = _at_gasUsed(address(v), _at_viewCalldata(e.token, e.ctx), AT_BOMB_BUDGET);
            assertTrue(okJC, "AS-28: the clean warm judgement call succeeds");
            IAtFeed(address(e.feed)).latestRoundData();
            bool okIC;
            (okIC, iC) =
                _at_gasUsed(address(e.feed), abi.encodeWithSelector(IAtFeed.description.selector), AT_BOMB_BUDGET);
            assertTrue(okIC, "AS-28: the clean direct description call succeeds");
        }
        uint256 jB;
        uint256 iB;
        {
            e.feed.setDescMode(5, AT_BOMB_BYTES); // DESC_BOMB
            bool okJB;
            (okJB, jB) = _at_gasUsed(address(v), _at_viewCalldata(e.token, e.ctx), AT_BOMB_BUDGET);
            assertTrue(okJB, "AS-28: the bomb judgement call succeeds");
            bool okIB;
            (okIB, iB) =
                _at_gasUsed(address(e.feed), abi.encodeWithSelector(IAtFeed.description.selector), AT_BOMB_BUDGET);
            assertTrue(okIB, "AS-28: the bomb direct description call succeeds");
        }
        assertTrue(iB >= AT_BOMB_CALLEE_MIN, "AS-28: the bomb callee gas clears the callee minimum");
        assertTrue(jB > iB, "AS-28: the bomb judgement gas exceeds the bomb direct description gas");
        assertTrue(jC > iC, "AS-28: the clean judgement gas exceeds the clean direct description gas");
        assertTrue(
            jB - iB <= (jC - iC) + AT_OVERHEAD_SLACK,
            "AS-28: the guard overhead under the bomb stays within slack of the clean overhead"
        );
        {
            e.feed.setDescMode(5, AT_NAIVE_BOMB_BYTES); // DESC_BOMB
            (bool okIN, uint256 iN) =
                _at_gasUsed(address(e.feed), abi.encodeWithSelector(IAtFeed.description.selector), AT_BOMB_BUDGET);
            assertTrue(okIN, "AS-28: the naive-control direct description call succeeds");
            (bool okNN, uint256 nN) = _at_gasUsed(
                address(naive),
                abi.encodeWithSelector(AttacksNaiveDescriptionReader.readAll.selector, address(e.feed)),
                AT_BOMB_BUDGET
            );
            assertTrue(okNN, "AS-28: the naive full-copy control call succeeds");
            assertTrue(nN > iN, "AS-28: the naive full copy costs more than the direct description read");
            assertTrue(
                nN - iN > AT_OVERHEAD_SLACK, "AS-28: the naive full copy overhead exceeds the guard's overhead slack"
            );
            uint256 naiveSize = naive.readAll(address(e.feed));
            assertEq(
                naiveSize, 64 + AT_NAIVE_BOMB_BYTES, "AS-28: the naive control copies exactly the bomb reply length"
            );
        }
    }

    function test_AS28_r19_descriptionHeadLengthsAgree() public {
        // Why the private constant is not read directly: DESCRIPTION_HEAD_LEN is `private`
        // (FD-U7A-12), so this test can only probe GuardCore._answersDescription's boundary
        // behaviour, not the symbol itself. Derived over the precondition domain (minLen in
        // {0,32,64,96,128,160}, subtrahend any uint256): these three arms accept exactly the pair
        // (64, 64), which is the value the shared symbol holds today.
        MockPriceFeed f1 = _freshFeed();
        f1.setDescMode(2, 63); // DESC_SHORT
        {
            (bool okRaw1, uint256 size1, , ) = _at_rawDescriptionHead(address(f1));
            assertTrue(okRaw1, "AS-28: the short-description raw read succeeds");
            assertEq(size1, 63, "AS-28: the short-description raw reply is 63 bytes");
        }
        {
            (bool callOk1, bool answered1) = _at_probeAnswers(address(f1));
            assertTrue(callOk1, "AS-28: the short-description probe call does not revert");
            assertFalse(answered1, "AS-28: a 63-byte description reply is not answered");
        }

        MockPriceFeed f2 = new MockPriceFeed();
        f2.setDescriptionText("");
        {
            (bool okRaw2, uint256 size2, uint256 word0_2, uint256 word1_2) = _at_rawDescriptionHead(address(f2));
            assertTrue(okRaw2, "AS-28: the empty-description raw read succeeds");
            assertEq(size2, 64, "AS-28: the empty-description raw reply is exactly 64 bytes");
            assertEq(word0_2, 0x20, "AS-28: the empty-description offset word is 0x20");
            assertEq(word1_2, 0, "AS-28: the empty-description length word is 0");
        }
        {
            (bool callOk2, bool answered2) = _at_probeAnswers(address(f2));
            assertTrue(callOk2, "AS-28: the empty-description probe call does not revert");
            assertTrue(answered2, "AS-28: a well-formed empty description is answered");
        }

        AttacksLengthLiarFeed f3 = new AttacksLengthLiarFeed();
        {
            (bool okRaw3, uint256 size3, uint256 word0_3, uint256 word1_3) = _at_rawDescriptionHead(address(f3));
            assertTrue(okRaw3, "AS-28: the length-liar raw read succeeds");
            assertEq(size3, 96, "AS-28: the length-liar raw reply is 96 bytes");
            assertEq(word0_3, 0x20, "AS-28: the length-liar offset word is 0x20");
            assertEq(word1_3, 33, "AS-28: the length-liar declared length word is 33");
        }
        {
            (bool callOk3, bool answered3) = _at_probeAnswers(address(f3));
            assertTrue(callOk3, "AS-28: the length-liar probe call does not revert");
            assertFalse(answered3, "AS-28: a 96-byte reply declaring a 33-byte string is not answered");
        }
    }

    // A reverting description() must not look like an absent read: evaluate() still needs to
    // record it as bit 8, exactly like any other unanswered description.
    function test_AS28_descRevertThroughEvaluate() public {
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setDescMode(1, 0);
        e.ctx.priceFeed = address(feed);
        (bool success, uint256 size, , ) = _at_rawDescriptionHead(address(feed));
        assertFalse(success, "AS-28: the raw reverting description read fails");
        assertEq(size, 0, "AS-28: the raw reverting description reply is empty");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-28: a reverting description through evaluate sets exactly bit 8");
        _assertEvalCount(1);
    }

    // A one-word description() reply is 32 bytes, short of the 64-byte head criterion evaluate()
    // needs before offset and length can even be read; it must set bit 8 on that short reply
    // exactly as it does on any other unanswered description.
    function test_AS28_descShortThroughEvaluate() public {
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setDescMode(2, 32);
        e.ctx.priceFeed = address(feed);
        (bool success, uint256 size, , ) = _at_rawDescriptionHead(address(feed));
        assertTrue(success, "AS-28: the raw short description read succeeds");
        assertEq(size, 32, "AS-28: the raw short description reply is one word");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-28: a one-word description through evaluate sets exactly bit 8");
        _assertEvalCount(1);
    }

    // A bad-offset description() reply is a full 64 bytes with a well-formed zero length word,
    // so only the offset criterion is violated; evaluate() must still set bit 8 on that offset
    // mismatch alone, independent of length or content.
    function test_AS28_descBadOffsetThroughEvaluate() public {
        Env memory e = _baseline();
        MockPriceFeed feed = _freshFeed();
        feed.setDescMode(3, 0x40);
        e.ctx.priceFeed = address(feed);
        (bool success, uint256 size, uint256 word0, uint256 word1) = _at_rawDescriptionHead(address(feed));
        assertTrue(success, "AS-28: the raw bad-offset description read succeeds");
        assertEq(size, 64, "AS-28: the raw bad-offset description reply is two words");
        assertEq(word0, 0x40, "AS-28: the raw bad-offset description offset word is not the head offset");
        assertEq(word1, 0, "AS-28: the raw bad-offset description length word is zero");
        uint256 bits = _eval(e.token, e.ctx);
        assertEq(bits, (uint256(1) << 8), "AS-28: a wrong description offset through evaluate sets exactly bit 8");
        _assertEvalCount(1);
    }
}

contract AttacksFailureTest is AttacksBase {
    // TS-16..TS-19: non-verdict failures (an empty revert is not reasonBits == 0; an
    // out-of-gas call is not a verdict either) and the TOCTOU window between an off-chain
    // permit read and the in-transaction check.

    function test_AS19_emptyRevert_malformedCtxIsNotAVerdict() public {
        // F-1: GuardedVault builds Ctx in memory from its own immutables and never
        // ABI-decodes a caller-supplied Ctx, so the integrator half of AS-19 has no demo
        // path; only the deployed form is pinned here (KG-U7A-3). GuardBits clause 7: an
        // empty revert or a Panic is not a verdict, it is a decode failure or an
        // out-of-gas condition, never reasonBits == 0.
        Env memory e = _baseline();
        RWAGuardView v = new RWAGuardView();

        bytes memory clean = abi.encodeWithSelector(
            RWAGuardView.isSafeToTrade.selector,
            e.token,
            e.ctx.priceFeed,
            uint256(uint160(e.ctx.actor)),
            e.ctx.counterparty,
            e.ctx.expectedImpl,
            uint256(e.ctx.maxFeedAge)
        );
        assertEq(
            _u6_hash(clean),
            _u6_hash(_at_viewCalldata(e.token, e.ctx)),
            "AS-19: the hand-built clean calldata matches the canonical encoder"
        );

        {
            (bool okClean, bytes memory retClean) = _at_viewRaw(address(v), clean, GAS_BOUND);
            assertTrue(okClean, "AS-19: the clean calldata call succeeds");
            assertEq(retClean.length, 64, "AS-19: the clean calldata reply is 64 bytes");
            (bool okDecodedClean, uint256 bitsClean) = abi.decode(retClean, (bool, uint256));
            assertTrue(okDecodedClean, "AS-19: the clean calldata decodes to ok true");
            assertEq(bitsClean, 0, "AS-19: the clean calldata reasonBits are 0");
        }

        bytes memory dirty = abi.encodeWithSelector(
            RWAGuardView.isSafeToTrade.selector,
            e.token,
            e.ctx.priceFeed,
            uint256(uint160(e.ctx.actor)) | (uint256(1) << 160),
            e.ctx.counterparty,
            e.ctx.expectedImpl,
            uint256(e.ctx.maxFeedAge)
        );
        {
            (bool okDirty, bytes memory retDirty) = _at_viewRaw(address(v), dirty, GAS_BOUND);
            assertFalse(okDirty, "AS-19: the dirty actor word decode fails");
            assertEq(retDirty.length, 0, "AS-19: the dirty actor word failure carries an empty revert");
            (uint256 selDirty, , ) = _u6_guardBlockedParts(retDirty);
            assertEq(selDirty, 0, "AS-19: the empty revert has no GuardBlocked selector to read");
        }
    }

    function test_AS19_outOfGas_integratorRefuses() public {
        // KG-U7D-4: agreement between the two forms under a gas adversary, the OOG
        // outcome shape, and any gas number besides GAS_BOUND are not asserted here.
        Env memory e = _u6_env();
        MockPriceFeed bf = _freshFeed();
        bf.setFeedMode(5, 0); // FEED_BURN
        bf.setGasBurn(type(uint256).max);
        {
            (uint8 feedMode, , , uint256 gasBurn, ) = bf.readModes();
            assertEq(uint256(feedMode), 5, "AS-19: the burning feed mode reads back as 5");
            assertEq(gasBurn, type(uint256).max, "AS-19: the burning feed gas burn reads back as the maximum");
        }

        GuardedVault gc = _u6_guarded(e, address(e.feed));
        GuardedVault gb = _u6_guarded(e, address(bf));
        _u6_fund(e.token, ALICE, address(gc), 10e18);
        _u6_fund(e.token, ALICE, address(gb), 10e18);
        {
            (bool okDepGc,) = _u6_deposit(address(gc), ALICE, 10e18);
            assertTrue(okDepGc, "AS-19: alice deposit into the clean-feed guarded vault succeeds");
        }
        {
            (bool okDepGb,) = _u6_deposit(address(gb), ALICE, 10e18);
            assertTrue(okDepGb, "AS-19: alice deposit into the burning-feed guarded vault succeeds");
        }

        {
            (bool okRedeemGc,) = _u6_callGas(
                address(gc), ALICE, abi.encodeWithSelector(GuardedVault.redeem.selector, uint256(1e18)), GAS_BOUND
            );
            assertTrue(okRedeemGc, "AS-19: the clean-feed guarded vault redeem under the gas bound succeeds");
            assertEq(gc.shares(ALICE), 9e18, "AS-19: alice shares in the clean-feed guarded vault are 9e18");
        }

        uint256 aliceBalanceBefore = MockEquityToken(e.token).balanceOf(ALICE);
        uint256 gbBalanceBefore = MockEquityToken(e.token).balanceOf(address(gb));

        {
            (bool okRedeemGb, bytes memory retRedeemGb) = _u6_callGas(
                address(gb), ALICE, abi.encodeWithSelector(GuardedVault.redeem.selector, uint256(1e18)), GAS_BOUND
            );
            assertFalse(okRedeemGb, "AS-19: the burning-feed guarded vault redeem under the gas bound fails");
            (uint256 selGb, address tokGb, uint256 bitsGb) = _u6_guardBlockedParts(retRedeemGb);
            assertTrue(
                retRedeemGb.length == 0
                    || (
                        retRedeemGb.length == 68 && selGb == uint256(uint32(RWAGuard.GuardBlocked.selector))
                            && tokGb == e.token && bitsGb != 0
                    ),
                "AS-19: the burning-feed guarded vault failure is an empty revert or a matching GuardBlocked"
            );
        }
        assertEq(gb.shares(ALICE), 10e18, "AS-19: alice shares in the burning-feed guarded vault stay 10e18");
        assertEq(gb.totalShares(), 10e18, "AS-19: total shares in the burning-feed guarded vault stay 10e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(ALICE),
            aliceBalanceBefore,
            "AS-19: alice token balance is unchanged after the burning-feed redeem fails"
        );
        assertEq(
            MockEquityToken(e.token).balanceOf(address(gb)),
            gbBalanceBefore,
            "AS-19: the burning-feed guarded vault token balance is unchanged after the redeem fails"
        );

        RWAGuardView v = new RWAGuardView();
        {
            Ctx memory ctxB = Ctx({
                priceFeed: address(bf),
                actor: e.ctx.actor,
                counterparty: e.ctx.counterparty,
                expectedImpl: e.ctx.expectedImpl,
                maxFeedAge: e.ctx.maxFeedAge
            });
            (bool okB, bytes memory retB) = _at_viewRaw(address(v), _at_viewCalldata(e.token, ctxB), GAS_BOUND);
            bool cleanPassB;
            if (okB && retB.length == 64) {
                (bool okDecodedB, uint256 bitsB) = abi.decode(retB, (bool, uint256));
                cleanPassB = okDecodedB && bitsB == 0;
            }
            assertFalse(cleanPassB, "AS-19: the deployed form under the burning feed never yields a clean pass");
        }
        {
            (bool okClean, bytes memory retClean) =
                _at_viewRaw(address(v), _at_viewCalldata(e.token, e.ctx), GAS_BOUND);
            assertTrue(okClean, "AS-19: the deployed form clean-feed control call succeeds");
            assertEq(retClean.length, 64, "AS-19: the deployed form clean-feed control reply is 64 bytes");
            (bool okDecodedClean, uint256 bitsClean) = abi.decode(retClean, (bool, uint256));
            assertTrue(okDecodedClean, "AS-19: the deployed form clean-feed control decodes to ok true");
            assertEq(bitsClean, 0, "AS-19: the deployed form clean-feed control reasonBits are 0");
        }
    }

    function test_AS24_a_deployedFormStalePermit() public {
        // FD-U7A-9: the flip is exactly one call, setBlocked on the plane; no vm.warp, no
        // second gate. The off-chain permit read before the flip is never re-derived after
        // it -- that staleness is the point pinned here as exposure, never closed.
        Env memory e = _baseline();
        RWAGuardView v = new RWAGuardView();

        assertFalse(e.plane.isBlocked(e.ctx.actor), "AS-24: the actor starts unblocked");
        (bool okBefore, uint256 bitsBefore) = v.isSafeToTrade(e.token, e.ctx);
        assertTrue(okBefore, "AS-24: the permit before the flip is ok");
        assertEq(bitsBefore, 0, "AS-24: the permit before the flip has zero reasonBits");

        e.plane.setBlocked(e.ctx.actor, true);
        assertTrue(e.plane.isBlocked(e.ctx.actor), "AS-24: the actor is blocked after the flip");

        (bool okAfter, uint256 bitsAfter) = v.isSafeToTrade(e.token, e.ctx);
        assertFalse(okAfter, "AS-24: the permit after the flip is blocked");
        assertEq(bitsAfter, (uint256(1) << 3), "AS-24: the permit after the flip carries bit 3");

        assertTrue(okBefore, "AS-24: the caller's already-read permit stays true -- it is now stale");
        assertEq(block.timestamp, T0, "AS-24: no time passed between the two reads");
    }

    function test_AS24_b_inTransactionNoWindow() public {
        // FD-U7A-9: byte-exact equivalent of expectRevert(bytes) -- a top-level
        // vm.expectRevert that is not satisfied fails with a Foundry-internal message
        // carrying no AS-24: prefix (F-6), so the comparison is done by hand instead.
        Env memory e = _u6_env();
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(g), 10e18);
        {
            (bool okDep,) = _u6_deposit(address(g), ALICE, 10e18);
            assertTrue(okDep, "AS-24: alice deposit into the guarded vault succeeds");
        }

        {
            (bool okRedeemCtl,) = _u6_redeem(address(g), ALICE, 1e18);
            assertTrue(okRedeemCtl, "AS-24: alice redeem before the flip succeeds");
            assertEq(g.shares(ALICE), 9e18, "AS-24: alice shares after the control redeem are 9e18");
        }

        RWAGuardView v = new RWAGuardView();
        {
            // Built from the vault's own immutables, so this is by construction the
            // tuple RWAGuard.enforce checks inside redeem, not a retyped literal.
            Ctx memory permitCtx = Ctx({
                priceFeed: g.priceFeed(),
                actor: ALICE,
                counterparty: ALICE,
                expectedImpl: g.expectedImpl(),
                maxFeedAge: g.maxFeedAge()
            });
            (bool okPermit, uint256 bitsPermit) = v.isSafeToTrade(e.token, permitCtx);
            assertTrue(okPermit, "AS-24: the off-chain permit before the flip is ok");
            assertEq(bitsPermit, 0, "AS-24: the off-chain permit before the flip has zero reasonBits");
        }

        e.plane.setBlocked(ALICE, true);

        (bool okRedeem, bytes memory retRedeem) = _u6_redeem(address(g), ALICE, 1e18);
        assertFalse(okRedeem, "AS-24: alice redeem after the flip is blocked inside the same call");
        assertEq(
            _u6_hash(retRedeem),
            _u6_hash(_u6_guardBlockedData(e.token, (uint256(1) << 3))),
            "AS-24: the blocked redeem hash matches GuardBlocked bit 3"
        );
        assertEq(g.shares(ALICE), 9e18, "AS-24: alice shares stay 9e18 after the blocked redeem");
    }
}
