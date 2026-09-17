// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TestBase, Vm} from "./Base.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {Ctx} from "../src/GuardBits.sol";
import {MockControlPlane, FixtureMutator} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

contract FixturesTest is TestBase {
    string  internal constant FIXTURE_PATH = "test/fixtures/equity-token-proxy.runtime.hex";
    string  internal constant RPC_ENV = "RWA_GUARD_RPC_URL";
    string  internal constant ENVOR_PROBE_NAME = "RWA_GUARD_ENVOR_PROBE_MUST_BE_UNSET";
    uint256 internal constant FIXTURE_RUNTIME_LEN = 283;
    uint256 internal constant T0 = 1_700_000_000;
    uint64  internal constant MAX_FEED_AGE = 3600;
    uint256 internal constant GAS_BAND_THRESHOLD = 300_000;
    uint256 internal constant BUDGET_HIGH = 1_000_000;
    uint256 internal constant BUDGET_LOW = 150_000;
    uint256 internal constant BURN_AMOUNT = 200_000;
    uint256 internal constant BURN_BUDGET = 2_000_000;
    uint256 internal constant BOMB_BYTES = 10_000_000;
    uint256 internal constant BOMB_BUDGET = 400_000_000;
    bytes4  internal constant PAUSED_SELECTOR_MEASURED = 0x5c975abb;
    // fixture addresses (named, not auto-discovered):
    address internal constant EQUITY_ETCH_ADDR = address(uint160(uint256(keccak256("rwa-guard.u5.equity-etch"))));
    address internal constant EXPECTED_IMPL    = address(uint160(uint256(keccak256("rwa-guard.u5.expected-impl"))));
    address internal constant ACTOR            = address(uint160(uint256(keccak256("rwa-guard.u5.actor"))));
    address internal constant COUNTERPARTY     = address(uint160(uint256(keccak256("rwa-guard.u5.counterparty"))));

    /// Raw staticcall with an explicit gas budget; copies at most `copyCap` bytes of returndata
    /// into `head`, regardless of how large the real returndata is (the caller never pays for an
    /// unbounded memory-expansion copy of a hostile answer).
    function _raw(address target, bytes memory cd, uint256 gasBudget, uint256 copyCap)
        internal
        view
        returns (bool success, uint256 size, bytes memory head)
    {
        assembly {
            let ok := staticcall(gasBudget, target, add(cd, 0x20), mload(cd), 0, 0)
            success := ok
            size := returndatasize()
            let copyLen := size
            if gt(copyLen, copyCap) { copyLen := copyCap }
            let p := mload(0x40)
            mstore(p, copyLen)
            returndatacopy(add(p, 0x20), 0, copyLen)
            mstore(0x40, and(add(add(p, 0x20), add(copyLen, 31)), not(31)))
            head := p
        }
    }

    /// Measures gas actually consumed by a single staticcall under an explicit budget. Used by the
    /// BURN / GAS_BAND self-checks in later segments to compare a measured call against a clean one.
    function _gasUsed(address target, bytes memory cd, uint256 gasBudget)
        internal
        view
        returns (bool success, uint256 used)
    {
        assembly {
            let before := gas()
            let ok := staticcall(gasBudget, target, add(cd, 0x20), mload(cd), 0, 0)
            let afterGas := gas()
            success := ok
            used := sub(before, afterGas)
        }
    }

    /// Counts recorded StaticCall entries whose `account` (the staticcall target) is `account`.
    function _countStatic(Vm.AccountAccess[] memory diff, address account) internal pure returns (uint256 count) {
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && diff[i].account == account) {
                count++;
            }
        }
    }

    /// Counts every recorded StaticCall entry, excluding the cheatcode address itself.
    function _countStaticAll(Vm.AccountAccess[] memory diff) internal pure returns (uint256 count) {
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind == Vm.AccountAccessKind.StaticCall && diff[i].account != address(vm)) {
                count++;
            }
        }
    }

    /// Extracts the leading 4-byte selector from a recorded call's `data`, masking off whatever
    /// follows so the comparison never depends on garbage/padding past byte 4.
    function _selectorOf(bytes memory data) internal pure returns (bool present, bytes4 sel) {
        if (data.length < 4) {
            return (false, bytes4(0));
        }
        assembly {
            let word := mload(add(data, 32))
            sel := and(word, shl(224, 0xffffffff))
        }
        present = true;
    }

    /// Strips trailing 0x0a / 0x0d / 0x20 bytes (the fixture file's trailing newline; see B6).
    function _trimTrailingWhitespace(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        uint256 end = b.length;
        while (end > 0) {
            bytes1 c = b[end - 1];
            if (c == 0x0a || c == 0x0d || c == 0x20) {
                end--;
            } else {
                break;
            }
        }
        bytes memory out = new bytes(end);
        for (uint256 i = 0; i < end; i++) {
            out[i] = b[i];
        }
        return string(out);
    }

    /// Loads and decodes the checked-in proxy runtime fixture: readFile -> trim -> parseBytes.
    function _loadFixtureRuntime() internal view returns (bytes memory) {
        string memory raw = vm.readFile(FIXTURE_PATH);
        string memory trimmed = _trimTrailingWhitespace(raw);
        return vm.parseBytes(trimmed);
    }

    /// Shared baseline for every §8/§9 self-check: control plane etched at the guard's compile-time
    /// constant, a standalone (non-proxied) C6 token (FD-U5-3 / B7 -- a real proxy would add a
    /// plane.implementation() staticcall on every token call, inflating AS-39's plane count), and a
    /// clean C9 feed. The full reasonBits on this baseline is exactly `1 << 0`: G0 is violated
    /// because the standalone token's codehash is not the known proxy codehash; every other gate is
    /// clean against this configuration.
    function _baseline() internal returns (MockEquityToken token, MockControlPlane plane, MockPriceFeed feed, Ctx memory ctx) {
        vm.warp(T0);

        vm.etch(GuardCore.CONTROL_PLANE, address(new MockControlPlane()).code);
        plane = MockControlPlane(GuardCore.CONTROL_PLANE);
        plane.setImplementation(EXPECTED_IMPL);

        token = new MockEquityToken();
        token.setRatios(1e18, 1e18, 0);

        feed = new MockPriceFeed();
        feed.setRound(7, 1e8, T0, T0, 7);
        feed.setDescriptionText("MOCK / USD");

        ctx = Ctx({
            priceFeed: address(feed),
            actor: ACTOR,
            counterparty: COUNTERPARTY,
            expectedImpl: EXPECTED_IMPL,
            maxFeedAge: MAX_FEED_AGE
        });
    }

    function assertEqBytes32(bytes32 a, bytes32 b, string memory reason) internal pure {
        if (a != b) revert(reason);
    }

    function assertEqBytes(bytes memory a, bytes memory b, string memory reason) internal pure {
        if (keccak256(a) != keccak256(b)) revert(reason);
    }

    function assertEqInt(int256 a, int256 b, string memory reason) internal pure {
        if (a != b) revert(reason);
    }

    function test_S9_createSelectFork_urlOnly() public {
        string memory url = vm.envOr(RPC_ENV, string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        // Decoding this return value without reverting is itself part of the self-check.
        vm.createSelectFork(url);
        assertTrue(block.chainid != 31337, "S9 createSelectFork(string): chainid != anvil default");
        assertTrue(block.number > 1, "S9 createSelectFork(string): block.number > 1");
    }

    function test_S9_createSelectFork_pinnedBlock() public {
        string memory url = vm.envOr(RPC_ENV, string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        uint256 head = block.number;
        vm.createSelectFork(url, head - 1);
        assertEq(block.number, head - 1, "S9 createSelectFork(string,uint256): pinned block");
    }

    function test_S9_envOr_returnsDefaultWhenUnset() public {
        string memory value = vm.envOr(ENVOR_PROBE_NAME, "rwa-guard-default");
        assertEqBytes32(
            keccak256(bytes(value)),
            keccak256(bytes("rwa-guard-default")),
            "S9 envOr: default returned when unset"
        );
    }

    function test_S9_skip_falseContinues() public {
        vm.skip(false);
        // The `true` arm is witnessed by the [SKIP] lines of tests 1-2 (E3), not by this test.
        assertTrue(true, "S9 skip: false continues execution");
    }

    function test_S9_deal_setsExactBalance() public {
        address a = ACTOR;
        vm.deal(a, 1 ether);
        assertEq(a.balance, 1 ether, "S9 deal: sets exact balance");
        vm.deal(a, 0);
        assertEq(a.balance, 0, "S9 deal: not additive, zero clears");
    }

    function test_S9_getDeployedCode_matchesDeployedRuntime() public {
        bytes memory viaCheatcode = vm.getDeployedCode("MockPriceFeed.sol:MockPriceFeed");
        bytes memory viaDeploy = address(new MockPriceFeed()).code;
        assertEqBytes32(
            keccak256(viaCheatcode), keccak256(viaDeploy), "S9 getDeployedCode: matches deployed runtime"
        );
    }

    function test_S9_getCode_matchesCreationCode() public {
        bytes memory viaCheatcode = vm.getCode("MockPriceFeed.sol:MockPriceFeed");
        assertEqBytes32(
            keccak256(viaCheatcode),
            keccak256(type(MockPriceFeed).creationCode),
            "S9 getCode: matches creation code"
        );
    }

    function test_S9_readFile_readsCheckedInFixture() public {
        string memory raw = vm.readFile(FIXTURE_PATH);
        bytes memory rawBytes = bytes(raw);
        assertTrue(rawBytes.length > 0, "S9 readFile: length > 0");
        assertTrue(
            rawBytes[0] == bytes1("0") && rawBytes[1] == bytes1("x"),
            "S9 readFile: first two bytes are 0x"
        );
        string memory trimmed = _trimTrailingWhitespace(raw);
        assertEq(bytes(trimmed).length, 2 + 2 * FIXTURE_RUNTIME_LEN, "S9 readFile: trimmed length matches fixture");
    }

    function test_S9_parseBytes_decodesExactBytes() public {
        bytes memory decoded = vm.parseBytes("0x0102ff");
        assertEqBytes(decoded, hex"0102ff", "S9 parseBytes: decodes exact bytes");
        assertEq(_loadFixtureRuntime().length, FIXTURE_RUNTIME_LEN, "S9 parseBytes: fixture runtime length");
    }

    function test_S9_expectRevertBytes_matchesTwoArgPayload() public {
        TwoArgReverter reverter = new TwoArgReverter();
        vm.expectRevert(abi.encodeWithSelector(TwoArgProbe.selector, address(0xA11CE), uint256(0x1234)));
        reverter.boom(address(0xA11CE), 0x1234);
    }

    function test_S9_expectRevertBytes_wrongPayloadFailsInnerCall() public {
        TwoArgReverter reverter = new TwoArgReverter();
        ExpectRevertHarness harness = new ExpectRevertHarness();
        bytes memory wrongPayload = abi.encodeWithSelector(TwoArgProbe.selector, address(0xA11CE), uint256(0x9999));
        (bool success,) =
            address(harness).call(abi.encodeWithSelector(ExpectRevertHarness.run.selector, reverter, wrongPayload));
        // [UNVERIFIED, KG-3]: forge's exact handling of a mismatched expectRevert payload inside a
        // nested call is not checked against the installed foundry version offline. If it instead
        // surfaces as a top-level test failure rather than a reverted inner call frame, this
        // assertion is expected to go red first; do not weaken it to force green -- see the design
        // doc Known Gaps / Boundary B37.
        assertFalse(success, "S9 expectRevert: wrong payload fails the inner call [UNVERIFIED, KG-3]");
    }

    function test_AS39a_stateDiffFanOutDiscriminates() public {
        (MockEquityToken token,, MockPriceFeed feed, Ctx memory ctx) = _baseline();

        // Arm (1): full ctx, standalone C6 (FD-U5-3 / B7 -- no proxy in the loop, so the plane's
        // implementation() staticcall a real proxy would add on every token call never fires here).
        uint256[4] memory arm1 = _fx_recordedEvaluate(address(token), address(feed), ctx);
        assertEq(arm1[0], 4, "AS-39: arm1 token staticcall count");
        assertEq(arm1[1], 4, "AS-39: arm1 plane staticcall count");
        assertEq(arm1[2], 2, "AS-39: arm1 feed staticcall count");
        // 10 not 11 -- EXTCODEHASH is kind Extcodehash, excluded by kind (never counted here);
        // token 4 + plane 4 + feed 2 = 10; never count DelegateCall.
        assertEq(arm1[3], 10, "AS-39: arm1 total staticcall count is 10, not 11");
        // Deliberately NO reasonBits assertion in any arm of AS-39(a): this function must stay outside every mutation expected-red set (MUTATION-OVERREACH sentinel). The standalone-token baseline would read 1<<0 (G0 violated, FD-U5-3); that value is asserted in AS-39(c)'s reset arm, not here.

        // Arm (2): actor/counterparty/priceFeed zeroed outside the recording window. Zeroing must
        // strictly reduce fan-out on every address counted, not just in total.
        Ctx memory ctxZeroed = Ctx({
            priceFeed: address(0),
            actor: address(0),
            counterparty: address(0),
            expectedImpl: ctx.expectedImpl,
            maxFeedAge: ctx.maxFeedAge
        });
        uint256[4] memory arm2 = _fx_recordedEvaluate(address(token), address(feed), ctxZeroed);
        assertEq(arm2[0], 4, "AS-39: arm2 token staticcall count");
        assertEq(arm2[1], 2, "AS-39: arm2 plane staticcall count");
        assertEq(arm2[2], 0, "AS-39: arm2 feed staticcall count is 0 (feed instance never called)");
        assertEq(arm2[3], 6, "AS-39: arm2 total staticcall count");

        // Arm (3): arm (1) with only expectedImpl zeroed. G4 still fires the plane read; it only
        // stops interpreting the returned word, so fan-out must be unchanged from arm (1).
        Ctx memory ctxNoImpl = Ctx({
            priceFeed: ctx.priceFeed,
            actor: ctx.actor,
            counterparty: ctx.counterparty,
            expectedImpl: address(0),
            maxFeedAge: ctx.maxFeedAge
        });
        uint256[4] memory arm3 = _fx_recordedEvaluate(address(token), address(feed), ctxNoImpl);
        assertEq(arm3[0], 4, "AS-39: arm3 token staticcall count");
        assertEq(arm3[1], 4, "AS-39: arm3 plane staticcall count");
        assertEq(arm3[2], 2, "AS-39: arm3 feed staticcall count");
        assertEq(arm3[3], 10, "AS-39: arm3 total staticcall count");
        // No reasonBits assertion for arm (3) (design doc, test 12).

        // AS-39(a) red on any count above => suspect the hand-written Vm.AccountAccess /
        // AccountAccessKind declarations in Base.sol first, the guard second.
        assertEq(arm1[0], arm2[0], "AS-39: G3 no longer reads the token, so zeroing the parties leaves the token count unchanged");
        assertTrue(arm1[1] != arm2[1], "AS-39: arm1 != arm2 plane count");
        assertTrue(arm1[2] != arm2[2], "AS-39: arm1 != arm2 feed count");
        assertEq(arm3[0], arm1[0], "AS-39: arm3 == arm1 token count");
        assertEq(arm3[1], arm1[1], "AS-39: arm3 == arm1 plane count");
        assertEq(arm3[2], arm1[2], "AS-39: arm3 == arm1 feed count");
    }

    /// Runs a single recorded GuardCore.evaluate call and returns the per-target StaticCall fan-out
    /// (token, plane, feed, total), packed into a fixed array (r[0]=token, r[1]=plane, r[2]=feed,
    /// r[3]=all) to minimize the caller's stack footprint (FD-U5-17a). The recording window still
    /// starts and stops immediately around the single `evaluate` call, exactly as it did inline in
    /// each arm. `evaluate`'s reasonBits return value is deliberately not captured or returned here
    /// (M1, U5 review): AS-39(a) must stay outside every mutation expected-red set.
    function _fx_recordedEvaluate(address token, address feedAddr, Ctx memory ctx)
        private
        returns (uint256[4] memory r)
    {
        vm.startStateDiffRecording();
        GuardCore.evaluate(token, ctx);
        Vm.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();
        r[0] = _countStatic(diff, token);
        r[1] = _countStatic(diff, GuardCore.CONTROL_PLANE);
        r[2] = _countStatic(diff, feedAddr);
        r[3] = _countStaticAll(diff);
    }

    function test_AS39b_stateDiffFieldsDecodable() public {
        (MockEquityToken token, MockControlPlane plane,, Ctx memory ctx) = _baseline();

        plane.setMutator(plane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));

        vm.startStateDiffRecording();
        GuardCore.evaluate(address(token), ctx);
        Vm.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();

        assertTrue(
            PAUSED_SELECTOR_MEASURED == bytes4(keccak256("paused()")),
            "AS-39: PAUSED_SELECTOR_MEASURED matches keccak-derived selector"
        );

        bool sawSelectorPrefix;
        bool foundPlaneEntry;
        bool planeReverted;
        bool foundTokenEntry;
        bool tokenReverted;

        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind != Vm.AccountAccessKind.StaticCall) {
                continue;
            }
            (bool present, bytes4 sel) = _selectorOf(diff[i].data);
            if (present && sel == PAUSED_SELECTOR_MEASURED) {
                sawSelectorPrefix = true;
                if (diff[i].account == GuardCore.CONTROL_PLANE) {
                    foundPlaneEntry = true;
                    planeReverted = diff[i].reverted;
                } else if (diff[i].account == address(token)) {
                    foundTokenEntry = true;
                    tokenReverted = diff[i].reverted;
                }
            }
        }

        assertTrue(sawSelectorPrefix, "AS-39: at least one StaticCall data prefix == PAUSED_SELECTOR_MEASURED");
        assertTrue(foundPlaneEntry, "AS-39: plane paused() entry present");
        assertTrue(foundTokenEntry, "AS-39: token paused() entry present (control)");
        assertTrue(planeReverted, "AS-39: plane paused() entry reverted == true");
        assertFalse(tokenReverted, "AS-39: token paused() entry reverted == false (control)");

        // Degrade discipline (verbatim, never delete): if this test goes red for framework
        // reasons, turn it red, downgrade AS-27b to count-only, and write it into open risks. Do
        // not rewrite this test's expected values to make it pass.
    }

    function test_AS39c_countingModeHaltsStaticReadAndIsReset() public {
        (MockEquityToken token, MockControlPlane plane,, Ctx memory ctx) = _baseline();

        plane.setCountingMode(true);

        vm.startStateDiffRecording();
        (, uint256 bits) = GuardCore.evaluate(address(token), ctx);
        Vm.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();

        // (1) a static-frame SSTORE halts the read (unreachable, not a normal revert-with-data):
        // G1 on CONTROL_PLANE.paused() sees success == false and places bit 17 (G1 unreadable),
        // while every other gate is unaffected -- no short-circuit (D4).
        assertEq(
            bits, (uint256(1) << 0) | (uint256(1) << 17) | (uint256(1) << 255), "AS-39: countingMode reasonBits"
        );

        // (2) the increment never lands: the SSTORE is discarded with the rest of the halted
        // static frame, so readCount() stays at 0.
        assertEq(plane.readCount(), 0, "AS-39: readCount stays 0 -- SSTORE never commits in a static frame");

        // (3) the plane is still read exactly 4 times (paused + isBlocked x2 + implementation):
        // the halted read is still a StaticCall attempt, not a missing one.
        assertEq(_countStatic(diff, GuardCore.CONTROL_PLANE), 4, "AS-39: plane StaticCall count unchanged at 4");

        // (4) MEASURED on foundry 1.8.1 (FD-U5-18): the halted plane paused() entry decodes with
        // reverted == FALSE. Foundry flags a REVERT-opcode failure (pinned true in AS-39(b) via the
        // C5 REVERT mutator) but NOT an exceptional halt such as this static-frame SSTORE.
        // Consequence for every consumer of the state-diff channel (AS-18b, AS-27b): `reverted` is
        // NOT a failed-read detector -- a halted read looks successful by that field. Detect failed
        // reads by the guard's unreadable bits (assertion (1)), never by `reverted`.
        // This assertion carries information only while AS-39(b)'s plane `reverted == true` arm is
        // green in the same run (that arm proves the field decodes at all). If a foundry upgrade
        // turns this red, that is the SG-7 version signal to re-run AS-39 -- not a literal to edit.
        bool foundPlanePaused;
        bool planePausedReverted;
        for (uint256 i = 0; i < diff.length; i++) {
            if (diff[i].kind != Vm.AccountAccessKind.StaticCall || diff[i].account != GuardCore.CONTROL_PLANE) {
                continue;
            }
            (bool present, bytes4 sel) = _selectorOf(diff[i].data);
            if (present && sel == PAUSED_SELECTOR_MEASURED) {
                foundPlanePaused = true;
                planePausedReverted = diff[i].reverted;
            }
        }
        assertTrue(foundPlanePaused, "AS-39: plane paused() halted entry present in the diff");
        assertFalse(planePausedReverted, "AS-39: plane paused() halted entry reverted == false (measured, foundry 1.8.1)");

        // Control: a typed CALL (not a STATICCALL) lets the same SSTORE commit normally.
        plane.paused();
        assertEq(plane.readCount(), 1, "AS-39: control -- typed CALL lets the counter commit");

        // Reset: countingMode must not leak into a later evaluation.
        plane.setCountingMode(false);
        (, uint256 bitsAfterReset) = GuardCore.evaluate(address(token), ctx);
        assertEq(bitsAfterReset, uint256(1) << 0, "AS-39: reset -- reasonBits back to clean baseline");
    }


    function test_C5_surface_declaredSelectorsReturn32Bytes() public {
        (, MockControlPlane plane, , ) = _baseline();

        (bool ok1, uint256 size1, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 32);
        assertTrue(ok1, "C5: paused() must succeed");
        assertEq(size1, 32, "C5: paused() must return exactly 32 bytes");

        (bool ok2, uint256 size2, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 32);
        assertTrue(ok2, "C5: isBlocked(address) must succeed");
        assertEq(size2, 32, "C5: isBlocked(address) must return exactly 32 bytes");

        (bool ok3, uint256 size3, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.implementation.selector), BUDGET_HIGH, 32);
        assertTrue(ok3, "C5: implementation() must succeed");
        assertEq(size3, 32, "C5: implementation() must return exactly 32 bytes");
    }

    function test_C5_surface_undeclaredSelectorsRevert() public {
        (, MockControlPlane plane, , ) = _baseline();

        bytes4[7] memory undeclared = [
            MockEquityToken.uiMultiplier.selector,
            MockEquityToken.newUIMultiplier.selector,
            MockEquityToken.effectiveAt.selector,
            MockPriceFeed.latestRoundData.selector,
            MockPriceFeed.description.selector,
            bytes4(keccak256("decimals()")),
            bytes4(keccak256("symbol()"))
        ];
        for (uint256 i = 0; i < undeclared.length; i++) {
            (bool ok, , ) = _raw(address(plane), abi.encodePacked(undeclared[i]), BUDGET_HIGH, 32);
            assertFalse(ok, "C5: undeclared selector must revert");
        }

        (bool okPaused, uint256 sizePaused, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 32);
        assertTrue(okPaused, "C5: paused() positive control must succeed");
        assertEq(sizePaused, 32, "C5: paused() positive control must return 32 bytes");
    }

    function test_C5_mutator_revert() public {
        (, MockControlPlane plane, , ) = _baseline();
        plane.setMutator(plane.paused.selector, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));

        (bool ok, uint256 size, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 32);
        assertFalse(ok, "C5: REVERT mutator must fail the call");
        assertEq(size, 0, "C5: REVERT mutator must return zero bytes");

        plane.setMutator(plane.paused.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool ok2, uint256 size2, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 32);
        assertTrue(ok2, "C5: restored NORMAL mutator must succeed");
        assertEq(size2, 32, "C5: restored NORMAL mutator must return 32 bytes");
    }

    function test_C5_mutator_length0() public {
        (, MockControlPlane plane, , ) = _baseline();
        plane.setMutator(plane.isBlocked.selector, FixtureMutator.LENGTH, 0, bytes32(0), bytes32(0));

        (bool ok, uint256 size, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 32);
        assertTrue(ok, "C5: LENGTH 0 must still succeed");
        assertEq(size, 0, "C5: LENGTH 0 must return zero bytes");

        plane.setMutator(plane.isBlocked.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool ok2, uint256 size2, ) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 32);
        assertTrue(ok2, "C5: restored NORMAL mutator must succeed");
        assertEq(size2, 32, "C5: restored NORMAL mutator must return 32 bytes");
    }

    function test_C5_mutator_length31() public {
        (, MockControlPlane plane, , ) = _baseline();
        plane.setBlocked(ACTOR, true);
        plane.setMutator(plane.isBlocked.selector, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0));

        (bool ok, uint256 size, bytes memory head) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 31);
        assertTrue(ok, "C5: LENGTH 31 must succeed");
        assertEq(size, 31, "C5: LENGTH 31 must return exactly 31 bytes");

        bytes32 word = bytes32(uint256(1));
        bytes memory expected = new bytes(31);
        for (uint256 i = 0; i < 31; i++) {
            expected[i] = word[i];
        }
        assertEqBytes(head, expected, "C5: LENGTH 31 must be the first 31 bytes of the true bool word");
    }

    function test_C5_mutator_length64() public {
        (, MockControlPlane plane, , ) = _baseline();
        plane.setBlocked(ACTOR, true);
        plane.setMutator(plane.isBlocked.selector, FixtureMutator.LENGTH, 64, bytes32(0), bytes32(0));

        (bool ok, uint256 size, bytes memory head) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 64);
        assertTrue(ok, "C5: LENGTH 64 must succeed");
        assertEq(size, 64, "C5: LENGTH 64 must return exactly 64 bytes");

        bytes32 word0;
        bytes32 word1;
        assembly {
            word0 := mload(add(head, 32))
            word1 := mload(add(head, 64))
        }
        assertEqBytes32(word0, bytes32(uint256(1)), "C5: LENGTH 64 word0 must be the normal word");
        assertEqBytes32(word1, bytes32(0), "C5: LENGTH 64 word1 must be explicitly zeroed");
    }

    function test_C5_mutator_boolWordTwo() public {
        (, MockControlPlane plane, , ) = _baseline();
        bytes32 wordTwo = bytes32(uint256(2));

        plane.setMutator(plane.paused.selector, FixtureMutator.RAW_WORD, 0, wordTwo, bytes32(0));
        (bool okP, uint256 sizeP, bytes memory headP) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 32);
        assertTrue(okP, "C5: RAW_WORD on paused() must succeed");
        assertEq(sizeP, 32, "C5: RAW_WORD on paused() must return 32 bytes");
        bytes32 gotP;
        assembly { gotP := mload(add(headP, 32)) }
        assertEqBytes32(gotP, wordTwo, "C5: paused() must return the exact raw word");

        plane.setMutator(plane.isBlocked.selector, FixtureMutator.RAW_WORD, 0, wordTwo, bytes32(0));
        (bool okB, uint256 sizeB, bytes memory headB) =
            _raw(address(plane), abi.encodeWithSelector(plane.isBlocked.selector, ACTOR), BUDGET_HIGH, 32);
        assertTrue(okB, "C5: RAW_WORD on isBlocked() must succeed");
        assertEq(sizeB, 32, "C5: RAW_WORD on isBlocked() must return 32 bytes");
        bytes32 gotB;
        assembly { gotB := mload(add(headB, 32)) }
        assertEqBytes32(gotB, wordTwo, "C5: isBlocked() must return the exact raw word");
    }

    function test_C5_mutator_addressHighBytesDirty() public {
        (, MockControlPlane plane, , ) = _baseline();
        bytes32 dirtyWord = bytes32((uint256(0xAB) << 160) | uint256(uint160(EXPECTED_IMPL)));
        plane.setMutator(plane.implementation.selector, FixtureMutator.RAW_WORD, 0, dirtyWord, bytes32(0));

        (bool ok, uint256 size, bytes memory head) =
            _raw(address(plane), abi.encodeWithSelector(plane.implementation.selector), BUDGET_HIGH, 32);
        assertTrue(ok, "C5: RAW_WORD on implementation() must succeed");
        assertEq(size, 32, "C5: RAW_WORD on implementation() must return 32 bytes");
        bytes32 got;
        assembly { got := mload(add(head, 32)) }
        assertEqBytes32(got, dirtyWord, "C5: implementation() must return the exact dirty word");
    }

    function test_C5_mutator_gasBand() public {
        (, MockControlPlane plane, , ) = _baseline();
        bytes32 wordA = bytes32(uint256(1));
        bytes32 wordB = bytes32(uint256(2));
        plane.setMutator(plane.paused.selector, FixtureMutator.GAS_BAND, GAS_BAND_THRESHOLD, wordA, wordB);
        bytes memory cd = abi.encodeWithSelector(plane.paused.selector);

        (bool ok1, , bytes memory head1) = _raw(address(plane), cd, BUDGET_HIGH, 32);
        assertTrue(ok1, "C5: GAS_BAND high budget must succeed");
        bytes32 got1;
        assembly { got1 := mload(add(head1, 32)) }
        assertEqBytes32(got1, wordA, "C5: GAS_BAND above threshold must return wordA");

        (bool ok2, , bytes memory head2) = _raw(address(plane), cd, BUDGET_LOW, 32);
        assertTrue(ok2, "C5: GAS_BAND low budget must succeed");
        bytes32 got2;
        assembly { got2 := mload(add(head2, 32)) }
        assertEqBytes32(got2, wordB, "C5: GAS_BAND below threshold must return wordB");

        (bool ok3, , bytes memory head3) = _raw(address(plane), cd, BUDGET_HIGH, 32);
        assertTrue(ok3, "C5: repeated GAS_BAND high budget must succeed");
        bytes32 got3;
        assembly { got3 := mload(add(head3, 32)) }
        assertEqBytes32(got3, wordA, "C5: repeated GAS_BAND above threshold must return wordA again");
    }

    function test_C5_mutator_burn() public {
        (, MockControlPlane plane, , ) = _baseline();
        bytes memory cd = abi.encodeWithSelector(plane.paused.selector);

        _gasUsed(address(plane), cd, BUDGET_HIGH); // warm-up: makes both clean measurements follow a STATICCALL to the plane, so both carry the same caller-side access charge

        (bool okA, uint256 usedClean) = _gasUsed(address(plane), cd, BUDGET_HIGH);
        assertTrue(okA, "C5: first clean NORMAL measurement must succeed");
        (bool okB, uint256 usedCleanAgain) = _gasUsed(address(plane), cd, BUDGET_HIGH);
        assertTrue(okB, "C5: second clean NORMAL measurement must succeed");
        assertEq(usedClean, usedCleanAgain, "C5: two clean NORMAL measurements must use identical gas");

        plane.setMutator(plane.paused.selector, FixtureMutator.BURN, BURN_AMOUNT, bytes32(0), bytes32(0));
        (bool okBurn, uint256 usedBurn) = _gasUsed(address(plane), cd, BUDGET_HIGH);
        assertTrue(okBurn, "C5: bounded BURN must still succeed");
        assertTrue(usedBurn > usedClean + (BURN_AMOUNT / 2), "C5: bounded BURN must cost materially more gas than clean");

        plane.setMutator(plane.paused.selector, FixtureMutator.BURN, type(uint256).max, bytes32(0), bytes32(0));
        (bool okExhaust, ) = _gasUsed(address(plane), cd, BURN_BUDGET);
        assertFalse(okExhaust, "C5: unbounded BURN must exhaust the fixed budget and fail");
    }

    function test_C5_mutator_unknownKindReverts() public {
        (, MockControlPlane plane, , ) = _baseline();
        plane.setMutator(plane.paused.selector, 9, 0, bytes32(0), bytes32(0));

        (bool ok, uint256 size, bytes memory head) =
            _raw(address(plane), abi.encodeWithSelector(plane.paused.selector), BUDGET_HIGH, 36);
        assertFalse(ok, "C5: unknown mutator kind must revert");
        assertEq(size, 36, "C5: UnknownMutatorKind revert data must be exactly 36 bytes");
        assertEqBytes(
            head,
            abi.encodeWithSelector(FixtureMutator.UnknownMutatorKind.selector, uint8(9)),
            "C5: revert data must be UnknownMutatorKind(9)"
        );
    }

    function test_C5_mutator_setterRejectsUnsupportedSelectorAndOversizeLength() public {
        (, MockControlPlane plane, , ) = _baseline();

        vm.expectRevert(
            abi.encodeWithSelector(MockControlPlane.UnsupportedSelector.selector, MockEquityToken.uiMultiplier.selector)
        );
        plane.setMutator(MockEquityToken.uiMultiplier.selector, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(FixtureMutator.MutatorLengthTooLarge.selector, uint256(1025)));
        plane.setMutator(plane.paused.selector, FixtureMutator.LENGTH, 1025, bytes32(0), bytes32(0));
    }

    function test_C6_surface_declaredSelectorsReturn32Bytes() public {
        (MockEquityToken token, , , ) = _baseline();

        bytes4[4] memory reads = [
            token.paused.selector,
            token.uiMultiplier.selector,
            token.newUIMultiplier.selector,
            token.effectiveAt.selector
        ];
        for (uint256 i = 0; i < reads.length; i++) {
            bytes memory cd = abi.encodeWithSelector(reads[i]);
            (bool ok, uint256 size, ) = _raw(address(token), cd, BUDGET_HIGH, 32);
            assertTrue(ok, "C6: declared selector must succeed");
            assertEq(size, 32, "C6: declared selector must return exactly 32 bytes");
        }
    }

    function test_C6_surface_implementationDecimalsSymbolRevert() public {
        (MockEquityToken token, , , ) = _baseline();

        bytes4[5] memory undeclared = [
            MockControlPlane.implementation.selector,
            bytes4(keccak256("decimals()")),
            bytes4(keccak256("symbol()")),
            MockPriceFeed.latestRoundData.selector,
            MockPriceFeed.description.selector
        ];
        for (uint256 i = 0; i < undeclared.length; i++) {
            (bool ok, , ) = _raw(address(token), abi.encodePacked(undeclared[i]), BUDGET_HIGH, 32);
            assertFalse(ok, "C6: undeclared selector must revert on the token");
        }

        (bool okBlocked, , ) =
            _raw(address(token), abi.encodeWithSignature("isBlocked(address)", ACTOR), BUDGET_HIGH, 32);
        assertFalse(okBlocked, "C6: isBlocked(address) must revert (the real token has none)");

        (bool okPaused, uint256 sizePaused, ) =
            _raw(address(token), abi.encodeWithSelector(token.paused.selector), BUDGET_HIGH, 32);
        assertTrue(okPaused, "C6: paused() positive control must succeed");
        assertEq(sizePaused, 32, "C6: paused() positive control must return 32 bytes");
    }


    function test_C6_mutator_revert() public {
        MockEquityToken token = new MockEquityToken();
        bytes4 sel = token.paused.selector;
        token.setMutator(sel, FixtureMutator.REVERT, 0, bytes32(0), bytes32(0));
        (bool success1, uint256 size1, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertFalse(success1, "C6: REVERT mutator must fail the staticcall");
        assertEq(size1, 0, "C6: REVERT mutator must return zero bytes");

        token.setMutator(sel, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool success2, uint256 size2, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(success2, "C6: NORMAL mutator must succeed");
        assertEq(size2, 32, "C6: NORMAL mutator must return exactly 32 bytes");
    }

    function test_C6_mutator_length0() public {
        MockEquityToken token = new MockEquityToken();
        bytes4 sel = token.uiMultiplier.selector;
        token.setMutator(sel, FixtureMutator.LENGTH, 0, bytes32(0), bytes32(0));
        (bool success, uint256 size, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(success, "C6: LENGTH 0 mutator must still succeed the call");
        assertEq(size, 0, "C6: LENGTH 0 mutator must return zero bytes");

        token.setMutator(sel, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool success2, uint256 size2, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(success2, "C6: restore to NORMAL must succeed");
        assertEq(size2, 32, "C6: restore to NORMAL must return 32 bytes");
    }

    function test_C6_mutator_length31() public {
        MockEquityToken token = new MockEquityToken();
        token.setPaused(true);
        bytes4 sel = token.paused.selector;
        token.setMutator(sel, FixtureMutator.LENGTH, 31, bytes32(0), bytes32(0));
        (bool success, uint256 size, bytes memory head) =
            _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 31);
        assertTrue(success, "C6: LENGTH 31 mutator must succeed");
        assertEq(size, 31, "C6: LENGTH 31 mutator must return exactly 31 bytes");
        bytes memory expected = new bytes(31);
        bytes32 normalWord = bytes32(uint256(1));
        for (uint256 i = 0; i < 31; i++) {
            expected[i] = normalWord[i];
        }
        assertEqBytes(head, expected, "C6: LENGTH 31 bytes must be the first 31 bytes of the normal word (pausedFlag is true)");

        token.setMutator(sel, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool successR, uint256 sizeR, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(successR, "C6: restore to NORMAL must succeed");
        assertEq(sizeR, 32, "C6: restore to NORMAL must return 32 bytes");
    }

    function test_C6_mutator_length64() public {
        MockEquityToken token = new MockEquityToken();
        bytes4 sel = token.paused.selector;
        token.setPaused(true);
        token.setMutator(sel, FixtureMutator.LENGTH, 64, bytes32(0), bytes32(0));
        (bool success, uint256 size, bytes memory head) =
            _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 64);
        assertTrue(success, "C6: LENGTH 64 mutator must succeed");
        assertEq(size, 64, "C6: LENGTH 64 mutator must return exactly 64 bytes");
        bytes32 word0;
        bytes32 word1;
        assembly {
            word0 := mload(add(head, 32))
            word1 := mload(add(head, 64))
        }
        assertEqBytes32(word0, bytes32(uint256(1)), "C6: LENGTH 64 word0 must equal the normal word (pausedFlag is true)");
        assertEqBytes32(word1, bytes32(0), "C6: LENGTH 64 word1 (explicit zero padding) must be zero");

        token.setMutator(sel, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool successR, uint256 sizeR, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(successR, "C6: restore to NORMAL must succeed");
        assertEq(sizeR, 32, "C6: restore to NORMAL must return 32 bytes");
    }

    function test_C6_mutator_boolWordTwo() public {
        MockEquityToken token = new MockEquityToken();
        bytes32 wordTwo = bytes32(uint256(2));

        bytes4 pausedSel = token.paused.selector;
        token.setMutator(pausedSel, FixtureMutator.RAW_WORD, 0, wordTwo, bytes32(0));
        (bool successP, uint256 sizeP, bytes memory headP) =
            _raw(address(token), abi.encodeWithSelector(pausedSel), gasleft(), 32);
        assertTrue(successP, "C6: RAW_WORD on paused() must succeed");
        assertEq(sizeP, 32, "C6: RAW_WORD on paused() must return 32 bytes");
        bytes32 gotP;
        assembly { gotP := mload(add(headP, 32)) }
        assertEqBytes32(gotP, wordTwo, "C6: paused() RAW_WORD must be the exact word 2");

    }

    function test_C6_mutator_hugeUint256() public {
        MockEquityToken token = new MockEquityToken();
        bytes32 maxWord = bytes32(type(uint256).max);
        bytes4 sel = token.uiMultiplier.selector;
        token.setMutator(sel, FixtureMutator.RAW_WORD, 0, maxWord, bytes32(0));
        (bool success, uint256 size, bytes memory head) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(success, "C6: RAW_WORD hugeUint256 must succeed");
        assertEq(size, 32, "C6: RAW_WORD hugeUint256 must return 32 bytes");
        bytes32 got;
        assembly { got := mload(add(head, 32)) }
        assertEqBytes32(got, maxWord, "C6: uiMultiplier() RAW_WORD must be exactly type(uint256).max");

        token.setMutator(sel, FixtureMutator.NORMAL, 0, bytes32(0), bytes32(0));
        (bool successR, uint256 sizeR, ) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 32);
        assertTrue(successR, "C6: restore to NORMAL must succeed");
        assertEq(sizeR, 32, "C6: restore to NORMAL must return 32 bytes");
    }

    function test_C6_effectiveAtAbove2pow64() public {
        MockEquityToken token = new MockEquityToken();
        uint256 farFuture = (uint256(1) << 64) + 1;
        token.setRatios(1e18, 1e18, farFuture);
        (bool success, uint256 size, bytes memory head) =
            _raw(address(token), abi.encodeWithSignature("effectiveAt()"), gasleft(), 32);
        assertTrue(success, "C6: effectiveAt() must answer after setRatios");
        assertEq(size, 32, "C6: effectiveAt() must return exactly 32 bytes");
        bytes32 got;
        assembly { got := mload(add(head, 32)) }
        assertEqBytes32(got, bytes32(farFuture), "C6: effectiveAt() must round-trip a value above 2**64 without truncation");
    }

    function test_C6_mutator_gasBand() public {
        MockEquityToken token = new MockEquityToken();
        bytes32 wordA = bytes32(uint256(1));
        bytes32 wordB = bytes32(uint256(2));
        bytes4 sel = token.effectiveAt.selector;
        token.setMutator(sel, FixtureMutator.GAS_BAND, GAS_BAND_THRESHOLD, wordA, wordB);

        (bool s1, uint256 sz1, bytes memory h1) = _raw(address(token), abi.encodeWithSelector(sel), BUDGET_HIGH, 32);
        assertTrue(s1, "C6: GAS_BAND high budget must succeed");
        assertEq(sz1, 32, "C6: GAS_BAND high budget must return 32 bytes");
        bytes32 got1;
        assembly { got1 := mload(add(h1, 32)) }
        assertEqBytes32(got1, wordA, "C6: GAS_BAND high budget must answer wordA");

        (bool s2, uint256 sz2, bytes memory h2) = _raw(address(token), abi.encodeWithSelector(sel), BUDGET_LOW, 32);
        assertTrue(s2, "C6: GAS_BAND low budget must succeed");
        assertEq(sz2, 32, "C6: GAS_BAND low budget must return 32 bytes");
        bytes32 got2;
        assembly { got2 := mload(add(h2, 32)) }
        assertEqBytes32(got2, wordB, "C6: GAS_BAND low budget must answer wordB");

        (bool s3, , bytes memory h3) = _raw(address(token), abi.encodeWithSelector(sel), BUDGET_HIGH, 32);
        assertTrue(s3, "C6: GAS_BAND second high budget must succeed");
        bytes32 got3;
        assembly { got3 := mload(add(h3, 32)) }
        assertEqBytes32(got3, wordA, "C6: GAS_BAND second high budget must again answer wordA");
    }

    function test_C6_mutator_burn() public {
        MockEquityToken token = new MockEquityToken();
        bytes4 sel = token.uiMultiplier.selector;
        bytes memory cd = abi.encodeWithSelector(sel);

        _gasUsed(address(token), cd, BURN_BUDGET);
        (bool clean1, uint256 cleanUsed1) = _gasUsed(address(token), cd, BURN_BUDGET);
        assertTrue(clean1, "C6: first NORMAL measurement (post warm-up) must succeed");
        (bool clean2, uint256 cleanUsed2) = _gasUsed(address(token), cd, BURN_BUDGET);
        assertTrue(clean2, "C6: second NORMAL measurement must succeed");
        assertEq(cleanUsed1, cleanUsed2, "C6: two NORMAL measurements must consume identical gas");

        token.setMutator(sel, FixtureMutator.BURN, BURN_AMOUNT, bytes32(0), bytes32(0));
        (bool burned, uint256 burnUsed) = _gasUsed(address(token), cd, BURN_BUDGET);
        assertTrue(burned, "C6: bounded BURN must still succeed within its budget");
        assertTrue(burnUsed > cleanUsed2 + (BURN_AMOUNT / 2), "C6: bounded BURN must consume materially more gas than clean");

        token.setMutator(sel, FixtureMutator.BURN, type(uint256).max, bytes32(0), bytes32(0));
        (bool exhausted, ) = _gasUsed(address(token), cd, BURN_BUDGET);
        assertFalse(exhausted, "C6: BURN at max with a fixed budget must exhaust gas and fail");
    }

    function test_C6_mutator_unknownKindReverts() public {
        MockEquityToken token = new MockEquityToken();
        bytes4 sel = token.paused.selector;
        token.setMutator(sel, 9, 0, bytes32(0), bytes32(0));
        (bool success, uint256 size, bytes memory head) = _raw(address(token), abi.encodeWithSelector(sel), gasleft(), 36);
        assertFalse(success, "C6: unknown mutator kind must fail the call");
        bytes memory expected = abi.encodeWithSelector(FixtureMutator.UnknownMutatorKind.selector, uint8(9));
        assertEq(size, expected.length, "C6: unknown mutator kind revert data length must match UnknownMutatorKind(9)");
        assertEqBytes(head, expected, "C6: unknown mutator kind must revert with UnknownMutatorKind(9)");
    }

    function test_C6_multiplierScaling_crossesEffAtWithReverseArm() public {
        MockEquityToken token = new MockEquityToken();
        vm.warp(T0);
        uint256 rawAmount = 1e18 + 1;
        uint256 newUi_ = 333_333_333_333_333_333;
        token.mintRaw(ACTOR, rawAmount);
        token.setRatios(1e18, newUi_, T0 + 1000);

        assertEq(token.balanceOf(ACTOR), (rawAmount * 1e18) / 1e18, "C6: at T0 balance must match raw*m/WAD with m == ui");
        assertEq(token.balanceOf(ACTOR), rawAmount, "C6: at T0 balance must equal raw exactly (m == 1e18)");
        assertEq(token.rawOf(ACTOR), rawAmount, "C6: rawOf must be untouched by reading balanceOf");

        vm.warp(T0 + 999);
        assertEq(token.balanceOf(ACTOR), (rawAmount * 1e18) / 1e18, "C6: one second before effectiveAt must still match raw*m/WAD with the old m");
        assertEq(token.balanceOf(ACTOR), rawAmount, "C6: reverse arm -- one second before effectiveAt must still use ui, not newUi");
        assertEq(token.rawOf(ACTOR), rawAmount, "C6: rawOf must be unchanged before the transition");

        vm.warp(T0 + 1000);
        assertEq(token.balanceOf(ACTOR), (rawAmount * newUi_) / 1e18, "C6: at effectiveAt balance must match raw*m/WAD with the new m");
        assertEq(token.balanceOf(ACTOR), newUi_, "C6: at effectiveAt (>=) balance must switch to newUi");
        assertEq(token.rawOf(ACTOR), rawAmount, "C6: rawOf must be unchanged across the entire transition");
    }

    function test_C6_transferRoundsRawDeltaUpAndConservesRaw() public {
        MockEquityToken token = new MockEquityToken();
        token.setRatios(3e18, 3e18, 0);
        token.mintRaw(ACTOR, 10);

        vm.prank(ACTOR);
        bool ok = token.transfer(COUNTERPARTY, 1);
        assertTrue(ok, "C6: transfer must report success");

        assertEq(token.rawOf(ACTOR), 9, "C6: transfer must round rawDelta up (9 remaining, not 10)");
        assertEq(token.rawOf(COUNTERPARTY), 1, "C6: recipient must gain the rounded-up rawDelta");
        assertEq(token.balanceOf(ACTOR), 27, "C6: sender display balance must reflect the raw ledger under m=3e18");
        assertEq(token.balanceOf(COUNTERPARTY), 3, "C6: recipient display balance must reflect the raw ledger under m=3e18");
        assertEq(token.rawOf(ACTOR) + token.rawOf(COUNTERPARTY), 10, "C6: raw units must be conserved across the transfer");
        assertEq(token.rawTotal(), 10, "C6: rawTotal must be unaffected by a transfer (only mintRaw changes it)");
    }

    function test_C6_transferRevertsOnInsufficientRawOrOverflow() public {
        MockEquityToken token = new MockEquityToken();
        token.setRatios(1e18, 1e18, 0);
        token.mintRaw(ACTOR, 1);

        vm.prank(ACTOR);
        vm.expectRevert(abi.encodeWithSelector(MockEquityToken.InsufficientRaw.selector, ACTOR, uint256(1), uint256(2)));
        token.transfer(COUNTERPARTY, 2);

        vm.prank(ACTOR);
        vm.expectRevert(abi.encodeWithSignature("Panic(uint256)", uint256(0x11)));
        token.transfer(COUNTERPARTY, type(uint256).max);
    }

    function test_C6_zeroMultiplier_balanceZeroTransferReverts() public {
        MockEquityToken token = new MockEquityToken();
        token.mintRaw(ACTOR, 5);

        assertEq(token.balanceOf(ACTOR), 0, "C6: balanceOf must be zero when m == 0 (ui/newUi never set)");
        assertEq(token.totalSupply(), 0, "C6: totalSupply must be zero when m == 0");

        vm.prank(ACTOR);
        vm.expectRevert(abi.encodeWithSelector(MockEquityToken.ZeroMultiplier.selector));
        token.transfer(COUNTERPARTY, 1);
    }

    function test_C6_transferFromSpendsDisplayAllowance() public {
        MockEquityToken token = new MockEquityToken();
        address spender = address(uint160(uint256(keccak256("rwa-guard.u5.p4.spender"))));
        token.setRatios(1e18, 1e18, 0);
        token.mintRaw(ACTOR, 10);

        vm.prank(ACTOR);
        token.approve(spender, 5);

        vm.prank(spender);
        bool ok = token.transferFrom(ACTOR, COUNTERPARTY, 3);
        assertTrue(ok, "C6: transferFrom within allowance must succeed");
        assertEq(token.allowance(ACTOR, spender), 2, "C6: allowance must be decremented by the display-unit amount spent");

        vm.prank(spender);
        vm.expectRevert(
            abi.encodeWithSelector(MockEquityToken.InsufficientAllowance.selector, ACTOR, spender, uint256(2), uint256(3))
        );
        token.transferFrom(ACTOR, COUNTERPARTY, 3);
    }

    function test_C6_reentrancyCallbackFires() public {
        MockEquityToken token = new MockEquityToken();
        token.setRatios(1e18, 1e18, 0);
        token.mintRaw(ACTOR, 5);

        CallbackProbe probe = new CallbackProbe();

        token.setCallback(address(probe), abi.encodeWithSelector(CallbackProbe.hit.selector));
        vm.prank(ACTOR);
        token.transfer(COUNTERPARTY, 1);
        assertEq(probe.hits(), 1, "C6: transfer with a hit() callback must fire it exactly once");
        assertEq(probe.lastCaller(), address(token), "C6: the callback must observe the token contract as its caller");

        token.setCallback(address(0), "");
        vm.prank(ACTOR);
        token.transfer(COUNTERPARTY, 1);
        assertEq(probe.hits(), 1, "C6: clearing the callback (target == address(0)) must disable it (control arm)");

        token.setCallback(address(probe), abi.encodeWithSelector(CallbackProbe.fail.selector));
        vm.prank(ACTOR);
        vm.expectRevert(abi.encodeWithSelector(ProbeFailed.selector));
        token.transfer(COUNTERPARTY, 1);
    }


    function test_etchPath_fixtureCodehashEqualsKnownConstant() public {
        bytes memory runtime = _loadFixtureRuntime();
        assertEq(runtime.length, 283, "ETCH: checked-in fixture runtime must be exactly 283 bytes");
        assertEqBytes32(
            keccak256(runtime),
            GuardCore.KNOWN_PROXY_CODEHASH,
            "ETCH: keccak256 of the checked-in runtime must equal GuardCore.KNOWN_PROXY_CODEHASH"
        );

        vm.etch(EQUITY_ETCH_ADDR, runtime);
        assertEqBytes32(
            EQUITY_ETCH_ADDR.codehash,
            GuardCore.KNOWN_PROXY_CODEHASH,
            "ETCH: EXTCODEHASH of the etched address must equal the known constant"
        );

        // Control: a plain (non-etched) MockEquityToken deployment must NOT collide with the
        // known proxy codehash, or this self-check would pass for a reason unrelated to the etch.
        address plainToken = address(new MockEquityToken());
        assertTrue(
            plainToken.codehash != GuardCore.KNOWN_PROXY_CODEHASH,
            "ETCH: a plain (non-etched) MockEquityToken deployment must not match the known proxy codehash"
        );
    }

    function test_proxyForwarding_stateLandsOnTokenStorage() public {
        // ① etch the control-plane fixture at the guard's compile-time CONTROL_PLANE constant.
        vm.etch(GuardCore.CONTROL_PLANE, address(new MockControlPlane()).code);
        // ② deploy the token fixture as the logic contract, point the plane's `impl` at it.
        MockEquityToken logic = new MockEquityToken();
        MockControlPlane(GuardCore.CONTROL_PLANE).setImplementation(address(logic));
        // ③ etch the checked-in real proxy runtime at a fresh token address.
        vm.etch(EQUITY_ETCH_ADDR, _loadFixtureRuntime());
        // ④ the etched proxy's codehash must match the guard's compile-time constant.
        assertEqBytes32(
            EQUITY_ETCH_ADDR.codehash,
            GuardCore.KNOWN_PROXY_CODEHASH,
            "PROXY: etched proxy codehash must equal GuardCore.KNOWN_PROXY_CODEHASH"
        );
        // ⑤ writing through the proxy address must land on the token fixture's own storage. A
        // failure here means the delegatecall assumption this file relies on does not hold, and
        // that must be reported, never worked around.
        MockEquityToken(EQUITY_ETCH_ADDR).setRatios(1e18, 1e18, 0);
        bytes memory tokenHead = _p5_rawUiMultiplier(EQUITY_ETCH_ADDR);
        assertEqBytes32(
            _p5_wordAt(tokenHead, 0),
            bytes32(uint256(1e18)),
            "PROXY: setRatios via the proxy must land on the token's own storage, read back through the proxy"
        );
        // ⑥ control: the logic contract's own address must never receive that write --
        // delegatecall never touches the callee's own storage.
        bytes memory logicHead = _p5_rawUiMultiplier(address(logic));
        assertEqBytes32(
            _p5_wordAt(logicHead, 0),
            bytes32(uint256(0)),
            "PROXY: the logic contract's own storage must remain untouched by calls made through the proxy"
        );
    }

    function test_AS38_surface() public {
        MockPriceFeed feed = new MockPriceFeed();

        (bool okRound, uint256 sizeRound,) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), gasleft(), 0);
        assertTrue(okRound, "AS-38: fresh C9 latestRoundData() must succeed");
        assertEq(sizeRound, 160, "AS-38: fresh C9 latestRoundData() must return exactly 160 bytes");

        (bool okDesc, uint256 sizeDesc, bytes memory headDesc) =
            _raw(address(feed), abi.encodeWithSignature("description()"), gasleft(), 64);
        assertTrue(okDesc, "AS-38: fresh C9 description() must succeed");
        assertEq(sizeDesc, 64, "AS-38: fresh C9 description() with an unset text must return 64 bytes");
        assertEqBytes32(_p5_wordAt(headDesc, 0), bytes32(uint256(0x20)), "AS-38: description() offset word must be 0x20");
        assertEqBytes32(_p5_wordAt(headDesc, 32), bytes32(uint256(0)), "AS-38: description() length word must be 0 for an unset text");

        (bool okPaused,,) = _raw(address(feed), abi.encodeWithSignature("paused()"), gasleft(), 0);
        assertFalse(okPaused, "AS-38: C9 must not implement paused()");
        (bool okBlocked,,) =
            _raw(address(feed), abi.encodeWithSignature("isBlocked(address)", ACTOR), gasleft(), 0);
        assertFalse(okBlocked, "AS-38: C9 must not implement isBlocked(address)");
        (bool okImpl,,) = _raw(address(feed), abi.encodeWithSignature("implementation()"), gasleft(), 0);
        assertFalse(okImpl, "AS-38: C9 must not implement implementation()");
        (bool okDecimals,,) = _raw(address(feed), abi.encodeWithSignature("decimals()"), gasleft(), 0);
        assertFalse(okDecimals, "AS-38: C9 must not implement decimals()");
        (bool okSymbol,,) = _raw(address(feed), abi.encodeWithSignature("symbol()"), gasleft(), 0);
        assertFalse(okSymbol, "AS-38: C9 must not implement symbol()");
    }

    function test_AS38_feedMode_clean() public {
        MockPriceFeed feed = new MockPriceFeed();
        uint256 roundId_ = (uint256(1) << 200) | 7;
        uint256 answeredInRound_ = (uint256(1) << 201) | 9;
        feed.setRound(roundId_, 1e8, 111, 222, answeredInRound_);
        vm.warp(T0);

        bytes memory head = _p5_rawLatestRound(address(feed), gasleft());
        assertEqBytes32(_p5_wordAt(head, 0), bytes32(roundId_), "AS-38: CLEAN w0 must equal the stored roundId, full width");
        assertEqBytes32(_p5_wordAt(head, 32), bytes32(uint256(1e8)), "AS-38: CLEAN w1 must equal the stored signed answer");
        assertEqBytes32(_p5_wordAt(head, 64), bytes32(uint256(111)), "AS-38: CLEAN w2 (startedAt) must equal the stored value");
        assertEqBytes32(_p5_wordAt(head, 96), bytes32(T0), "AS-38: CLEAN w3 (updatedAt) must follow block.timestamp when followNow is on");
        assertEqBytes32(_p5_wordAt(head, 128), bytes32(answeredInRound_), "AS-38: CLEAN w4 must equal the stored answeredInRound, full width");
    }

    function test_AS38_feedMode_revert() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setFeedMode(1 /* FEED_REVERT, see §5b table */, 0);
        (bool ok, uint256 size,) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), gasleft(), 0);
        assertFalse(ok, "AS-38: FEED_REVERT must make latestRoundData() fail");
        assertEq(size, 0, "AS-38: FEED_REVERT must return zero bytes");
    }

    function test_AS38_feedMode_short0() public {
        _p5_assertShortMatchesCleanPrefix(0);
    }

    function test_AS38_feedMode_short32() public {
        _p5_assertShortMatchesCleanPrefix(32);
    }

    function test_AS38_feedMode_short128() public {
        _p5_assertShortMatchesCleanPrefix(128);
    }

    function test_AS38_feedMode_short159() public {
        _p5_assertShortMatchesCleanPrefix(159);
    }

    function test_AS38_feedMode_long192() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setRound((uint256(1) << 90) | 5, 123_456, 10, 20, (uint256(1) << 91) | 6);
        bytes memory refClean = _p5_referenceClean(address(feed));

        feed.setFeedMode(3 /* FEED_LONG, see §5b table */, 0);
        (bool ok, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), gasleft(), 192);
        assertTrue(ok, "AS-38: FEED_LONG must succeed");
        assertEq(size, 192, "AS-38: FEED_LONG must return exactly 192 bytes");
        assertEqBytes(
            _p5_slice(head, 0, 160), refClean, "AS-38: FEED_LONG's first 160 bytes must equal the CLEAN encoding"
        );
        assertEqBytes32(_p5_wordAt(head, 160), bytes32(0), "AS-38: FEED_LONG's trailing 32 bytes must be zero");
    }

    function test_AS38_feedMode_gasBand() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setRound(10, 10, 10, 10, 10);
        feed.setFeedMode(4 /* FEED_GAS_BAND, see §5b table */, 0);
        feed.setGasBand(GAS_BAND_THRESHOLD, 11, 9);

        bytes memory highHead1 = _p5_rawLatestRound(address(feed), BUDGET_HIGH);
        assertEqBytes32(_p5_wordAt(highHead1, 0), bytes32(uint256(10)), "AS-38: GAS_BAND above threshold must return the primary roundId");
        assertEqBytes32(_p5_wordAt(highHead1, 128), bytes32(uint256(10)), "AS-38: GAS_BAND above threshold must return the primary answeredInRound");

        bytes memory lowHead = _p5_rawLatestRound(address(feed), BUDGET_LOW);
        assertEqBytes32(_p5_wordAt(lowHead, 0), bytes32(uint256(11)), "AS-38: GAS_BAND below threshold must return the alternate roundId");
        assertEqBytes32(_p5_wordAt(lowHead, 128), bytes32(uint256(9)), "AS-38: GAS_BAND below threshold must return the alternate answeredInRound");
        assertTrue(uint256(_p5_wordAt(lowHead, 128)) < uint256(_p5_wordAt(lowHead, 0)), "AS-38: the GAS_BAND alternate pair must be internally incoherent (answeredInRound < roundId)");

        bytes memory highHead2 = _p5_rawLatestRound(address(feed), BUDGET_HIGH);
        assertEqBytes(highHead1, highHead2, "AS-38: two calls at the same high gas budget must return identical bytes");
    }

    function test_AS38_feedMode_burn() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setRound(1, 1, 1, 1, 1);
        bytes memory cd = abi.encodeWithSignature("latestRoundData()");

        // Warm-up: makes clean1 and clean2 both follow a STATICCALL to the feed, so both carry the same caller-side access charge (on foundry 1.8.1 that charge depends on the kind of the preceding call, not on the feed's state).
        (bool warmOk,) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertTrue(warmOk, "AS-38: CLEAN warm-up call must succeed");

        (bool clean1Ok, uint256 clean1Used) = _gasUsed(address(feed), cd, BURN_BUDGET);
        (bool clean2Ok, uint256 clean2Used) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertTrue(clean1Ok, "AS-38: first CLEAN measurement must succeed");
        assertTrue(clean2Ok, "AS-38: second CLEAN measurement must succeed");
        assertEq(clean1Used, clean2Used, "AS-38: two CLEAN measurements at the same budget must consume identical gas");

        // Control: CLEAN's cost must not depend on the stored _gasBurn value -- only FEED_BURN acts on it.
        // Both measurements below follow the same non-static CALL to the feed (a setGasBurn write): on
        // foundry 1.8.1 the caller-side cost of a measured STATICCALL depends on the kind of call that
        // precedes it (+2500 after a STATICCALL to the same address). Only the stored value differs.
        feed.setGasBurn(0);
        (bool zeroBurnOk, uint256 zeroBurnUsed) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertTrue(zeroBurnOk, "AS-38: CLEAN after setGasBurn(0) must succeed");
        feed.setGasBurn(BURN_AMOUNT);
        (bool setterOnlyOk, uint256 setterOnlyUsed) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertTrue(setterOnlyOk, "AS-38: CLEAN with a stored burn amount must still succeed");
        assertEq(setterOnlyUsed, zeroBurnUsed, "AS-38: setGasBurn without FEED_BURN must not change CLEAN gas");

        feed.setFeedMode(5 /* FEED_BURN, see §5b table */, 0);
        (bool burnOk, uint256 burnUsed) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertTrue(burnOk, "AS-38: a bounded BURN must still return successfully");
        assertTrue(burnUsed > zeroBurnUsed + BURN_AMOUNT / 2, "AS-38: a bounded BURN must consume meaningfully more gas than CLEAN");

        feed.setGasBurn(type(uint256).max);
        (bool exhaustOk,) = _gasUsed(address(feed), cd, BURN_BUDGET);
        assertFalse(exhaustOk, "AS-38: an unbounded BURN must exhaust the fixed budget and fail");
    }

    function test_AS38_feedMode_unknownReverts() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setFeedMode(6, 0);
        (bool ok, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), gasleft(), 36);
        assertFalse(ok, "AS-38: an unknown feedMode must revert, never fall back to CLEAN");
        assertEq(size, 36, "AS-38: UnknownFeedMode(uint8) revert data must be exactly 36 bytes");
        assertEqBytes(
            head,
            abi.encodeWithSelector(MockPriceFeed.UnknownFeedMode.selector, uint8(6)),
            "AS-38: an unknown feedMode must revert with UnknownFeedMode(mode)"
        );
    }

    function test_AS38_descMode_clean() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescriptionText(bytes("MOCK / USD"));
        (bool ok, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), gasleft(), 96);
        assertTrue(ok, "AS-38: CLEAN description() must succeed");
        assertEq(size, 96, "AS-38: CLEAN description() for a 10-byte text must return 96 bytes");
        assertEqBytes32(_p5_wordAt(head, 0), bytes32(uint256(0x20)), "AS-38: description() offset word must be 0x20");
        assertEqBytes32(_p5_wordAt(head, 32), bytes32(uint256(10)), "AS-38: description() length word must equal the text length");

        bytes memory body = _p5_slice(head, 64, 32);
        bytes memory text = bytes("MOCK / USD");
        for (uint256 i = 0; i < 10; i++) {
            assertEq(uint256(uint8(body[i])), uint256(uint8(text[i])), "AS-38: description() body bytes 64..73 must equal the stored text");
        }
        for (uint256 i = 10; i < 32; i++) {
            assertEq(uint256(uint8(body[i])), 0, "AS-38: description() body bytes 74..95 must be zero padding");
        }
    }

    // ── part5 private helpers ──────────────────────────────────────────────

    function _p5_wordAt(bytes memory data, uint256 offset) private pure returns (bytes32 word) {
        assembly {
            word := mload(add(add(data, 32), offset))
        }
    }

    function _p5_slice(bytes memory data, uint256 offset, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[offset + i];
        }
    }

    function _p5_rawUiMultiplier(address target) private view returns (bytes memory head) {
        (bool ok, uint256 size, bytes memory h) =
            _raw(target, abi.encodeWithSignature("uiMultiplier()"), gasleft(), 32);
        assertTrue(ok, "PROXY: raw uiMultiplier() staticcall must succeed");
        assertEq(size, 32, "PROXY: raw uiMultiplier() must return exactly 32 bytes");
        head = h;
    }

    function _p5_rawLatestRound(address feedAddr, uint256 gasBudget) private view returns (bytes memory head) {
        (bool ok, uint256 size, bytes memory h) =
            _raw(feedAddr, abi.encodeWithSignature("latestRoundData()"), gasBudget, 160);
        assertTrue(ok, "AS-38: latestRoundData() staticcall must succeed within the given gas budget");
        assertEq(size, 160, "AS-38: latestRoundData() must return exactly 160 bytes");
        head = h;
    }

    function _p5_referenceClean(address feedAddr) private view returns (bytes memory refClean) {
        // feedAddr is still in its default FEED_CLEAN mode here; capture the canonical 160-byte
        // encoding once, before the caller switches to FEED_SHORT/FEED_LONG on the same config.
        refClean = _p5_rawLatestRound(feedAddr, gasleft());
    }

    function _p5_assertShortMatchesCleanPrefix(uint256 arg) private {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setRound((uint256(1) << 100) | 42, -777, 111, 222, (uint256(1) << 101) | 43);
        bytes memory refClean = _p5_referenceClean(address(feed));

        feed.setFeedMode(2 /* FEED_SHORT, see §5b table */, arg);
        (bool ok, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), gasleft(), arg);
        assertTrue(ok, "AS-38: FEED_SHORT must succeed for an in-domain length");
        assertEq(size, arg, "AS-38: FEED_SHORT must return exactly `arg` bytes");
        assertEqBytes(
            head,
            _p5_slice(refClean, 0, arg),
            "AS-38: FEED_SHORT's returned bytes must be an exact prefix of the CLEAN encoding"
        );
    }


    function test_AS38_descMode_revert() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescMode(1, 0); // DESC_REVERT

        (bool success, uint256 size, ) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 0);

        assertFalse(success, "AS-38: DESC_REVERT must not answer");
        assertEq(size, 0, "AS-38: DESC_REVERT must produce zero returndata (revert(0,0))");
    }

    function test_AS38_descMode_short0() public {
        MockPriceFeed feed = new MockPriceFeed();

        (bool cleanOk, uint256 cleanSize, bytes memory cleanHead) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);
        assertTrue(cleanOk, "AS-38: DESC_CLEAN reference read must succeed before switching to SHORT");
        assertEq(cleanSize, 64, "AS-38: an empty description's CLEAN encoding must be exactly 64 bytes");

        feed.setDescMode(2, 0); // DESC_SHORT, arg 0

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);

        assertTrue(success, "AS-38: DESC_SHORT(0) must still answer");
        assertEq(size, 0, "AS-38: DESC_SHORT(0) returndatasize must equal the configured arg");
        assertEqBytes(head, _p6_slice(cleanHead, 0), "AS-38: DESC_SHORT(0) must be an exact prefix of the CLEAN encoding");
    }

    function test_AS38_descMode_short32() public {
        MockPriceFeed feed = new MockPriceFeed();

        (bool cleanOk, uint256 cleanSize, bytes memory cleanHead) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);
        assertTrue(cleanOk, "AS-38: DESC_CLEAN reference read must succeed before switching to SHORT");
        assertEq(cleanSize, 64, "AS-38: an empty description's CLEAN encoding must be exactly 64 bytes");

        feed.setDescMode(2, 32); // DESC_SHORT, arg 32

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);

        assertTrue(success, "AS-38: DESC_SHORT(32) must still answer");
        assertEq(size, 32, "AS-38: DESC_SHORT(32) returndatasize must equal the configured arg");
        assertEqBytes(head, _p6_slice(cleanHead, 32), "AS-38: DESC_SHORT(32) must be an exact prefix of the CLEAN encoding");
    }

    function test_AS38_descMode_short63() public {
        MockPriceFeed feed = new MockPriceFeed();

        (bool cleanOk, uint256 cleanSize, bytes memory cleanHead) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);
        assertTrue(cleanOk, "AS-38: DESC_CLEAN reference read must succeed before switching to SHORT");
        assertEq(cleanSize, 64, "AS-38: an empty description's CLEAN encoding must be exactly 64 bytes");

        feed.setDescMode(2, 63); // DESC_SHORT, arg 63

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 64);

        assertTrue(success, "AS-38: DESC_SHORT(63) must still answer");
        assertEq(size, 63, "AS-38: DESC_SHORT(63) returndatasize must equal the configured arg");
        assertEqBytes(head, _p6_slice(cleanHead, 63), "AS-38: DESC_SHORT(63) must be an exact prefix of the CLEAN encoding");
    }

    function test_AS38_descMode_badOffset() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescriptionText(bytes("MOCK / USD"));
        feed.setDescMode(3, 0x40); // DESC_BAD_OFFSET, arg != 0x20 so the setter accepts it

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 96);

        assertTrue(success, "AS-38: DESC_BAD_OFFSET must answer");
        assertEq(size, 64, "AS-38: DESC_BAD_OFFSET returndatasize must be exactly 64");
        assertEqBytes32(_p6_wordAt(head, 0), bytes32(uint256(0x40)), "AS-38: DESC_BAD_OFFSET word0 must equal the configured bad offset");
        assertEqBytes32(_p6_wordAt(head, 32), bytes32(uint256(0)), "AS-38: DESC_BAD_OFFSET word1 must be 0 (the only legal length for a 64-byte answer), independent of the stored text");
    }

    function test_AS38_descMode_hugeLen() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescMode(4, 0); // DESC_HUGE_LEN; arg is unused by this mode

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 96);

        assertTrue(success, "AS-38: DESC_HUGE_LEN must answer");
        assertEq(size, 64, "AS-38: DESC_HUGE_LEN returndatasize must be exactly 64");
        assertEqBytes32(_p6_wordAt(head, 0), bytes32(uint256(0x20)), "AS-38: DESC_HUGE_LEN word0 must be the ABI string offset");
        assertEqBytes32(_p6_wordAt(head, 32), bytes32(type(uint256).max), "AS-38: DESC_HUGE_LEN word1 must be type(uint256).max");
    }

    function test_AS38_descMode_bomb() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescMode(5, BOMB_BYTES); // DESC_BOMB

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BOMB_BUDGET, 64);

        assertTrue(success, "AS-38: DESC_BOMB must still answer under a bounded gas budget");
        assertEq(size, 64 + BOMB_BYTES, "AS-38: DESC_BOMB returndatasize must equal 64 + the configured bomb length");
        assertEqBytes32(_p6_wordAt(head, 0), bytes32(uint256(0x20)), "AS-38: DESC_BOMB word0 must be the ABI string offset");
        assertEqBytes32(_p6_wordAt(head, 32), bytes32(BOMB_BYTES), "AS-38: DESC_BOMB word1 must equal the configured bomb length");
    }

    function test_AS38_descMode_tailPadIsAnswered() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescriptionText("MOCK / USD");

        (bool cleanOk, uint256 cleanSize, bytes memory cleanHead) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 96);
        assertTrue(cleanOk, "AS-38: DESC_CLEAN reference read must succeed before switching to TAIL_PAD");
        assertEq(cleanSize, 96, "AS-38: DESC_CLEAN reference size must be 96 for a 10-byte description");

        feed.setDescMode(6, 0); // DESC_TAIL_PAD; arg is unused by this mode

        (bool success, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 128);

        assertTrue(success, "AS-38: DESC_TAIL_PAD must answer");
        assertEq(size, 128, "AS-38: DESC_TAIL_PAD returndatasize must be 96 (CLEAN) + 32 (pad)");
        assertEqBytes(_p6_slice(head, 96), cleanHead, "AS-38: DESC_TAIL_PAD's first 96 bytes must equal the CLEAN encoding");
        assertEqBytes32(_p6_wordAt(head, 96), bytes32(0), "AS-38: DESC_TAIL_PAD's trailing 32 bytes must be explicitly zero");

        assertTrue(
            GuardCore._answersDescription(address(feed)),
            "AS-38: the guard's <= criterion must treat TAIL_PAD's extra padding as answered"
        );

        feed.setDescMode(2, 63); // DESC_SHORT, arg < 64 (negative control on the same feed)
        assertFalse(
            GuardCore._answersDescription(address(feed)),
            "AS-38: DESC_SHORT below 64 bytes must fail the guard's returndatasize() >= 64 criterion"
        );
    }

    function test_AS38_descMode_unknownReverts() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setDescMode(7, 0); // unknown mode number; the setter does not reject it

        (bool success, , bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("description()"), BUDGET_HIGH, 36);

        assertFalse(success, "AS-38: an unrecognized descMode must revert, never silently fall back to CLEAN");
        assertEqBytes(
            head,
            abi.encodeWithSelector(MockPriceFeed.UnknownDescMode.selector, uint8(7)),
            "AS-38: descMode default branch must revert UnknownDescMode(mode)"
        );
    }

    function test_AS38_followNow_withReverseArm() public {
        MockPriceFeed feed = new MockPriceFeed();

        vm.warp(T0);
        (bool ok1, uint256 size1, bytes memory head1) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);
        assertTrue(ok1, "AS-38: default-on followNow must answer with no setter calls at all");
        assertEq(size1, 160, "AS-38: default-on followNow must return exactly 160 bytes");
        assertEqBytes32(_p6_wordAt(head1, 96), bytes32(T0), "AS-38: default-on followNow must evaluate updatedAt = block.timestamp at T0");

        vm.warp(T0 + 500);
        (, , bytes memory head2) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);
        assertEqBytes32(_p6_wordAt(head2, 96), bytes32(T0 + 500), "AS-38: default-on followNow must track a later warp to T0 + 500");

        feed.setFollowNow(false);
        feed.setRound(0, 0, 0, 4242, 0);

        vm.warp(T0 + 900);
        (, , bytes memory head3) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);
        assertEqBytes32(_p6_wordAt(head3, 96), bytes32(uint256(4242)), "AS-38: followNow off must return the literal updatedAt, not block.timestamp");

        vm.warp(T0 + 5000);
        (, , bytes memory head4) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);
        assertEqBytes32(_p6_wordAt(head4, 96), bytes32(uint256(4242)), "AS-38: followNow off must stay frozen at 4242 across a later warp (reverse arm)");
    }

    function test_AS38_cleanDoesNotRationalize() public {
        MockPriceFeed feed = new MockPriceFeed();
        feed.setFollowNow(false);
        feed.setRound(5, -1, 0, 0, 4);

        (bool ok, uint256 size, bytes memory head) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);

        assertTrue(ok, "AS-38: CLEAN must answer an internally-incoherent configuration");
        assertEq(size, 160, "AS-38: CLEAN must return exactly 160 bytes even when incoherent");
        assertEqBytes32(_p6_wordAt(head, 32), bytes32(type(uint256).max), "AS-38: CLEAN must not rationalize a negative answer (-1 as a full 32-byte word)");
        assertEqBytes32(_p6_wordAt(head, 96), bytes32(uint256(0)), "AS-38: CLEAN must not rationalize updatedAt == 0 into block.timestamp");
        assertEqBytes32(_p6_wordAt(head, 128), bytes32(uint256(4)), "AS-38: CLEAN must not rationalize answeredInRound < roundId");

        feed.setRound(5, -1, 0, T0 + 100, 4);
        (, , bytes memory head2) =
            _raw(address(feed), abi.encodeWithSignature("latestRoundData()"), BUDGET_HIGH, 160);
        assertEqBytes32(_p6_wordAt(head2, 96), bytes32(T0 + 100), "AS-38: CLEAN with followNow off must return the literal updatedAt exactly");
    }

    function test_AS38_stateInvariantAcrossEvaluate() public {
        (MockEquityToken token, , MockPriceFeed feed, Ctx memory ctx) = _baseline();

        _fx_FeedSnapshot memory snap0 = _fx_snapshotFeed(feed);

        (bool ok, uint256 reasonBits) = GuardCore.evaluate(address(token), ctx);
        assertEq(reasonBits, uint256(1) << 0, "AS-38: a full evaluate over the baseline must leave C9 unwritten (reasonBits)");
        assertFalse(ok, "AS-38: the baseline is never ok (G0 is always violated for a standalone token)");

        // NAMED COMMENT: no counter, structurally -- the guard reads C9 exclusively via STATICCALL,
        // and any SSTORE/TSTORE/LOG in that frame halts the read instead of incrementing anything;
        // the general argument is proven at AS-39(c) against MockControlPlane's countingMode escape
        // hatch. Storage-slot equality below is the strongest form of that same claim for C9.
        _fx_FeedSnapshot memory snap1 = _fx_snapshotFeed(feed);

        assertEq(snap1.roundId, snap0.roundId, "AS-38: readRoundConfig().roundId must be invariant across evaluate");
        assertEqInt(snap1.answer, snap0.answer, "AS-38: readRoundConfig().answer must be invariant across evaluate");
        assertEq(snap1.startedAt, snap0.startedAt, "AS-38: readRoundConfig().startedAt must be invariant across evaluate");
        assertEq(snap1.updatedAt, snap0.updatedAt, "AS-38: readRoundConfig().updatedAt must be invariant across evaluate");
        assertEq(snap1.answeredInRound, snap0.answeredInRound, "AS-38: readRoundConfig().answeredInRound must be invariant across evaluate");
        assertEq(snap1.followNow, snap0.followNow, "AS-38: readRoundConfig().followNow must be invariant across evaluate");
        assertEq(uint256(snap1.feedMode), uint256(snap0.feedMode), "AS-38: readModes().feedMode must be invariant across evaluate");
        assertEq(uint256(snap1.descMode), uint256(snap0.descMode), "AS-38: readModes().descMode must be invariant across evaluate");
        assertEq(snap1.modeArg, snap0.modeArg, "AS-38: readModes().modeArg must be invariant across evaluate");
        assertEq(snap1.gasBurn, snap0.gasBurn, "AS-38: readModes().gasBurn must be invariant across evaluate");
        assertEq(snap1.gasThreshold, snap0.gasThreshold, "AS-38: readModes().gasThreshold must be invariant across evaluate");

        for (uint256 i = 0; i < 16; i++) {
            assertEqBytes32(
                snap1.slots[i],
                snap0.slots[i],
                "AS-38: a C9 storage slot must be invariant across evaluate"
            );
        }
    }

    /// Memory snapshot of every observable piece of MockPriceFeed (C9) state used by the AS-38
    /// state-invariance self-check: the decoded round config, the decoded mode config, and the raw
    /// first 16 storage slots. Declared to let test_AS38_stateInvariantAcrossEvaluate (D3, FD-U5-17)
    /// carry the "before" and "after" readings as two struct pointers instead of ~19 scalars, keeping
    /// stack usage under the legacy-codegen limit.
    struct _fx_FeedSnapshot {
        uint256 roundId;
        int256 answer;
        uint256 startedAt;
        uint256 updatedAt;
        uint256 answeredInRound;
        bool followNow;
        uint8 feedMode;
        uint8 descMode;
        uint256 modeArg;
        uint256 gasBurn;
        uint256 gasThreshold;
        bytes32[16] slots;
    }

    function _fx_snapshotFeed(MockPriceFeed feed) private view returns (_fx_FeedSnapshot memory snap) {
        (snap.roundId, snap.answer, snap.startedAt, snap.updatedAt, snap.answeredInRound, snap.followNow) =
            feed.readRoundConfig();
        (snap.feedMode, snap.descMode, snap.modeArg, snap.gasBurn, snap.gasThreshold) = feed.readModes();
        for (uint256 i = 0; i < 16; i++) {
            snap.slots[i] = vm.load(address(feed), bytes32(i));
        }
    }

    function test_AS38_setterRejectsOutOfDomainArgs() public {
        MockPriceFeed feed = new MockPriceFeed();

        vm.expectRevert(abi.encodeWithSelector(MockPriceFeed.ModeArgOutOfDomain.selector, uint8(2), uint256(160)));
        feed.setFeedMode(2, 160); // FEED_SHORT, arg >= 160

        vm.expectRevert(abi.encodeWithSelector(MockPriceFeed.ModeArgOutOfDomain.selector, uint8(2), uint256(64)));
        feed.setDescMode(2, 64); // DESC_SHORT, arg >= 64

        vm.expectRevert(abi.encodeWithSelector(MockPriceFeed.ModeArgOutOfDomain.selector, uint8(3), uint256(0x20)));
        feed.setDescMode(3, 0x20); // DESC_BAD_OFFSET, arg == 0x20

        vm.expectRevert(
            abi.encodeWithSelector(MockPriceFeed.ModeArgOutOfDomain.selector, uint8(5), uint256(2 ** 32 + 1))
        );
        feed.setDescMode(5, 2 ** 32 + 1); // DESC_BOMB, arg > BOMB_MAX
    }

    /// Reads a 32-byte word out of a raw returndata head at a given byte offset. Callers only ever
    /// pass an offset such that `offset + 32 <= head.length`; this helper does no bounds checking of
    /// its own, mirroring the same "caller guarantees the shape" contract as `_raw`.
    function _p6_wordAt(bytes memory head, uint256 offset) private pure returns (bytes32 word) {
        assembly {
            word := mload(add(add(head, 32), offset))
        }
    }

    /// Returns the first `len` bytes of `data` as a new array. Used to compare a SHORT/TAIL_PAD
    /// returndata head against the corresponding prefix of a previously captured CLEAN encoding.
    function _p6_slice(bytes memory data, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[i];
        }
    }
}

error TwoArgProbe(address who, uint256 bits);
error ProbeFailed();

/// Two-argument custom-error reverter used by the S9 expectRevert(bytes) self-checks (tests 10-11):
/// a minimal external call whose entire job is to revert with a payload carrying two arguments, so
/// the positive and negative arms can assert on something more specific than a bare selector.
contract TwoArgReverter {
    function boom(address who, uint256 bits) external pure {
        revert TwoArgProbe(who, bits);
    }
}

/// Wraps a call to TwoArgReverter behind vm.expectRevert so callers never need a second copy of the
/// expected-revert bookkeeping. `run` always calls `boom` with the same fixed arguments
/// (address(0xA11CE), 0x1234); it is `expected` that varies between the positive arm (test 10,
/// matching payload) and the negative arm (test 11, mismatched payload).
contract ExpectRevertHarness is TestBase {
    function run(TwoArgReverter r, bytes calldata expected) external {
        vm.expectRevert(expected);
        r.boom(address(0xA11CE), 0x1234);
    }
}

/// Reentrancy-callback target for MockEquityToken's setCallback surface (test 44). `hit()` records
/// that it was reached and by whom; `fail()` always reverts with ProbeFailed(), giving the transfer
/// path's callback-bubbling behaviour something distinctive to assert on.
contract CallbackProbe {
    uint256 public hits;
    address public lastCaller;

    function hit() external {
        hits += 1;
        lastCaller = msg.sender;
    }

    function fail() external pure {
        revert ProbeFailed();
    }
}
