// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GatesBaseline} from "./Gates.t.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";
import {RWAGuard} from "../src/RWAGuard.sol";
import {VaultBase} from "../src/demo/VaultBase.sol";
import {NaiveVault} from "../src/demo/NaiveVault.sol";
import {GuardedVault} from "../src/demo/GuardedVault.sol";

abstract contract DemoVaultsBaseline is GatesBaseline {
    address internal constant ALICE = address(uint160(uint256(keccak256("rwa-guard.u6.alice"))));
    address internal constant BOB = address(uint160(uint256(keccak256("rwa-guard.u6.bob"))));
    address internal constant CAROL = address(uint160(uint256(keccak256("rwa-guard.u6.carol"))));
    uint256 internal constant GAS_BOUND = 5_000_000;

    function _u6_env() internal returns (Env memory) {
        return _baseline();
    }

    function _u6_naive(Env memory e) internal returns (NaiveVault) {
        return new NaiveVault(e.token);
    }

    function _u6_guarded(Env memory e, address feed) internal returns (GuardedVault) {
        return new GuardedVault(e.token, feed, address(e.logic), 0);
    }

    function _u6_fund(address tok, address who, address vault, uint256 raw) internal {
        MockEquityToken(tok).mintRaw(who, raw);
        vm.prank(who);
        MockEquityToken(tok).approve(vault, type(uint256).max);
    }

    function _u6_call(address target, address who, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = target.call(cd);
    }

    function _u6_callGas(address target, address who, bytes memory cd, uint256 gasLimit)
        internal
        returns (bool ok, bytes memory ret)
    {
        vm.prank(who);
        (ok, ret) = target.call{gas: gasLimit}(cd);
    }

    function _u6_deposit(address vault, address who, uint256 amount) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = _u6_call(vault, who, abi.encodeWithSelector(NaiveVault.deposit.selector, amount));
    }

    function _u6_redeem(address vault, address who, uint256 shares_) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = _u6_call(vault, who, abi.encodeWithSelector(NaiveVault.redeem.selector, shares_));
    }

    function _u6_guardBlockedData(address tok, uint256 bits) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(RWAGuard.GuardBlocked.selector, tok, bits);
    }

    function _u6_transferFailedData(address tok, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(VaultBase.TransferFailed.selector, tok, inner);
    }

    function _u6_guardBlockedParts(bytes memory ret) internal pure returns (uint256 sel, address tok, uint256 bits) {
        if (ret.length != 68) {
            return (0, address(0), 0);
        }
        assembly {
            sel := shr(224, mload(add(ret, 32)))
            tok := mload(add(ret, 36))
            bits := mload(add(ret, 68))
        }
    }

    function _u6_sumShares(address vault, address[3] memory holders) internal view returns (uint256 total) {
        for (uint256 i = 0; i < holders.length; i++) {
            total += VaultBase(vault).shares(holders[i]);
        }
    }

    function _u6_hash(bytes memory b) internal pure returns (uint256) {
        return uint256(keccak256(b));
    }
}

contract DemoVaultsTest is DemoVaultsBaseline {
    function test_AS29_a_naivePaysDoubleAfterEffective() public {
        // T-2: the naive vault pays twice the fair amount and the next holder is left short.
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _u6_fund(e.token, ALICE, address(n), 100e18);
        _u6_fund(e.token, BOB, address(n), 100e18);
        (bool okDepA,) = _u6_deposit(address(n), ALICE, 100e18);
        assertTrue(okDepA, "AS-29: alice deposit into the naive vault succeeds");
        (bool okDepB,) = _u6_deposit(address(n), BOB, 100e18);
        assertTrue(okDepB, "AS-29: bob deposit into the naive vault succeeds");
        MockEquityToken(e.token).setRatios(1e18, 5e17, T0 + 1);
        assertEq(MockEquityToken(e.token).uiMultiplier(), 1e18, "AS-29: uiMultiplier read back is 1e18");
        assertEq(MockEquityToken(e.token).newUIMultiplier(), 5e17, "AS-29: newUIMultiplier read back is 5e17");
        assertEq(MockEquityToken(e.token).effectiveAt(), T0 + 1, "AS-29: effectiveAt read back is T0 plus 1");
        vm.warp(T0 + 1);
        assertEq(
            MockEquityToken(e.token).balanceOf(address(n)),
            100e18,
            "AS-29: naive vault balance is 100e18 before the redeem"
        );
        uint256 correct = MockEquityToken(e.token).balanceOf(address(n)) * n.shares(ALICE) / n.totalShares();
        assertEq(correct, 50e18, "AS-29: the fair amount for alice is 50e18");
        (bool okRedeemA, bytes memory retRedeemA) = _u6_redeem(address(n), ALICE, 100e18);
        assertTrue(okRedeemA, "AS-29: alice redeem from the naive vault succeeds");
        uint256 amountOut = abi.decode(retRedeemA, (uint256));
        assertEq(amountOut, 100e18, "AS-29: the naive vault pays out 100e18");
        assertTrue(amountOut != correct, "AS-29: the naive payout does not equal the fair amount");
        assertEq(amountOut, 2 * correct, "AS-29: the naive payout is twice the fair amount");
        assertEq(amountOut - correct, 50e18, "AS-29: the naive overpayment is 50e18");
        assertEq(MockEquityToken(e.token).balanceOf(address(n)), 0, "AS-29: naive vault balance is drained to 0");
        assertEq(n.totalShares(), 100e18, "AS-29: total shares are 100e18 after alice redeems");
        assertEq(n.shares(BOB), 100e18, "AS-29: bob still holds 100e18 shares");
        assertEq(MockEquityToken(e.token).balanceOf(ALICE), 100e18, "AS-29: alice received a balance of 100e18");
        (bool okRedeemB, bytes memory retRedeemB) = _u6_redeem(address(n), BOB, 100e18);
        assertFalse(okRedeemB, "AS-29: bob redeem from the drained naive vault fails");
        assertEq(retRedeemB.length, 228, "AS-29: bob failed redeem revert length is 228");
        assertEq(
            _u6_hash(retRedeemB),
            _u6_hash(
                _u6_transferFailedData(
                    e.token,
                    abi.encodeWithSelector(MockEquityToken.InsufficientRaw.selector, address(n), uint256(0), uint256(200e18))
                )
            ),
            "AS-29: bob failed redeem hash matches the InsufficientRaw wrapped transfer failure"
        );
    }

    function test_AS29_b_guardedBlocksAfterEffective() public {
        Env memory e = _u6_env();
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(g), 100e18);
        _u6_fund(e.token, BOB, address(g), 100e18);
        (bool okDepA,) = _u6_deposit(address(g), ALICE, 100e18);
        assertTrue(okDepA, "AS-29: alice deposit into the guarded vault succeeds");
        (bool okDepB,) = _u6_deposit(address(g), BOB, 100e18);
        assertTrue(okDepB, "AS-29: bob deposit into the guarded vault succeeds");
        assertEq(g.priceFeed(), address(e.feed), "AS-29: the guarded vault priceFeed is the shared feed");
        assertEq(g.expectedImpl(), address(e.logic), "AS-29: the guarded vault expectedImpl is the shared logic");
        assertEq(uint256(g.maxFeedAge()), 0, "AS-29: the guarded vault maxFeedAge is 0");
        (, , , , , bool followNow) = e.feed.readRoundConfig();
        assertTrue(followNow, "AS-29: the shared feed followNow reads back true");
        assertEq(
            uint256(uint32(RWAGuard.GuardBlocked.selector)),
            uint256(uint32(bytes4(keccak256("GuardBlocked(address,uint256)")))),
            "AS-29: the GuardBlocked selector matches its signature hash"
        );
        (bool okRedeemOne,) = _u6_redeem(address(g), ALICE, 1);
        assertTrue(okRedeemOne, "AS-29: alice redeem of 1 before the ratio change succeeds");
        MockEquityToken(e.token).setRatios(1e18, 5e17, T0 + 1);
        vm.warp(T0 + 1);
        uint256 balanceBefore = MockEquityToken(e.token).balanceOf(address(g));
        (bool okRedeemBig, bytes memory retRedeemBig) = _u6_redeem(address(g), ALICE, 100e18);
        assertFalse(okRedeemBig, "AS-29: alice redeem after the ratio transition is blocked");
        assertEq(retRedeemBig.length, 68, "AS-29: the blocked redeem revert length is 68");
        assertEq(
            _u6_hash(retRedeemBig),
            _u6_hash(_u6_guardBlockedData(e.token, uint256(1) << 5)),
            "AS-29: the blocked redeem hash matches GuardBlocked bit 5"
        );
        assertEq(g.shares(ALICE), 100e18 - 1, "AS-29: alice shares stay unchanged after the blocked redeem");
        assertEq(g.totalShares(), 200e18 - 1, "AS-29: total shares stay unchanged after the blocked redeem");
        assertEq(
            MockEquityToken(e.token).balanceOf(address(g)),
            balanceBefore,
            "AS-29: the guarded vault balance is unchanged after the blocked redeem"
        );
    }

    function test_AS29_c_scheduledNotEffective() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(n), 100e18);
        _u6_fund(e.token, BOB, address(n), 100e18);
        _u6_fund(e.token, ALICE, address(g), 100e18);
        _u6_fund(e.token, BOB, address(g), 100e18);
        (bool okDepAN,) = _u6_deposit(address(n), ALICE, 100e18);
        assertTrue(okDepAN, "AS-29: alice deposit into the naive vault succeeds");
        (bool okDepBN,) = _u6_deposit(address(n), BOB, 100e18);
        assertTrue(okDepBN, "AS-29: bob deposit into the naive vault succeeds");
        (bool okDepAG,) = _u6_deposit(address(g), ALICE, 100e18);
        assertTrue(okDepAG, "AS-29: alice deposit into the guarded vault succeeds");
        (bool okDepBG,) = _u6_deposit(address(g), BOB, 100e18);
        assertTrue(okDepBG, "AS-29: bob deposit into the guarded vault succeeds");
        MockEquityToken(e.token).setRatios(1e18, 5e17, T0 + 1);
        uint256 correct = MockEquityToken(e.token).balanceOf(address(n)) * n.shares(ALICE) / n.totalShares();
        assertEq(correct, 100e18, "AS-29: the fair amount before the transition is effective is 100e18");
        (bool okNaive, bytes memory retNaive) = _u6_redeem(address(n), ALICE, 100e18);
        assertTrue(okNaive, "AS-29: the naive redeem before the transition is effective succeeds");
        assertEq(
            abi.decode(retNaive, (uint256)),
            100e18,
            "AS-29: the naive redeem pays the fair amount before the transition"
        );
        (bool okGuarded, bytes memory retGuarded) = _u6_redeem(address(g), ALICE, 100e18);
        assertFalse(okGuarded, "AS-29: the guarded redeem before the transition is effective is blocked");
        assertEq(retGuarded.length, 68, "AS-29: the blocked scheduled redeem revert length is 68");
        assertEq(
            _u6_hash(retGuarded),
            _u6_hash(_u6_guardBlockedData(e.token, uint256(1) << 5)),
            "AS-29: the blocked scheduled redeem hash matches GuardBlocked bit 5"
        );
        assertEq(g.shares(ALICE), 100e18, "AS-29: alice shares in the guarded vault stay unchanged");
        assertEq(g.totalShares(), 200e18, "AS-29: total shares in the guarded vault stay unchanged");
    }

    function test_AS29b_noTransitionArmsAgree() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(n), 100e18);
        _u6_fund(e.token, BOB, address(n), 100e18);
        (bool okDepAN,) = _u6_deposit(address(n), ALICE, 100e18);
        assertTrue(okDepAN, "AS-29: alice deposit into the naive vault succeeds");
        (bool okDepBN,) = _u6_deposit(address(n), BOB, 100e18);
        assertTrue(okDepBN, "AS-29: bob deposit into the naive vault succeeds");
        (bool okRedeemN, bytes memory retRedeemN) = _u6_redeem(address(n), ALICE, 40e18);
        assertTrue(okRedeemN, "AS-29: alice partial redeem from the naive vault succeeds");
        assertEq(abi.decode(retRedeemN, (uint256)), 40e18, "AS-29: the naive partial redeem pays 40e18");
        assertEq(n.shares(ALICE), 60e18, "AS-29: alice keeps 60e18 shares in the naive vault");
        assertEq(n.shares(BOB), 100e18, "AS-29: bob keeps 100e18 shares in the naive vault");
        assertEq(n.totalShares(), 160e18, "AS-29: total shares in the naive vault are 160e18");
        assertEq(MockEquityToken(e.token).balanceOf(address(n)), 160e18, "AS-29: naive vault balance is 160e18");

        _u6_fund(e.token, ALICE, address(g), 100e18);
        _u6_fund(e.token, BOB, address(g), 100e18);
        (bool okDepAG,) = _u6_deposit(address(g), ALICE, 100e18);
        assertTrue(okDepAG, "AS-29: alice deposit into the guarded vault succeeds");
        (bool okDepBG,) = _u6_deposit(address(g), BOB, 100e18);
        assertTrue(okDepBG, "AS-29: bob deposit into the guarded vault succeeds");
        (bool okRedeemG, bytes memory retRedeemG) = _u6_redeem(address(g), ALICE, 40e18);
        assertTrue(okRedeemG, "AS-29: alice partial redeem from the guarded vault succeeds");
        assertEq(abi.decode(retRedeemG, (uint256)), 40e18, "AS-29: the guarded partial redeem pays 40e18");
        assertEq(g.shares(ALICE), 60e18, "AS-29: alice keeps 60e18 shares in the guarded vault");
        assertEq(g.shares(BOB), 100e18, "AS-29: bob keeps 100e18 shares in the guarded vault");
        assertEq(g.totalShares(), 160e18, "AS-29: total shares in the guarded vault are 160e18");
        assertEq(MockEquityToken(e.token).balanceOf(address(g)), 160e18, "AS-29: guarded vault balance is 160e18");

        assertEq(
            MockEquityToken(e.token).balanceOf(ALICE),
            80e18,
            "AS-29: alice combined balance after both redeems is 80e18"
        );

        GuardedVault g0 = _u6_guarded(e, address(0));
        _u6_fund(e.token, ALICE, address(g0), 1e18);
        (bool okDepG0,) = _u6_deposit(address(g0), ALICE, 1e18);
        assertTrue(okDepG0, "AS-29: alice deposit into the zero-feed guarded vault succeeds");
        (bool okRedeemG0, bytes memory retRedeemG0) = _u6_redeem(address(g0), ALICE, 1e18);
        assertFalse(okRedeemG0, "AS-29: the zero-feed guarded vault blocks the redeem");
        assertEq(retRedeemG0.length, 68, "AS-29: the zero-feed guarded redeem revert length is 68");
        (uint256 selG0, , uint256 bitsG0) = _u6_guardBlockedParts(retRedeemG0);
        assertEq(
            selG0,
            uint256(uint32(RWAGuard.GuardBlocked.selector)),
            "AS-29: the zero-feed guarded redeem selector matches GuardBlocked"
        );
        assertTrue(bitsG0 != 0, "AS-29: the zero-feed guarded redeem bits are nonzero");
        assertTrue(
            (bitsG0 & (uint256(1) << 255)) != 0, "AS-29: the zero-feed guarded redeem sets the aggregate bit"
        );
    }

    function test_AS30_naiveReentryBlocked() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _as30_arms(e, address(n));
    }

    function test_AS30_guardedReentryBlocked() public {
        Env memory e = _u6_env();
        GuardedVault g = _u6_guarded(e, address(e.feed));
        assertEq(
            uint256(uint32(NaiveVault.redeem.selector)),
            uint256(uint32(GuardedVault.redeem.selector)),
            "AS-30: the naive and guarded redeem selectors match"
        );
        _as30_arms(e, address(g));
    }

    function test_AS31_crossAccountRedeemRejected() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _as31_crossAccount(e, address(n));
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _as31_crossAccount(e, address(g));
    }

    function test_AS31b_privilegedSelectorsAbsent() public {
        string[15] memory sigs = [
            string("owner()"),
            "admin()",
            "pause()",
            "unpause()",
            "transferOwnership(address)",
            "renounceOwnership()",
            "upgradeTo(address)",
            "upgradeToAndCall(address,bytes)",
            "sweep(address)",
            "withdraw(uint256)",
            "emergencyWithdraw()",
            "rescueTokens(address,uint256)",
            "grantRole(bytes32,address)",
            "setPriceFeed(address)",
            "initialize(address)"
        ];
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _u6_fund(e.token, ALICE, address(n), 10e18);
        (bool okDepN,) = _u6_deposit(address(n), ALICE, 10e18);
        assertTrue(okDepN, "AS-31: alice deposit into the naive vault succeeds");
        for (uint256 i = 0; i < sigs.length; i++) {
            _as31_probe(address(n), sigs[i]);
        }
        (bool okSharesN, bytes memory retSharesN) =
            _u6_call(address(n), ALICE, abi.encodeWithSignature("shares(address)", ALICE));
        assertTrue(okSharesN, "AS-31: the naive vault shares getter control call succeeds");
        assertEq(retSharesN.length, 32, "AS-31: the naive vault shares getter control return length is 32");
        assertEq(abi.decode(retSharesN, (uint256)), 10e18, "AS-31: the naive vault shares getter control returns 10e18");
        assertEq(n.totalShares(), 10e18, "AS-31: the naive vault total shares are 10e18 after the probes");

        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(g), 10e18);
        (bool okDepG,) = _u6_deposit(address(g), ALICE, 10e18);
        assertTrue(okDepG, "AS-31: alice deposit into the guarded vault succeeds");
        for (uint256 i = 0; i < sigs.length; i++) {
            _as31_probe(address(g), sigs[i]);
        }
        (bool okSharesG, bytes memory retSharesG) =
            _u6_call(address(g), ALICE, abi.encodeWithSignature("shares(address)", ALICE));
        assertTrue(okSharesG, "AS-31: the guarded vault shares getter control call succeeds");
        assertEq(retSharesG.length, 32, "AS-31: the guarded vault shares getter control return length is 32");
        assertEq(
            abi.decode(retSharesG, (uint256)), 10e18, "AS-31: the guarded vault shares getter control returns 10e18"
        );
        assertEq(g.totalShares(), 10e18, "AS-31: the guarded vault total shares are 10e18 after the probes");
    }

    function test_AS31c_layoutSlotsMatch() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _u6_fund(e.token, ALICE, address(n), 100e18);
        (bool okDepN,) = _u6_deposit(address(n), ALICE, 100e18);
        assertTrue(okDepN, "AS-31: alice deposit into the naive vault succeeds");
        assertEq(
            uint256(vm.load(address(n), bytes32(uint256(1)))),
            100e18,
            "AS-31: the naive vault totalShares slot equals 100e18"
        );
        assertEq(
            uint256(vm.load(address(n), keccak256(abi.encode(ALICE, uint256(0))))),
            100e18,
            "AS-31: the naive vault mapping slot for alice equals 100e18"
        );
        assertEq(
            uint256(vm.load(address(n), keccak256(abi.encode(ALICE, uint256(1))))),
            0,
            "AS-31: the naive vault control slot derived from slot 1 is 0"
        );
        assertEq(uint256(vm.load(address(n), bytes32(uint256(2)))), 1, "AS-31: the naive vault lock slot equals 1");
        assertEq(uint256(vm.load(address(n), bytes32(uint256(0)))), 0, "AS-31: the naive vault raw slot 0 equals 0");
        assertEq(uint256(vm.load(address(n), bytes32(uint256(3)))), 0, "AS-31: the naive vault raw slot 3 equals 0");

        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(g), 70e18);
        (bool okDepG,) = _u6_deposit(address(g), ALICE, 70e18);
        assertTrue(okDepG, "AS-31: alice deposit into the guarded vault succeeds");
        assertEq(
            uint256(vm.load(address(g), bytes32(uint256(1)))),
            70e18,
            "AS-31: the guarded vault totalShares slot equals 70e18"
        );
        assertEq(
            uint256(vm.load(address(g), keccak256(abi.encode(ALICE, uint256(0))))),
            70e18,
            "AS-31: the guarded vault mapping slot for alice equals 70e18"
        );
        assertEq(
            uint256(vm.load(address(g), keccak256(abi.encode(ALICE, uint256(1))))),
            0,
            "AS-31: the guarded vault control slot derived from slot 1 is 0"
        );
        assertEq(uint256(vm.load(address(g), bytes32(uint256(2)))), 1, "AS-31: the guarded vault lock slot equals 1");
        assertEq(uint256(vm.load(address(g), bytes32(uint256(0)))), 0, "AS-31: the guarded vault raw slot 0 equals 0");
        assertEq(uint256(vm.load(address(g), bytes32(uint256(3)))), 0, "AS-31: the guarded vault raw slot 3 equals 0");
    }

    function test_AS19b_burningFeedFailsOnlyGuarded() public {
        Env memory e = _u6_env();
        MockPriceFeed bf = _freshFeed();
        bf.setFeedMode(5, 0);
        bf.setGasBurn(type(uint256).max);
        {
            (uint8 feedMode, , , uint256 gasBurn, ) = bf.readModes();
            assertEq(uint256(feedMode), 5, "AS-19: the burning feed mode reads back as 5");
            assertEq(gasBurn, type(uint256).max, "AS-19: the burning feed gas burn reads back as the maximum");
        }

        NaiveVault n = _u6_naive(e);
        GuardedVault gc = _u6_guarded(e, address(e.feed));
        GuardedVault gb = _u6_guarded(e, address(bf));
        _u6_fund(e.token, ALICE, address(n), 10e18);
        _u6_fund(e.token, ALICE, address(gc), 10e18);
        _u6_fund(e.token, ALICE, address(gb), 10e18);
        {
            (bool okDepN,) = _u6_deposit(address(n), ALICE, 10e18);
            assertTrue(okDepN, "AS-19: alice deposit into the naive vault succeeds");
        }
        {
            (bool okDepGc,) = _u6_deposit(address(gc), ALICE, 10e18);
            assertTrue(okDepGc, "AS-19: alice deposit into the clean-feed guarded vault succeeds");
        }
        {
            (bool okDepGb,) = _u6_deposit(address(gb), ALICE, 10e18);
            assertTrue(okDepGb, "AS-19: alice deposit into the burning-feed guarded vault succeeds");
        }

        {
            (bool okRedeemN,) = _u6_callGas(
                address(n), ALICE, abi.encodeWithSelector(NaiveVault.redeem.selector, uint256(1e18)), GAS_BOUND
            );
            assertTrue(okRedeemN, "AS-19: the naive vault redeem under the gas bound succeeds");
            assertEq(n.shares(ALICE), 9e18, "AS-19: alice shares in the naive vault are 9e18");
        }

        {
            (bool okRedeemGc,) = _u6_callGas(
                address(gc), ALICE, abi.encodeWithSelector(NaiveVault.redeem.selector, uint256(1e18)), GAS_BOUND
            );
            assertTrue(okRedeemGc, "AS-19: the clean-feed guarded vault redeem under the gas bound succeeds");
            assertEq(gc.shares(ALICE), 9e18, "AS-19: alice shares in the clean-feed guarded vault are 9e18");
        }

        {
            (bool okRedeemGb, bytes memory retRedeemGb) = _u6_callGas(
                address(gb), ALICE, abi.encodeWithSelector(NaiveVault.redeem.selector, uint256(1e18)), GAS_BOUND
            );
            assertFalse(okRedeemGb, "AS-19: the burning-feed guarded vault redeem under the gas bound fails");
            (uint256 selGb, address tokGb, ) = _u6_guardBlockedParts(retRedeemGb);
            assertTrue(
                retRedeemGb.length == 0
                    || (retRedeemGb.length == 68 && selGb == uint256(uint32(RWAGuard.GuardBlocked.selector)) && tokGb == e.token),
                "AS-19: the burning-feed guarded vault failure is an empty revert or a matching GuardBlocked"
            );
        }
        assertEq(gb.shares(ALICE), 10e18, "AS-19: alice shares in the burning-feed guarded vault stay 10e18");
    }

    function _as30_arms(Env memory e, address vault) internal {
        // T-4: the lock turns the callback re-entry into ReentrantCall, and the token bubbles it.
        assertEq(uint256(vm.load(vault, bytes32(uint256(2)))), 1, "AS-30: the lock slot starts at 1");
        _u6_fund(e.token, ALICE, vault, 10e18);
        (bool okDep0,) = _u6_deposit(vault, ALICE, 5e18);
        assertTrue(okDep0, "AS-30: the initial deposit with no callback armed succeeds");
        assertEq(VaultBase(vault).shares(ALICE), 5e18, "AS-30: alice shares are 5e18 after the initial deposit");
        MockEquityToken(e.token).setCallback(vault, abi.encodeWithSelector(NaiveVault.redeem.selector, uint256(1)));
        assertEq(
            uint256(vm.load(e.token, bytes32(uint256(8)))),
            uint256(uint160(vault)),
            "AS-30: the callback target slot holds the vault address"
        );
        (bool okDep1, bytes memory retDep1) = _u6_deposit(vault, ALICE, 1e18);
        assertFalse(okDep1, "AS-30: a deposit re-entry through the armed callback is blocked");
        assertEq(retDep1.length, 132, "AS-30: the blocked deposit re-entry revert length is 132");
        assertEq(
            _u6_hash(retDep1),
            _u6_hash(_u6_transferFailedData(e.token, abi.encodePacked(VaultBase.ReentrantCall.selector))),
            "AS-30: the blocked deposit re-entry hash matches the wrapped ReentrantCall"
        );
        assertEq(
            VaultBase(vault).shares(ALICE), 5e18, "AS-30: alice shares stay 5e18 after the blocked deposit re-entry"
        );
        MockEquityToken(e.token).setCallback(address(0), "");
        (bool okDep2,) = _u6_deposit(vault, ALICE, 1e18);
        assertTrue(okDep2, "AS-30: the deposit succeeds once the callback is disarmed");
        assertEq(VaultBase(vault).shares(ALICE), 6e18, "AS-30: alice shares reach 6e18 after the unblocked deposit");
        MockEquityToken(e.token).setCallback(vault, abi.encodeWithSelector(NaiveVault.redeem.selector, uint256(1)));
        (bool okRed1, bytes memory retRed1) = _u6_redeem(vault, ALICE, 1e18);
        assertFalse(okRed1, "AS-30: a redeem re-entry through the armed callback is blocked");
        assertEq(retRed1.length, 132, "AS-30: the blocked redeem re-entry revert length is 132");
        assertEq(
            _u6_hash(retRed1),
            _u6_hash(_u6_transferFailedData(e.token, abi.encodePacked(VaultBase.ReentrantCall.selector))),
            "AS-30: the blocked redeem re-entry hash matches the wrapped ReentrantCall"
        );
        assertEq(
            VaultBase(vault).shares(ALICE), 6e18, "AS-30: alice shares stay 6e18 after the blocked redeem re-entry"
        );
        MockEquityToken(e.token).setCallback(address(0), "");
        (bool okRed2,) = _u6_redeem(vault, ALICE, 1e18);
        assertTrue(okRed2, "AS-30: the redeem succeeds once the callback is disarmed");
        assertEq(VaultBase(vault).shares(ALICE), 5e18, "AS-30: alice shares return to 5e18 after the unblocked redeem");
        assertEq(
            uint256(vm.load(vault, bytes32(uint256(2)))), 1, "AS-30: the lock slot returns to 1 after the unblocked redeem"
        );
        (bool okDisc, bytes memory retDisc) = _u6_redeem(vault, e.token, 1);
        assertFalse(okDisc, "AS-30: the discriminator redeem from the token address is rejected");
        assertEq(retDisc.length, 68, "AS-30: the discriminator revert length is 68");
        assertEq(
            _u6_hash(retDisc),
            _u6_hash(abi.encodeWithSelector(VaultBase.InsufficientShares.selector, uint256(0), uint256(1))),
            "AS-30: the discriminator hash matches InsufficientShares of 0 and 1"
        );
    }

    function _as31_crossAccount(Env memory e, address vault) internal {
        _u6_fund(e.token, ALICE, vault, 100e18);
        _u6_fund(e.token, CAROL, vault, 10e18);
        (bool okDepA,) = _u6_deposit(vault, ALICE, 100e18);
        assertTrue(okDepA, "AS-31: alice deposit succeeds");
        (bool okDepC,) = _u6_deposit(vault, CAROL, 10e18);
        assertTrue(okDepC, "AS-31: carol deposit succeeds");
        assertEq(VaultBase(vault).totalShares(), 110e18, "AS-31: total shares are 110e18 after both deposits");
        (bool okBob, bytes memory retBob) = _u6_redeem(vault, BOB, 100e18);
        assertFalse(okBob, "AS-31: bob cannot redeem shares he never deposited");
        assertEq(retBob.length, 68, "AS-31: bob rejected redeem revert length is 68");
        assertEq(
            _u6_hash(retBob),
            _u6_hash(abi.encodeWithSelector(VaultBase.InsufficientShares.selector, uint256(0), uint256(100e18))),
            "AS-31: bob rejected redeem hash matches InsufficientShares of 0 and 100e18"
        );
        (bool okCarol, bytes memory retCarol) = _u6_redeem(vault, CAROL, 100e18);
        assertFalse(okCarol, "AS-31: carol cannot redeem more shares than she holds");
        assertEq(retCarol.length, 68, "AS-31: carol rejected redeem revert length is 68");
        assertEq(
            _u6_hash(retCarol),
            _u6_hash(abi.encodeWithSelector(VaultBase.InsufficientShares.selector, uint256(10e18), uint256(100e18))),
            "AS-31: carol rejected redeem hash matches InsufficientShares of 10e18 and 100e18"
        );
        assertEq(VaultBase(vault).totalShares(), 110e18, "AS-31: total shares stay 110e18 after both rejections");
        (bool okAlice,) = _u6_redeem(vault, ALICE, 100e18);
        assertTrue(okAlice, "AS-31: alice can redeem her own shares");
    }

    function _as31_probe(address vault, string memory sig) internal {
        (bool ok, bytes memory ret) =
            _u6_call(vault, ALICE, abi.encodePacked(bytes4(keccak256(bytes(sig))), new bytes(128)));
        assertFalse(ok, "AS-31: the privileged selector probe must fail");
        assertEq(ret.length, 0, "AS-31: the privileged selector probe returns no data");
    }
}

uint8 constant U6_MODE_UNSET = 0;
uint8 constant U6_MODE_EMPTY = 1;
uint8 constant U6_MODE_W1 = 2;
uint8 constant U6_MODE_W0 = 3;
uint8 constant U6_MODE_W2 = 4;
uint8 constant U6_MODE_LEN31 = 5;
uint8 constant U6_MODE_LEN64 = 6;
uint8 constant U6_MODE_REVERT_SHORT = 7;
uint8 constant U6_MODE_REVERT_LONG = 8;

contract U6ShapeToken {
    uint8 private _mode;

    error ShapeRevert(uint256 code);
    error ShapeUnset();

    function setMode(uint8 m) external {
        _mode = m;
    }

    function mode() external view returns (uint8) {
        return _mode;
    }

    function transfer(address, uint256) external view {
        _shape();
    }

    function transferFrom(address, address, uint256) external view {
        _shape();
    }

    function _shape() private view {
        uint8 m = _mode;
        if (m == U6_MODE_REVERT_SHORT) {
            revert ShapeRevert(0xA36);
        }
        if (m == U6_MODE_EMPTY) {
            assembly ("memory-safe") {
                return(0, 0)
            }
        }
        if (m == U6_MODE_W1) {
            assembly ("memory-safe") {
                mstore(0, 1)
                return(0, 32)
            }
        }
        if (m == U6_MODE_W0) {
            assembly ("memory-safe") {
                mstore(0, 0)
                return(0, 32)
            }
        }
        if (m == U6_MODE_W2) {
            assembly ("memory-safe") {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (m == U6_MODE_LEN31) {
            assembly ("memory-safe") {
                mstore(0, shl(8, 1))
                return(0, 31)
            }
        }
        if (m == U6_MODE_LEN64) {
            assembly ("memory-safe") {
                mstore(0, 1)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (m == U6_MODE_REVERT_LONG) {
            assembly ("memory-safe") {
                let p := mload(0x40)
                mstore(p, 1)
                mstore(add(p, 32), 2)
                mstore(add(p, 64), 3)
                mstore(add(p, 96), 4)
                mstore(add(p, 128), 5)
                mstore(add(p, 160), 6)
                mstore(add(p, 192), 7)
                mstore(add(p, 224), 8)
                mstore(add(p, 256), 9)
                mstore(add(p, 288), 10)
                revert(p, 300)
            }
        }
        revert ShapeUnset();
    }
}

contract DemoVaultShapesTest is DemoVaultsBaseline {
    function test_AS36_1_noCode() public {
        Env memory e = _u6_env();
        assertEq(NEVER_DEPLOYED.code.length, 0, "AS-36: never-deployed address has no code");
        {
            NaiveVault n0 = new NaiveVault(NEVER_DEPLOYED);
            (bool okN, bytes memory retN) = _u6_deposit(address(n0), ALICE, 1);
            assertFalse(okN, "AS-36: naive vault deposit to a never-deployed token fails");
            assertEq(retN.length, 36, "AS-36: never-deployed naive deposit revert length is 36");
            assertEq(
                _u6_hash(retN),
                _u6_hash(abi.encodeWithSelector(VaultBase.NotAContract.selector, NEVER_DEPLOYED)),
                "AS-36: never-deployed naive deposit hash matches NotAContract"
            );
            assertEq(n0.totalShares(), 0, "AS-36: never-deployed naive vault total shares stay 0");
        }
        {
            GuardedVault g0 = new GuardedVault(NEVER_DEPLOYED, address(e.feed), address(e.logic), 0);
            (bool okG, bytes memory retG) = _u6_deposit(address(g0), ALICE, 1);
            assertFalse(okG, "AS-36: guarded vault deposit to a never-deployed token fails");
            assertEq(retG.length, 36, "AS-36: never-deployed guarded deposit revert length is 36");
            assertEq(
                _u6_hash(retG),
                _u6_hash(abi.encodeWithSelector(VaultBase.NotAContract.selector, NEVER_DEPLOYED)),
                "AS-36: never-deployed guarded deposit hash matches NotAContract"
            );
            assertEq(g0.totalShares(), 0, "AS-36: never-deployed guarded vault total shares stay 0");
        }
        {
            assertEq(address(0).code.length, 0, "AS-36: the zero address has no code");
            NaiveVault nz = new NaiveVault(address(0));
            (bool okZ, bytes memory retZ) = _u6_deposit(address(nz), ALICE, 1);
            assertFalse(okZ, "AS-36: naive vault deposit to the zero-address token fails");
            assertEq(retZ.length, 36, "AS-36: zero-address naive deposit revert length is 36");
            assertEq(
                _u6_hash(retZ),
                _u6_hash(abi.encodeWithSelector(VaultBase.NotAContract.selector, address(0))),
                "AS-36: zero-address naive deposit hash matches NotAContract"
            );
            assertEq(nz.totalShares(), 0, "AS-36: zero-address naive vault total shares stay 0");
        }
        {
            U6ShapeToken s = new U6ShapeToken();
            s.setMode(U6_MODE_W1);
            NaiveVault nv = new NaiveVault(address(s));
            (bool okDep,) = _u6_deposit(address(nv), ALICE, 5);
            assertTrue(okDep, "AS-36: the etch-arm deposit against the W1 shape token succeeds");
            (bool okRedeemCtl,) = _u6_redeem(address(nv), ALICE, 1);
            assertTrue(okRedeemCtl, "AS-36: the etch-arm control redeem succeeds before the etch");
            vm.etch(address(s), "");
            assertEq(address(s).code.length, 0, "AS-36: the etched shape token has no code");
            (bool okRedeemEtched, bytes memory retRedeemEtched) = _u6_redeem(address(nv), ALICE, 1);
            assertFalse(okRedeemEtched, "AS-36: the redeem after etching the shape token to empty fails");
            assertEq(retRedeemEtched.length, 36, "AS-36: the post-etch redeem revert length is 36");
            assertEq(
                _u6_hash(retRedeemEtched),
                _u6_hash(abi.encodeWithSelector(VaultBase.NotAContract.selector, address(s))),
                "AS-36: the post-etch redeem hash matches NotAContract"
            );
            assertEq(nv.shares(ALICE), 4, "AS-36: alice shares stay 4 after the post-etch redeem failure");
        }
    }

    function test_AS36_2_callReverts() public {
        _as36_failAllPaths(
            U6_MODE_REVERT_SHORT, abi.encodeWithSelector(U6ShapeToken.ShapeRevert.selector, uint256(0xA36)), 164
        );
        _as36_failAllPaths(U6_MODE_REVERT_LONG, abi.encode(1, 2, 3, 4, 5, 6, 7, 8), 356);
    }

    function test_AS36_3_emptyReturn() public {
        _as36_succeedAllPaths(U6_MODE_EMPTY);
        _as36_failAllPaths(U6_MODE_W0, abi.encode(uint256(0)), 132);
        U6ShapeToken s = new U6ShapeToken();
        s.setMode(U6_MODE_EMPTY);
        NaiveVault n = new NaiveVault(address(s));
        (bool okMax,) = _u6_deposit(address(n), ALICE, type(uint256).max);
        assertTrue(okMax, "AS-36: depositing the maximum uint256 succeeds against the empty-return token");
        (bool okOverflow, bytes memory retOverflow) = _u6_deposit(address(n), ALICE, 1);
        assertFalse(okOverflow, "AS-36: a further deposit of 1 overflows total shares");
        assertEq(retOverflow.length, 36, "AS-36: the overflow revert length is 36");
        assertEq(
            _u6_hash(retOverflow),
            _u6_hash(abi.encodeWithSignature("Panic(uint256)", uint256(0x11))),
            "AS-36: the overflow revert hash matches Panic 0x11"
        );
    }

    function test_AS36_4_wordOne() public {
        _as36_succeedAllPaths(U6_MODE_W1);
        _as36_failAllPaths(U6_MODE_LEN64, abi.encode(uint256(1), uint256(0)), 164);
    }

    function test_AS36_5_wordZero() public {
        _as36_failAllPaths(U6_MODE_W0, abi.encode(uint256(0)), 132);
        _as36_succeedAllPaths(U6_MODE_W1);
    }

    function test_AS36_6_wordTwo() public {
        // T-1: a word of 2 is not true here; only the exact word 1 counts.
        _as36_failAllPaths(U6_MODE_W2, abi.encode(uint256(2)), 132);
        _as36_succeedAllPaths(U6_MODE_W1);
    }

    function test_AS36_7_len31() public {
        bytes memory inner = abi.encodePacked(bytes30(0), bytes1(0x01));
        assertEq(inner.length, 31, "AS-36: the len31 inner data length is 31");
        _as36_failAllPaths(U6_MODE_LEN31, inner, 132);
        _as36_succeedAllPaths(U6_MODE_W1);
    }

    function test_AS36_8_len64() public {
        _as36_failAllPaths(U6_MODE_LEN64, abi.encode(uint256(1), uint256(0)), 164);
        _as36_succeedAllPaths(U6_MODE_W1);
    }

    function test_AS40_shareConservation_naive() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        _as40_corpus(e, address(n));
    }

    function test_AS40_shareConservation_guarded() public {
        Env memory e = _u6_env();
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _as40_corpus(e, address(g));
    }

    function _as36_failAllPaths(uint8 mode, bytes memory inner, uint256 expectedLen) internal {
        if (mode == U6_MODE_REVERT_LONG) {
            assertEq(inner.length, 256, "AS-36: the revert-long truncated inner data length is 256");
        }
        Env memory e = _u6_env();
        U6ShapeToken s = new U6ShapeToken();
        bytes memory expectedData = _u6_transferFailedData(address(s), inner);
        {
            s.setMode(mode);
            NaiveVault n = new NaiveVault(address(s));
            (bool okDep, bytes memory retDep) = _u6_deposit(address(n), ALICE, 1);
            assertFalse(okDep, "AS-36: the naive deposit against the shaped token fails");
            assertEq(retDep.length, expectedLen, "AS-36: the naive deposit revert length matches expected");
            assertEq(
                _u6_hash(retDep), _u6_hash(expectedData), "AS-36: the naive deposit revert hash matches TransferFailed"
            );
        }
        {
            s.setMode(U6_MODE_W1);
            NaiveVault n2 = new NaiveVault(address(s));
            (bool okDep2,) = _u6_deposit(address(n2), ALICE, 5);
            assertTrue(okDep2, "AS-36: the naive deposit succeeds while the shaped token answers word one");
            s.setMode(mode);
            (bool okRedeem, bytes memory retRedeem) = _u6_redeem(address(n2), ALICE, 1);
            assertFalse(okRedeem, "AS-36: the naive redeem against the shaped token fails");
            assertEq(retRedeem.length, expectedLen, "AS-36: the naive redeem revert length matches expected");
            assertEq(
                _u6_hash(retRedeem),
                _u6_hash(expectedData),
                "AS-36: the naive redeem revert hash matches TransferFailed"
            );
            assertEq(n2.shares(ALICE), 5, "AS-36: alice shares stay 5 after the naive redeem failure");
        }
        {
            s.setMode(mode);
            GuardedVault g = new GuardedVault(address(s), address(e.feed), address(e.logic), 0);
            {
                (bool okDepG, bytes memory retDepG) = _u6_deposit(address(g), ALICE, 1);
                assertFalse(okDepG, "AS-36: the guarded deposit against the shaped token fails");
                assertEq(retDepG.length, expectedLen, "AS-36: the guarded deposit revert length matches expected");
                assertEq(
                    _u6_hash(retDepG),
                    _u6_hash(expectedData),
                    "AS-36: the guarded deposit revert hash matches TransferFailed"
                );
            }
            s.setMode(U6_MODE_W1);
            {
                (bool okDepGCtl,) = _u6_deposit(address(g), ALICE, 2);
                assertTrue(okDepGCtl, "AS-36: the guarded deposit succeeds while the shaped token answers word one");
            }
        }
    }

    function _as36_succeedAllPaths(uint8 mode) internal {
        Env memory e = _u6_env();
        U6ShapeToken s = new U6ShapeToken();
        s.setMode(mode);
        {
            NaiveVault n = new NaiveVault(address(s));
            (bool okDep,) = _u6_deposit(address(n), ALICE, 5);
            assertTrue(okDep, "AS-36: the naive deposit against the succeeding shaped token succeeds");
            (bool okRedeem,) = _u6_redeem(address(n), ALICE, 2);
            assertTrue(okRedeem, "AS-36: the naive redeem against the succeeding shaped token succeeds");
            assertEq(n.shares(ALICE), 3, "AS-36: alice shares are 3 after the naive deposit and redeem");
        }
        {
            GuardedVault g = new GuardedVault(address(s), address(e.feed), address(e.logic), 0);
            (bool okDepG,) = _u6_deposit(address(g), ALICE, 5);
            assertTrue(okDepG, "AS-36: the guarded deposit against the succeeding shaped token succeeds");
        }
    }

    function _as40_corpus(Env memory e, address vault) internal {
        _u6_fund(e.token, ALICE, vault, 20e18);
        _u6_fund(e.token, BOB, vault, 40e18);
        _u6_fund(e.token, CAROL, vault, 10e18);
        address[3] memory holders = [ALICE, BOB, CAROL];

        {
            (bool ok,) = _u6_deposit(vault, ALICE, 10e18);
            assertTrue(ok, "AS-40: S1 alice deposit succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S1 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 10e18, "AS-40: S1 total shares are 10e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S1 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_redeem(vault, ALICE, 4e18);
            assertTrue(ok, "AS-40: S2 alice redeem succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S2 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 6e18, "AS-40: S2 total shares are 6e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S2 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_deposit(vault, BOB, 30e18);
            assertTrue(ok, "AS-40: S3 bob deposit succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S3 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 36e18, "AS-40: S3 total shares are 36e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S3 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_deposit(vault, CAROL, 5e18);
            assertTrue(ok, "AS-40: S4 carol deposit succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S4 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 41e18, "AS-40: S4 total shares are 41e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S4 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_deposit(vault, ALICE, 1e18);
            assertTrue(ok, "AS-40: S5 alice deposit succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S5 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 42e18, "AS-40: S5 total shares are 42e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S5 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_redeem(vault, BOB, 7e18);
            assertTrue(ok, "AS-40: S6 bob redeem succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S6 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 35e18, "AS-40: S6 total shares are 35e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S6 vault balance equals total shares"
        );
        {
            uint256 acSum = VaultBase(vault).shares(ALICE) + VaultBase(vault).shares(CAROL);
            assertEq(acSum, 12e18, "AS-40: S6 control alice plus carol shares equal 12e18");
            assertTrue(acSum != 35e18, "AS-40: S6 control alice plus carol shares differ from the total shares");
        }

        {
            (bool ok,) = _u6_redeem(vault, CAROL, 5e18);
            assertTrue(ok, "AS-40: S7 carol redeem succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S7 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 30e18, "AS-40: S7 total shares are 30e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S7 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_redeem(vault, ALICE, 7e18);
            assertTrue(ok, "AS-40: S8 alice redeem succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S8 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 23e18, "AS-40: S8 total shares are 23e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S8 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_redeem(vault, BOB, 23e18);
            assertTrue(ok, "AS-40: S9 bob redeem succeeds");
        }
        assertEq(VaultBase(vault).shares(BOB), 0, "AS-40: S9 bob shares are 0");
        assertEq(
            _u6_sumShares(vault, holders), VaultBase(vault).totalShares(), "AS-40: S9 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 0, "AS-40: S9 total shares are 0");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S9 vault balance equals total shares"
        );

        {
            (bool ok,) = _u6_deposit(vault, ALICE, 2e18);
            assertTrue(ok, "AS-40: S10 alice deposit succeeds");
        }
        assertEq(
            _u6_sumShares(vault, holders),
            VaultBase(vault).totalShares(),
            "AS-40: S10 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 2e18, "AS-40: S10 total shares are 2e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S10 vault balance equals total shares"
        );

        {
            (bool ok, bytes memory ret) = _u6_redeem(vault, ALICE, 0);
            assertFalse(ok, "AS-40: S11 alice redeem of zero fails");
            assertEq(ret.length, 4, "AS-40: S11 zero-amount revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-40: S11 zero-amount revert hash matches ZeroAmount"
            );
        }
        assertEq(
            _u6_sumShares(vault, holders),
            VaultBase(vault).totalShares(),
            "AS-40: S11 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 2e18, "AS-40: S11 total shares are 2e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S11 vault balance equals total shares"
        );

        {
            (bool ok, bytes memory ret) = _u6_redeem(vault, ALICE, 3e18);
            assertFalse(ok, "AS-40: S12 alice redeem beyond her balance fails");
            assertEq(ret.length, 68, "AS-40: S12 insufficient-shares revert length is 68");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.InsufficientShares.selector, uint256(2e18), uint256(3e18))),
                "AS-40: S12 insufficient-shares revert hash matches the have and want values"
            );
        }
        assertEq(
            _u6_sumShares(vault, holders),
            VaultBase(vault).totalShares(),
            "AS-40: S12 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 2e18, "AS-40: S12 total shares are 2e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S12 vault balance equals total shares"
        );

        {
            (bool ok, bytes memory ret) = _u6_redeem(vault, BOB, 1);
            assertFalse(ok, "AS-40: S13 bob redeem with no shares fails");
            assertEq(ret.length, 68, "AS-40: S13 insufficient-shares revert length is 68");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.InsufficientShares.selector, uint256(0), uint256(1))),
                "AS-40: S13 insufficient-shares revert hash matches the have and want values"
            );
        }
        assertEq(
            _u6_sumShares(vault, holders),
            VaultBase(vault).totalShares(),
            "AS-40: S13 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 2e18, "AS-40: S13 total shares are 2e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S13 vault balance equals total shares"
        );

        {
            (bool ok, bytes memory ret) = _u6_deposit(vault, CAROL, 0);
            assertFalse(ok, "AS-40: S14 carol deposit of zero fails");
            assertEq(ret.length, 4, "AS-40: S14 zero-amount revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-40: S14 zero-amount revert hash matches ZeroAmount"
            );
        }
        assertEq(
            _u6_sumShares(vault, holders),
            VaultBase(vault).totalShares(),
            "AS-40: S14 sum of shares equals total shares"
        );
        assertEq(VaultBase(vault).totalShares(), 2e18, "AS-40: S14 total shares are 2e18");
        assertEq(
            MockEquityToken(e.token).balanceOf(vault),
            VaultBase(vault).totalShares(),
            "AS-40: S14 vault balance equals total shares"
        );

        assertEq(MockEquityToken(e.token).balanceOf(vault), 2e18, "AS-40: final vault balance is 2e18");
    }
}
