// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {DemoVaultsBaseline} from "./DemoVaults.t.sol";
import {Ctx} from "../src/GuardBits.sol";
import {RWAGuardView} from "../src/RWAGuardView.sol";
import {VaultBase} from "../src/demo/VaultBase.sol";
import {NaiveVault} from "../src/demo/NaiveVault.sol";
import {GuardedVault} from "../src/demo/GuardedVault.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";

// Integration arms for the two demo vaults that test/DemoVaults.t.sol and test/DemoVaultEdges.t.sol do not carry.
// Every other item of this integration section has exactly one home, cited below and not restated here:
//   AS-29 (a): test/DemoVaults.t.sol::test_AS29_a_naivePaysDoubleAfterEffective
//   AS-29 (b): test/DemoVaults.t.sol::test_AS29_b_guardedBlocksAfterEffective
//   AS-29 (c): test/DemoVaults.t.sol::test_AS29_c_scheduledNotEffective
//   AS-29b: test/DemoVaults.t.sol::test_AS29b_noTransitionArmsAgree
//   AS-30 naive arm: test/DemoVaults.t.sol::test_AS30_naiveReentryBlocked
//   AS-30 guarded arm: test/DemoVaults.t.sol::test_AS30_guardedReentryBlocked
//   AS-31: test/DemoVaults.t.sol::test_AS31_crossAccountRedeemRejected
//   AS-31b: test/DemoVaults.t.sol::test_AS31b_privilegedSelectorsAbsent
//   AS-31c: test/DemoVaults.t.sol::test_AS31c_layoutSlotsMatch
//   AS-19b: test/DemoVaults.t.sol::test_AS19b_burningFeedFailsOnlyGuarded
//   AS-36 (1): test/DemoVaults.t.sol::test_AS36_1_noCode
//   AS-36 (2): test/DemoVaults.t.sol::test_AS36_2_callReverts
//   AS-36 (3): test/DemoVaults.t.sol::test_AS36_3_emptyReturn
//   AS-36 (4): test/DemoVaults.t.sol::test_AS36_4_wordOne
//   AS-36 (5): test/DemoVaults.t.sol::test_AS36_5_wordZero
//   AS-36 (6): test/DemoVaults.t.sol::test_AS36_6_wordTwo
//   AS-36 (7): test/DemoVaults.t.sol::test_AS36_7_len31
//   AS-36 (8): test/DemoVaults.t.sol::test_AS36_8_len64
//   AS-40 naive arm: test/DemoVaults.t.sol::test_AS40_shareConservation_naive
//   AS-40 guarded arm: test/DemoVaults.t.sol::test_AS40_shareConservation_guarded
//   read-only observer arm: test/DemoVaultEdges.t.sol::test_U6_2_observerSeesPreState
//   zero amount: test/DemoVaultEdges.t.sol::test_U6_3_zeroAmountRejected
// Accepted differences in form: every failure is checked by a low-level call, its length and its hash;
// AS-31b and AS-31c keep the behaviour and slot halves in the repo, and their ABI and layout artifact halves run outside it;
// AS-19b accepts two failure forms for the burning feed; the read-only observer arm reads shares only.
// New in this file: AS-29d, the zero expectedImpl vault arm under AS-21, and the transfer-time state arms under AS-30.

// Called by the token from inside its transfer, after the token ledger update, while the vault call is still running.
// It reads the vault public getters and reverts with what it saw unless they equal the armed expectation.
contract IntegrationCeiObserver {
    address private _vault;
    address private _holder;
    uint256 private _expectedShares;
    uint256 private _expectedTotal;
    uint256 public hits;

    error IntegrationCeiMismatch(uint256 seenShares, uint256 seenTotal);

    function arm(address vault, address holder, uint256 expectedShares, uint256 expectedTotal) external {
        _vault = vault;
        _holder = holder;
        _expectedShares = expectedShares;
        _expectedTotal = expectedTotal;
    }

    function observe() external {
        uint256 seenShares = VaultBase(_vault).shares(_holder);
        uint256 seenTotal = VaultBase(_vault).totalShares();
        if (seenShares != _expectedShares || seenTotal != _expectedTotal) {
            revert IntegrationCeiMismatch(seenShares, seenTotal);
        }
        hits += 1;
    }
}

contract IntegrationTest is DemoVaultsBaseline {
    // Shared state for AS-29d and AS-21: one token, one feed, a naive and a guarded vault, alice and bob with 100e18 shares in each.
    // The ratio moves from 1e18 to 5e17 at T0 plus 1, time reaches it, and the transition then closes at 5e17 with no pending change.
    // The feed follows block time, so it is fresh at every read.
    function _as29_postTransitionAssembly(Env memory e) internal returns (NaiveVault n, GuardedVault g) {
        n = _u6_naive(e);
        g = _u6_guarded(e, address(e.feed));
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
        vm.warp(T0 + 1);
        MockEquityToken(e.token).setRatios(5e17, 5e17, 0);
        assertEq(MockEquityToken(e.token).uiMultiplier(), 5e17, "AS-29: uiMultiplier reads back 5e17 after the transition closes");
        assertEq(MockEquityToken(e.token).newUIMultiplier(), 5e17, "AS-29: newUIMultiplier reads back 5e17 after the transition closes");
        assertEq(MockEquityToken(e.token).effectiveAt(), 0, "AS-29: effectiveAt reads back 0 after the transition closes");
        e.feed.setFollowNow(true);
        (,,,,, bool followNow) = e.feed.readRoundConfig();
        assertTrue(followNow, "AS-29: the shared feed followNow reads back true");
    }

    // AS-30 transfer-time state arms. The token calls the observer after its ledger update, inside the vault token call.
    // Each arm first runs a control that expects the pre-state and must fail, then the real arm that expects the post-state.
    // A pass shows the vault wrote shares and total shares before its single token call, in deposit and in redeem.
    // This proves that the view it sees is self-consistent, not that read-only reentrancy is prevented.
    // 这证明的是「看见的那一份是自洽的」,不是「防住了只读重入」。
    // The lock still blocks re-entry into deposit and redeem; it does not stop a getter being read mid-call.
    // The value a guard feed would read during enforce is not pinned here.
    function _as30_ceiArms(Env memory e, address vault) internal {
        IntegrationCeiObserver o = new IntegrationCeiObserver();
        _u6_fund(e.token, ALICE, vault, 100e18);
        _u6_fund(e.token, BOB, vault, 100e18);
        (bool okDep0,) = _u6_deposit(vault, ALICE, 100e18);
        assertTrue(okDep0, "AS-30: alice deposit before the observer is armed succeeds");
        MockEquityToken(e.token).setCallback(address(o), abi.encodeWithSelector(IntegrationCeiObserver.observe.selector));
        assertEq(
            uint256(vm.load(e.token, bytes32(uint256(8)))),
            uint256(uint160(address(o))),
            "AS-30: the callback target slot holds the observer address"
        );
        o.arm(vault, BOB, 0, 100e18);
        (bool okDepCtl, bytes memory retDepCtl) = _u6_deposit(vault, BOB, 100e18);
        assertFalse(okDepCtl, "AS-30: the control deposit against a pre-state expectation fails");
        assertEq(retDepCtl.length, 196, "AS-30: the control failed deposit revert length is 196");
        assertEq(
            _u6_hash(retDepCtl),
            _u6_hash(
                _u6_transferFailedData(
                    e.token,
                    abi.encodeWithSelector(
                        IntegrationCeiObserver.IntegrationCeiMismatch.selector, uint256(100e18), uint256(200e18)
                    )
                )
            ),
            "AS-30: the control failed deposit carries the post-state the observer saw"
        );
        assertEq(VaultBase(vault).shares(BOB), 0, "AS-30: bob shares stay 0 after the control deposit");
        o.arm(vault, BOB, 100e18, 200e18);
        (bool okDep1,) = _u6_deposit(vault, BOB, 100e18);
        assertTrue(okDep1, "AS-30: the main deposit against the post-state expectation succeeds");
        assertEq(o.hits(), 1, "AS-30: the observer ran once during the main deposit");
        o.arm(vault, ALICE, 100e18, 200e18);
        (bool okRedCtl, bytes memory retRedCtl) = _u6_redeem(vault, ALICE, 40e18);
        assertFalse(okRedCtl, "AS-30: the control redeem against a pre-state expectation fails");
        assertEq(retRedCtl.length, 196, "AS-30: the control failed redeem revert length is 196");
        assertEq(
            _u6_hash(retRedCtl),
            _u6_hash(
                _u6_transferFailedData(
                    e.token,
                    abi.encodeWithSelector(
                        IntegrationCeiObserver.IntegrationCeiMismatch.selector, uint256(60e18), uint256(160e18)
                    )
                )
            ),
            "AS-30: the control failed redeem carries the post-state the observer saw"
        );
        assertEq(VaultBase(vault).shares(ALICE), 100e18, "AS-30: alice shares stay 100e18 after the control redeem");
        o.arm(vault, ALICE, 60e18, 160e18);
        (bool okRed1,) = _u6_redeem(vault, ALICE, 40e18);
        assertTrue(okRed1, "AS-30: the main redeem against the post-state expectation succeeds");
        assertEq(o.hits(), 2, "AS-30: the observer ran once more during the main redeem");
        assertEq(VaultBase(vault).shares(ALICE), 60e18, "AS-30: alice shares are 60e18 after the main redeem");
        assertEq(VaultBase(vault).totalShares(), 160e18, "AS-30: total shares are 160e18 after the main redeem");
        MockEquityToken(e.token).setCallback(address(0), "");
        assertEq(uint256(vm.load(e.token, bytes32(uint256(8)))), 0, "AS-30: the callback target slot is cleared after the arms");
    }

    // AS-29d. After the ratio transition closes, the guard no longer blocks, and both vaults pay the wrong amount together.
    // This exposure is declared here, not fixed.
    // The guard reports the absence of eight named conditions plus one unreadable bit.
    // It does not check the integrator's own accounting.
    // After the transition closes, both vaults overpay 1:1 while reasonBits is exactly 0 and the guard lets the redeem through.
    // Numbers, all derived from the token rules: m = 5e17, each vault holds 200e18 raw, so its balance is 100e18.
    // Alice holds half the shares, so the fair amount is 50e18; each vault pays shares 1:1, which is 100e18.
    // Paying 100e18 at m = 5e17 moves 200e18 raw, so the first redeem drains the vault and bob is left with nothing.
    // The fair amount is computed here from the token balance and the share split, never asked of a vault.
    // The guarded vault is read and redeemed first; the naive arm runs last, on a vault the guarded redeem never touched.
    // Controls live in other functions so that this one stays green under every guard mutation:
    //   test/DemoVaults.t.sol::test_AS29_b_guardedBlocksAfterEffective: a guarded vault is blocked with bit 5 while the transition is in flight;
    //   test/DemoVaults.t.sol::test_AS29_c_scheduledNotEffective: a change that is scheduled but not yet effective;
    //   test_AS21_zeroExpectedImplVaultBlocked below: a vault blocked in this same state.
    function test_AS29d_afterTransitionBothArmsOverpay() public {
        Env memory e = _u6_env();
        (NaiveVault n, GuardedVault g) = _as29_postTransitionAssembly(e);
        bytes memory retG;
        assertEq(g.priceFeed(), address(e.feed), "AS-29: the guarded vault priceFeed is the refreshed shared feed");
        {
            (bool okView, uint256 bitsView) = (new RWAGuardView()).isSafeToTrade(
                e.token,
                Ctx({
                    priceFeed: g.priceFeed(),
                    actor: ALICE,
                    counterparty: ALICE,
                    expectedImpl: g.expectedImpl(),
                    maxFeedAge: g.maxFeedAge()
                })
            );
            assertEq(bitsView, 0, "AS-29: the view reports reasonBits exactly 0 for the guarded vault context");
            assertTrue(okView, "AS-29: the view reports the guarded vault context as safe to trade");
        }
        assertEq(MockEquityToken(e.token).balanceOf(address(g)), 100e18, "AS-29: guarded vault balance is 100e18 before the redeem");
        assertEq(
            (MockEquityToken(e.token).balanceOf(address(g)) * g.shares(ALICE)) / g.totalShares(),
            50e18,
            "AS-29: the fair amount for alice in the guarded vault is 50e18"
        );
        {
            bool okG;
            (okG, retG) = _u6_redeem(address(g), ALICE, 100e18);
            assertTrue(okG, "AS-29: alice redeem from the guarded vault after the transition closes succeeds");
            assertEq(retG.length, 32, "AS-29: the guarded redeem return length is 32");
            uint256 outG = abi.decode(retG, (uint256));
            assertEq(outG, 100e18, "AS-29: the guarded vault pays out 100e18");
            assertEq(outG, 2 * 50e18, "AS-29: the guarded payout is twice the fair amount");
            assertEq(outG - 50e18, 50e18, "AS-29: the guarded overpayment is 50e18");
        }
        {
            assertEq(MockEquityToken(e.token).balanceOf(address(g)), 0, "AS-29: guarded vault balance is drained to 0");
            assertEq(g.totalShares(), 100e18, "AS-29: guarded total shares are 100e18 after alice redeems");
            assertEq(g.shares(BOB), 100e18, "AS-29: bob still holds 100e18 shares in the guarded vault");
            (bool okBobG, bytes memory retBobG) = _u6_redeem(address(g), BOB, 100e18);
            assertFalse(okBobG, "AS-29: bob redeem from the drained guarded vault fails");
            assertEq(retBobG.length, 228, "AS-29: bob failed guarded redeem revert length is 228");
            assertEq(
                _u6_hash(retBobG),
                _u6_hash(
                    _u6_transferFailedData(
                        e.token,
                        abi.encodeWithSelector(
                            MockEquityToken.InsufficientRaw.selector, address(g), uint256(0), uint256(200e18)
                        )
                    )
                ),
                "AS-29: bob failed guarded redeem hash matches the InsufficientRaw wrapped transfer failure"
            );
        }
        {
            assertEq(
                (MockEquityToken(e.token).balanceOf(address(n)) * n.shares(ALICE)) / n.totalShares(),
                50e18,
                "AS-29: the fair amount for alice in the naive vault is 50e18"
            );
            (bool okN, bytes memory retN) = _u6_redeem(address(n), ALICE, 100e18);
            assertTrue(okN, "AS-29: alice redeem from the naive vault in the same scenario succeeds");
            assertEq(retN.length, 32, "AS-29: the naive redeem return length is 32");
            assertEq(_u6_hash(retN), _u6_hash(retG), "AS-29: the naive and guarded redeem return bytes are identical");
        }
    }

    // AS-21 vault arm. A guarded vault deployed with a zero expectedImpl, in the same state as AS-29d.
    // A zero expectedImpl is unreadable for the implementation gate: bit 20 is set, and any unreadable bit also sets bit 255.
    // Expected bits are derived from that rule, not measured: (1 << 20) | (1 << 255).
    // So every redeem from such a vault is blocked, and no share or balance moves.
    // It is also the same-state control for AS-29d: the view that reports 0 there reports these two bits here.
    function test_AS21_zeroExpectedImplVaultBlocked() public {
        Env memory e = _u6_env();
        _as29_postTransitionAssembly(e);
        GuardedVault gz = new GuardedVault(e.token, address(e.feed), address(0), 0);
        assertEq(gz.expectedImpl(), address(0), "AS-21: the zero-impl guarded vault expectedImpl reads back as the zero address");
        assertEq(gz.priceFeed(), address(e.feed), "AS-21: the zero-impl guarded vault priceFeed is the refreshed shared feed");
        _u6_fund(e.token, CAROL, address(gz), 2e18);
        (bool okDepC,) = _u6_deposit(address(gz), CAROL, 1e18);
        assertTrue(okDepC, "AS-21: carol deposit into the zero-impl guarded vault succeeds");
        assertEq(gz.shares(CAROL), 1e18, "AS-21: carol holds 1e18 shares after the deposit");
        assertEq(MockEquityToken(e.token).balanceOf(address(gz)), 1e18, "AS-21: the zero-impl guarded vault balance is 1e18 after the deposit");
        {
            (bool okView, uint256 bitsView) = (new RWAGuardView()).isSafeToTrade(
                e.token,
                Ctx({
                    priceFeed: gz.priceFeed(),
                    actor: CAROL,
                    counterparty: CAROL,
                    expectedImpl: gz.expectedImpl(),
                    maxFeedAge: gz.maxFeedAge()
                })
            );
            assertFalse(okView, "AS-21: the view reports the zero-impl context as not safe to trade");
            assertEq(bitsView, (uint256(1) << 20) | (uint256(1) << 255), "AS-21: the view reports exactly bit 20 and bit 255 for the zero-impl context");
        }
        {
            (bool okRedeem, bytes memory retRedeem) = _u6_redeem(address(gz), CAROL, 1e18);
            assertFalse(okRedeem, "AS-21: the zero-impl guarded vault blocks the redeem");
            assertEq(retRedeem.length, 68, "AS-21: the blocked zero-impl redeem revert length is 68");
            assertEq(
                _u6_hash(retRedeem),
                _u6_hash(_u6_guardBlockedData(e.token, (uint256(1) << 20) | (uint256(1) << 255))),
                "AS-21: the blocked zero-impl redeem hash matches GuardBlocked with bit 20 and bit 255"
            );
        }
        assertEq(gz.shares(CAROL), 1e18, "AS-21: carol shares stay 1e18 after the blocked redeem");
        assertEq(gz.totalShares(), 1e18, "AS-21: zero-impl vault total shares stay 1e18 after the blocked redeem");
        assertEq(MockEquityToken(e.token).balanceOf(address(gz)), 1e18, "AS-21: the zero-impl guarded vault balance stays 1e18 after the blocked redeem");
    }

    function test_AS30_ceiNaiveTransferSeesPostState() public {
        Env memory e = _u6_env();
        _as30_ceiArms(e, address(_u6_naive(e)));
    }

    function test_AS30_ceiGuardedTransferSeesPostState() public {
        Env memory e = _u6_env();
        _as30_ceiArms(e, address(_u6_guarded(e, address(e.feed))));
    }
}
