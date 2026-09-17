// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {DemoVaultsBaseline} from "./DemoVaults.t.sol";
import {RWAGuard} from "../src/RWAGuard.sol";
import {VaultBase} from "../src/demo/VaultBase.sol";
import {NaiveVault} from "../src/demo/NaiveVault.sol";
import {GuardedVault} from "../src/demo/GuardedVault.sol";

contract U6ObserverFeed {
    address private _vault;
    address private _holder;
    uint256 private _expected;

    error U6ObserverMismatch(uint256 seen, uint256 expected);

    function arm(address vault, address holder, uint256 expected) external {
        _vault = vault;
        _holder = holder;
        _expected = expected;
    }

    function armed() external view returns (bool) {
        return _vault != address(0);
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        uint256 seen = VaultBase(_vault).shares(_holder);
        if (seen != _expected) revert U6ObserverMismatch(seen, _expected);
        return (7, 1e8, block.timestamp, block.timestamp, 7);
    }

    function description() external pure returns (string memory) {
        return "MOCK / USD";
    }
}

contract DemoVaultEdgesTest is DemoVaultsBaseline {
    function test_U6_1_alwaysFreshFeedPasses() public {
        Env memory e = _u6_env();
        GuardedVault g = _u6_guarded(e, address(e.feed));
        _u6_fund(e.token, ALICE, address(g), 5e18);
        e.feed.setRound(999, 1, 1, 1, 999);
        e.feed.setDescriptionText("FAKE / USD");
        vm.warp(T0 + 31_536_000);
        {
            (bool ok,) = _u6_deposit(address(g), ALICE, 5e18);
            assertTrue(ok, "AS-U6-1: alice deposit into the guarded vault succeeds");
        }
        {
            (bool ok,) = _u6_redeem(address(g), ALICE, 3e18);
            assertTrue(ok, "AS-U6-1: alice redeem against the always-fresh feed succeeds");
        }
        assertEq(g.shares(ALICE), 2e18, "AS-U6-1: alice shares are 2e18 after the redeem");
        e.feed.setFollowNow(false);
        e.feed.setRound(999, 1, 1, 1, 998);
        {
            (bool ok, bytes memory ret) = _u6_redeem(address(g), ALICE, 1e18);
            assertFalse(ok, "AS-U6-1: the control redeem after the feed stops following now is blocked");
            assertEq(ret.length, 68, "AS-U6-1: the control blocked redeem revert length is 68");
            (uint256 sel, , uint256 bits) = _u6_guardBlockedParts(ret);
            assertEq(
                sel,
                uint256(uint32(RWAGuard.GuardBlocked.selector)),
                "AS-U6-1: the control blocked redeem selector matches GuardBlocked"
            );
            assertTrue(bits != 0, "AS-U6-1: the control blocked redeem bits are nonzero");
        }
        assertEq(g.shares(ALICE), 2e18, "AS-U6-1: alice shares stay 2e18 after the control redeem");
    }

    function test_U6_2_observerSeesPreState() public {
        // T-3: the feed reads vault state during enforce and sees the pre-redeem share balance.
        Env memory e = _u6_env();
        U6ObserverFeed o = new U6ObserverFeed();
        GuardedVault g = new GuardedVault(e.token, address(o), address(e.logic), 0);
        _u6_fund(e.token, ALICE, address(g), 100e18);
        {
            (bool ok,) = _u6_deposit(address(g), ALICE, 100e18);
            assertTrue(ok, "AS-U6-2: alice deposit into the guarded vault succeeds");
        }
        o.arm(address(g), ALICE, 60e18);
        assertTrue(o.armed(), "AS-U6-2: the observer feed reads armed as true");
        {
            (bool ok, bytes memory ret) = _u6_redeem(address(g), ALICE, 40e18);
            assertFalse(ok, "AS-U6-2: the control redeem against a wrong armed expectation is blocked");
            assertEq(ret.length, 68, "AS-U6-2: the control blocked redeem revert length is 68");
            (uint256 sel, , uint256 bits) = _u6_guardBlockedParts(ret);
            assertEq(
                sel,
                uint256(uint32(RWAGuard.GuardBlocked.selector)),
                "AS-U6-2: the control blocked redeem selector matches GuardBlocked"
            );
            assertTrue(bits != 0, "AS-U6-2: the control blocked redeem bits are nonzero");
        }
        assertEq(g.shares(ALICE), 100e18, "AS-U6-2: alice shares stay 100e18 after the control redeem");
        o.arm(address(g), ALICE, 100e18);
        {
            (bool ok,) = _u6_redeem(address(g), ALICE, 40e18);
            assertTrue(ok, "AS-U6-2: the main redeem against the matching pre-state expectation succeeds");
        }
        assertEq(g.shares(ALICE), 60e18, "AS-U6-2: alice shares are 60e18 after the main redeem");
        assertEq(g.totalShares(), 60e18, "AS-U6-2: total shares are 60e18 after the main redeem");
    }

    function test_U6_3_zeroAmountRejected() public {
        Env memory e = _u6_env();
        NaiveVault n = _u6_naive(e);
        GuardedVault g = _u6_guarded(e, address(e.feed));
        {
            (bool ok, bytes memory ret) = _u6_deposit(address(n), ALICE, 0);
            assertFalse(ok, "AS-U6-3: the naive vault rejects a zero deposit");
            assertEq(ret.length, 4, "AS-U6-3: the naive zero deposit revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-U6-3: the naive zero deposit hash matches ZeroAmount"
            );
        }
        {
            (bool ok, bytes memory ret) = _u6_redeem(address(n), ALICE, 0);
            assertFalse(ok, "AS-U6-3: the naive vault rejects a zero redeem");
            assertEq(ret.length, 4, "AS-U6-3: the naive zero redeem revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-U6-3: the naive zero redeem hash matches ZeroAmount"
            );
        }
        {
            (bool ok, bytes memory ret) = _u6_deposit(address(g), ALICE, 0);
            assertFalse(ok, "AS-U6-3: the guarded vault rejects a zero deposit");
            assertEq(ret.length, 4, "AS-U6-3: the guarded zero deposit revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-U6-3: the guarded zero deposit hash matches ZeroAmount"
            );
        }
        {
            (bool ok, bytes memory ret) = _u6_redeem(address(g), ALICE, 0);
            assertFalse(ok, "AS-U6-3: the guarded vault rejects a zero redeem");
            assertEq(ret.length, 4, "AS-U6-3: the guarded zero redeem revert length is 4");
            assertEq(
                _u6_hash(ret),
                _u6_hash(abi.encodeWithSelector(VaultBase.ZeroAmount.selector)),
                "AS-U6-3: the guarded zero redeem hash matches ZeroAmount"
            );
        }
        _u6_fund(e.token, ALICE, address(n), 1);
        _u6_fund(e.token, ALICE, address(g), 1);
        {
            (bool ok,) = _u6_deposit(address(n), ALICE, 1);
            assertTrue(ok, "AS-U6-3: the control naive deposit of 1 succeeds");
        }
        {
            (bool ok,) = _u6_redeem(address(n), ALICE, 1);
            assertTrue(ok, "AS-U6-3: the control naive redeem of 1 succeeds");
        }
        {
            (bool ok,) = _u6_deposit(address(g), ALICE, 1);
            assertTrue(ok, "AS-U6-3: the control guarded deposit of 1 succeeds");
        }
        {
            (bool ok,) = _u6_redeem(address(g), ALICE, 1);
            assertTrue(ok, "AS-U6-3: the control guarded redeem of 1 succeeds");
        }
    }
}
