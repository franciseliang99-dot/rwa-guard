// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// 演示件。仅本地 / 演示使用,不部署到任何公链。

import {VaultBase} from "./VaultBase.sol";
import {RWAGuard} from "../RWAGuard.sol";
import {Ctx} from "../GuardBits.sol";

/// @title GuardedVault
/// @notice The experiment arm: identical to NaiveVault except that redeem calls RWAGuard.enforce as its first statement.
/// @dev enforce runs after the nonReentrant lock is taken and before any read or write of vault state, so a feed that reads back sees the pre-state.
/// @dev Bad input to the vault reverts with a vault error; a gate the guard cannot pass sets reason bits and reverts GuardBlocked.
/// @dev This vault does not catch the guard revert. A caller that catches must match the GuardBlocked selector before reading bits; an empty revert or a Panic is not a verdict.
/// @dev deposit carries no enforce so the demo differs in exactly one place; a real integration would likely guard both entry points.
/// @dev priceFeed, expectedImpl and maxFeedAge are immutables chosen by the deployer and never taken from the caller; maxFeedAge 0 is the strictest value, not a default.
/// @dev Known cost: a hostile feed can burn all gas inside enforce, an out-of-gas failure that NaiveVault does not have.
/// @dev actor and counterparty are both msg.sender: there is no counterparty, and that is an explicit choice.
/// @dev There is no migration path: if the feed or the expected implementation must change, this vault cannot follow.
/// @dev That is acceptable only because this vault is a demo that is never deployed.
/// @dev The constructor does not validate inputs; a zero feed makes every redeem revert GuardBlocked with unreadable bits.
/// @dev A feed that answers fresh and positive passes the feed gates even with a wrong price; the guard does not judge the price.
contract GuardedVault is VaultBase {
    address public immutable priceFeed;
    address public immutable expectedImpl;
    uint64 public immutable maxFeedAge;
    constructor(address token_, address priceFeed_, address expectedImpl_, uint64 maxFeedAge_) VaultBase(token_) {
        priceFeed = priceFeed_;
        expectedImpl = expectedImpl_;
        maxFeedAge = maxFeedAge_;
    }
    function deposit(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        shares[msg.sender] += amount;
        totalShares += amount;
        emit Deposited(msg.sender, amount);
        _safeTransferFrom(token, msg.sender, address(this), amount);
    }
    function redeem(uint256 shares_) external nonReentrant returns (uint256 amountOut) {
        RWAGuard.enforce(token, Ctx({priceFeed: priceFeed, actor: msg.sender, counterparty: msg.sender, expectedImpl: expectedImpl, maxFeedAge: maxFeedAge}));
        if (shares_ == 0) revert ZeroAmount();
        uint256 have = shares[msg.sender];
        if (shares_ > have) revert InsufficientShares(have, shares_);
        amountOut = shares_;
        shares[msg.sender] = have - shares_;
        totalShares -= shares_;
        emit Redeemed(msg.sender, shares_, amountOut);
        _safeTransfer(token, msg.sender, amountOut);
    }
}
