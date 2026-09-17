// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// 演示件。仅本地 / 演示使用,不部署到任何公链。

import {VaultBase} from "./VaultBase.sol";

/// @title NaiveVault
/// @notice The control arm: it pays one token unit per share and checks nothing about the token ratio.
/// @dev On a ratio change it does not revert and returns no error code; it pays a wrong amount.
/// @dev It still logs Redeemed carrying that wrong amount, so silence here means no failure signal, not a missing log line.
/// @dev This is the failure the demo exists to show: a bug that produces no error.
/// @dev deposit and redeem are identical to GuardedVault except the first statement of redeem there.
contract NaiveVault is VaultBase {
    constructor(address token_) VaultBase(token_) {}
    function deposit(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        shares[msg.sender] += amount;
        totalShares += amount;
        emit Deposited(msg.sender, amount);
        _safeTransferFrom(token, msg.sender, address(this), amount);
    }
    function redeem(uint256 shares_) external nonReentrant returns (uint256 amountOut) {
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
