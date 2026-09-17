// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// 演示件。仅本地 / 演示使用,不部署到任何公链。

/// @title VaultBase
/// @notice Shared base of the two demo vaults: one lock and one token-call helper, so the two arms cannot drift apart.
/// @notice Demo code for local walkthroughs only; it is never deployed and must not hold value.
/// @dev Storage order is fixed: shares at slot 0, totalShares at slot 1, _lock at slot 2; token is an immutable and takes no slot.
/// @dev The derived vaults must not declare any storage variable, so both arms keep the same layout.
/// @dev The lock is a uint256 in plain storage, 1 when idle and 2 while a locked call runs, set to 1 in the constructor.
/// @dev The lock stays in plain storage by design, never a transient slot.
/// @dev The lock stops re-entry into deposit and redeem of the same vault; getters stay readable mid-call, so this is not that read-only reentrancy is blocked.
/// @dev Every token call is a plain CALL with a selector derived at compile time from the signature string.
/// @dev Case 0: a token address with no code reverts NotAContract before the call, since a call to an empty account succeeds with no data.
/// @dev Case 1: a reverting call reverts TransferFailed with at most the first 256 bytes of the revert data; longer data is cut on purpose.
/// @dev Case 2 and 3: success with no data, or success with exactly one 32-byte word equal to 1, is a completed transfer; any other word fails.
/// @dev Case 4: success with any other data length fails, because a shape that does not match cannot be read.
/// @dev Correct for the fixtures in this repo and for standard and USDT-style return shapes only; a mature safe-transfer library covers many more token quirks.
/// @dev Fee-on-transfer and rebasing tokens are out of scope; a ratio change on the observed token is a renamed rebasing risk, and the vault sits on that path.
/// @dev Polarity: a 32-byte word of 2 is a failed transfer here, while the guard reads a paused word of 2 as paused, which is a violation.
/// @dev The two go in opposite directions and both are deny-safe: ambiguity must land on the safe side, and the safe sides differ.
/// @dev For paused the safe side is to treat the token as paused; for a transfer it is to treat the transfer as not done.
/// @dev Folding the two into one rule, in either direction, opens a path from ambiguity to loss.
/// @dev deposit and redeem in both vaults are nonReentrant and ordered checks, then state updates and the log line, then the single token call.
/// @dev No function here or in the vaults can move another account shares or take the vault balance; there is no owner, pause, upgrade or sweep.
/// @dev InsufficientShares reports what the caller holds first and what was asked second.
abstract contract VaultBase {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    address public immutable token;
    constructor(address token_) {
        token = token_;
        _lock = 1;
    }
    error InsufficientShares(uint256 have, uint256 want);
    error ZeroAmount();
    error ReentrantCall();
    error TransferFailed(address token, bytes returndata);
    error NotAContract(address token);
    event Deposited(address indexed account, uint256 amount);
    event Redeemed(address indexed account, uint256 shares, uint256 amountOut);
    uint256 private _lock;
    bytes4 private constant _SEL_TRANSFER = bytes4(keccak256(bytes("transfer(address,uint256)")));
    bytes4 private constant _SEL_TRANSFER_FROM = bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));
    uint256 private constant _RETURNDATA_COPY_BOUND = 256;
    modifier nonReentrant() {
        if (_lock != 1) revert ReentrantCall();
        _lock = 2;
        _;
        _lock = 1;
    }
    function _safeTransfer(address token_, address to, uint256 amount) internal {
        _callToken(token_, abi.encodeWithSelector(_SEL_TRANSFER, to, amount));
    }
    function _safeTransferFrom(address token_, address from, address to, uint256 amount) internal {
        _callToken(token_, abi.encodeWithSelector(_SEL_TRANSFER_FROM, from, to, amount));
    }
    function _callToken(address token_, bytes memory data) private {
        if (token_.code.length == 0) revert NotAContract(token_);
        bool success;
        uint256 size;
        uint256 word;
        assembly ("memory-safe") {
            success := call(gas(), token_, 0, add(data, 0x20), mload(data), 0, 0)
            size := returndatasize()
            if and(success, eq(size, 32)) {
                returndatacopy(0, 0, 32)
                word := mload(0)
            }
        }
        if (success && (size == 0 || (size == 32 && word == 1))) return;
        uint256 n = size > _RETURNDATA_COPY_BOUND ? _RETURNDATA_COPY_BOUND : size;
        bytes memory ret = new bytes(n);
        assembly ("memory-safe") {
            returndatacopy(add(ret, 0x20), 0, n)
        }
        revert TransferFailed(token_, ret);
    }
}
