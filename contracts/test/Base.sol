// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice 只声明本仓真正用到的 cheatcode。
/// @dev 刻意不 vendor forge-std:见 foundry.toml 顶部。地址是 foundry 的固定常量
///      `address(uint160(uint256(keccak256("hevm cheat code"))))`。
/// @dev 本文件的 state-diff 类型声明对应的 foundry 版本是 1.8.1,换版本必须重跑 AS-39。
interface Vm {
    function warp(uint256 newTimestamp) external;
    function prank(address msgSender) external;
    function label(address addr, string calldata newLabel) external;
    function expectRevert(bytes calldata revertData) external;
    function mockCall(address callee, bytes calldata data, bytes calldata returnData) external;
    function mockCallRevert(address callee, bytes calldata data, bytes calldata revertData) external;
    function clearMockedCalls() external;
    function etch(address target, bytes calldata newRuntimeBytecode) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function load(address target, bytes32 slot) external view returns (bytes32);

    // [UNVERIFIED] — field order/types copied from the U5 §9 draft; not checked against the installed
    // foundry's cheatcode ABI (no forge-std, no network). Verification = AS-39(a) exact fan-out counts.
    // AS-39(a) red ⇒ suspect THESE declarations first, the guard second. Never rewrite expected values.
    enum AccountAccessKind { Call, DelegateCall, CallCode, StaticCall, Create, SelfDestruct, Resume, Balance, Extcodesize, Extcodehash, Extcodecopy }
    struct ChainInfo { uint256 forkId; uint256 chainId; }
    struct StorageAccess { address account; bytes32 slot; bool isWrite; bytes32 previousValue; bytes32 newValue; bool reverted; }
    struct AccountAccess {
        ChainInfo chainInfo; AccountAccessKind kind; address account; address accessor; bool initialized;
        uint256 oldBalance; uint256 newBalance; bytes deployedCode; uint256 value; bytes data; bool reverted;
        StorageAccess[] storageAccesses; uint64 depth;
    }

    function createSelectFork(string calldata urlOrAlias) external returns (uint256 forkId);
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256 forkId);
    function envOr(string calldata name, string calldata defaultValue) external view returns (string memory value);
    function skip(bool skipTest) external;
    function deal(address account, uint256 newBalance) external;
    function getDeployedCode(string calldata artifactPath) external view returns (bytes memory runtimeBytecode);
    function getCode(string calldata artifactPath) external view returns (bytes memory creationBytecode);
    function readFile(string calldata path) external view returns (string memory data);
    function parseBytes(string calldata stringifiedValue) external pure returns (bytes memory parsedValue);
    function startStateDiffRecording() external;
    function stopAndReturnStateDiff() external returns (AccountAccess[] memory accountAccesses);
}

/// @notice 最小测试基座。断言失败即 revert —— forge 据此判 fail,不需要 DSTest 的 `failed()` 标志位。
abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition, string memory reason) internal pure {
        if (!condition) revert(reason);
    }

    function assertFalse(bool condition, string memory reason) internal pure {
        if (condition) revert(reason);
    }

    function assertEq(uint256 a, uint256 b, string memory reason) internal pure {
        if (a != b) revert(reason);
    }

    function assertEq(address a, address b, string memory reason) internal pure {
        if (a != b) revert(reason);
    }

    function assertEq(bool a, bool b, string memory reason) internal pure {
        if (a != b) revert(reason);
    }
}
