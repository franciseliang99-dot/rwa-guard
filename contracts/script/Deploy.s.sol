// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {RWAGuardView} from "../src/RWAGuardView.sol";

// Only the two broadcast cheatcodes are declared. No env / file / key cheatcode exists in this
// interface, so none can be called: reading a key or an RPC URL from inside this script is
// structurally impossible, not merely avoided by convention. This interface has a distinct name
// so there is no second `Vm` contract name in this project.
interface DeployBroadcastCheats {
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// @notice Deploys the only contract of this system, RWAGuardView, with a plain `new` -- no
///         constructor arguments, because the contract takes none.
/// @dev Both target chains receive the same build artifact deployed this same way; this script
///      never uses CREATE2, so the two chains are expected to end up with different addresses.
///      Address parity carries no meaning here: the contract is stateless and takes no
///      constructor arguments, so there is nothing a matching address would protect, and a
///      CREATE2 deployment would add a salt that has to be remembered for no benefit.
///      This script reads no keys and no RPC endpoint from inside Solidity: the operator
///      supplies a wallet (a keystore account is preferred over a raw private key), a sender
///      address and an RPC endpoint entirely through the forge CLI, never through this file.
///      The contracts-local .gitignore excludes .env and broadcast/ so neither a key file nor
///      a broadcast record can end up committed.
contract Deploy {
    DeployBroadcastCheats internal constant CHEATS =
        DeployBroadcastCheats(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev Raised when the deployed runtime bytecode does not match the compiled artifact's
    ///      runtime code -- the load-bearing proof that `new` produced exactly this contract.
    error DeployedRuntimeMismatch(address deployed);

    function run() external returns (RWAGuardView guard) {
        CHEATS.startBroadcast();
        guard = new RWAGuardView();
        CHEATS.stopBroadcast();
        if (keccak256(address(guard).code) != keccak256(type(RWAGuardView).runtimeCode)) {
            revert DeployedRuntimeMismatch(address(guard));
        }
    }
}
