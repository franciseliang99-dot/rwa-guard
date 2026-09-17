// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Bytecode-structure acceptance for the deployed guard. Three groups live here:
//   - the AS-32 opcode census (V2, V3, V4, V4b, V4c), the host and vault census, and the behaviour half of the
//     zero-upgrade surface;
//   - the AS-23a..AS-23g derivation checks, which recompute the guard constants from the checked-in proxy runtime
//     and compare them with the GuardCore symbols (no constant value is copied into this file);
//   - the AS-33a codehash-closure check: a positive arm on the real proxy runtime, then every row of an explicit
//     population, then the one named exception.
//
// How the census reads bytecode: instruction by instruction, skipping the immediate bytes of PUSH1..PUSH32 (PUSH0
// has none), over the runtime with the solc CBOR metadata tail stripped. The walk and the strip each have a
// self-test with a known answer. The positive arms (STATICCALL, EXTCODEHASH, RETURN and REVERT, each found at least
// once) run in the same test function as every absence they guard, so a scanner that finds nothing cannot pass.
//
// Compile settings: the solc version, the optimizer switch and runs, the EVM version and the metadata settings in
// foundry.toml change the bytes this file judges. Any change to those settings requires re-running this file.
//
// Cited, not restated: V5 (storage slots stay zero) and the forced-ETH inertness invariant are discharged by
// test_U3_9_storageSlotsStayZero and test_U3_10_forcedEthDoesNotChangeVerdict in test/RWAGuardView.t.sol; this
// file does not copy their logic.
// Not asserted on purpose: "the guard's balance is always 0". A SELFDESTRUCT beneficiary or a block fee recipient
// can credit ETH that the contract cannot refuse. What holds instead: no balance is read on any decision path (the
// V4b census), and any value credited to the guard is permanently unrecoverable, because no withdrawal path exists.
// Judged elsewhere: the empty storage layout (AS-32a), the ABI half of the zero-upgrade surface and the address
// checksum live in build_parity.sh, because a Solidity test cannot read compiler output or run external tools.
//
// Why this file imports one symbol from every other test file and every mock: cheatcode artifact reads (getCode,
// getDeployedCode) are served only from the compiled import closure of the files a filtered run selects. The
// imports below keep every AS-33a population file in that closure; if a file drops out of it, the filtered run of
// this file goes red, not green. The imported types are never deployed with `new`: every population member is
// created from its artifact through getCode and create, so this contract embeds none of their creation code.

import {TestBase} from "./Base.sol";
import {GuardCore} from "../src/GuardCore.sol";
import {RWAGuardView} from "../src/RWAGuardView.sol";
import {Ctx} from "../src/GuardBits.sol";
import {AttacksLyingLogic} from "./Attacks.t.sol";
import {U6ObserverFeed} from "./DemoVaultEdges.t.sol";
import {U6ShapeToken} from "./DemoVaults.t.sol";
import {DualFormLayoutTest} from "./DualForm.t.sol";
import {TwoArgReverter} from "./Fixtures.t.sol";
import {GatesTest} from "./Gates.t.sol";
import {GuardBitsTest} from "./GuardBits.t.sol";
import {IntegrationCeiObserver} from "./Integration.t.sol";
import {RWAGuardHost} from "./RWAGuard.t.sol";
import {RWAGuardViewTest} from "./RWAGuardView.t.sol";
import {MockControlPlane} from "./mocks/MockControlPlane.sol";
import {MockEquityToken} from "./mocks/MockEquityToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

contract OpcodesTest is TestBase {
    string internal constant OP_FIXTURE_PATH = "test/fixtures/equity-token-proxy.runtime.hex";
    address internal constant OP_PROXY_ETCH = address(uint160(uint256(keccak256("rwa-guard.opcodes.proxy-etch"))));
    address internal constant OP_EMPTY_ETCH = address(uint160(uint256(keccak256("rwa-guard.opcodes.empty-etch"))));
    uint256 internal constant OP_POPULATION_ROWS = 35;
    uint256 internal constant OP_POPULATION_CAP = 64;

    // ===== failure messages: "AS-<digits>: <sub> <criterion>; measured <value>" =====
    function _op_eqU(uint256 measured, uint256 expected, string memory criterion) internal pure {
        if (measured != expected) revert(string.concat(criterion, "; measured ", _op_dec(measured)));
    }

    function _op_geU(uint256 measured, uint256 floor, string memory criterion) internal pure {
        if (measured < floor) revert(string.concat(criterion, "; measured ", _op_dec(measured)));
    }

    function _op_eq32(bytes32 measured, bytes32 expected, string memory criterion) internal pure {
        if (measured != expected) revert(string.concat(criterion, "; measured ", _op_hex32(measured)));
    }

    function _op_ne32(bytes32 measured, bytes32 other, string memory criterion) internal pure {
        if (measured == other) revert(string.concat(criterion, "; measured ", _op_hex32(measured)));
    }

    function _op_isTrue(bool measured, string memory criterion) internal pure {
        if (!measured) revert(string.concat(criterion, "; measured false"));
    }

    function _op_isFalse(bool measured, string memory criterion) internal pure {
        if (measured) revert(string.concat(criterion, "; measured true"));
    }

    function _op_dec(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 t = v;
        uint256 digits = 0;
        while (t != 0) {
            digits++;
            t /= 10;
        }
        bytes memory out = new bytes(digits);
        while (v != 0) {
            digits--;
            out[digits] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(out);
    }

    function _op_hex32(bytes32 v) internal pure returns (string memory) {
        bytes16 alphabet = "0123456789abcdef";
        bytes memory out = new bytes(66);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(v[i]);
            out[2 + 2 * i] = alphabet[b >> 4];
            out[3 + 2 * i] = alphabet[b & 0x0f];
        }
        return string(out);
    }
    // ===== instruction walk, metadata strip, census targets, deployment and fixture =====
    function _op_count(bytes memory code, uint8 op) internal pure returns (uint256 n) {
        uint256 i = 0;
        while (i < code.length) {
            uint8 o = uint8(code[i]);
            if (o == op) n++;
            if (o >= 0x60 && o <= 0x7f) {
                i += 1 + uint256(o - 0x5f);
            } else {
                i += 1;
            }
        }
    }

    function _op_walkEnd(bytes memory code) internal pure returns (uint256 end) {
        uint256 i = 0;
        while (i < code.length) {
            uint8 o = uint8(code[i]);
            if (o >= 0x60 && o <= 0x7f) {
                i += 1 + uint256(o - 0x5f);
            } else {
                i += 1;
            }
        }
        end = i;
    }

    function _op_offsetsOf(bytes memory code, uint8 op) internal pure returns (uint256[] memory offs) {
        offs = new uint256[](_op_count(code, op));
        uint256 k = 0;
        uint256 i = 0;
        while (i < code.length) {
            uint8 o = uint8(code[i]);
            if (o == op) {
                offs[k] = i;
                k++;
            }
            if (o >= 0x60 && o <= 0x7f) {
                i += 1 + uint256(o - 0x5f);
            } else {
                i += 1;
            }
        }
    }

    function _op_occurrences(bytes memory hay, bytes memory needle) internal pure returns (uint256 n, uint256 firstOffset) {
        firstOffset = type(uint256).max;
        if (needle.length == 0 || needle.length > hay.length) return (0, firstOffset);
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) {
                if (n == 0) firstOffset = i;
                n++;
            }
        }
    }

    function _op_metaSplit(bytes memory code) internal pure returns (bool ok, uint256 bodyLen) {
        uint256 n = code.length;
        if (n < 2) return (false, 0);
        uint256 metaLen = (uint256(uint8(code[n - 2])) << 8) | uint256(uint8(code[n - 1]));
        if (metaLen + 2 > n) return (false, 0);
        uint8 header = uint8(code[n - metaLen - 2]);
        if (header < 0xa0 || header > 0xbf) return (false, 0);
        return (true, n - metaLen - 2);
    }

    function _op_prefix(bytes memory code, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = code[i];
        }
    }

    function _op_body(bytes memory code, string memory label) internal pure returns (bytes memory body) {
        (bool ok, uint256 bodyLen) = _op_metaSplit(code);
        _op_isTrue(ok, string.concat("AS-32: strip ", label, " metadata tail parses as a CBOR map with a big-endian length"));
        body = _op_prefix(code, bodyLen);
    }

    function _op_positiveArms(bytes memory body, string memory label) internal pure {
        _op_geU(_op_count(body, 0xfa), 1, string.concat("AS-32: positive STATICCALL count in stripped ", label, " runtime is at least 1"));
        _op_geU(_op_count(body, 0x3f), 1, string.concat("AS-32: positive EXTCODEHASH count in stripped ", label, " runtime is at least 1"));
        _op_geU(_op_count(body, 0xf3), 1, string.concat("AS-32: positive RETURN count in stripped ", label, " runtime is at least 1"));
        _op_geU(_op_count(body, 0xfd), 1, string.concat("AS-32: positive REVERT count in stripped ", label, " runtime is at least 1"));
    }

    function _op_viewBody() internal returns (bytes memory body) {
        address v = _op_deploy("RWAGuardView.sol:RWAGuardView", "");
        body = _op_body(v.code, "RWAGuardView");
        _op_eqU(_op_walkEnd(body), body.length, "AS-32: strip RWAGuardView walk end equals stripped length");
    }

    function _op_create(bytes memory init) internal returns (address a) {
        assembly ("memory-safe") {
            a := create(0, add(init, 0x20), mload(init))
        }
    }

    function _op_deploy(string memory artifact, bytes memory args) internal returns (address a) {
        a = _op_create(bytes.concat(vm.getCode(artifact), args));
        _op_geU(a.code.length, 1, string.concat("AS-32: deploy ", artifact, " runtime length is at least 1"));
    }

    function _op_fixture() internal view returns (bytes memory runtime) {
        bytes memory raw = bytes(vm.readFile(OP_FIXTURE_PATH));
        uint256 end = raw.length;
        while (end > 0) {
            bytes1 c = raw[end - 1];
            if (c == 0x0a || c == 0x0d || c == 0x20) {
                end--;
            } else {
                break;
            }
        }
        bytes memory trimmed = new bytes(end);
        for (uint256 i = 0; i < end; i++) {
            trimmed[i] = raw[i];
        }
        runtime = vm.parseBytes(string(trimmed));
    }
    // ===== AS-33a population: one row per concrete type, the self row and three code states =====
    function _op_rowDeploy(address[] memory addrs, bytes32[] memory hashes, string[] memory ids, uint256 k, string memory artifact, bytes memory args) internal returns (uint256) {
        _op_isTrue(k < ids.length, "AS-33: 33a population rows fit OP_POPULATION_CAP");
        address a = _op_create(bytes.concat(vm.getCode(artifact), args));
        _op_geU(a.code.length, 1, string.concat("AS-33: 33a population runtime length of ", artifact, " is at least 1"));
        addrs[k] = a;
        hashes[k] = a.codehash;
        ids[k] = artifact;
        return k + 1;
    }

    function _op_rowSuite(address[] memory addrs, bytes32[] memory hashes, string[] memory ids, uint256 k, string memory artifact) internal view returns (uint256) {
        _op_isTrue(k < ids.length, "AS-33: 33a population rows fit OP_POPULATION_CAP");
        bytes memory rt = vm.getDeployedCode(artifact);
        _op_geU(rt.length, 1, string.concat("AS-33: 33a population deployed code length of ", artifact, " is at least 1"));
        addrs[k] = address(0);
        hashes[k] = keccak256(rt);
        ids[k] = artifact;
        return k + 1;
    }

    function _op_rowHash(address[] memory addrs, bytes32[] memory hashes, string[] memory ids, uint256 k, address a, bytes32 h, string memory id) internal pure returns (uint256) {
        _op_isTrue(k < ids.length, "AS-33: 33a population rows fit OP_POPULATION_CAP");
        addrs[k] = a;
        hashes[k] = h;
        ids[k] = id;
        return k + 1;
    }

    function _op_population() internal returns (address[] memory addrs, bytes32[] memory hashes, string[] memory ids) {
        addrs = new address[](OP_POPULATION_CAP);
        hashes = new bytes32[](OP_POPULATION_CAP);
        ids = new string[](OP_POPULATION_CAP);
        uint256 k = 0;
        vm.etch(OP_EMPTY_ETCH, "");
        // AS-33a population begin
        k = _op_rowDeploy(addrs, hashes, ids, k, "MockEquityToken.sol:MockEquityToken", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "MockControlPlane.sol:MockControlPlane", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "MockPriceFeed.sol:MockPriceFeed", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Attacks.t.sol:AttacksAlwaysFreshFeed", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Attacks.t.sol:AttacksLyingLogic", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Attacks.t.sol:AttacksLengthLiarFeed", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Attacks.t.sol:AttacksNaiveDescriptionReader", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "DemoVaults.t.sol:U6ShapeToken", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "DemoVaultEdges.t.sol:U6ObserverFeed", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Fixtures.t.sol:TwoArgReverter", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Fixtures.t.sol:ExpectRevertHarness", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Fixtures.t.sol:CallbackProbe", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "Integration.t.sol:IntegrationCeiObserver", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "RWAGuard.t.sol:RWAGuardHost", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "RWAGuardView.sol:RWAGuardView", "");
        k = _op_rowDeploy(addrs, hashes, ids, k, "NaiveVault.sol:NaiveVault", abi.encode(address(0)));
        k = _op_rowDeploy(addrs, hashes, ids, k, "GuardedVault.sol:GuardedVault", abi.encode(address(0), address(0), address(0), uint64(0)));
        k = _op_rowSuite(addrs, hashes, ids, k, "Attacks.t.sol:AttacksExposureTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "Attacks.t.sol:AttacksFeedTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "Attacks.t.sol:AttacksFailureTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "DemoVaultEdges.t.sol:DemoVaultEdgesTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "DemoVaults.t.sol:DemoVaultsTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "DemoVaults.t.sol:DemoVaultShapesTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "DualForm.t.sol:DualFormLayoutTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "DualForm.t.sol:DualFormAgreementTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "Fixtures.t.sol:FixturesTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "Gates.t.sol:GatesTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "GuardBits.t.sol:GuardBitsTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "Integration.t.sol:IntegrationTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "RWAGuard.t.sol:RWAGuardTest");
        k = _op_rowSuite(addrs, hashes, ids, k, "RWAGuardView.t.sol:RWAGuardViewTest");
        k = _op_rowHash(addrs, hashes, ids, k, address(this), address(this).codehash, "Opcodes.t.sol:OpcodesTest");
        k = _op_rowHash(addrs, hashes, ids, k, OP_EMPTY_ETCH, OP_EMPTY_ETCH.codehash, "empty-etch-state");
        k = _op_rowHash(addrs, hashes, ids, k, address(0), keccak256(""), "empty-code-hash");
        k = _op_rowHash(addrs, hashes, ids, k, address(0), bytes32(0), "never-deployed-hash");
        // AS-33a population end
        assembly ("memory-safe") {
            mstore(addrs, k)
            mstore(hashes, k)
            mstore(ids, k)
        }
    }
    // ===== tests 1-9: scanner, strip, view bytes, V2..V4c census, zero-upgrade surface =====
    function test_AS32_scannerSelfTest() public pure {
        bytes memory p32 = hex"7f" hex"5555555555555555" hex"5555555555555555" hex"5555555555555555" hex"5555555555555555" hex"00";
        _op_eqU(p32.length, 34, "AS-32: scanner PUSH32 probe length is 34");
        _op_eqU(_op_count(p32, 0x55), 0, "AS-32: scanner SSTORE count in PUSH32 probe is 0");
        _op_eqU(_op_count(p32, 0x7f), 1, "AS-32: scanner PUSH32 count in PUSH32 probe is 1");
        _op_eqU(_op_count(p32, 0x00), 1, "AS-32: scanner STOP count in PUSH32 probe is 1");
        _op_eqU(_op_walkEnd(p32), 34, "AS-32: scanner walk end of PUSH32 probe is 34");
        uint256[] memory offs = _op_offsetsOf(p32, 0x7f);
        _op_eqU(offs.length, 1, "AS-32: scanner PUSH32 offset count in PUSH32 probe is 1");
        _op_eqU(offs[0], 0, "AS-32: scanner PUSH32 offset in PUSH32 probe is 0");
        bytes memory pBare = hex"55";
        _op_eqU(_op_count(pBare, 0x55), 1, "AS-32: scanner SSTORE count in bare SSTORE probe is 1");
        bytes memory p0 = hex"5f55";
        _op_eqU(_op_count(p0, 0x55), 1, "AS-32: scanner SSTORE count after PUSH0 is 1");
        _op_eqU(_op_walkEnd(p0), 2, "AS-32: scanner walk end of PUSH0 probe is 2");
        bytes memory pTrunc = hex"6155";
        _op_eqU(_op_count(pTrunc, 0x55), 0, "AS-32: scanner SSTORE count in truncated PUSH2 probe is 0");
        _op_eqU(_op_walkEnd(pTrunc), 3, "AS-32: scanner walk end of truncated PUSH2 probe is 3");
    }

    function test_AS32_stripSelfTest() public pure {
        bytes memory syn = hex"605500a14155010004";
        _op_eqU(_op_count(syn, 0x55), 1, "AS-32: strip raw SSTORE count in synthetic probe is 1");
        _op_eqU(_op_count(syn, 0xa1), 1, "AS-32: strip raw LOG1 count in synthetic probe is 1");
        _op_eqU(_op_walkEnd(syn), 9, "AS-32: strip raw walk end of synthetic probe is 9");
        (bool ok, uint256 bodyLen) = _op_metaSplit(syn);
        _op_isTrue(ok, "AS-32: strip synthetic probe tail is accepted");
        _op_eqU(bodyLen, 3, "AS-32: strip synthetic probe body length is 3");
        bytes memory body = _op_body(syn, "synthetic probe");
        _op_eq32(keccak256(body), keccak256(hex"605500"), "AS-32: strip synthetic probe body keccak equals keccak of hex 605500");
        _op_eqU(_op_count(body, 0x55), 0, "AS-32: strip stripped SSTORE count in synthetic probe is 0");
        _op_eqU(_op_count(body, 0xa1), 0, "AS-32: strip stripped LOG1 count in synthetic probe is 0");
        _op_eqU(_op_count(body, 0x60), 1, "AS-32: strip stripped PUSH1 count in synthetic probe is 1");
        _op_eqU(_op_count(body, 0x00), 1, "AS-32: strip stripped STOP count in synthetic probe is 1");
        _op_eqU(_op_walkEnd(body), 3, "AS-32: strip stripped walk end of synthetic probe is 3");
        (ok, bodyLen) = _op_metaSplit(hex"6055000020");
        _op_isFalse(ok, "AS-32: strip tail with length 32 over 5 bytes is rejected");
        (ok, bodyLen) = _op_metaSplit(hex"605500554155010004");
        _op_isFalse(ok, "AS-32: strip tail with header byte 0x55 is rejected");
        (ok, bodyLen) = _op_metaSplit(hex"00");
        _op_isFalse(ok, "AS-32: strip one-byte input is rejected");
    }

    function test_AS32_viewCodeMatchesArtifact() public {
        address v = _op_deploy("RWAGuardView.sol:RWAGuardView", "");
        _op_eq32(keccak256(v.code), keccak256(vm.getDeployedCode("RWAGuardView.sol:RWAGuardView")), "AS-32: view-bytes RWAGuardView runtime keccak equals its artifact keccak");
        address gv = _op_deploy("GuardedVault.sol:GuardedVault", abi.encode(address(0), address(0), address(0), uint64(0)));
        _op_eq32(keccak256(gv.code), keccak256(vm.getDeployedCode("GuardedVault.sol:GuardedVault")), "AS-32: view-bytes GuardedVault zero-argument runtime keccak equals its artifact keccak");
        address nv = _op_deploy("NaiveVault.sol:NaiveVault", abi.encode(address(0)));
        _op_eq32(keccak256(nv.code), keccak256(vm.getDeployedCode("NaiveVault.sol:NaiveVault")), "AS-32: view-bytes NaiveVault zero-argument runtime keccak equals its artifact keccak");
        address ctl = _op_deploy("GuardedVault.sol:GuardedVault", abi.encode(address(1), address(2), address(3), uint64(4)));
        _op_ne32(keccak256(ctl.code), keccak256(vm.getDeployedCode("GuardedVault.sol:GuardedVault")), "AS-32: view-bytes control GuardedVault nonzero-argument runtime keccak differs from its artifact keccak");
    }

    function test_AS32_V2_noSstore() public {
        bytes memory body = _op_viewBody();
        _op_positiveArms(body, "RWAGuardView");
        _op_eqU(_op_count(body, 0x55), 0, "AS-32: V2 SSTORE count in stripped RWAGuardView runtime is 0");
    }

    function test_AS32_V3_noTransientStorage() public {
        bytes memory body = _op_viewBody();
        _op_positiveArms(body, "RWAGuardView");
        _op_eqU(_op_count(body, 0x5d), 0, "AS-32: V3 TSTORE count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0x5c), 0, "AS-32: V3 TLOAD count in stripped RWAGuardView runtime is 0");
    }

    function test_AS32_V4_onlyStaticcallExternal() public {
        bytes memory body = _op_viewBody();
        _op_positiveArms(body, "RWAGuardView");
        _op_eqU(_op_count(body, 0xf4), 0, "AS-32: V4 DELEGATECALL count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xf1), 0, "AS-32: V4 CALL count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xf2), 0, "AS-32: V4 CALLCODE count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xf0), 0, "AS-32: V4 CREATE count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xf5), 0, "AS-32: V4 CREATE2 count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xff), 0, "AS-32: V4 SELFDESTRUCT count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xa0), 0, "AS-32: V4 LOG0 count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xa1), 0, "AS-32: V4 LOG1 count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xa2), 0, "AS-32: V4 LOG2 count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xa3), 0, "AS-32: V4 LOG3 count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0xa4), 0, "AS-32: V4 LOG4 count in stripped RWAGuardView runtime is 0");
    }

    function test_AS32_V4b_noBalanceReads() public {
        bytes memory body = _op_viewBody();
        _op_positiveArms(body, "RWAGuardView");
        _op_eqU(_op_count(body, 0x47), 0, "AS-32: V4b SELFBALANCE count in stripped RWAGuardView runtime is 0");
        _op_eqU(_op_count(body, 0x31), 0, "AS-32: V4b BALANCE count in stripped RWAGuardView runtime is 0");
    }

    function test_AS32_V4c_noCaller() public {
        bytes memory body = _op_viewBody();
        _op_positiveArms(body, "RWAGuardView");
        _op_eqU(_op_count(body, 0x33), 0, "AS-32: V4c CALLER count in stripped RWAGuardView runtime is 0");
    }

    function test_AS32_zeroUpgradeSurface() public {
        address v = _op_deploy("RWAGuardView.sol:RWAGuardView", "");
        Ctx memory ctx;
        bool ok;
        bytes memory ret;
        (ok, ret) = v.call(abi.encodeCall(RWAGuardView.isSafeToTrade, (address(0), ctx)));
        _op_isTrue(ok, "AS-32: zero-upgrade control isSafeToTrade call success flag is true");
        _op_eqU(ret.length, 64, "AS-32: zero-upgrade control isSafeToTrade returndata length is 64");
        (ok, ret) = v.call(abi.encodeWithSignature("initialize()"));
        _op_isFalse(ok, "AS-32: zero-upgrade initialize() call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade initialize() returndata length is 0");
        (ok, ret) = v.call(abi.encodeWithSignature("upgradeTo(address)", address(0)));
        _op_isFalse(ok, "AS-32: zero-upgrade upgradeTo(address) call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade upgradeTo(address) returndata length is 0");
        (ok, ret) = v.call(abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(0), bytes("")));
        _op_isFalse(ok, "AS-32: zero-upgrade upgradeToAndCall(address,bytes) call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade upgradeToAndCall(address,bytes) returndata length is 0");
        (ok, ret) = v.call(abi.encodeWithSignature("proxiableUUID()"));
        _op_isFalse(ok, "AS-32: zero-upgrade proxiableUUID() call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade proxiableUUID() returndata length is 0");
        vm.deal(address(this), 1);
        (ok, ret) = v.call{value: 1}("");
        _op_isFalse(ok, "AS-32: zero-upgrade empty calldata with 1 wei call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade empty calldata with 1 wei returndata length is 0");
        (ok, ret) = v.call("");
        _op_isFalse(ok, "AS-32: zero-upgrade empty calldata without value call success flag is false");
        _op_eqU(ret.length, 0, "AS-32: zero-upgrade empty calldata without value returndata length is 0");
    }
    // ===== tests 10-20: host and vault census, AS-23a..AS-23g, AS-33a =====
    function test_AS32_hostCensus() public {
        address host = _op_deploy("RWAGuard.t.sol:RWAGuardHost", "");
        bytes memory body = _op_body(host.code, "RWAGuardHost");
        _op_eqU(_op_walkEnd(body), body.length, "AS-32: strip RWAGuardHost walk end equals stripped length");
        _op_positiveArms(body, "RWAGuardHost");
        address gv = _op_deploy("GuardedVault.sol:GuardedVault", abi.encode(address(0), address(0), address(0), uint64(0)));
        _op_geU(_op_count(_op_body(gv.code, "GuardedVault"), 0x33), 1, "AS-32: host CALLER positive count in stripped GuardedVault runtime is at least 1");
        _op_eqU(_op_count(body, 0x33), 0, "AS-32: host CALLER count in stripped RWAGuardHost runtime is 0");
        _op_eqU(_op_count(body, 0x55), 0, "AS-32: host SSTORE count in stripped RWAGuardHost runtime is 0");
        _op_eqU(_op_count(body, 0x5c), 0, "AS-32: host TLOAD count in stripped RWAGuardHost runtime is 0");
        _op_eqU(_op_count(body, 0x5d), 0, "AS-32: host TSTORE count in stripped RWAGuardHost runtime is 0");
        _op_eqU(_op_count(body, 0xf4), 0, "AS-32: host DELEGATECALL count in stripped RWAGuardHost runtime is 0");
    }

    function test_AS32_vaultExtcodesizeCensus() public {
        bytes memory viewBody = _op_viewBody();
        _op_positiveArms(viewBody, "RWAGuardView");
        address gv = _op_deploy("GuardedVault.sol:GuardedVault", abi.encode(address(0), address(0), address(0), uint64(0)));
        address nv = _op_deploy("NaiveVault.sol:NaiveVault", abi.encode(address(0)));
        _op_geU(_op_count(_op_body(gv.code, "GuardedVault"), 0x3b), 1, "AS-32: vault-extcodesize EXTCODESIZE count in stripped GuardedVault runtime is at least 1");
        _op_geU(_op_count(_op_body(nv.code, "NaiveVault"), 0x3b), 1, "AS-32: vault-extcodesize EXTCODESIZE count in stripped NaiveVault runtime is at least 1");
        _op_eqU(_op_count(viewBody, 0x3b), 0, "AS-32: vault-extcodesize EXTCODESIZE count in stripped RWAGuardView runtime is 0");
    }

    function test_AS23a_fixtureLength() public view {
        bytes memory runtime = _op_fixture();
        _op_eqU(runtime.length, 283, "AS-23: 23a fixture runtime length in bytes is 283");
    }

    function test_AS23b_fixtureKeccak() public view {
        bytes memory runtime = _op_fixture();
        _op_eq32(keccak256(runtime), GuardCore.KNOWN_PROXY_CODEHASH, "AS-23: 23b keccak of fixture runtime equals GuardCore.KNOWN_PROXY_CODEHASH");
    }

    function test_AS23c_singlePush32AtOffset28() public view {
        bytes memory runtime = _op_fixture();
        uint256[] memory offs = _op_offsetsOf(runtime, 0x7f);
        _op_eqU(offs.length, 1, "AS-23: 23c PUSH32 count in fixture runtime is 1");
        _op_eqU(offs[0], 28, "AS-23: 23c PUSH32 offset in fixture runtime is 28");
    }

    function test_AS23d_push32ImmediateIsControlPlane() public view {
        bytes memory runtime = _op_fixture();
        uint256[] memory offs = _op_offsetsOf(runtime, 0x7f);
        _op_eqU(offs.length, 1, "AS-23: 23d PUSH32 count in fixture runtime is 1");
        uint256 p = offs[0] + 1;
        _op_geU(runtime.length, p + 32, "AS-23: 23d fixture runtime holds the 32-byte PUSH32 immediate");
        uint256 w = 0;
        for (uint256 i = 0; i < 32; i++) {
            w = (w << 8) | uint256(uint8(runtime[p + i]));
        }
        _op_eqU(w >> 160, 0, "AS-23: 23d high 12 bytes of the PUSH32 immediate are 0");
        _op_eq32(bytes32(uint256(uint160(w))), bytes32(uint256(uint160(GuardCore.CONTROL_PLANE))), "AS-23: 23d low 20 bytes of the PUSH32 immediate equal GuardCore.CONTROL_PLANE");
    }

    function test_AS23e_controlPlaneOccursOnceAt41() public view {
        bytes memory runtime = _op_fixture();
        bytes memory needle = abi.encodePacked(GuardCore.CONTROL_PLANE);
        _op_eqU(needle.length, 20, "AS-23: 23e GuardCore.CONTROL_PLANE needle length is 20");
        (uint256 n, uint256 first) = _op_occurrences(runtime, needle);
        _op_eqU(n, 1, "AS-23: 23e occurrence count of the GuardCore.CONTROL_PLANE bytes in fixture runtime is 1");
        _op_eqU(first, 41, "AS-23: 23e offset of the GuardCore.CONTROL_PLANE bytes in fixture runtime is 41");
    }

    function test_AS23f_keccakCalibration() public view {
        _op_eq32(keccak256(""), 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470, "AS-23: 23f keccak of the empty string equals the calibration value");
        bytes memory runtime = _op_fixture();
        _op_ne32(keccak256(bytes(vm.readFile(OP_FIXTURE_PATH))), keccak256(runtime), "AS-23: 23f keccak of the fixture file text differs from keccak of its decoded bytes");
    }

    function test_AS23g_etchedCodehashEqualsConstant() public {
        bytes memory runtime = _op_fixture();
        _op_eqU(OP_PROXY_ETCH.code.length, 0, "AS-23: 23g code length at OP_PROXY_ETCH before the etch is 0");
        vm.etch(OP_PROXY_ETCH, runtime);
        _op_eqU(OP_PROXY_ETCH.code.length, runtime.length, "AS-23: 23g code length at OP_PROXY_ETCH after the etch equals the fixture length");
        _op_eq32(OP_PROXY_ETCH.codehash, GuardCore.KNOWN_PROXY_CODEHASH, "AS-23: 23g EXTCODEHASH at OP_PROXY_ETCH equals GuardCore.KNOWN_PROXY_CODEHASH");
    }

    function test_AS33a_positiveArm() public view {
        bytes memory runtime = _op_fixture();
        _op_isTrue(GuardCore._isKnownCodehash(keccak256(runtime)), "AS-33: 33a _isKnownCodehash of the fixture runtime keccak is true");
        _op_isFalse(GuardCore._isKnownCodehash(keccak256("")), "AS-33: 33a _isKnownCodehash of keccak of the empty string is false");
    }

    function test_AS33a_closure() public {
        bytes memory runtime = _op_fixture();
        _op_isTrue(GuardCore._isKnownCodehash(keccak256(runtime)), "AS-33: 33a closure positive arm _isKnownCodehash of the fixture runtime keccak is true");
        (, bytes32[] memory hashes, string[] memory ids) = _op_population();
        for (uint256 i = 0; i < ids.length; i++) {
            _op_isFalse(GuardCore._isKnownCodehash(hashes[i]), string.concat("AS-33: 33a closure _isKnownCodehash of population row ", ids[i], " is false"));
        }
        _op_eqU(ids.length, OP_POPULATION_ROWS, "AS-33: 33a closure population row count equals OP_POPULATION_ROWS");
        _op_eqU(OP_PROXY_ETCH.code.length, 0, "AS-33: 33a closure code length at OP_PROXY_ETCH before the named exception etch is 0");
        vm.etch(OP_PROXY_ETCH, runtime);
        _op_isTrue(GuardCore._isKnownCodehash(OP_PROXY_ETCH.codehash), "AS-33: 33a closure named exception _isKnownCodehash of the real proxy runtime etched at OP_PROXY_ETCH is true");
    }
}
