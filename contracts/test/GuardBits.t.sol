// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TestBase} from "./Base.sol";
import {GuardBits} from "../src/GuardBits.sol";

/// @notice U1 §6 的四项验收(AS-26a / AS-26b / AS-26c / 负向攻击场景)。除了 AS-26b 里的
///         `(uint256(1) << 7)` —— 那是 U1 §6 的规约原文 —— 全部断言都是关系式,一个字面
///         位号都不含:U1 §1 逐字禁止任何测试定义第二份位号。
/// @dev 诚实边界,别把这四项读成「位布局已被钉住」:
///      · 九个单位常量(G0…G6 / G8 / U_AGGREGATE)与 237 个未分配位,被这里的任何一条断言
///        引用零次 ⇒ 它们挪到任何位,这四项都会全绿 —— 这是 KG-13,知情接受的 open risk;
///        在 U1 这一层内失效方向是 fail-open(位摆错了照样发车)。
///      · ⚠ 别读成「没有任何东西覆盖」:按 AV-1,U7 的 test/Gates.t.sol 要对每道闸断言【完整
///        256 位】且期望值写成【独立字面移位】(AS-18 两条最强:八个门位 + U_AGGREGATE +「其余
///        位为 0」一并钉住)⇒ 整体错位在那里会红。U8 一条断言都不碰位号。⚠ 但那个文件尚未存在(U7 产出):U7 不落地 ⇒ 补偿不存在。
///      · KNOWN_MASK 按定义就是那三项的或,所以 AS-26c 的第一条是重言式 —— 它只在有人改
///        写那个组合表达式本身时才会红。
///      · AS-26c 的第二条与负向攻击断言在逻辑上是同一个谓词(`&` 可交换)。U1 §6 要求两条
///        都写,所以两条都在;能把它们区分开的只有失败消息里的 reason。
contract GuardBitsTest is TestBase {
    /// @notice AS-26a:unreadable 平面恰好是 violated 平面按统一偏移移位的结果。
    /// @dev 三个互相独立写下的常量(UNREADABLE_MASK / VIOLATED_MASK / UNREADABLE_SHIFT);
    ///      改任一个而不同改另两个就会红。
    function test_AS26a_unreadablePlaneIsViolatedPlaneShifted() public pure {
        assertEq(
            GuardBits.UNREADABLE_MASK,
            GuardBits.VIOLATED_MASK << GuardBits.UNREADABLE_SHIFT,
            "AS-26a"
        );
    }

    /// @notice AS-26b:保留的是【两个】位,不是一个 —— 保留位与它自己的 unreadable 对偶。
    /// @dev 右边把 RESERVED_MASK 对着一个硬字面量重算,所以这是本文件里唯一一条把某个位
    ///      拴在独立写下的位置上的断言;U1 §6 的规约原文就是这个形状,照抄。
    function test_AS26b_reservedPairIsSymmetric() public pure {
        assertEq(
            GuardBits.RESERVED_MASK,
            (uint256(1) << 7) | ((uint256(1) << 7) << GuardBits.UNREADABLE_SHIFT),
            "AS-26b"
        );
    }

    /// @notice AS-26c:已知集合的组成,以及保留位刻意【不在】已知集合里。
    function test_AS26c_knownMaskCompositionExcludesReserved() public pure {
        assertEq(
            GuardBits.KNOWN_MASK,
            GuardBits.VIOLATED_MASK | GuardBits.UNREADABLE_MASK | GuardBits.U_AGGREGATE,
            "AS-26c"
        );
        assertEq(
            GuardBits.KNOWN_MASK & GuardBits.RESERVED_MASK,
            0,
            "AS-26c reserved-excluded"
        );
    }

    /// @notice 负向攻击场景(U1 §6 末条):只置了保留位的载荷,在「已知位」这个口径下是
    ///         完全未知的 —— 解码器据此可以判定它不是本版本产出的,走 BLOCK 而不是放行。
    /// @dev 这条没有被分配 AS- 编号(U1 §6 只称它「攻击场景断言(负向)」),故 reason 里
    ///      带的是它的出处行号,用来与 AS-26c 的第二条区分开。
    function test_reservedOnlyPayloadIsWhollyUnknown() public pure {
        uint256 bits = GuardBits.RESERVED_MASK;
        assertEq(
            bits & GuardBits.KNOWN_MASK,
            0,
            "U1:157 neg - reserved-only payload is wholly unknown"
        );
    }
}
