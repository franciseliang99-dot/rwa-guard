// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title GuardBits — RWA Guard 判定结果位布局的唯一具名定义
/// @notice 本文件是「判定结果位布局」唯一的具名定义处与唯一事实源:任何别的合约、解码器、文档、测试都不得
///         再为这些位起第二套名字。测试按 AV-1 以独立字面移位写出完整期望值,是对本处的核对,不是第二份布局。零依赖、零函数、零状态、零继承。
/// @notice 判定结果是一个 `uint256 reasonBits`,编码八道闸:每道闸一个 violated 位(读到了,
///         而且是坏消息)、一个 unreadable 位(根本没读到),外加一个聚合位。
///         unreadable 位一律由 `UNREADABLE_SHIFT` 派生 —— 它们刻意没有名字,因为两套独立的
///         名字会让两个位平面各改一半而没人发现。
/// @dev 集成方解码契约(七条)。承重的是第二条:它是「未知不等于放行」在链下解码器一侧的
///      唯一落点 —— 将来加一道闸时,它守的是「旧解码器把新置的位静默忽略」这条从「判不出」
///      到「放行」的路径。
///
/// 1. `ok == (reasonBits == 0)`。绝不从位的子集重新推导 `ok`。
///
/// 2. `reasonBits & ~((1 << 255) | 0x17F017F) != 0` ⇒ 当 BLOCK 处理。
///    口径:已知位 = bits 0–6、8、16–22、24、255;任何未知置位都意味着这份载荷来自一个
///    更新的版本,旧解码器必须拦,而不是静默忽略。
///    🔴 实现里请用 `GuardBits.KNOWN_MASK` 表达,不要抄这串字面量。
///
/// 3. `(reasonBits & 0x800080)` 必须为 0(bit 7 与 bit 23 永久保留);非零 ⇒ 这份载荷不是
///    本版本产出的。
///
/// 4. bit 255 是聚合,不是第九道闸:它置位 ⟺ unreadable 平面上至少一位置位。
///    🔴 判据用 `UNREADABLE_MASK`,**绝不写成位区间** —— 连续区间比这张掩码**宽一位**,
///       多出来的那一位是 `RESERVED`(第 3 条)、任何路径不得置位 ⇒ 两种写法只在
///       「该保留位恒为 0」这条**写在别处**的不变式下外延相等。以掩码为判据,聚合位就不
///       依赖一个恒为零的位;而照区间写出来的断言**在任何语料上都绿**,钉不住任何东西。
///    ⚠ 这里曾经写过一个位区间,它比掩码宽一位 —— 别再往回写。本条刻意不复述那个区间,
///       复述了,「旧写法清干净了吗」的普查就会在这句说明上命中。
///
/// 5. 逐闸互斥:对每道闸 n,violated 位与它自己的 unreadable 位互斥。但不同闸的两类位可以
///    同时出现(例如喂价给了未来时间戳时,bit 8 与 bit 22 会同时置位)—— 那不是不变式违反。
///
/// 6. bit 0(G0)置位时,bits 1 / 3 / 4 是关于那个规范控制面的真陈述,不一定是关于这个
///    代币实际控制者的陈述。
///
/// 7. 🔴 捕获 `enforce` 的 revert 时,必须先匹配 `GuardBlocked` 的 selector,再解码
///    `reasonBits`。一个空 revert 或 `Panic(uint256)` 不是一个判决,是一次解码失败或 gas
///    耗尽 —— 把它当成 `reasonBits == 0` 来读,就正好造出那条从「判不出」到「放行」的路径。
library GuardBits {
    uint256 internal constant UNREADABLE_SHIFT = 16;

    // violated 位
    uint256 internal constant G0_IDENTITY         = 1 << 0;
    uint256 internal constant G1_GLOBAL_PAUSE     = 1 << 1;
    uint256 internal constant G2_TOKEN_PAUSE      = 1 << 2;
    uint256 internal constant G3_BLOCKED          = 1 << 3;
    uint256 internal constant G4_IMPL_DRIFT       = 1 << 4;   // 标签是「实现漂移」,不是 "upgrade freshness"
    uint256 internal constant G5_RATIO_TRANSITION = 1 << 5;
    uint256 internal constant G6_FEED_STALE       = 1 << 6;
    // bit 7 RESERVED(G7 已撤)—— 任何路径不得置位
    uint256 internal constant G8_FEED_INCOHERENT  = 1 << 8;

    // unreadable 位 = 对应 violated 位 << 16
    uint256 internal constant U_AGGREGATE     = 1 << 255;

    uint256 internal constant VIOLATED_MASK   = 0x17F;       // bits 0-6, 8
    uint256 internal constant UNREADABLE_MASK = 0x17F0000;   // bits 16-22, 24
    uint256 internal constant RESERVED_MASK   = 0x800080;    // bit 7 | bit 23 —— 恒为 0
    uint256 internal constant KNOWN_MASK      = VIOLATED_MASK | UNREADABLE_MASK | U_AGGREGATE;
}

// 文件作用域,声明在 GuardBits.sol
struct Ctx {
    address priceFeed;      // G6 / G8:调用方钉死的喂价合约
    address actor;          // G3:行为方。⚠ 绝不从 msg.sender 推断
    address counterparty;   // G3:交易对手。无对手时填与 actor 相同的地址(显式动作)
    address expectedImpl;   // G4:调用方审计过的实现地址
    uint64  maxFeedAge;     // G6:陈旧度容忍(秒)。0 = 最严格,不是未设值
}
