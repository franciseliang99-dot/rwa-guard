// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardBits, Ctx} from "./GuardBits.sol";

/// @title GuardCore — 八道闸判定逻辑的唯一实现
/// @notice 本 library 回答一个问题:「给定一个代币地址和一组调用方断言,现在对它动手安不安全?」
///         返回 `(bool ok, uint256 reasonBits)`。
///         位布局的唯一定义在 `GuardBits.sol`:本文件不定义第二份位号,unreadable 位一律由
///         `GuardBits.UNREADABLE_SHIFT` 现场派生,不取第二套名字。
///
/// @dev ════ D1 · 任何输入都不会让本 library revert ════
///      每一个坏输入都变成【一个位】。本文件零 `require`、零 `revert`、零 `assert`、零自定义
///      error —— 没有任何一处输入校验会 revert。
///      🔴 已知例外恰有一个:整个调用 frame 的 gas 被耗尽。它在本层不可观测、不可缓解,本
///      library 结构上对它做不了任何事 —— 所以这条的射程写成「输入」,不写成「绝不 revert」。
///      源码层还能 revert 的语言构件恰好三处,每一处都有就地点名的缓解 —— ① ② 靠求值顺序,
///      ③ 的顺序只是其中较弱的一条、另有一条更强的(见该函数处),三处都在下面就地点名:
///        ① G6 的那次减法(分支顺序:先排除未来时间戳)
///        ② `returndatacopy`(长度判据在它之前求值)
///        ③ `_answersDescription` 的 `size - DESCRIPTION_HEAD_LEN`(由 `&&` 的短路门控)
///      这三处是对「源码层可 revert 构件」做类型枚举得到的:算术 2 处、且这 2 处都是减法
///      (上面的 ① 与 ③;不存在第三处减法)、`returndatacopy` 1 处、显式
///      revert/require/assert 0 处、数组越界 0 处(定长
///      `bytes32[5]` 的下标全是字面量)、除零/模零 0 处、`abi.decode` 0 处(全部手工解码)。
///
/// @dev ════ D2 · 「读不到」与「读到了但是坏的」是两类位 ════
///      violated 位(读到了,而且是坏消息)与 unreadable 位(根本没读到)刻意保持可区分,
///      后者 = 前者 << 16。解码方不得把两者合并:合并就等于把「我没观测到」和「我观测到了
///      一条坏事实」说成同一句话。
///
/// @dev ════ D3 · 逐闸:读不到吸收违反,并就此收闸 ════
///      对每一道闸:先判「读不到」,命中即置 unreadable 位并【就此收闸】—— violated 谓词
///      不求值,该闸已经读回来的字一律丢弃。
///      代码形状就是这条规则的证明,八道闸无例外:
///          if (<读不到>) bits |= U位;  else if (<违反>) bits |= V位;
///      (「读不到」有多条成因时,既可以一条成因占一支 `else if`(G0 / G6),也可以把多条
///       成因并进同一支的析取(G3 / G4 / G5)—— 本文件里两种都有,支数不承重。承重的恰三条,
///       本注释块是这个成员集的【权威】,设计文档只许逐字引用、不许另写一份:
///       ① 全部 U 支在前 · ② 「违反」恰一支、在链尾、写在 `else if` 的条件里、不预先算进
///       局部变量 · ③ 任一 U 支成立时 V 不求值。)
///      ⚠ 这里曾经给 U 的支数写过一条全称,而 G3 / G4 / G5 是它的反例 —— 别再往回写。
///      ⇒「同一道闸的 violated 位与 unreadable 位同时置位」这件事【写不出来】,不靠测试去发现。
///      🔴 代价写明,别当它不存在:一个真在封禁名单上的行为方,可以让同一道闸的另一次读停机,
///      把 bit 3 换成 bit 19。两者都使 `ok == false` ⇒【安全侧零损失】,损失的只是理由的精度。
///      反方向(让违反吸收读不到)会把「我没读到」谎报成「我读到了一条封禁」= 陈述一个未观测
///      的事实,更坏。
///
/// @dev ════ D4 · 全部求值,无短路 —— 闸间与闸内都是 ════
///      八道闸全部求值,不因 G0 失败而跳过其余:短路会让后续各闸的位保持干净,而干净的位读作
///      「条件不成立」—— 那正是把「读不到」伪装成「通过」的形状。gas 更贵是知情接受的代价。
///      🔴【闸内也不短路】:G3 的四次读、G5 的三次读必须先全部发出、结果落进局部变量,再组合
///      判据。写成 `r1 && r2 && r3` 会在第一次失败时跳过后面的读 = 静默削掉扇出;而在「全部读
///      都成功」那一臂上,短路与不短路的读取次数【完全相同】⇒ 那个写法在按次数计量的检查上
///      结构性隐形。本文件里 `||` / `|=` 对判据的组合一律发生在【该发出的读已经全部发出之后】,
///      绝不用来决定某一次读发不发。
///
/// @dev ════ 跨闸同时置位是合法的,而且是最诚实的描述 ════
///      「逐闸互斥」说的是:对【每一道闸】n,它的 violated 位与它自己的 unreadable 位互斥。
///      逐闸,不是跨闸。下面两组属于【不同的闸】,同时置位完全合法:
///        ① `updatedAt > block.timestamp` ⇒ 同时置 bit 8(G8 违反:轮次不自洽)与
///           bit 22(G6 读不到:年龄这个量无定义)。
///        ② `latestRoundData()` 不答 ⇒ 同时置 bit 8(「不答」逐字就在 G8 的谓词里)与
///           bit 22(G6 读不到)。
///      🔴 以上两组的前提【都是】`ctx.priceFeed != address(0)`。地址为零时按 G8 的唯一
///      unreadable 路径【就此收闸】:只置 bit 22 与 bit 24,【bit 8 不置位】。
///      不写这一段,第一个读到它的人会把它报成不变式违反。
///
/// @dev ════ 调用形态(三条硬约束)════
///      F1. 禁 typed interface 调用(`IToken(t).paused()` 这种形态):typed 调用把「返回了
///          垃圾」和「revert 了」塌成同一种失败,而「无法识别的返回形状」必须被【检测】,
///          不能只是被 revert 穿过去。⇒ 本文件零 `interface` 声明,全部外部读取走原始
///          `staticcall` + 显式长度校验。
///      F2. 禁 Solidity 高层 `address.staticcall(bytes)`:它把 returndata【无界拷贝】进一个新
///          `bytes` —— 一个恶意喂价返回 10 MB,内存扩展当场把调用方的 gas 烧光。
///      F3. u2(长度)判据【只存在于一处】—— `_staticRead`。两份长度检查就是其中一份哪天
///          写错的方式。
///      🔴 不设 staticcall 的 gas 上限,这是裁决不是遗漏:被饿死的读返回 `success == false`
///      ⇒ 该闸的 unreadable 位置位 ⇒ `ok == false`,结构上产不出一个假的 `ok`;而设上限会造出
///      一道与拒绝服务无法区分、且【不可修】(编译期常量)的闸。returndata 炸弹那一半已由 F2
///      与 `_answersDescription` 的定长前缀结构性解掉,不需要 gas 上限来兜。
///
/// @dev ════ 本 library 结构上没有的东西 ════
///      · 零 storage slot、零 `immutable`、零构造器参数、零可注入配置:library 没有构造期,
///        而同一份常量在两种交付形态下必须是同一份字节。
///      · 零 test-only 分支、零 test-only 常量、零可注入的 codehash 集合 —— 让步只能发生在
///        测试夹具那一侧。
///      · 零 event、零 error:判定结果全在 `reasonBits` 里。
///      · 零 `msg.sender`:在 library 形态下它是终端用户,在部署合约形态下它是集成方合约 ⇒
///        读它会让【同一输入在两种形态下给出不同判决】。行为方必须作为显式输入 `ctx.actor`
///        抵达。🔴 也绝不提供「不传 actor 时默认取 `msg.sender`」的便利重载:一个默认值会让
///        「我没想过这个字段」和「我确认过就是它」在字节上不可区分,而这个字段决定了封禁名单
///        查的是谁。
///      · 给不了重入守护:library 语言层禁止声明可变状态 ⇒ 锁没地方放;唯一的替代载体是
///        transient storage,而本系统要求 `TSTORE` / `TLOAD` 各 0 次 ⇒ 义务在契约上转移给集成方
///        的 CEI 次序。
///        ⚠ 只读重入面是【真实存在】的:本 library 会向调用方提供的 `ctx.priceFeed` 发
///        staticcall,那个合约可以在 staticcall 里回读集成方的中间状态 —— 它写不了,但看得见。
///        本单元对此不做任何缓解(做不了)。
library GuardCore {
    // ═════════════════════════════════════════════════════════════════════════
    // 值常量(三个;另有一个只供 `_answersDescription` 用的 `private` 长度常量,就近声明在该函数上方)
    //
    // 🔴 一律 `constant`:library 没有构造期;更根本的是同一份常量在两种交付形态下必须是
    //    同一份字节。绝不 `immutable`、绝不做成构造器参数、绝不做成可注入的集合。
    // 🟢 前两个是【从代码里导出的值】,不是转抄的值:
    //      · `keccak256(签入的 283 字节代理 runtime) == KNOWN_PROXY_CODEHASH`
    //      · 那份 runtime 里恰好只有一个 `PUSH32`,其立即数高 12 字节全零、低 20 字节
    //        `== CONTROL_PLANE`,且该 20 字节序列在整个 runtime 中只出现一次。
    //    ⚠ 这两条导出关系由 `test/` 下的 codehash 测试断言,而那个测试尚未落地 ⇒ 在它落地
    //    之前,下面这两个字面量【没有任何机械检查】。这是一句如实的边界,不是一句宽慰。
    // ═════════════════════════════════════════════════════════════════════════
    bytes32 internal constant KNOWN_PROXY_CODEHASH =
        0x2f367e6a678e7b30ab613d5963e541e6f4d3ca586de76e2f441fbfeb1a27c440;

    address internal constant CONTROL_PLANE =
        0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5;

    /// @dev 账户存在但无代码(EOA / 未部署)时 `EXTCODEHASH` 返回的值。
    bytes32 internal constant EMPTY_CODE_HASH = keccak256("");

    // ═════════════════════════════════════════════════════════════════════════
    // selector 常量(8 个)
    //
    // 🔴 全部由编译期从【签名字符串】导出,本文件一个十六进制 selector 字面量都不出现:
    //    抄一个十六进制值进来,就多一处会与签名漂移的「真相」。
    // 🔴 另一种导出机制(`interface` 类型的 `.selector`)刻意【住在测试文件里】,不在本文件:
    //    两种机制若都住在这里,「两种机制结果一致」的断言就是拿本文件和它自己比,承载 0 bit。
    //    这也是本文件零 `interface` 声明的第二个理由(第一个见 F1)。
    // ⚠ 具名常量而不是把表达式内联到调用点:`isBlocked(address)` 被用 4 次、`paused()` 被用
    //    2 次,内联就是同一个签名字符串的 4 份 / 2 份表示。具名让每个签名在本文件里恰好出现一次。
    // ═════════════════════════════════════════════════════════════════════════
    bytes4 internal constant SEL_PAUSED            = bytes4(keccak256(bytes("paused()")));
    bytes4 internal constant SEL_IS_BLOCKED        = bytes4(keccak256(bytes("isBlocked(address)")));
    bytes4 internal constant SEL_UI_MULTIPLIER     = bytes4(keccak256(bytes("uiMultiplier()")));
    bytes4 internal constant SEL_NEW_UI_MULTIPLIER = bytes4(keccak256(bytes("newUIMultiplier()")));
    bytes4 internal constant SEL_EFFECTIVE_AT      = bytes4(keccak256(bytes("effectiveAt()")));
    bytes4 internal constant SEL_IMPLEMENTATION    = bytes4(keccak256(bytes("implementation()")));
    bytes4 internal constant SEL_LATEST_ROUND_DATA = bytes4(keccak256(bytes("latestRoundData()")));
    bytes4 internal constant SEL_DESCRIPTION       = bytes4(keccak256(bytes("description()")));

    // ═════════════════════════════════════════════════════════════════════════
    // 判定入口
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice 对 `token` 跑完八道闸,返回完整的 `reasonBits` 与 `ok`。
    /// @dev 执行顺序固定:G0 → G1 → G2 → G3 → G4 → G5 →(一次 `latestRoundData()`)→ G6 → G8。
    ///      任何输入都不 revert(含 `token == address(0)`、`ctx` 全零)—— 见 D1。
    /// @param token 被判定的代币地址。不可信。
    /// @param ctx   调用方的断言集合。⚠ 其中的行为方【绝不】从 `msg.sender` 推断。
    /// @return ok         `ok == (reasonBits == 0)`,绝不从位的子集重新推导。
    /// @return reasonBits 只含 `GuardBits.KNOWN_MASK` 内的位;保留位恒为 0。
    function evaluate(address token, Ctx memory ctx)
        internal
        view
        returns (bool ok, uint256 reasonBits)
    {
        // ─────────────────────────────────────────────────────────────────────
        // 1 · G0 身份(bit 0 / bit 16)—— 用 `EXTCODEHASH` opcode,不是 call
        //
        // 三态,显式分支且互斥:
        //   ① `h == 0`               账户不存在                     ⇒ 读不到(bit 16)
        //   ② `h == EMPTY_CODE_HASH` 账户存在但无代码(EOA / 未部署)⇒ 读不到(bit 16)
        //   ③ 其余且不是已知 codehash                                ⇒ 违反(bit 0)
        // ⚠ `token == address(0)` 不特判、不 revert:`EXTCODEHASH(0)` 返回 0 ⇒ 走 ①。
        // ⚠ G0 只有这一条谓词。不要往里加「是否暴露预期接口」—— codehash 钉住的是代理,
        //    而代理把一切 delegate 给背后的实现,接口在不在由【当前实现】决定,不由代理代码
        //    决定。接口存在性已经分散到真正需要那个 selector 的每道闸的 unreadable 位上了,
        //    那样更好:它告诉你【哪一个】selector 消失了。
        // ⚠ 「目标地址无代码」这条成因(u4)在整个判定路径上【只实现这一次】—— 它就是 G0
        //    本身。对控制面与喂价刻意不做独立预检:长度判据(u2)已经在【位】的层面完全吸收
        //    它(对无代码地址发 staticcall 返回 `success == true` 且 returndata 为空 ⇒ 长度
        //    判据判它读不到,行为逐位相同),而两套判据就是其中一套哪天与另一套不一致的方式。
        // ─────────────────────────────────────────────────────────────────────
        {
            bytes32 h = token.codehash;
            if (h == bytes32(0)) {
                reasonBits |= GuardBits.G0_IDENTITY << GuardBits.UNREADABLE_SHIFT;
            } else if (h == EMPTY_CODE_HASH) {
                reasonBits |= GuardBits.G0_IDENTITY << GuardBits.UNREADABLE_SHIFT;
            } else if (!_isKnownCodehash(h)) {
                reasonBits |= GuardBits.G0_IDENTITY;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 2 · G1 全局暂停(bit 1 / bit 17):对控制面调 `paused()`,预期恰好 32 字节
        //
        // 🔴 `bool` 的 deny-safe 读法是 `true ⟺ word != 0`。写成 `word == 1` 时,一个返回 `2`
        //    的实现会被读成 `false` =「没暂停 / 没被封禁」= 一个干净的位,而对方明明说了
        //    非 false 的东西。
        // ⚠ 射程声明:这条只管【判定路径读取外部合约的 `bool`】,别把它当全仓通则 —— 别处
        //    (例如转账成功与否的判读)安全的那一侧本来就不同,那里的极性相反,而两者【都是】
        //    deny-safe:deny-safe 不是往固定方向倒,是让歧义导向安全的那一侧。
        // ─────────────────────────────────────────────────────────────────────
        {
            (bool readable, bytes32 word) =
                _readWord(CONTROL_PLANE, abi.encodeWithSelector(SEL_PAUSED));
            if (!readable) {
                reasonBits |= GuardBits.G1_GLOBAL_PAUSE << GuardBits.UNREADABLE_SHIFT;
            } else if (word != bytes32(0)) {
                reasonBits |= GuardBits.G1_GLOBAL_PAUSE;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 3 · G2 代币暂停(bit 2 / bit 18):对 `token` 调 `paused()`,预期恰好 32 字节
        //     `bool` 的读法同 G1:`true ⟺ word != 0`。
        // ─────────────────────────────────────────────────────────────────────
        {
            (bool readable, bytes32 word) =
                _readWord(token, abi.encodeWithSelector(SEL_PAUSED));
            if (!readable) {
                reasonBits |= GuardBits.G2_TOKEN_PAUSE << GuardBits.UNREADABLE_SHIFT;
            } else if (word != bytes32(0)) {
                reasonBits |= GuardBits.G2_TOKEN_PAUSE;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 4 · G3 封禁(bit 3 / bit 19)—— 四次查询,顺序固定:
        //       token.isBlocked(actor) → token.isBlocked(counterparty)
        //       → 控制面.isBlocked(actor) → 控制面.isBlocked(counterparty)
        //
        // ⚠ 为什么是四次而不是两次:`isBlocked` 这个 selector 在代币和控制面【两处都存在】,
        //    而代币的 `isBlocked` 是不是转发到控制面,本项目【没有测过】。别脑补它转发。
        //    若它不转发而各有一份名单,只读控制面就会静默漏掉代币侧记录的封禁 —— 那是一条
        //    从「真实存在一条封禁」到「位是干净的」的路径。未知之下 deny-by-default 的正确
        //    形状是【都读】。
        // ⚠ 行为方 / 对手方为零地址时,与【那个字段】相关的两次 `isBlocked` 不发出,位照样
        //    置上(bit 19)⇒ 这不是被禁止的短路(被禁的短路是「跳过一道闸而它的位保持干净」)。
        //    🔴 而这条「不发」的理由【只对实参成立】,别外推:问 `isBlocked(address(0))` 会
        //    得到一个【问错了主语】的真答案,拿它置 bit 3 等于把一条关于零地址的封禁冒充成
        //    关于行为方的 ⇒ 不发在这里不是优化,是语义上必须的。
        //    抹除是【逐字段】的:一个字段为零只抹掉它自己那两次读,另一个字段的两次照发。
        // ⚠ 行为方与对手方相同时【不去重】,四次读照发 —— 「无对手时填与行为方相同的地址」
        //    是常态;去重会让扇出在常态下掉下来。
        // 🔴 闸内不短路:下面四次读各自只受「它的实参是否为零」门控,绝不受前一次读的结果
        //    门控。`unreadable` 的累加只改变判据,不改变「发不发」。
        // ⚠ 四次读的结果按位或攒进 `words`:`任意一次 word != 0` 与 `(w1|w2|w3|w4) != 0`
        //    是同一个命题(而且只在 `else if` 里求值 ⇒ 读不到时这些字被丢弃,没有参与判决)。
        // ─────────────────────────────────────────────────────────────────────
        {
            bool actorSet = ctx.actor != address(0);
            bool counterpartySet = ctx.counterparty != address(0);

            // 读不到的第一类成因:身份性实参为零地址(在发调用之前判)。
            bool unreadable = !actorSet || !counterpartySet;
            bytes32 words;

            if (actorSet) {
                (bool r, bytes32 w) =
                    _readWord(token, abi.encodeWithSelector(SEL_IS_BLOCKED, ctx.actor));
                unreadable = unreadable || !r;
                words |= w;
            }
            if (counterpartySet) {
                (bool r, bytes32 w) =
                    _readWord(token, abi.encodeWithSelector(SEL_IS_BLOCKED, ctx.counterparty));
                unreadable = unreadable || !r;
                words |= w;
            }
            if (actorSet) {
                (bool r, bytes32 w) =
                    _readWord(CONTROL_PLANE, abi.encodeWithSelector(SEL_IS_BLOCKED, ctx.actor));
                unreadable = unreadable || !r;
                words |= w;
            }
            if (counterpartySet) {
                (bool r, bytes32 w) = _readWord(
                    CONTROL_PLANE, abi.encodeWithSelector(SEL_IS_BLOCKED, ctx.counterparty)
                );
                unreadable = unreadable || !r;
                words |= w;
            }

            if (unreadable) {
                reasonBits |= GuardBits.G3_BLOCKED << GuardBits.UNREADABLE_SHIFT;
            } else if (words != bytes32(0)) {
                reasonBits |= GuardBits.G3_BLOCKED;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 5 · G4 实现漂移(bit 4 / bit 20):对【控制面】调 `implementation()`,预期恰好 32 字节
        //
        // 🔴 调的是控制面,【永远不是代币】。那 283 字节代理的字节码里确实含这个 selector,
        //    但那是它【向外发出】的,不是它对外派发的 —— 对代币调 `implementation()` 会
        //    revert,而 deny-by-default 会把这个接错线静默吸收成「G4 读不到」。
        // 🔴 绝不 mask 后比对:mask 能从一个同时编码了别的数据的字里凑出一个与调用方断言
        //    相等的地址 = 一条从垃圾到干净位的路。判读不到(bit 20)才对,而且它与「读到了
        //    但不是你审计的那一份」(bit 4)保持可区分。
        // 🔴 调用方断言的实现地址为零时,这次调用【照发】:该字段既不是这次调用的目标(目标
        //    是那个常量)也不是实参(这次调用无参),零值抹掉的是【比较基准】不是【观测能力】
        //    ⇒ 控制面的读次数不因它变化。置 bit 20 后就此收闸,读回来的那个字丢弃。
        // ⚠ G4 断言的命题是:「此刻这个代币背后的实现,不是你审计过的那一份」。那个期望值是
        //    【调用方的断言】,不是本系统能验证的东西。
        // ─────────────────────────────────────────────────────────────────────
        {
            (bool readable, bytes32 word) =
                _readWord(CONTROL_PLANE, abi.encodeWithSelector(SEL_IMPLEMENTATION));
            if (
                !readable
                    || (uint256(word) >> 160) != 0
                    || ctx.expectedImpl == address(0)
            ) {
                reasonBits |= GuardBits.G4_IMPL_DRIFT << GuardBits.UNREADABLE_SHIFT;
            } else if (address(uint160(uint256(word))) != ctx.expectedImpl) {
                reasonBits |= GuardBits.G4_IMPL_DRIFT;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 6 · G5 比例过渡(bit 5 / bit 21):对 `token` 调 `uiMultiplier()` /
        //     `newUIMultiplier()` / `effectiveAt()`,各预期恰好 32 字节
        //
        // 🔴 三次读【全部发出】后才组合判据(闸内不短路)。代币是不可信的:它可以让第一次读
        //    返回一个不等的值、同时让第三次读停机。
        // ⚠ 两个乘数按原始 `bytes32` 比相等,【不作数值解释】—— 不解释就没有截断面。
        //    三个字必须各自保留(判据要用到两两相等与第三个的数值),所以这里不能像 G3 那样
        //    按位或塌成一个。
        // 🔴 生效时刻必须以【全宽 `uint256`】与 `block.timestamp` 比较,绝不下转 `uint64`:
        //    下转会把一个远期时间戳回绕成过去,于是「还没生效」为假 ⇒ 一道该拦的闸静默放行。
        // ⚠ 生效时刻 `== 0` 是【有意义的干净值,不是未设值哨兵】。
        // ⚠ 刻意避开「生效时刻非零就拦」这种写法:在「过渡完成后不清零」的实现下它会永久
        //    拦死该代币,而是否清零本项目从未观测到。现谓词里每一个拦截条件要么由发行方
        //    可解除(把两个乘数弄相等),要么随时钟自行到期 ⇒【不存在永久拒绝分支】。
        // ─────────────────────────────────────────────────────────────────────
        {
            (bool rUi, bytes32 wUi) =
                _readWord(token, abi.encodeWithSelector(SEL_UI_MULTIPLIER));
            (bool rNew, bytes32 wNew) =
                _readWord(token, abi.encodeWithSelector(SEL_NEW_UI_MULTIPLIER));
            (bool rEff, bytes32 wEff) =
                _readWord(token, abi.encodeWithSelector(SEL_EFFECTIVE_AT));

            if (!rUi || !rNew || !rEff) {
                reasonBits |= GuardBits.G5_RATIO_TRANSITION << GuardBits.UNREADABLE_SHIFT;
            } else if (
                wUi != wNew
                    || (uint256(wEff) != 0 && block.timestamp < uint256(wEff))
            ) {
                reasonBits |= GuardBits.G5_RATIO_TRANSITION;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 7–10 · 喂价那一次读,以及 G6 / G8
        //
        // 🔴 `latestRoundData()` 【只发一次】,且先于 G6 与 G8 求值:一个恶意喂价可以基于
        //    `gasleft()` 给两次调用返回【不同轮次】的数据,使两道闸判在不同数据上。
        //    ⇒ 读一次,把解出来的值当参数传给两道闸。
        // ─────────────────────────────────────────────────────────────────────
        {
            bool feedSet = ctx.priceFeed != address(0);

            bool roundReadable;
            uint256 roundId;
            int256 answer;
            uint256 updatedAt;
            uint256 answeredInRound;

            if (feedSet) {
                (roundReadable, roundId, answer, updatedAt, answeredInRound) =
                    _readRound(ctx.priceFeed);
            }

            // ── 8 · G6 喂价陈旧(bit 6 / bit 22)──────────────────────────────
            // 🔴 那次减法【必须在比较之后】:`updatedAt > block.timestamp` 时绝不执行减法
            //    —— 内建下溢检查会让整个守护合约 revert,而一个调用方钉死的恶意喂价因此能
            //    把它炸掉。所以这里写成**四支**(首支裸 `if` + 三支 `else if`),减法【只出现
            //    在最后一支】,而进入它的前提是它前面那一支已经排除了未来时间戳。
            //    ⚠ 支数与 `else if` 的支数不是同一个量,别把这里的「四」读成四个 `else if`。
            //    ⚠ 绝不写成 `block.timestamp - updatedAt > maxFeedAge && updatedAt <= ...`:
            //    `&&` 左边先求值 ⇒ 减法先发生 ⇒ 当场 revert。顺序本身就是缓解措施。
            // ⚠ 容忍度 `== 0` 意味着【最严格】(任何非零年龄都超容忍),不是未设值。
            //    它是 `uint64`,与 `uint256` 比较走隐式加宽,不下转。
            if (!feedSet) {
                reasonBits |= GuardBits.G6_FEED_STALE << GuardBits.UNREADABLE_SHIFT;
            } else if (!roundReadable) {
                reasonBits |= GuardBits.G6_FEED_STALE << GuardBits.UNREADABLE_SHIFT;
            } else if (updatedAt > block.timestamp) {
                // 年龄这个量在未来时间戳下无定义 ⇒ 读不到,不是违反。
                reasonBits |= GuardBits.G6_FEED_STALE << GuardBits.UNREADABLE_SHIFT;
            } else if (block.timestamp - updatedAt > ctx.maxFeedAge) {
                reasonBits |= GuardBits.G6_FEED_STALE;
            }

            // ── 9 · `description()` 只问「答不答」,紧贴唯一消费它的那道闸 ──────────
            bool descriptionAnswered;
            if (feedSet) {
                descriptionAnswered = _answersDescription(ctx.priceFeed);
            }

            // ── 10 · G8 喂价自洽(bit 8 / bit 24)────────────────────────────
            // 🔴 G8 唯一的 unreadable 路径就是喂价地址为零(「我连问都没法问」)。这是
            //    【有意的】,不要去「修」它:地址为零时就此收闸,bit 8 不求值 —— 因为那时
            //    两次喂价读根本没发出,而「没发出」按字面也算「不答」,会连带置上 bit 8。
            // 🔴 地址非零、调用真的发出去了而对方不答,归【违反】(bit 8)不归读不到:
            //    G8 的命题是「这个被钉死的合约像不像一个喂价」——「它不答」正是这个问题的
            //    答案,是读到了的坏事实。这是本文件里唯一一处「不答归违反」,射程只有这一格。
            // 🔴 G8 只检验 `description()` 是否【应答】,永不比较它返回的字符串:比较字符串
            //    就是名字解析,而多个互不相同的合约会返回逐字节相同的名字。
            // ⚠ 六个析取项里【与解出来的值无关的两项排在最前】:它们为真时后四项(涉及
            //    解出来的值)根本不求值 —— 免得把语义加在未观测的值上。
            // 🔴 这两项按本闸「地址非零、调用发出去了而对方不答 ⇒ 归违反」那条归【违反】
            //    (bit 8),不归读不到;此处的「排在最前」
            //    只管求值顺序,不是位分类。把它们挪进上面那条 `!feedSet` 支会把 bit 8
            //    换成 bit 24,推翻本闸那个有意的唯一例外 —— 不要那样「修」。
            // ⚠ `updatedAt == 0` 刻意不特判:它使 bit 8 置位(轮次不完整),同时 G6 照常
            //    求值也会置 bit 6。两个位都置,都说的是真话。
            if (!feedSet) {
                reasonBits |= GuardBits.G8_FEED_INCOHERENT << GuardBits.UNREADABLE_SHIFT;
            } else if (
                !descriptionAnswered
                    || !roundReadable
                    || updatedAt == 0
                    || answer <= 0
                    || answeredInRound < roundId
                    || updatedAt > block.timestamp
            ) {
                reasonBits |= GuardBits.G8_FEED_INCOHERENT;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 11 · 聚合与收尾
        //
        // bit 255 是聚合位,不是第九道闸:它置位 ⟺ unreadable 平面上至少一位置位。
        // 🔴 判据用 `GuardBits.UNREADABLE_MASK`,不抄位区间的字面量:区间 [16, 24] 含 9 个位,
        //    而 unreadable 平面只有 8 个 —— 差的 bit 23 是保留位、任何路径不得置位,两种写法
        //    只在「bit 23 恒为 0」这条不变式下外延相等。以掩码为判据,聚合位就不依赖一个
        //    恒为零的位。
        // 🔴 `ok == (reasonBits == 0)`,绝不从位的子集重新推导。
        // ⚠ 两条由测试强制的断言(本文件不写运行期检查,因为零 `require` 是硬约束):
        //      `(reasonBits & GuardBits.RESERVED_MASK) == 0`
        //      `(reasonBits & ~GuardBits.KNOWN_MASK) == 0`
        //    上面八道闸只置 `GuardBits` 里具名的 violated 位与它们左移 16 位的对应位,外加
        //    这一个聚合位 ⇒ 两条在构造上成立,但【目前还没有任何东西会在它被破坏时出声】。
        // ─────────────────────────────────────────────────────────────────────
        if ((reasonBits & GuardBits.UNREADABLE_MASK) != 0) {
            reasonBits |= GuardBits.U_AGGREGATE;
        }
        ok = (reasonBits == 0);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 已知 codehash 集合
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice 今天是一个单元素集:`h == KNOWN_PROXY_CODEHASH`。
    /// @dev 保留函数形态以便未来扩展,但【绝不】做成 `constant` 数组 / mapping / 可注入集合:
    ///      library 没有构造期、语言层也不许有可变状态;而一个「集合」形态即便今天只有一个
    ///      成员,也给未来留了注入点。
    ///      ⚠ 不特判 `h == 0` / `h == EMPTY_CODE_HASH`:G0 的三态分支在调用它之前已经分流,
    ///      对那两个输入返回 `false` 也是对的(deny 侧),多一个特判就是多一份表示。
    function _isKnownCodehash(bytes32 h) internal pure returns (bool) {
        return h == KNOWN_PROXY_CODEHASH;
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 三个读取助手 —— 全部落进同一个原语,各自只用【参数】表达长度语义
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice 读一个恰好 32 字节的返回字。
    /// @dev `callData` 由调用点用 `abi.encodeWithSelector` 构造 —— 刻意用一次内存分配换取
    ///      「长度判据唯一」:拆成「无参版 + 带地址参数版」两个助手,就是两份各自实现判据的
    ///      地方。
    /// @return readable `success` 且返回长度恰好 32。
    /// @return word     `readable` 时是那 32 字节;否则是 0,而且【调用方不得解释它】。
    function _readWord(address target, bytes memory callData)
        internal
        view
        returns (bool readable, bytes32 word)
    {
        (bool ok_, , bytes32[5] memory out) = _staticRead(target, callData, 32, 32);
        readable = ok_;
        // 不可读时 `out` 整块是零初始化的(拷贝受长度判据门控,一个字节都没写进来)。
        word = out[0];
    }

    /// @notice 读那一次 `latestRoundData()`,预期恰好 160 字节(5 个 32 字节字)。
    /// @dev 字偏移表(逐字,别数错):
    ///        0 = roundId · 32 = answer · 64 = startedAt · 96 = updatedAt · 128 = answeredInRound
    ///      ⚠ `startedAt`(偏移 64)本作品【不使用】,但必须出现在这张表里,否则下一个人会
    ///      数错。偏移写错是本作品最典型的静默错误:把 `startedAt` 当 `updatedAt` 用,陈旧度
    ///      那道闸照样返回一个【格式正确的错答案】。
    ///      ⚠ `answer` 按 `int256` 有符号解释;`roundId` / `answeredInRound` 按【全字】比较,
    ///      不截到 80 位 —— 全字比较对 deny 方向安全:高位有脏数据只会让
    ///      `answeredInRound < roundId` 更容易为真 ⇒ 判违反 ⇒ 拦。
    ///      前条件:调用点保证喂价地址非零(地址为零时 `evaluate` 根本不调它)。
    ///      `!readable` 时四个值全 0 且不得解释。
    function _readRound(address feed)
        internal
        view
        returns (
            bool readable,
            uint256 roundId,
            int256 answer,
            uint256 updatedAt,
            uint256 answeredInRound
        )
    {
        (bool ok_, , bytes32[5] memory out) =
            _staticRead(feed, abi.encodeWithSelector(SEL_LATEST_ROUND_DATA), 160, 160);
        readable = ok_;
        roundId = uint256(out[0]); // 偏移 0
        answer = int256(uint256(out[1])); // 偏移 32
        // out[2] = startedAt(偏移 64)—— 解出来了也不用,刻意不往外传。
        updatedAt = uint256(out[3]); // 偏移 96
        answeredInRound = uint256(out[4]); // 偏移 128
    }

    /// @dev `description()` 应答的头部长度(偏移字 + 长度字 = 64 字节)。`_answersDescription` 里
    ///      传给 `_staticRead` 的 `minLen` 实参与 `size - …` 的被减数【都只许引用这一个符号】:
    ///      两处共用一个值,「可读 ⇒ `size >= DESCRIPTION_HEAD_LEN`」使那次减法对任意取值(取值须满足 `_staticRead` 的前条件:32 的倍数且不大于 160)都不下溢。
    ///      `private`:测试不读它;两处相等由 `test/Attacks.t.sol` 的边界长度行为臂钉住。
    uint256 private constant DESCRIPTION_HEAD_LEN = 64;

    /// @notice 只问 `description()` 答不答,只拷 64 字节前缀,永不读字符串本体。
    /// @dev 四条判据,全部满足才算答了:
    ///        ① `success` 且返回长度 >= 64      ← 整条由原语以 `minLen = DESCRIPTION_HEAD_LEN`(= 64)承担
    ///        ② 拷头 64 字节 → 偏移字、长度字
    ///        ③ 偏移 == 0x20
    ///        ④ `length <= size - DESCRIPTION_HEAD_LEN`
    ///      🔴 第 ④ 条逐字就是这个形状。两种写法被禁,因为它们在声明长度巨大时【自己会在
    ///      内建检查下溢出并 revert】—— 一个恶意 `description()` 就能让守护合约本身炸掉:
    ///        · `64 + roundUp32(length) <= size`
    ///        · `length + 64 <= size`
    ///      本实现里那次减法安全,靠【两条各自充分的理由】,而它们的强度不一样:
    ///        (a) `&&` 短路:`readable` 写在最左,而它蕴含 `size >= minLen == DESCRIPTION_HEAD_LEN` ⇒ 减法只在
    ///            `readable` 为真时求值。⚠ 这一条【一次重排就能废掉】,所以它不是承重的那条。
    ///        (b) 承重:`_staticRead` 的后条件「`!readable` 时 `out` 整块为 0」使
    ///            `offset == 0x20` 蕴含 `readable` ⇒ 即便把 `readable` 挪到最右,`offset` 那一项
    ///            也会先短路掉减法。(b) 不依赖 `readable` 的位置,只依赖那条后条件。
    ///      ⇒ 合起来的实质,**射程限于【合取序重排】这一族**:只要 (a) 或 (b) 的那一项在减法
    ///        左边,减法就不可达;这一族里能让它 revert 的只有「把 `length <= size - DESCRIPTION_HEAD_LEN` 整项
    ///        挪到最左」这一种。长度再大只是让不等式为假。
    ///      射程之外那一族(两处长度取值各改一处)现在的状态,照实写,别读成全关:
    ///        · 结构性修法已落地:传给 `_staticRead` 的 `minLen` 实参与这里的被减数【共用
    ///          `DESCRIPTION_HEAD_LEN` 这一个符号】。只要两处都引用它,对任意取值 K(取值须满足 `_staticRead` 的前条件:32 的倍数且不大于 160),
    ///          「`readable` ⇒ `size >= K`」与 (b) 合起来使这次减法的下溢在结构上不可表达。
    ///        · 仍然可达的形状:把其中一处改回字面量(或改成别的符号)。封闭子类仍是恰 2 处
    ///          (那个 `minLen` 实参 + 这里的被减数),无第三处。
    ///        · 钉子:`test/Attacks.t.sol` 的 `test_AS28_r19_descriptionHeadLengthsAgree` 用三条边界
    ///          长度的应答(63 字节 · 恰 64 字节且串长 0 · 96 字节且声明串长 33)直接问本函数。
    ///          按推导,在前条件定义域内(`minLen` ∈ {0,32,64,96,128,160},被减数任意)它只放行
    ///          两处都等于 64 这一组;这一句是推导,不是穷举实跑。
    ///        · fail 方向【按哪一处改、往哪边改而定,不是单一方向】(按推导):
    ///          - `minLen` 实参改成 32:原语只拷 `minLen` 字节,长度字不被拷、恒读作 0 ⇒ 偏移字为
    ///            0x20 的 ≥ 64 字节应答无论声明多长都判「答了」,bit 8 丢失 = 安全轴 **fail-open**;
    ///            偏移字为 0x20 的 32–63 字节应答则下溢 ⇒ `evaluate` revert。
    ///          - `minLen` 实参改成 0:什么都不拷,偏移字恒读作 0 ⇒ 一律判「不答」(bit 8)=
    ///            安全轴 fail-closed,可用性轴全线误报。
    ///          - `minLen` 实参改大(96 起):短于它的诚实应答不可读 ⇒ 判「不答」(bit 8)= 安全轴
    ///            fail-closed,可用性轴误报。
    ///          - 被减数改小(< 64):声明串长超出 `size - 64`、但超出量不大于「64 − 被减数」字节的应答判「答了」=
    ///            安全轴 **fail-open**(超出更多的仍判「不答」);这一方向今天只有上面那条钉子会红。
    ///          - 被减数改大(> 64):偏移字为 0x20、可读且短于它的应答下溢 ⇒ 整个 `evaluate` revert ⇒ 调用方拿不到
    ///            `ok == true`(安全轴 fail-closed —— ⚠ 集成方若 try/catch 吞掉 `Panic` 并读成
    ///            `reasonBits == 0`,安全轴也会反过来);余下的诚实应答可能判「不答」(bit 8)。
    ///            可用性轴 fail-open:一个调用方钉死的恶意喂价可以把本库炸掉 —— 这恰是 INV-8 存在的理由。
    ///        · 天花板:U7 其余切片 + 部署前独立第三方专业审计。**合取序那一族(下面 ⚠ 那条)
    ///          不因此关闭;本族只到「源码层共用符号 + 测试钉子」为止,不声称更多。**
    ///      ⚠ 这里刻意【不】把它收紧成一条对全部合取序成立的全称:把该项挪到合取式最左时
    ///        减法无条件求值,(a)(b) 都救不了它 —— 那一侧为假,而全称会把它一起声称进来。
    ///      ⚠ 用 `<=` 而不是精确等长是刻意的:多余的尾部填充在诚实但非标准的编码器上会出现,
    ///      而这道闸只问「答不答」。收紧到精确等长会造出一道与拒绝服务无法区分的闸。
    ///      ⚠ ③④ 不是第二份长度检查:它们判的是【返回内容自己声明的偏移与串长跟返回长度自不
    ///      自洽】,那是编码自洽性;u2 判的是「返回长度等不等于预期长度」,只在原语里。
    function _answersDescription(address feed) internal view returns (bool answered) {
        (bool readable, uint256 size, bytes32[5] memory out) = _staticRead(
            feed, abi.encodeWithSelector(SEL_DESCRIPTION), DESCRIPTION_HEAD_LEN, type(uint256).max
        );
        uint256 offset = uint256(out[0]);
        uint256 length = uint256(out[1]);
        answered = readable && offset == 0x20 && length <= size - DESCRIPTION_HEAD_LEN;
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 唯一的原始 staticcall 原语 —— u2 判据与全文件唯一的 assembly 块都在这里
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice 对 `target` 发一次 staticcall,并按 `[minLen, maxLen]` 判它读不读得到。
    /// @dev 🔴 【u2 的长度判据只存在于这一处】,逐字是
    ///        `readable = success && size >= minLen && size <= maxLen`
    ///      (下面的 Yul 没有 `>=` / `<=`,用 `iszero(lt(...))` / `iszero(gt(...))` 表达同一句)。
    ///      三个助手靠【参数】表达各自的长度语义,而不是各写一份判据:
    ///        · 恰好 N  ⇒ `minLen == maxLen == N`(32 与 160 两处)
    ///        · >= N    ⇒ `minLen == N, maxLen == 上界`(`description()` 那处)
    ///      🔴 拷贝长度不是第四个参数,而是【由 `minLen` 导出】:恒 `returndatacopy(out, 0,
    ///      minLen)` ⇒ 「我要求了多少字节」和「我拷了多少字节」是同一个数,两者错开这件事
    ///      结构上不可能发生。
    ///      🔴 u2 是承重的那一道:对一个【没有代码】的地址发 staticcall,会返回
    ///      `success == true` 且 returndata 为空。只检查 `success` 会把「这个合约根本不存在」
    ///      静默路由成通过 —— 而在回退部署上,代币与控制面可以全都不存在,那是每次调用的
    ///      日常路径,不是理论情形。
    ///      🔴 `returndatacopy` 【必须排在长度判据之后】:它在 `offset + len > returndatasize()`
    ///      时会 revert。这是与 G6 那次减法同级别的第二处「靠顺序缓解」的点。
    ///      `assembly ("memory-safe")` 是一句【声明】,编译器不会替你证明它。它为真的三条前提:
    ///        ① 只读 `callData` 那块内存(数据起点 `add(callData, 0x20)`,长度 `mload(callData)`);
    ///        ② 只写 `out` 那一块【已经由编译器分配并零初始化】的内存(5 个连续字);
    ///        ③ 全程不读不写空闲内存指针 —— 本函数在 assembly 里不分配任何内存。
    ///      staticcall 的输出区给 `0, 0` ⇒ 它一个字节都不写内存 ⇒ 10 MB returndata 不产生任何
    ///      内存扩展,gas 消耗有界。
    ///      前条件(注释强制的不变式,【不是】机械检查的):`minLen % 32 == 0` ∧
    ///      `minLen <= 160`(= 缓冲容量)∧ `minLen <= maxLen`。三个调用点全部传字面常量。
    /// @return readable 见上面那条唯一的判据。
    /// @return size     `returndatasize()`,无论读不读得到都如实返回。
    /// @return out      `readable` 时前 `minLen` 字节落在 `out[0 ..]`,其余字为 0;
    ///                  `!readable` 时整块为 0。
    function _staticRead(
        address target,
        bytes memory callData,
        uint256 minLen,
        uint256 maxLen
    ) private view returns (bool readable, uint256 size, bytes32[5] memory out) {
        assembly ("memory-safe") {
            let success := staticcall(
                gas(), target, add(callData, 0x20), mload(callData), 0, 0
            )
            size := returndatasize()

            // readable = success && size >= minLen && size <= maxLen   ← 唯一的一处
            readable :=
                and(success, and(iszero(lt(size, minLen)), iszero(gt(size, maxLen))))

            // 拷贝在长度判据【之后】,且只拷 minLen 字节。
            if readable { returndatacopy(out, 0, minLen) }
        }
    }
}
