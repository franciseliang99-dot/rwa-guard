#!/usr/bin/env bash
set -u
set -o pipefail
export LC_ALL=C
unset CDPATH GREP_OPTIONS
# No errexit option: every red row ends with forge rc 1, and bash 3.2 ignores errexit
# inside functions called from conditionals.

# mutation_battery.sh -- source mutation battery for the security-sensitive
# judgement core.
#
# For each row below, the battery applies one source mutation -- a bit of
# one of the eight guard gates, of the reentrancy lock, or of the naive
# demo vault's share accounting -- on a fresh scratch copy of the tree.
# Each arm is checked against a declared expected-red set of test
# functions, then the mutation is restored and the row is re-verified
# green.
#
# usage: ./forge.sh battery [--only <id>]
# rows: M-G0 M-G1 M-G2 M-G3 M-G4 M-G5 M-G6 M-G8 M-LOCK M-NAIVE M-PERM M-CTX
# exit: 0 pass, 1 battery red, 2 usage, 3 row carries no bit, 4 undetermined, 5 work tree changed, 6 cleanup failed, 128+n interrupted
#
# Exit code precedence: INTERRUPTED > 5 > 4 > 3 > 1 > 6 > 0. Rows keep
# running after a row-level 1/3/4.
#
# Isolation. Every mutation lands only on a scratch copy made under
# ${TMPDIR:-/tmp}; the script never edits the tree it was invoked from.
# It exports its own FOUNDRY_OUT and FOUNDRY_CACHE_PATH, rooted under
# that scratch run directory, before any forge.sh call, so a run of this
# battery never shares build state with a plain ./forge.sh test. The
# source tree is checksummed before and after the whole run, and any
# difference is reported by path. test/Fork.t.sol and test/Opcodes.t.sol
# are excluded by file from every arm, including the baseline, the same
# way every time; the excluded ids are printed one per line so the
# exclusion's effect can be told apart from a silent no-op.

# Row identifiers, in run order for a no-argument invocation.
ROWS="M-G0 M-G1 M-G2 M-G3 M-G4 M-G5 M-G6 M-G8 M-LOCK M-NAIVE M-PERM M-CTX"

# The one AS-18 function that must never redden under any row; used by
# check_overreach to detect an over-broad mutation.
OVERREACH_SENTINEL="test_AS18b_fanoutCounts"

# Exit codes. Precedence: INTERRUPTED > 5 > 4 > 3 > 1 > 6 > 0.
EXIT_PASS=0
EXIT_BATTERY_RED=1
EXIT_USAGE=2
EXIT_NO_BIT=3
EXIT_UNDETERMINED=4
EXIT_WORKTREE_CHANGED=5
EXIT_CLEANUP_FAILED=6
EXIT_INTERRUPTED_HUP=129
EXIT_INTERRUPTED_INT=130
EXIT_INTERRUPTED_TERM=143

# expected_table AS-token shape: the token is always a table column, never
# parsed from the function name.
AS_TOKEN_RE='^AS-[0-9]+$'

# forge_test's summary and suite-count lines.
SUMMARY_RE='[0-9]+ tests passed, [0-9]+ failed, [0-9]+ skipped \([0-9]+ total tests\)'
SUITE_COUNT_RE='Ran [0-9]+ test suites'

# Path globals; setup_run assigns each of these in turn, and each
# assignment there is followed by its own : "${VAR:?}" guard.
SRC=""
BASE_TMP=""
RUN=""
WORK=""
LOGS=""
PRISTINE=""
ARM=""

# Run-state globals; setup_run and the row driver assign these.
N0=""
S0=""
K0=""
ONLY=""
FINAL=""
PHASE=""

# rules_table, post_table and excluded_table: exact-byte data tables read
# by apply_rules / check_post / print_exclusions. Empty lines and lines
# starting with # are comments; everything else is @-delimited data.
rules_table() {   # <row>@<file>@<replace|delete>@<K>@<old line text, indentation stripped>@<new text (empty for delete)>
cat <<'EOF'
M-G0@src/GuardCore.sol@replace@2@reasonBits |= GuardBits.G0_IDENTITY << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G0@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G0_IDENTITY;@reasonBits |= 0;
M-G1@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G1_GLOBAL_PAUSE << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G1@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G1_GLOBAL_PAUSE;@reasonBits |= 0;
M-G2@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G2_TOKEN_PAUSE << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G2@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G2_TOKEN_PAUSE;@reasonBits |= 0;
M-G3@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G3_BLOCKED << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G3@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G3_BLOCKED;@reasonBits |= 0;
M-G4@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G4_IMPL_DRIFT << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G4@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G4_IMPL_DRIFT;@reasonBits |= 0;
M-G5@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G5_RATIO_TRANSITION << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G5@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G5_RATIO_TRANSITION;@reasonBits |= 0;
M-G6@src/GuardCore.sol@replace@3@reasonBits |= GuardBits.G6_FEED_STALE << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G6@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G6_FEED_STALE;@reasonBits |= 0;
M-G8@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G8_FEED_INCOHERENT << GuardBits.UNREADABLE_SHIFT;@reasonBits |= 0;
M-G8@src/GuardCore.sol@replace@1@reasonBits |= GuardBits.G8_FEED_INCOHERENT;@reasonBits |= 0;
M-LOCK@src/demo/VaultBase.sol@replace@1@if (_lock != 1) revert ReentrantCall();@if (false) revert ReentrantCall();
M-NAIVE@src/demo/NaiveVault.sol@delete@1@totalShares -= shares_;@
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G0_IDENTITY         = 1 << 0;@uint256 internal constant G0_IDENTITY         = 1 << 1;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G1_GLOBAL_PAUSE     = 1 << 1;@uint256 internal constant G1_GLOBAL_PAUSE     = 1 << 2;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G2_TOKEN_PAUSE      = 1 << 2;@uint256 internal constant G2_TOKEN_PAUSE      = 1 << 3;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G3_BLOCKED          = 1 << 3;@uint256 internal constant G3_BLOCKED          = 1 << 4;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G4_IMPL_DRIFT       = 1 << 4;   // 标签是「实现漂移」,不是 "upgrade freshness"@uint256 internal constant G4_IMPL_DRIFT       = 1 << 5;   // 标签是「实现漂移」,不是 "upgrade freshness"
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G5_RATIO_TRANSITION = 1 << 5;@uint256 internal constant G5_RATIO_TRANSITION = 1 << 6;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G6_FEED_STALE       = 1 << 6;@uint256 internal constant G6_FEED_STALE       = 1 << 8;
M-PERM@src/GuardBits.sol@replace@1@uint256 internal constant G8_FEED_INCOHERENT  = 1 << 8;@uint256 internal constant G8_FEED_INCOHERENT  = 1 << 0;
M-CTX@src/GuardBits.sol@replace@1@address priceFeed;      // G6 / G8:调用方钉死的喂价合约@address expectedImpl;   // M-CTX: swapped from slot 0
M-CTX@src/GuardBits.sol@replace@1@address expectedImpl;   // G4:调用方审计过的实现地址@address priceFeed;      // M-CTX: swapped from slot 3
EOF
}

# Each rule declares K and must match exactly K lines (0 = the row spins,
# more = overreach); "exactly once per text" cannot hold because two
# texts repeat verbatim (G0 unreadable x2, G6 unreadable x3), so K plus
# the completeness and diff-count postconditions keep that intent.
#
# The U_AGGREGATE line is kept in every row: it is the aggregate over the
# unreadable plane, not a gate; editing it would stack a second mutation;
# kept, it models a dead gate exactly (bit 255 disappears only when that
# gate was the only unreadable source).

post_table() {    # <row>@<file>@<fixed string>@<required line count in the mutated file>
cat <<'EOF'
M-G0@src/GuardCore.sol@GuardBits.G0_@0
M-G0@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G1@src/GuardCore.sol@GuardBits.G1_@0
M-G1@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G2@src/GuardCore.sol@GuardBits.G2_@0
M-G2@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G3@src/GuardCore.sol@GuardBits.G3_@0
M-G3@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G4@src/GuardCore.sol@GuardBits.G4_@0
M-G4@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G5@src/GuardCore.sol@GuardBits.G5_@0
M-G5@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G6@src/GuardCore.sol@GuardBits.G6_@0
M-G6@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-G8@src/GuardCore.sol@GuardBits.G8_@0
M-G8@src/GuardCore.sol@reasonBits |= GuardBits.U_AGGREGATE;@1
M-LOCK@src/demo/VaultBase.sol@_lock != 1@0
M-LOCK@src/demo/VaultBase.sol@if (false) revert ReentrantCall();@1
M-NAIVE@src/demo/NaiveVault.sol@totalShares -= shares_;@0
M-NAIVE@src/demo/GuardedVault.sol@totalShares -= shares_;@1
M-PERM@src/GuardBits.sol@G0_IDENTITY         = 1 << 1;@1
M-PERM@src/GuardBits.sol@G1_GLOBAL_PAUSE     = 1 << 2;@1
M-PERM@src/GuardBits.sol@G2_TOKEN_PAUSE      = 1 << 3;@1
M-PERM@src/GuardBits.sol@G3_BLOCKED          = 1 << 4;@1
M-PERM@src/GuardBits.sol@G4_IMPL_DRIFT       = 1 << 5;@1
M-PERM@src/GuardBits.sol@G5_RATIO_TRANSITION = 1 << 6;@1
M-PERM@src/GuardBits.sol@G6_FEED_STALE       = 1 << 8;@1
M-PERM@src/GuardBits.sol@G8_FEED_INCOHERENT  = 1 << 0;@1
M-CTX@src/GuardBits.sol@// M-CTX: swapped from slot@2
M-CTX@src/GuardBits.sol@address priceFeed;      // G6@0
M-CTX@src/GuardBits.sol@address expectedImpl;   // G4@0
EOF
}
excluded_table() { # <file>@<id> <id> ...   (ids expanded one by one; never a range)
cat <<'EOF'
test/Fork.t.sol@AS-2 AS-2b AS-2c
test/Opcodes.t.sol@AS-32 AS-32a AS-23a AS-23b AS-23c AS-23d AS-23e AS-23f AS-23g AS-33a
EOF
}

# expected_table: the final expected-red sets, one line per (row,
# function). An empty expected row is a finding. A first run that
# disagrees goes back to the design with reasons in both directions;
# expected sets are never edited to measured values.
#
# Always-green functions (never appear below):
#   Clean arms: AS0, AS5_2, AS9, AS12_1, AS13_b, AS13b_b, AS17_2, AS16,
#     AS14, AS35.
#   Self-checks: AS25, AS26, GuardBits x4.
#   Sentinel: AS18b.
#   Feed and gas: AS27_gasBand, AS27b, AS28_c, AS28_r19, AS34.
#   G6 plus G8 fed: AS19 x2 and AS19b.
#   Vault arms: AS29d; both AS30 CEI arms under the M-G rows and under
#     M-LOCK; AS30_ceiGuarded; AS40_guarded; AS31/31b/31c; AS36 x8.
#   Fixtures: AS39a, AS39b, and the AS-38 functions other than
#     stateInvariant.
#   Clean files: RWAGuard, RWAGuardView, DemoVaultEdges; DualForm is
#     clean under the M-G*, M-LOCK and M-NAIVE rows only.
#   (This list is for the M-G*, M-LOCK and M-NAIVE rows; M-PERM and
#   M-CTX carry their own reasoning in their blocks.)
#
# Clean arms: test/RWAGuardView.t.sol, test/RWAGuard.t.sol and
# test/DualForm.t.sol enter no M-G* row below (DualForm does enter
# M-PERM and M-CTX). Reason: form-agreement
# relations hold because both forms share one evaluate; the inequality
# controls (viewDecodesSpecOrderCalldata, crossTupleDiscrimination,
# interveningWriteChangesVerdict) survive because every non-zero tuple
# spans at least two gates; the zero-ctx tuple spans G3, G4, G6 and G8.
# Margin-1: U4_4 and U4_5 reverted>=7, and gateSpan>=3 in U4_2, U4_3,
# U4_7 and U3_10, sit at margin 1 under one mutation: the no-stacking
# rule (every arm on a fresh copy, never stacked) is load-bearing for
# them.
#
# AS-30 / AS-29(a) / AS-29b / AS-40 are green under every M-G row, not
# under every row below: AS-30 re-entry arms are red in M-LOCK; the
# naive CEI arm, AS29_a, AS29b and AS40_naive are red in M-NAIVE.

expected_table() {
cat <<'EOF'
# ---- M-G0 --------------------------------------------------------------
# AS-21 k=2 j=1: the Attacks dirty-high-bytes function (non-proxy token,
# bits 0/20/255) is red; test_AS21_zeroExpectedImplVaultBlocked runs on
# the proxy baseline where G0 is clean (value 20|255) and stays green.
# EXTCODEHASH is not a StaticCall, so the fan-out sentinel is blind in
# the M-G0 column; whether the optimizer drops it under M-G0 is
# unobserved here (the Opcodes file is excluded).
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-3 k=1 j=1 (only member).
# k/j: AS-4 k=3 j=3 here. Codehash 0 means G0 unreadable, and empty
#   replies mean token reads unreadable.
# k/j: AS-18 k=7 j=2 here (the two noShortCircuit functions only; no
#   combo arm touches G0). The fan-out sentinel counts fan-out only and
#   is never red.
# k/j: AS-21 k=2 j=1 here: the Integration function runs on the proxy
#   baseline, value 20|255, so G0 is clean there.
# k/j: AS-38 k=25 by name, j=1 here (stateInvariant); the others never
#   call evaluate (the tail-pad arm reaches only the raw description
#   reader).
# k/j: AS-39 k=3, j=1 here (the counting-mode function). The two
#   read-set functions assert read-set properties only, so a red there
#   would be overreach.
M-G0 test_AS3_foreignCodehashIsExactlyBit0 AS-3 derived
M-G0 test_AS4a_neverDeployedToken AS-4 derived
M-G0 test_AS4b_eoaToken AS-4 derived
M-G0 test_AS4c_zeroAddressToken AS-4 derived
M-G0 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G0 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G0 test_AS21_implWordDirtyHighBytesUnreadable AS-21 derived
M-G0 test_AS39c_countingModeHaltsStaticReadAndIsReset AS-39 derived
M-G0 test_AS38_stateInvariantAcrossEvaluate AS-38 derived

# ---- M-G1 --------------------------------------------------------------
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-5 k=4 j=3 here (the plane-not-paused arm is the clean member).
# k/j: AS-18 k=7 j=3 here (the two noShortCircuit functions plus the
#   g3-absorbs-beside-g1 combo).
# k/j: AS-39 k=3, j=1 here (the counting-mode function, same function as
#   in M-G0). The two read-set functions assert read-set properties
#   only, so a red there would be overreach.
M-G1 test_AS5_1_planePaused AS-5 derived
M-G1 test_AS5_3_planeHasNoCode AS-5 derived
M-G1 test_AS5_4_planePausedRevertsUnreadable AS-5 derived
M-G1 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G1 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G1 test_AS18_combo6_g3AbsorbsBesideG1 AS-18 derived
M-G1 test_AS39c_countingModeHaltsStaticReadAndIsReset AS-39 derived

# ---- M-G2 --------------------------------------------------------------
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-4 k=3 j=3 here. Codehash 0 means G0 unreadable, and empty
#   replies mean token reads unreadable.
# k/j: AS-5 k=4 j=1 here (the plane-has-no-code arm only).
# k/j: AS-6 k=3 j=3 here (all three members).
# k/j: AS-18 k=7 j=3 here (the two noShortCircuit functions plus the
#   violated-and-unreadable-across-gates combo).
# k/j: AS-20 k=1 j=1 (only member).
M-G2 test_AS4a_neverDeployedToken AS-4 derived
M-G2 test_AS4b_eoaToken AS-4 derived
M-G2 test_AS4c_zeroAddressToken AS-4 derived
M-G2 test_AS5_3_planeHasNoCode AS-5 derived
M-G2 test_AS6_1_tokenPaused AS-6 derived
M-G2 test_AS6_2_pausedWord31Bytes AS-6 derived
M-G2 test_AS6_3_pausedWord64Bytes AS-6 derived
M-G2 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G2 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G2 test_AS18_combo4_violatedAndUnreadableAcrossGates AS-18 derived
M-G2 test_AS20_pausedWordTwoIsPaused AS-20 derived

# ---- M-G3 --------------------------------------------------------------
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-4 k=3 j=3 here. Codehash 0 means G0 unreadable, and empty
#   replies mean token reads unreadable.
# k/j: AS-5 k=4 j=1 here (the plane-has-no-code arm only).
# k/j: AS-7 k=4 j=4 here (all four members).
# k/j: AS-8 k=3 j=3 here (all three members).
# k/j: AS-18 k=7 j=5 here (the two noShortCircuit functions plus the
#   violated-and-unreadable-across-gates, zero-ctx and
#   g3-absorbs-beside-g1 combos).
# k/j: AS-24 k=2 j=2 here (both members).
M-G3 test_AS4a_neverDeployedToken AS-4 derived
M-G3 test_AS4b_eoaToken AS-4 derived
M-G3 test_AS4c_zeroAddressToken AS-4 derived
M-G3 test_AS5_3_planeHasNoCode AS-5 derived
M-G3 test_AS7_1_tokenBlocksActor AS-7 derived
M-G3 test_AS7_2_tokenBlocksCounterparty AS-7 derived
M-G3 test_AS7_3_planeBlocksActor AS-7 derived
M-G3 test_AS7_4_planeBlocksCounterparty AS-7 derived
M-G3 test_AS8_zeroActor AS-8 derived
M-G3 test_AS8_zeroCounterparty AS-8 derived
M-G3 test_AS8_positiveControl AS-8 derived
M-G3 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G3 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G3 test_AS18_combo4_violatedAndUnreadableAcrossGates AS-18 derived
M-G3 test_AS18_combo5_zeroCtx AS-18 derived
M-G3 test_AS18_combo6_g3AbsorbsBesideG1 AS-18 derived
M-G3 test_AS24_a_deployedFormStalePermit AS-24 measured
M-G3 test_AS24_b_inTransactionNoWindow AS-24 measured

# ---- M-G4 --------------------------------------------------------------
# M-G4 also includes test_AS21_zeroExpectedImplVaultBlocked: an
# expectedImpl of zero sets bit 20.
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-5 k=4 j=1 here (the plane-has-no-code arm only).
# k/j: AS-10 k=1 j=1 (only member).
# k/j: AS-15 k=1 j=1 (only member).
# k/j: AS-18 k=7 j=4 here (the two noShortCircuit functions plus the
#   zero-ctx and drift-ratio-incomplete-round combos).
# k/j: AS-21 k=2 j=2 here (both members).
M-G4 test_AS5_3_planeHasNoCode AS-5 derived
M-G4 test_AS10_implDrift AS-10 derived
M-G4 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G4 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G4 test_AS18_combo5_zeroCtx AS-18 derived
M-G4 test_AS18_combo7_driftRatioIncompleteRound AS-18 derived
M-G4 test_AS15_implDriftToLyingLogicDetected AS-15 measured
M-G4 test_AS21_implWordDirtyHighBytesUnreadable AS-21 measured
M-G4 test_AS21_zeroExpectedImplVaultBlocked AS-21 measured

# ---- M-G5 --------------------------------------------------------------
# test_AS29_a_naivePaysDoubleAfterEffective, test_AS29b_noTransitionArmsAgree
# and test_AS29d_afterTransitionBothArmsOverpay stay green here: the a
# arm never calls the guard; the b arm uses clean redeems plus a
# zero-feed arm fed by both G6 and G8; the d arm is post-transition with
# bits exactly 0.
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# k/j: AS-4 k=3 j=3 here. Codehash 0 means G0 unreadable, and empty
#   replies mean token reads unreadable.
# k/j: AS-5 k=4 j=1 here (the plane-has-no-code arm only).
# k/j: AS-12 k=4 j=3 here (the resting-state-clean arm is the clean
#   member).
# k/j: AS-17 k=2 j=1 here (the at-effective arm is the clean member).
# k/j: AS-18 k=7 j=3 here (the two noShortCircuit functions plus the
#   drift-ratio-incomplete-round combo).
# k/j: AS-22 k=2 j=2 here (both members).
# k/j: AS-29 k=5 j=2 here {b, c}: the a arm never calls the guard; the b
#   arm uses clean redeems plus a zero-feed arm fed by both G6 and G8;
#   the d arm is post-transition with bits exactly 0.
M-G5 test_AS4a_neverDeployedToken AS-4 derived
M-G5 test_AS4b_eoaToken AS-4 derived
M-G5 test_AS4c_zeroAddressToken AS-4 derived
M-G5 test_AS5_3_planeHasNoCode AS-5 derived
M-G5 test_AS12_2_multipliersDiffer AS-12 derived
M-G5 test_AS12_3_effectiveAtInFuture AS-12 derived
M-G5 test_AS12_4_wrongLength AS-12 derived
M-G5 test_AS17_1_oneSecondBeforeEffective AS-17 derived
M-G5 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G5 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G5 test_AS18_combo7_driftRatioIncompleteRound AS-18 derived
M-G5 test_AS22_effectiveAtAbove2Pow64IsFuture AS-22 derived
M-G5 test_AS22_effectiveAtAbove2Pow255IsFuture AS-22 derived
M-G5 test_AS29_b_guardedBlocksAfterEffective AS-29 derived
M-G5 test_AS29_c_scheduledNotEffective AS-29 derived

# ---- M-G6 --------------------------------------------------------------
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# Controls fed by one G6 bit and one G8 bit that assert only bits!=0 or
# bit 255 stay green in both this row and M-G8: AS19 x2, the AS19b
# burning arm, the AS29b zero-feed arm, and the two DemoVaultEdges
# controls test_U6_1_alwaysFreshFeedPasses and
# test_U6_2_observerSeesPreState.
# k/j: AS-11 k=2 j=2 here and in M-G8 (cross-gate: bits 22 and 24, or 8
#   and 22).
# k/j: AS-13 (own id 13) k=5 j=3 here (test_AS13_b_zeroMaxFreshClean and
#   test_AS13b_b_offsetSwappedClean are clean). By name prefix: 3 of the
#   AS13_ functions and 2 of the AS13b_ functions.
# k/j: AS-18 k=7 j=4 here (the two noShortCircuit functions plus the
#   violated-and-unreadable-across-gates and zero-ctx combos).
# k/j: AS-28 k=7 j=1 here (the future-updated-at function). The
#   gas-bounded function asserts gas only; the head-lengths-agree
#   function probes the raw description reader directly.
M-G6 test_AS11_bit24_forward AS-11 derived
M-G6 test_AS11_bit24_reverse AS-11 derived
M-G6 test_AS13_a_ageExceedsMax AS-13 derived
M-G6 test_AS13_c_zeroMaxOneSecondStale AS-13 derived
M-G6 test_AS13b_a_offsetStale AS-13 derived
M-G6 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G6 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G6 test_AS18_combo4_violatedAndUnreadableAcrossGates AS-18 derived
M-G6 test_AS18_combo5_zeroCtx AS-18 derived
M-G6 test_AS28_b_futureUpdatedAtSetsBit8AndBit22 AS-28 derived

# ---- M-G8 --------------------------------------------------------------
# `GAS_BAND` 那条腿对「G8 静默死掉」结构上瞎
# The unreadable-side AS-18 function loses bit N+16 for N=1..6, bit 0
# for N=0, bit 8 for N=8.
# Controls fed by one G6 bit and one G8 bit that assert only bits!=0 or
# bit 255 stay green in both this row and M-G6: AS19 x2, the AS19b
# burning arm, the AS29b zero-feed arm, and the two DemoVaultEdges
# controls test_U6_1_alwaysFreshFeedPasses and
# test_U6_2_observerSeesPreState.
# k/j: AS-11 k=2 j=2 here and in M-G6 (cross-gate: bits 22 and 24, or 8
#   and 22).
# k/j: AS-18 k=7 j=4 here (the two noShortCircuit functions plus the
#   zero-ctx and drift-ratio-incomplete-round combos).
# k/j: AS-27 k=3 j=1 here: the gas-band function asserts bits==0 (a
#   negative assertion); the feed-read-exactly-twice function counts
#   reads.
# k/j: AS-28 k=7 j=5 here (the two measured functions plus the three
#   description-through-evaluate functions). The gas-bounded function
#   asserts gas only; the head-lengths-agree function probes the raw
#   description reader directly.
M-G8 test_AS11_bit24_forward AS-11 derived
M-G8 test_AS11_bit24_reverse AS-11 derived
M-G8 test_AS18_noShortCircuit_allGatesViolated AS-18 derived
M-G8 test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-G8 test_AS18_combo5_zeroCtx AS-18 derived
M-G8 test_AS18_combo7_driftRatioIncompleteRound AS-18 derived
M-G8 test_AS27_roundConsistency_positiveControl AS-27 measured
M-G8 test_AS28_a_hugeDescriptionLengthIsIncoherent AS-28 measured
M-G8 test_AS28_b_futureUpdatedAtSetsBit8AndBit22 AS-28 measured
M-G8 test_AS28_descRevertThroughEvaluate AS-28 derived
M-G8 test_AS28_descShortThroughEvaluate AS-28 derived
M-G8 test_AS28_descBadOffsetThroughEvaluate AS-28 derived

# ---- M-LOCK ------------------------------------------------------------
# AS-30 k=4 j=2 here: the two CEI arms stay green; their observer reads
# getters and never re-enters.
# k/j: AS-30 k=4 j=2 here: the CEI arms' observer reads getters only and
#   never re-enters.
M-LOCK test_AS30_naiveReentryBlocked AS-30 derived
M-LOCK test_AS30_guardedReentryBlocked AS-30 derived

# ---- M-NAIVE -----------------------------------------------------------
# Four names here (the naive CEI arm pins totalShares at callback time);
# the substitution is scoped to NaiveVault only; the function
# test_AS40_shareConservation_guarded is asserted PASS exactly once
# (row_extra).
# k/j: AS-29 k=5 j=2 here {a, 29b}: the b arm is guarded only; the c arm
#   does not read naive totalShares after its redeem; the d arm has
#   amountOut equal to the shares moved.
# k/j: AS-30 k=4 j=1 here: the naive CEI arm; the guarded CEI arm and
#   both re-entry arms assert no naive totalShares.
# k/j: AS-40 k=2 j=1 here; GuardedVault is untouched.
M-NAIVE test_AS29_a_naivePaysDoubleAfterEffective AS-29 measured
M-NAIVE test_AS29b_noTransitionArmsAgree AS-29 measured
M-NAIVE test_AS40_shareConservation_naive AS-40 measured
M-NAIVE test_AS30_ceiNaiveTransferSeesPostState AS-30 derived

# ---- M-PERM ------------------------------------------------------------
# The eight gate constants are permuted inside their own slots (one
# cycle 0->1->2->3->4->5->6->8->0); every mask, the shift and bit 255 are
# unchanged, so _checkBits, AS-25/26 and every span count stay green.
# A function reddens iff it compares evaluated bits with an independent
# literal and the gate set in some plane is neither empty nor all eight
# (the full violated plane maps to itself: AS18 allGatesViolated and
# DualForm combo1 stay green). This is the whole-shift arm that KG-13
# asked for, done in-slot: a +1 shift would push G6 onto reserved bit 7.
# Derived twice by two independent readers; the two lists agreed line
# for line (77 each) before the first run.
# Per file: Gates 32, DualForm 27, Attacks 13, Fixtures 2, DemoVaults 2,
#   Integration 1; GuardBits, RWAGuard, RWAGuardView, DemoVaultEdges 0.
M-PERM test_AS10_implDrift AS-10 derived
M-PERM test_AS11_bit24_forward AS-11 derived
M-PERM test_AS11_bit24_reverse AS-11 derived
M-PERM test_AS12_2_multipliersDiffer AS-12 derived
M-PERM test_AS12_3_effectiveAtInFuture AS-12 derived
M-PERM test_AS12_4_wrongLength AS-12 derived
M-PERM test_AS13_a_ageExceedsMax AS-13 derived
M-PERM test_AS13_c_zeroMaxOneSecondStale AS-13 derived
M-PERM test_AS13b_a_offsetStale AS-13 derived
M-PERM test_AS15_implDriftToLyingLogicDetected AS-15 derived
M-PERM test_AS17_1_oneSecondBeforeEffective AS-17 derived
M-PERM test_AS18_combo4_violatedAndUnreadableAcrossGates AS-18 derived
M-PERM test_AS18_combo5_zeroCtx AS-18 derived
M-PERM test_AS18_combo6_g3AbsorbsBesideG1 AS-18 derived
M-PERM test_AS18_combo7_driftRatioIncompleteRound AS-18 derived
M-PERM test_AS18_noShortCircuit_allGatesUnreadable AS-18 derived
M-PERM test_AS1_combo2_allReadableGatesUnreadable AS-1 derived
M-PERM test_AS1_combo3_planeHasNoCode AS-1 derived
M-PERM test_AS1_combo4_violatedAndUnreadableAcrossGates AS-1 derived
M-PERM test_AS1_combo5_zeroCtx AS-1 derived
M-PERM test_AS1_combo6_g3AbsorbsBesideG1 AS-1 derived
M-PERM test_AS1_combo7_driftRatioIncompleteRound AS-1 derived
M-PERM test_AS1_crossTupleDiscrimination AS-1 derived
M-PERM test_AS1_g0UnreadableNotAlone AS-1 derived
M-PERM test_AS1_g0ViolatedAlone AS-1 derived
M-PERM test_AS1_g1UnreadableAlone AS-1 derived
M-PERM test_AS1_g1ViolatedAlone AS-1 derived
M-PERM test_AS1_g2UnreadableAlone AS-1 derived
M-PERM test_AS1_g2ViolatedAlone AS-1 derived
M-PERM test_AS1_g3UnreadableAlone AS-1 derived
M-PERM test_AS1_g3ViolatedAlone AS-1 derived
M-PERM test_AS1_g4UnreadableAlone AS-1 derived
M-PERM test_AS1_g4ViolatedAlone AS-1 derived
M-PERM test_AS1_g5UnreadableAlone AS-1 derived
M-PERM test_AS1_g5ViolatedAlone AS-1 derived
M-PERM test_AS1_g6UnreadableNotAlone AS-1 derived
M-PERM test_AS1_g6ViolatedAlone AS-1 derived
M-PERM test_AS1_g8UnreadableNotAlone AS-1 derived
M-PERM test_AS1_g8ViolatedAlone AS-1 derived
M-PERM test_AS1_interveningWriteChangesVerdict AS-1 derived
M-PERM test_AS1a_counterpartyEqualsActor AS-1 derived
M-PERM test_AS1a_maxFeedAgeBoundaries AS-1 derived
M-PERM test_AS1a_viewDecodesSpecOrderCalldata AS-1 derived
M-PERM test_AS20_pausedWordTwoIsPaused AS-20 derived
M-PERM test_AS21_implWordDirtyHighBytesUnreadable AS-21 derived
M-PERM test_AS21_zeroExpectedImplVaultBlocked AS-21 derived
M-PERM test_AS22_effectiveAtAbove2Pow255IsFuture AS-22 derived
M-PERM test_AS22_effectiveAtAbove2Pow64IsFuture AS-22 derived
M-PERM test_AS24_a_deployedFormStalePermit AS-24 derived
M-PERM test_AS24_b_inTransactionNoWindow AS-24 derived
M-PERM test_AS27_roundConsistency_positiveControl AS-27 derived
M-PERM test_AS28_a_hugeDescriptionLengthIsIncoherent AS-28 derived
M-PERM test_AS28_b_futureUpdatedAtSetsBit8AndBit22 AS-28 derived
M-PERM test_AS28_descBadOffsetThroughEvaluate AS-28 derived
M-PERM test_AS28_descRevertThroughEvaluate AS-28 derived
M-PERM test_AS28_descShortThroughEvaluate AS-28 derived
M-PERM test_AS29_b_guardedBlocksAfterEffective AS-29 derived
M-PERM test_AS29_c_scheduledNotEffective AS-29 derived
M-PERM test_AS38_stateInvariantAcrossEvaluate AS-38 derived
M-PERM test_AS39c_countingModeHaltsStaticReadAndIsReset AS-39 derived
M-PERM test_AS3_foreignCodehashIsExactlyBit0 AS-3 derived
M-PERM test_AS4a_neverDeployedToken AS-4 derived
M-PERM test_AS4b_eoaToken AS-4 derived
M-PERM test_AS4c_zeroAddressToken AS-4 derived
M-PERM test_AS5_1_planePaused AS-5 derived
M-PERM test_AS5_3_planeHasNoCode AS-5 derived
M-PERM test_AS5_4_planePausedRevertsUnreadable AS-5 derived
M-PERM test_AS6_1_tokenPaused AS-6 derived
M-PERM test_AS6_2_pausedWord31Bytes AS-6 derived
M-PERM test_AS6_3_pausedWord64Bytes AS-6 derived
M-PERM test_AS7_1_tokenBlocksActor AS-7 derived
M-PERM test_AS7_2_tokenBlocksCounterparty AS-7 derived
M-PERM test_AS7_3_planeBlocksActor AS-7 derived
M-PERM test_AS7_4_planeBlocksCounterparty AS-7 derived
M-PERM test_AS8_positiveControl AS-8 derived
M-PERM test_AS8_zeroActor AS-8 derived
M-PERM test_AS8_zeroCounterparty AS-8 derived

# ---- M-CTX -------------------------------------------------------------
# Ctx fields 1 (priceFeed) and 4 (expectedImpl) swap declaration order.
# Named construction and named reads are blind to it; only code that
# fixes field order by position reddens: positional Ctx(...), abi.encode
# compared with a spec-order encoding, and hand-built spec-order
# calldata. src/ builds Ctx by name only. Derived twice, 4 each, agreed.
M-CTX test_AS19_emptyRevert_malformedCtxIsNotAVerdict AS-19 derived
M-CTX test_AS1a_encodeLength160AndSpecOrder AS-1 derived
M-CTX test_AS1a_positionalConstructionNamedReadBack AS-1 derived
M-CTX test_AS1a_viewDecodesSpecOrderCalldata AS-1 derived
EOF
}

# New global: tracks the worst row-class seen so far for the row in progress; reset by the driver before each row.
ROW_CLASS=""

# usage: print the verbatim CLI usage block to stdout.
usage() {
  say "usage: ./forge.sh battery [--only <id>]"
  say "rows: $ROWS"
  say "exit: 0 pass, 1 battery red, 2 usage, 3 row carries no bit, 4 undetermined, 5 work tree changed, 6 cleanup failed, 128+n interrupted"
}

# say <text...>: print one line to stdout.
say() {
  printf '%s\n' "$*"
}

# raise <exit code>: escalate FINAL to <code> if it outranks the current FINAL (order INTERRUPTED > 5 > 4 > 3 > 1 > 6 > 0, see exit_rank); FINAL starts empty, and a row-level 1/3/4 never stops later rows from running.
raise() {
  local code=$1
  if [ -z "$FINAL" ] || [ "$(exit_rank "$code")" -gt "$(exit_rank "$FINAL")" ]; then
    FINAL=$code
  fi
}

# sha_file <path>: print only the sha256 hex digest of <path>, no filename.
sha_file() {
  shasum -a 256 -- "$1" | sed -e 's/ .*//'
}

# manifest <dir> <listfile>: write the sorted "<sha256>  <relative path>" lines for every regular file under <dir> to <listfile> (paths exactly as `find . -type f` prints them from inside <dir>, e.g. "./zz_probe"), then print "<hex> <n>" (sha256 and line count of <listfile>) to stdout. Makes no mktemp call: its only scratch file is "<listfile>.files", removed before it returns. Every caller runs after setup_run and passes <listfile> under $LOGS. A failure is reported through the return code only; no WORKTREE line is printed here.
manifest() {
  local dir=$1 listfile=$2 scratch f count digest
  scratch="$listfile.files"
  : > "$listfile" || return 1
  ( cd "$dir" && find . -type f -print ) | sort > "$scratch" || { rm -f -- "$scratch"; return 1; }
  count=0
  while IFS= read -r f; do
    count=$((count + 1))
    printf '%s  %s\n' "$(sha_file "$dir/$f")" "$f" >> "$listfile"
  done < "$scratch"
  rm -f -- "$scratch"
  digest=$(sha_file "$listfile")
  printf '%s %s\n' "$digest" "$count"
}

# manifest_changed <before listfile> <after listfile>: print each relative path that was added, removed or whose hash differs between the two manifest listfiles, one path per line, sorted and unique, nothing else. Reads only the two files, never a pipe into a loop; returns non-zero only if either file is missing. Used by Step 7 and copy_pristine.
manifest_changed() {
  local before=$1 after=$2
  [ -f "$before" ] && [ -f "$after" ] || return 1
  diff "$before" "$after" | grep -E '^[<>] ' | sed -e 's/^[<>] [^ ]*  //' | sort -u
  return 0
}

# scrub_env: unset every exported FOUNDRY_*/DAPP_* variable plus ETH_RPC_URL, RWA_GUARD_RPC_URL and RWA_GUARD_ENVOR_PROBE_MUST_BE_UNSET; print only the names it unset, or "(none)" if it unset none.
scrub_env() {
  local v names="" envlist
  # KG-U7B-5(c): the exit status used to be dropped -- not by the pipe (this
  # script sets pipefail) but because "for v in $(...)" never reads it. A
  # compgen that produced nothing therefore ran zero iterations and printed
  # the same "(none)" report line as an environment that genuinely had
  # nothing to unset. compgen -e cannot legitimately come back empty here:
  # the script exports LC_ALL before this point, so a non-zero status means
  # the environment could not be listed at all.
  if ! envlist=$(compgen -e); then
    say "BATTERY-ERROR: compgen -e could not list the environment"
    exit "$EXIT_UNDETERMINED"
  fi
  for v in $(printf '%s\n' "$envlist" | sort); do
    case "$v" in
      FOUNDRY_*|DAPP_*|ETH_RPC_URL|RWA_GUARD_RPC_URL|RWA_GUARD_ENVOR_PROBE_MUST_BE_UNSET)
        unset "$v"
        names="$names $v"
        ;;
    esac
  done
  if [ -z "$names" ]; then
    say "BATTERY: env unset: (none)"
  else
    say "BATTERY: env unset:$names"
  fi
}

# parse_args "$@": sets ONLY to the requested row id, or "" to run every row; -h/--help prints usage and exits 0; anything else prints USAGE: <msg> then EXIT: 2 USAGE and exits 2 before anything is created.
parse_args() {
  if [ $# -eq 0 ]; then
    ONLY=""
    return 0
  fi
  case "$1" in
    -h|--help)
      usage
      exit "$EXIT_PASS"
      ;;
    --only)
      if [ $# -ne 2 ]; then
        say "USAGE: --only takes exactly one row id"
        say "EXIT: $EXIT_USAGE USAGE"
        exit "$EXIT_USAGE"
      fi
      case " $ROWS " in
        *" $2 "*)
          ONLY=$2
          return 0
          ;;
        *)
          say "USAGE: unknown row id: $2"
          say "EXIT: $EXIT_USAGE USAGE"
          exit "$EXIT_USAGE"
          ;;
      esac
      ;;
    *)
      say "USAGE: unrecognized argument: $1"
      say "EXIT: $EXIT_USAGE USAGE"
      exit "$EXIT_USAGE"
      ;;
  esac
}

# exit_rank <exit code>: print its precedence (higher wins), order INTERRUPTED > 5 > 4 > 3 > 1 > 6 > 0; used only by raise.
exit_rank() {
  case "$1" in
    129|130|143) printf '%s\n' 6 ;;
    5) printf '%s\n' 5 ;;
    4) printf '%s\n' 4 ;;
    3) printf '%s\n' 3 ;;
    1) printf '%s\n' 2 ;;
    6) printf '%s\n' 1 ;;
    0) printf '%s\n' 0 ;;
    *) printf '%s\n' -1 ;;
  esac
}

# class_rank <MATCH|MISMATCH|NO-BIT|UNDETERMINED>: print its severity (higher is worse); used only by record_class.
class_rank() {
  case "$1" in
    UNDETERMINED) printf '%s\n' 3 ;;
    NO-BIT) printf '%s\n' 2 ;;
    MISMATCH) printf '%s\n' 1 ;;
    MATCH) printf '%s\n' 0 ;;
    *) printf '%s\n' -1 ;;
  esac
}

# record_class <MATCH|MISMATCH|NO-BIT|UNDETERMINED>: escalate ROW_CLASS to the worst value seen so far for the row in progress (UNDETERMINED > NO-BIT > MISMATCH > MATCH), and raise the matching exit code (MATCH raises nothing).
record_class() {
  local cls=$1
  if [ -z "$ROW_CLASS" ] || [ "$(class_rank "$cls")" -gt "$(class_rank "$ROW_CLASS")" ]; then
    ROW_CLASS=$cls
  fi
  case "$cls" in
    UNDETERMINED) raise "$EXIT_UNDETERMINED" ;;
    NO-BIT) raise "$EXIT_NO_BIT" ;;
    MISMATCH) raise "$EXIT_BATTERY_RED" ;;
    MATCH) : ;;
  esac
}

# setup_run: assign SRC, BASE_TMP, RUN, WORK, LOGS, PRISTINE and ARM in order,
# each followed by its own guard line; refuse a symlink under SRC or a BASE_TMP
# whose real path is SRC or lies under it (both print BATTERY-ERROR: <reason>
# and exit 4 directly, since nothing has been created yet); create the run,
# work and log directories; export FOUNDRY_OUT/FOUNDRY_CACHE_PATH right after
# WORK exists; install the HUP/INT/TERM traps. Reads $0 and TMPDIR. Writes the
# seven path globals, FOUNDRY_OUT, FOUNDRY_CACHE_PATH and PHASE.
setup_run() {
  PHASE=setup

  SRC=$(cd "$(dirname "$0")" && pwd -P)
  : "${SRC:?}"

  if [ -n "$(find "$SRC" -type l 2>/dev/null)" ]; then
    say "BATTERY-ERROR: a symlink exists under the source tree"
    exit "$EXIT_UNDETERMINED"
  fi

  BASE_TMP=${TMPDIR:-/tmp}
  : "${BASE_TMP:?}"

  local base_real
  base_real=$(cd "$BASE_TMP" 2>/dev/null && pwd -P)
  case "$base_real" in
    "$SRC"|"$SRC"/*)
      say "BATTERY-ERROR: the scratch base resolves under the source tree"
      exit "$EXIT_UNDETERMINED"
      ;;
  esac

  RUN=$(mktemp -d "${BASE_TMP%/}/rwa-guard-battery.XXXXXX") || {
    say "BATTERY-ERROR: mktemp could not create the run directory"
    exit "$EXIT_UNDETERMINED"
  }
  : "${RUN:?}"

  WORK="$RUN/work"
  : "${WORK:?}"
  LOGS="$RUN/logs"
  : "${LOGS:?}"
  mkdir -p -- "$WORK" "$LOGS" || {
    say "BATTERY-ERROR: could not create the work and log directories"
    exit "$EXIT_UNDETERMINED"
  }

  FOUNDRY_OUT="$WORK/out"
  FOUNDRY_CACHE_PATH="$WORK/cache"
  export FOUNDRY_OUT FOUNDRY_CACHE_PATH

  PRISTINE="$WORK/pristine"
  : "${PRISTINE:?}"
  ARM="$WORK/arm"
  : "${ARM:?}"

  trap 'on_signal HUP' HUP
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
}

# finish [code]: the single exit point. Raises <code> if given (both "raise 4;
# finish 4" and a bare "finish 4" work, since an empty FINAL defaults to
# EXIT_PASS here). Guarded against re-entry: a second call exits immediately
# with the already-decided $FINAL. Prints the row SUMMARY (read from
# $LOGS/results.log, one "RESULT <id>: <class>" line per row -- the row
# driver must append that same line there; an absent file means zero rows
# ran), then, only if $LOGS/manifest.before exists, the after-run worktree
# manifest and a WORKTREE-CHANGED line per differing path (raising 5 on any),
# then removes $WORK if present and reports its rc (raising 6 on a nonzero
# rc), then reports $LOGS as kept, then the final EXIT line, then exits.
# Reads LOGS, SRC, WORK, FINAL; writes FINAL and the new re-entry guard
# FINISH_DONE.
finish() {
  if [ -n "${FINISH_DONE:-}" ]; then
    exit "${FINAL:-$EXIT_PASS}"
  fi
  FINISH_DONE=1
  PHASE=finish

  if [ $# -ge 1 ] && [ -n "$1" ]; then
    raise "$1"
  fi

  local results rows n_match n_mismatch n_nobit n_undet
  results="${LOGS:-}/results.log"
  rows=0
  n_match=0
  n_mismatch=0
  n_nobit=0
  n_undet=0
  if [ -n "${LOGS:-}" ] && [ -f "$results" ]; then
    rows=$(grep -c '^RESULT ' "$results")
    n_match=$(grep -cE ': MATCH$' "$results")
    n_mismatch=$(grep -cE ': MISMATCH$' "$results")
    n_nobit=$(grep -cE ': NO-BIT$' "$results")
    n_undet=$(grep -cE ': UNDETERMINED$' "$results")
  fi
  say "SUMMARY: rows=$rows match=$n_match mismatch=$n_mismatch no-bit=$n_nobit undetermined=$n_undet"

  if [ -n "${LOGS:-}" ] && [ -f "$LOGS/manifest.before" ]; then
    local after_digest after_n changed after_line
    if after_line=$(manifest "$SRC" "$LOGS/manifest.after"); then
      after_digest=${after_line%% *}
      after_n=${after_line##* }
      changed=$(manifest_changed "$LOGS/manifest.before" "$LOGS/manifest.after")
      if [ -n "$changed" ]; then
        say "WORKTREE: after sha256 $after_digest files $after_n -> CHANGED"
        printf '%s\n' "$changed" > "$LOGS/worktree.after.changed.txt"
        while IFS= read -r p; do
          say "WORKTREE-CHANGED: $p"
        done < "$LOGS/worktree.after.changed.txt"
        raise "$EXIT_WORKTREE_CHANGED"
      else
        say "WORKTREE: after sha256 $after_digest files $after_n -> unchanged"
      fi
    else
      say "WORKTREE: after manifest failed"
      raise "$EXIT_UNDETERMINED"
    fi
  fi

  local cleanup_rc=0
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    rm -rf -- "${WORK:?}"
    cleanup_rc=$?
  fi
  say "CLEANUP: rm -rf work rc=$cleanup_rc"
  if [ "$cleanup_rc" -ne 0 ]; then
    raise "$EXIT_CLEANUP_FAILED"
  fi

  if [ -n "${LOGS:-}" ]; then
    say "LOGS: $LOGS (kept)"
  fi

  : "${FINAL:=$EXIT_PASS}"
  case "$FINAL" in
    129) say "EXIT: 129 INTERRUPTED" ;;
    130) say "EXIT: 130 INTERRUPTED" ;;
    143) say "EXIT: 143 INTERRUPTED" ;;
    0) say "EXIT: 0 PASS" ;;
    1) say "EXIT: 1 BATTERY-RED" ;;
    2) say "EXIT: 2 USAGE" ;;
    3) say "EXIT: 3 NO-BIT" ;;
    4) say "EXIT: 4 UNDETERMINED" ;;
    5) say "EXIT: 5 WORKTREE-CHANGED" ;;
    6) say "EXIT: 6 CLEANUP-FAILED" ;;
    *) say "EXIT: $FINAL UNKNOWN" ;;
  esac
  exit "$FINAL"
}

# on_signal <HUP|INT|TERM>: the three traps installed by setup_run call this.
# Prints INTERRUPTED: <name> during <phase> (the main driver must keep PHASE
# current for this to be informative), raises the matching interrupted exit
# code, then calls finish. Reads PHASE; no other globals.
on_signal() {
  local name=$1 code
  case "$name" in
    HUP)  code=$EXIT_INTERRUPTED_HUP ;;
    INT)  code=$EXIT_INTERRUPTED_INT ;;
    TERM) code=$EXIT_INTERRUPTED_TERM ;;
    *)    code=$EXIT_INTERRUPTED_TERM ;;
  esac
  say "INTERRUPTED: $name during ${PHASE:-unknown}"
  raise "$code"
  finish
}

# copy_pristine: copies SRC to PRISTINE, checks the pristine manifest against
# $LOGS/manifest.before (which must already exist), then removes the two
# excluded_table files from PRISTINE and asserts each is gone. On any failure
# prints COPY-FIDELITY: <reason> or EXCLUSION-FAILED: <file> and calls
# finish 4. Reads SRC, LOGS, PRISTINE. Writes $LOGS/manifest.pristine and
# $LOGS/excluded_table.copy.txt, and the PRISTINE tree itself.
copy_pristine() {
  PHASE=copy_pristine

  if ! cp -R "$SRC" "$PRISTINE"; then
    say "COPY-FIDELITY: cp -R could not create the pristine copy"
    finish "$EXIT_UNDETERMINED"
  fi

  # KG-U7B-6: both return codes used to be dropped. manifest returns non-zero
  # when it could not truncate the listfile or when find|sort failed, and in
  # that case the listfile can be left empty -- and an empty listfile diffed
  # against another empty listfile produces no output, which the [ -n ... ]
  # test below then reads as "nothing changed". manifest_changed returns
  # non-zero when either listfile is missing, and prints nothing when it
  # does, so that case was indistinguishable from a clean copy as well.
  local pristine_line pristine_rc changed changed_rc
  pristine_line=$(manifest "$PRISTINE" "$LOGS/manifest.pristine")
  pristine_rc=$?
  if [ "$pristine_rc" -ne 0 ]; then
    say "COPY-FIDELITY: the pristine manifest could not be built"
    finish "$EXIT_UNDETERMINED"
  fi
  set -- $pristine_line
  if [ "$#" -ne 2 ] || [ -z "$1" ] || [ "$2" = "0" ]; then
    say "COPY-FIDELITY: the pristine manifest is empty or malformed"
    finish "$EXIT_UNDETERMINED"
  fi
  changed=$(manifest_changed "$LOGS/manifest.before" "$LOGS/manifest.pristine")
  changed_rc=$?
  if [ "$changed_rc" -ne 0 ]; then
    say "COPY-FIDELITY: the two manifests could not be compared"
    finish "$EXIT_UNDETERMINED"
  fi
  if [ -n "$changed" ]; then
    say "COPY-FIDELITY: the pristine copy does not match the source manifest"
    finish "$EXIT_UNDETERMINED"
  fi

  local etbl line file
  etbl="$LOGS/excluded_table.copy.txt"
  excluded_table > "$etbl"
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    file=${line%%@*}
    rm -f -- "$PRISTINE/$file"
    if [ -e "$PRISTINE/$file" ]; then
      say "EXCLUSION-FAILED: $file"
      finish "$EXIT_UNDETERMINED"
    fi
  done < "$etbl"
}

# print_exclusions: for each excluded_table line, prints EXCLUDED: <file>
# (present in source: yes|no), one EXCLUDED-ID: <id> line per id, the pinned
# Chinese sentence once, then EXCLUDED-NOTE: <file>: <n> ids ...; after both
# files, prints the pinned "no fork arm ran this round" sentence once. Pure
# reporting: never calls finish. Reads SRC, LOGS. Writes
# $LOGS/excluded_table.print.txt.
print_exclusions() {
  PHASE=print_exclusions
  local etbl line file ids id n present
  etbl="$LOGS/excluded_table.print.txt"
  excluded_table > "$etbl"
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    file=${line%%@*}
    ids=${line#*@}
    if [ -f "$SRC/$file" ]; then
      present=yes
    else
      present=no
    fi
    say "EXCLUDED: $file (present in source: $present)"
    n=0
    for id in $ids; do
      say "EXCLUDED-ID: $id"
      n=$((n + 1))
    done
    say "这两/三条在本电池里没有被测过"
    say "EXCLUDED-NOTE: $file: $n ids above are not tested by this battery; their power is excluded here, not absent"
  done < "$etbl"
  say "本轮未跑 fork 臂"
}

# validate_tables: materializes rules_table, post_table and expected_table
# under $LOGS and checks every row in ROWS has at least one line in each
# table; no line names an unknown row; every rules_table line carries exactly
# 5 @ and a positive-integer K; every post_table line carries exactly 3 @;
# every expected_table AS-token matches AS_TOKEN_RE and its source column is
# derived or measured; no (row, function) pair repeats; every expected
# function name and OVERREACH_SENTINEL exist as "function <name>(" somewhere
# under $PRISTINE/test/*.t.sol. A structural problem prints
# TABLE-INVALID: <reason> and calls finish 4; a name that is not found as a
# function prints TABLE-NAME-UNKNOWN: <name> and calls finish 4. Reads ROWS,
# AS_TOKEN_RE, OVERREACH_SENTINEL, LOGS, PRISTINE. Writes scratch files under
# $LOGS (left in place).
validate_tables() {
  PHASE=validate_tables
  local rtbl ptbl etbl pairs
  local line row rest k stripped at_count
  local fn tok src_col extra

  rtbl="$LOGS/rules_table.validate.txt"
  ptbl="$LOGS/post_table.validate.txt"
  etbl="$LOGS/expected_table.validate.txt"
  pairs="$LOGS/expected_pairs.validate.txt"

  rules_table > "$rtbl"
  post_table > "$ptbl"
  expected_table > "$etbl"
  : > "$pairs"

  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    stripped=${line//@/}
    at_count=$(( ${#line} - ${#stripped} ))
    if [ "$at_count" -ne 5 ]; then
      say "TABLE-INVALID: rules_table line does not carry exactly 5 @: $line"
      finish "$EXIT_UNDETERMINED"
    fi
    row=${line%%@*}
    case " $ROWS " in
      *" $row "*) : ;;
      *)
        say "TABLE-INVALID: rules_table names an unknown row: $row"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
    rest=${line#*@}
    rest=${rest#*@}
    # KG-U7B-7: the op field was never validated, and apply_rules treats every
    # value other than "replace" as a delete -- so a typo silently turned a
    # replacement into a deletion instead of failing the table.
    case "${rest%%@*}" in
      replace|delete) : ;;
      *)
        say "TABLE-INVALID: rules_table op is not replace or delete: $line"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
    rest=${rest#*@}
    k=${rest%%@*}
    case "$k" in
      ''|*[!0-9]*)
        say "TABLE-INVALID: rules_table K is not a positive integer: $line"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
    if [ "$k" -eq 0 ]; then
      say "TABLE-INVALID: rules_table K is not a positive integer: $line"
      finish "$EXIT_UNDETERMINED"
    fi
  done < "$rtbl"

  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    stripped=${line//@/}
    at_count=$(( ${#line} - ${#stripped} ))
    if [ "$at_count" -ne 3 ]; then
      say "TABLE-INVALID: post_table line does not carry exactly 3 @: $line"
      finish "$EXIT_UNDETERMINED"
    fi
    row=${line%%@*}
    case " $ROWS " in
      *" $row "*) : ;;
      *)
        say "TABLE-INVALID: post_table names an unknown row: $row"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
  done < "$ptbl"

  while IFS=' ' read -r row fn tok src_col extra; do
    case "$row" in
      ''|'#'*) continue ;;
    esac
    if [ -n "$extra" ]; then
      say "TABLE-INVALID: expected_table line has extra fields: $row $fn $tok $src_col $extra"
      finish "$EXIT_UNDETERMINED"
    fi
    case " $ROWS " in
      *" $row "*) : ;;
      *)
        say "TABLE-INVALID: expected_table names an unknown row: $row"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
    if [[ ! "$tok" =~ $AS_TOKEN_RE ]]; then
      say "TABLE-INVALID: expected_table AS-token shape: $row $fn $tok"
      finish "$EXIT_UNDETERMINED"
    fi
    case "$src_col" in
      derived|measured) : ;;
      *)
        say "TABLE-INVALID: expected_table source is not derived or measured: $row $fn $src_col"
        finish "$EXIT_UNDETERMINED"
        ;;
    esac
    if ! grep -F -q -- "function $fn(" "$PRISTINE"/test/*.t.sol 2>/dev/null; then
      say "TABLE-NAME-UNKNOWN: $fn"
      finish "$EXIT_UNDETERMINED"
    fi
    printf '%s %s\n' "$row" "$fn" >> "$pairs"
  done < "$etbl"

  if ! grep -F -q -- "function $OVERREACH_SENTINEL(" "$PRISTINE"/test/*.t.sol 2>/dev/null; then
    say "TABLE-NAME-UNKNOWN: $OVERREACH_SENTINEL"
    finish "$EXIT_UNDETERMINED"
  fi

  sort "$pairs" > "$pairs.sorted"
  sort -u "$pairs" > "$pairs.uniq"
  if ! cmp -s "$pairs.sorted" "$pairs.uniq"; then
    say "TABLE-INVALID: expected_table has a duplicate row/function pair"
    finish "$EXIT_UNDETERMINED"
  fi
  rm -f -- "$pairs.sorted" "$pairs.uniq"

  for row in $ROWS; do
    if ! grep -q "^${row}@" "$rtbl"; then
      say "TABLE-INVALID: row $row has no rules_table line"
      finish "$EXIT_UNDETERMINED"
    fi
    if ! grep -q "^${row}@" "$ptbl"; then
      say "TABLE-INVALID: row $row has no post_table line"
      finish "$EXIT_UNDETERMINED"
    fi
    if ! grep -q "^${row} " "$etbl"; then
      say "TABLE-INVALID: row $row has no expected_table line"
      finish "$EXIT_UNDETERMINED"
    fi
  done
}

# make_arm (no args; reads PRISTINE ARM; writes no globals; no files under $LOGS): if $ARM exists, rm -rf it, then cp -R from PRISTINE to ARM for a fresh copy per call; prints nothing on success and returns EXIT_PASS, or on a failed rm or cp prints BATTERY-ERROR: make_arm <rm|cp> rc=<rc> and returns EXIT_UNDETERMINED.
make_arm() {
  PHASE="make_arm"
  local rc
  if [ -e "$ARM" ]; then
    rm -rf -- "${ARM:?}"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      say "BATTERY-ERROR: make_arm rm rc=$rc"
      return "$EXIT_UNDETERMINED"
    fi
  fi
  cp -R "$PRISTINE" "$ARM"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    say "BATTERY-ERROR: make_arm cp rc=$rc"
    return "$EXIT_UNDETERMINED"
  fi
  return "$EXIT_PASS"
}

# apply_rules <id> (reads LOGS ARM; writes $LOGS/<id>.rules.txt and one $LOGS/<id>.rule<i>.count per rule of this row; sets ROW_FILES, ROW_WANT_REMOVED and ROW_WANT_ADDED, reset at entry): runs the row's rules_table substitutions on ARM in table order, prints a ROW line per rule plus SUBST-COUNT on a wrong count or BATTERY-ERROR on a perl failure, always continuing to the next rule, and returns the worst of EXIT_PASS, EXIT_NO_BIT and EXIT_UNDETERMINED seen.
apply_rules() {
  local id=$1
  PHASE="apply_rules $id"
  local tbl line row file op k old new i status rc countfile c cline
  ROW_FILES=""
  ROW_WANT_REMOVED=0
  ROW_WANT_ADDED=0
  tbl="$LOGS/$id.rules.txt"
  rules_table > "$tbl"
  i=0
  status=$EXIT_PASS
  while IFS='@' read -r row file op k old new; do
    case "$row" in
      ''|'#'*) continue ;;
    esac
    if [ "$row" != "$id" ]; then
      continue
    fi
    i=$((i + 1))
    case " $ROW_FILES " in
      *" $file "*) : ;;
      *) ROW_FILES="${ROW_FILES:+$ROW_FILES }$file" ;;
    esac
    ROW_WANT_REMOVED=$((ROW_WANT_REMOVED + k))
    if [ "$op" = "replace" ]; then
      ROW_WANT_ADDED=$((ROW_WANT_ADDED + k))
    fi
    countfile="$LOGS/$id.rule$i.count"
    OLD=$old NEW=$new OP=$op perl -i -ne 'BEGIN{$n=0} if (/^([ \t]*)\Q$ENV{OLD}\E$/) { $n++; print "$1$ENV{NEW}\n" if $ENV{OP} eq "replace"; next } print; END { printf STDERR "count=%d\n", $n }' "$ARM/$file" 2> "$countfile"
    rc=$?
    c=""
    while IFS= read -r cline; do
      case "$cline" in
        count=*) c=${cline#count=} ;;
      esac
    done < "$countfile"
    if [ "$rc" -ne 0 ] || [ -z "$c" ]; then
      say "BATTERY-ERROR: perl rc=$rc $id rule $i"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
      continue
    fi
    say "ROW $id: rule $i $file count=$c want=$k"
    if [ "$c" -ne "$k" ]; then
      say "SUBST-COUNT: $id rule $i count=$c want=$k"
      if [ "$status" -lt "$EXIT_NO_BIT" ]; then
        status=$EXIT_NO_BIT
      fi
    fi
  done < "$tbl"
  return "$status"
}

# check_diff <id> (reads PRISTINE ARM LOGS ROW_FILES ROW_WANT_REMOVED ROW_WANT_ADDED; writes no globals; writes $LOGS/<id>.diff.<n>.txt per file of ROW_FILES and $LOGS/<id>.scope.txt): cmp and diff each row file against PRISTINE, then diff -r -q the whole tree to confirm the change is scoped to ROW_FILES, printing DIFF-EMPTY, DIFF-SCOPE, one ROW line and DIFF-COUNT as they apply, or BATTERY-ERROR on a cmp/diff rc of 2 or more, and returns the worst of EXIT_PASS, EXIT_NO_BIT and EXIT_UNDETERMINED seen.
check_diff() {
  local id=$1
  PHASE="check_diff $id"
  local f n removed added cmp_rc diff_rc scope_rc status dline line p matched collected
  n=0
  removed=0
  added=0
  status=$EXIT_PASS
  for f in $ROW_FILES; do
    n=$((n + 1))
    cmp -s "$PRISTINE/$f" "$ARM/$f"
    cmp_rc=$?
    if [ "$cmp_rc" -eq 0 ]; then
      say "DIFF-EMPTY: $id $f"
      if [ "$status" -lt "$EXIT_NO_BIT" ]; then
        status=$EXIT_NO_BIT
      fi
    elif [ "$cmp_rc" -ge 2 ]; then
      say "BATTERY-ERROR: cmp rc=$cmp_rc $id $f"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
    fi
    diff "$PRISTINE/$f" "$ARM/$f" > "$LOGS/$id.diff.$n.txt"
    diff_rc=$?
    if [ "$diff_rc" -ge 2 ]; then
      say "BATTERY-ERROR: diff rc=$diff_rc $id $f"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
    fi
    while IFS= read -r dline; do
      case "$dline" in
        '<'*) removed=$((removed + 1)) ;;
        '>'*) added=$((added + 1)) ;;
      esac
    done < "$LOGS/$id.diff.$n.txt"
  done
  diff -r -q "$PRISTINE" "$ARM" > "$LOGS/$id.scope.txt"
  scope_rc=$?
  if [ "$scope_rc" -ge 2 ]; then
    say "BATTERY-ERROR: diff -r -q rc=$scope_rc $id"
    if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
      status=$EXIT_UNDETERMINED
    fi
  fi
  collected=""
  while IFS= read -r line; do
    matched=""
    for p in $ROW_FILES; do
      if [ "$line" = "Files $PRISTINE/$p and $ARM/$p differ" ]; then
        matched=$p
        break
      fi
    done
    if [ -n "$matched" ]; then
      case " $collected " in
        *" $matched "*) : ;;
        *) collected="${collected:+$collected }$matched" ;;
      esac
    else
      say "DIFF-SCOPE: $id $line"
      if [ "$status" -lt "$EXIT_NO_BIT" ]; then
        status=$EXIT_NO_BIT
      fi
    fi
  done < "$LOGS/$id.scope.txt"
  say "ROW $id: diff removed=$removed added=$added want removed=$ROW_WANT_REMOVED added=$ROW_WANT_ADDED files=${collected:-(none)}"
  if [ "$removed" -ne "$ROW_WANT_REMOVED" ] || [ "$added" -ne "$ROW_WANT_ADDED" ]; then
    say "DIFF-COUNT: $id removed=$removed added=$added want removed=$ROW_WANT_REMOVED added=$ROW_WANT_ADDED"
    if [ "$status" -lt "$EXIT_NO_BIT" ]; then
      status=$EXIT_NO_BIT
    fi
  fi
  return "$status"
}

# check_post <id> (reads LOGS ARM; writes no globals; writes $LOGS/<id>.post.txt): greps -cF each row's fixed string in the mutated file, prints a ROW line per line of the row plus POSTCOND on a wrong count or BATTERY-ERROR on grep rc 2, and returns the worst of EXIT_PASS, EXIT_NO_BIT and EXIT_UNDETERMINED seen.
check_post() {
  local id=$1
  PHASE="check_post $id"
  local tbl line row rest file rest2 w string c grep_rc status
  tbl="$LOGS/$id.post.txt"
  post_table > "$tbl"
  status=$EXIT_PASS
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    row=${line%%@*}
    if [ "$row" != "$id" ]; then
      continue
    fi
    rest=${line#*@}
    file=${rest%%@*}
    rest2=${rest#*@}
    w=${rest2##*@}
    string=${rest2%@*}
    c=$(grep -cF -- "$string" "$ARM/$file")
    grep_rc=$?
    if [ "$grep_rc" -eq 2 ]; then
      say "BATTERY-ERROR: grep rc=2 $id $file"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
      continue
    fi
    say "ROW $id: post $file \"$string\" count=$c want=$w"
    if [ "$c" -ne "$w" ]; then
      say "POSTCOND: $id $file \"$string\" count=$c want=$w"
      if [ "$status" -lt "$EXIT_NO_BIT" ]; then
        status=$EXIT_NO_BIT
      fi
    fi
  done < "$tbl"
  return "$status"
}

# forge_build <label>: reads WORK ARM LOGS; writes $LOGS/<label>.build.log and sets BUILD_RC, reset to empty at entry; returns 0 with BUILD_RC carrying the forge rc, or 4 with one BATTERY-ERROR line if the rm -rf of $WORK/out and $WORK/cache fails; prints nothing on the ordinary path.
forge_build() {
  local label=$1
  PHASE="forge_build $label"
  BUILD_RC=""

  local rm_rc
  rm -rf -- "${WORK:?}/out" "${WORK:?}/cache"
  rm_rc=$?
  if [ "$rm_rc" -ne 0 ]; then
    say "BATTERY-ERROR: forge_build rm -rf rc=$rm_rc"
    return "$EXIT_UNDETERMINED"
  fi

  ( cd "$ARM" && sh ./forge.sh build --force ) > "$LOGS/$label.build.log" 2>&1
  BUILD_RC=$?

  return "$EXIT_PASS"
}

# forge_test <label>: reads ARM LOGS SUMMARY_RE SUITE_COUNT_RE; writes $LOGS/<label>.test.log, $LOGS/<label>.summary.txt and $LOGS/<label>.suites.txt (plus, through red_names, $LOGS/<label>.red.raw and $LOGS/<label>.red.txt); sets TEST_RC TEST_P TEST_F TEST_S TEST_T TEST_K TEST_RED_N, all reset to empty at entry; calls red_names <label>; prints one PARSE-MISMATCH line per violated parse rule; returns 0 if red_names returned 0 and every parse rule held, else 4.
forge_test() {
  local label=$1
  PHASE="forge_test $label"
  TEST_RC=""
  TEST_P=""
  TEST_F=""
  TEST_S=""
  TEST_T=""
  TEST_K=""
  TEST_RED_N=""

  local status=$EXIT_PASS
  local rn_status
  local test_log summary_file suites_file
  test_log="$LOGS/$label.test.log"
  summary_file="$LOGS/$label.summary.txt"
  suites_file="$LOGS/$label.suites.txt"

  ( cd "$ARM" && sh ./forge.sh test ) > "$test_log" 2>&1
  TEST_RC=$?

  red_names "$label"
  rn_status=$?
  if [ "$rn_status" -gt "$status" ]; then
    status=$rn_status
  fi

  grep -oE "$SUMMARY_RE" "$test_log" > "$summary_file"
  grep -oE "$SUITE_COUNT_RE" "$test_log" > "$suites_file"

  local last_summary last_suite
  last_summary=$(tail -n 1 -- "$summary_file")
  last_suite=$(tail -n 1 -- "$suites_file")

  if [ -z "$last_summary" ]; then
    say "PARSE-MISMATCH: $label no summary line"
    status=$EXIT_UNDETERMINED
  elif [[ "$last_summary" =~ ^([0-9]+)\ tests\ passed,\ ([0-9]+)\ failed,\ ([0-9]+)\ skipped\ \(([0-9]+)\ total\ tests\)$ ]]; then
    TEST_P=${BASH_REMATCH[1]}
    TEST_F=${BASH_REMATCH[2]}
    TEST_S=${BASH_REMATCH[3]}
    TEST_T=${BASH_REMATCH[4]}
  else
    say "PARSE-MISMATCH: $label summary line does not match SUMMARY_RE"
    status=$EXIT_UNDETERMINED
  fi

  if [ -z "$last_suite" ]; then
    say "PARSE-MISMATCH: $label no suite count"
    status=$EXIT_UNDETERMINED
  elif [[ "$last_suite" =~ ^Ran\ ([0-9]+)\ test\ suites$ ]]; then
    TEST_K=${BASH_REMATCH[1]}
  else
    say "PARSE-MISMATCH: $label suite count line does not match SUITE_COUNT_RE"
    status=$EXIT_UNDETERMINED
  fi

  if [ -n "$TEST_P" ] && [ -n "$TEST_F" ] && [ -n "$TEST_S" ] && [ -n "$TEST_T" ]; then
    if [ $((10#$TEST_P + 10#$TEST_F + 10#$TEST_S)) -ne $((10#$TEST_T)) ]; then
      say "PARSE-MISMATCH: $label P+F+S != T"
      status=$EXIT_UNDETERMINED
    fi
  fi

  if [ -n "$TEST_F" ]; then
    if [ $((10#$TEST_F)) -eq 0 ] && [ "$TEST_RC" -eq 0 ]; then
      :
    elif [ $((10#$TEST_F)) -gt 0 ] && [ "$TEST_RC" -eq 1 ]; then
      :
    else
      say "PARSE-MISMATCH: $label not ((F=0 and rc=0) or (F>0 and rc=1)): F=$TEST_F rc=$TEST_RC"
      status=$EXIT_UNDETERMINED
    fi
  fi

  TEST_RED_N=$(grep -c '' "$LOGS/$label.red.txt" 2>/dev/null)
  : "${TEST_RED_N:=0}"

  if [ -n "$TEST_F" ]; then
    if [ $((10#$TEST_RED_N)) -ne $((10#$TEST_F)) ]; then
      say "PARSE-MISMATCH: $label red name count $TEST_RED_N != F $TEST_F"
      status=$EXIT_UNDETERMINED
    fi
  fi

  return "$status"
}

# red_names <label>: reads LOGS; writes $LOGS/<label>.red.raw and $LOGS/<label>.red.txt; returns 0, or 4 with one BATTERY-ERROR line if the perl step or the sort step exits non-zero.
red_names() {
  local label=$1
  PHASE="red_names $label"

  local perl_rc sort_rc

  perl -ne 'print "$1\n" if /^\[FAIL[^\]]*\] (\w+)\(/' "$LOGS/$label.test.log" > "$LOGS/$label.red.raw"
  perl_rc=$?
  if [ "$perl_rc" -ne 0 ]; then
    say "BATTERY-ERROR: red_names rc=$perl_rc $label"
    return "$EXIT_UNDETERMINED"
  fi

  sort -u "$LOGS/$label.red.raw" > "$LOGS/$label.red.txt"
  sort_rc=$?
  if [ "$sort_rc" -ne 0 ]; then
    say "BATTERY-ERROR: red_names rc=$sort_rc $label"
    return "$EXIT_UNDETERMINED"
  fi

  return "$EXIT_PASS"
}

# check_overreach <id> <label> (reads LOGS OVERREACH_SENTINEL; writes no globals; no files under $LOGS): prints MUTATION-OVERREACH and returns EXIT_NO_BIT if OVERREACH_SENTINEL is present in the red set of <label>, else prints nothing and returns EXIT_PASS.
# state-diff `reverted` marks only REVERT failures; it is not a read-failure detector.
check_overreach() {
  local id=$1
  local label=$2
  PHASE="check_overreach $id"
  if grep -qxF -- "$OVERREACH_SENTINEL" "$LOGS/$label.red.txt"; then
    say "MUTATION-OVERREACH: $id"
    return "$EXIT_NO_BIT"
  fi
  return "$EXIT_PASS"
}

# check_prefix <id> <label> (reads LOGS; writes $LOGS/<id>.expected.txt; no other globals): for each expected_table row of <id>, in table order, whose function name is in the red set of <label>, greps <label>'s test log for the bare FAIL line (a) and the AS-token-prefixed FAIL line (b), the AS-token always taken from the table column and never parsed from the function name; prints a ROW line always, a PREFIX-FAIL line unless a>=1 and a=b, and a BATTERY-ERROR line (skipping that row's checks) on a grep rc of 2; returns the worst of EXIT_PASS, EXIT_NO_BIT and EXIT_UNDETERMINED seen.
check_prefix() {
  local id=$1
  local label=$2
  PHASE="check_prefix $id"
  local all row fn token source status a a_rc b b_rc
  status=$EXIT_PASS
  all="$LOGS/$id.expected.all.txt"
  expected_table > "$all"
  : > "$LOGS/$id.expected.txt"
  while IFS=' ' read -r row fn token source; do
    case "$row" in
      ''|'#'*) continue ;;
    esac
    if [ "$row" != "$id" ]; then
      continue
    fi
    echo "$row $fn $token $source" >> "$LOGS/$id.expected.txt"
    if ! grep -qxF -- "$fn" "$LOGS/$label.red.txt"; then
      continue
    fi
    a=$(grep -c -- "^\[FAIL[^]]*\] $fn(" "$LOGS/$label.test.log")
    a_rc=$?
    if [ "$a_rc" -eq 2 ]; then
      say "BATTERY-ERROR: check_prefix grep rc=2 $id"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
      continue
    fi
    b=$(grep -c -- "^\[FAIL: $token: .*\] $fn(" "$LOGS/$label.test.log")
    b_rc=$?
    if [ "$b_rc" -eq 2 ]; then
      say "BATTERY-ERROR: check_prefix grep rc=2 $id"
      if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
        status=$EXIT_UNDETERMINED
      fi
      continue
    fi
    say "ROW $id: prefix $fn a=$a b=$b want $token"
    if [ "$a" -lt 1 ] || [ "$a" -ne "$b" ]; then
      say "PREFIX-FAIL: $id $fn a=$a b=$b want $token"
      if [ "$status" -lt "$EXIT_NO_BIT" ]; then
        status=$EXIT_NO_BIT
      fi
    fi
  done < "$all"
  return "$status"
}

# compare_sets <id> <label> (reads LOGS; writes $LOGS/<id>.expected.txt, $LOGS/<id>.expected.names.txt, $LOGS/<id>.missing.txt and $LOGS/<id>.extra.txt; no other globals): set-diffs the expected names of <id> against the red set of <label> in both directions, always printing a missing ROW line then an extra ROW line (names single-space separated, or (none)), and a BATTERY-ERROR line per grep rc of 2; returns EXIT_BATTERY_RED if either set is non-empty, else the worst of EXIT_PASS and EXIT_UNDETERMINED seen.
compare_sets() {
  local id=$1
  local label=$2
  PHASE="compare_sets $id"
  local all row fn token source status rc line missing_n extra_n missing_list extra_list
  status=$EXIT_PASS
  all="$LOGS/$id.expected.all.txt"
  expected_table > "$all"
  : > "$LOGS/$id.expected.txt"
  : > "$LOGS/$id.expected.names.raw.txt"
  while IFS=' ' read -r row fn token source; do
    case "$row" in
      ''|'#'*) continue ;;
    esac
    if [ "$row" != "$id" ]; then
      continue
    fi
    echo "$row $fn $token $source" >> "$LOGS/$id.expected.txt"
    echo "$fn" >> "$LOGS/$id.expected.names.raw.txt"
  done < "$all"
  sort -u "$LOGS/$id.expected.names.raw.txt" > "$LOGS/$id.expected.names.txt"

  grep -vxF -f "$LOGS/$label.red.txt" -- "$LOGS/$id.expected.names.txt" > "$LOGS/$id.missing.txt"
  rc=$?
  if [ "$rc" -eq 2 ]; then
    say "BATTERY-ERROR: compare_sets grep rc=2 $id"
    if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
      status=$EXIT_UNDETERMINED
    fi
  fi

  grep -vxF -f "$LOGS/$id.expected.names.txt" -- "$LOGS/$label.red.txt" > "$LOGS/$id.extra.txt"
  rc=$?
  if [ "$rc" -eq 2 ]; then
    say "BATTERY-ERROR: compare_sets grep rc=2 $id"
    if [ "$status" -lt "$EXIT_UNDETERMINED" ]; then
      status=$EXIT_UNDETERMINED
    fi
  fi

  missing_n=0
  missing_list=""
  while IFS= read -r line; do
    missing_n=$((missing_n + 1))
    missing_list="${missing_list:+$missing_list }$line"
  done < "$LOGS/$id.missing.txt"
  say "ROW $id: missing $missing_n: ${missing_list:-(none)}"

  extra_n=0
  extra_list=""
  while IFS= read -r line; do
    extra_n=$((extra_n + 1))
    extra_list="${extra_list:+$extra_list }$line"
  done < "$LOGS/$id.extra.txt"
  say "ROW $id: extra $extra_n: ${extra_list:-(none)}"

  if [ "$missing_n" -gt 0 ] || [ "$extra_n" -gt 0 ]; then
    if [ "$status" -lt "$EXIT_BATTERY_RED" ]; then
      status=$EXIT_BATTERY_RED
    fi
  fi
  return "$status"
}

# row_extra <id> <label> (reads LOGS; writes no globals; no files under $LOGS): for M-NAIVE only, greps <label>'s test log for the pinned PASS line of test_AS40_shareConservation_guarded and prints its count, returning EXIT_BATTERY_RED if the count is not exactly 1; for every other <id> prints nothing and returns EXIT_PASS.
row_extra() {
  local id=$1
  local label=$2
  PHASE="row_extra $id"
  if [ "$id" != "M-NAIVE" ]; then
    return "$EXIT_PASS"
  fi
  local c
  c=$(grep -c -- '^\[PASS\] test_AS40_shareConservation_guarded(' "$LOGS/$label.test.log")
  say "ROW M-NAIVE: pinned pass test_AS40_shareConservation_guarded count=$c want 1"
  if [ "$c" -ne 1 ]; then
    return "$EXIT_BATTERY_RED"
  fi
  return "$EXIT_PASS"
}

# restore <id> (reads PRISTINE ARM LOGS N0 S0 K0; writes no globals; writes $LOGS/<id>.restore.rules.txt, $LOGS/<id>.restore.files.txt and $LOGS/<id>.restore.scope.txt, plus, through forge_build/forge_test, $LOGS/<id>.restore.*): copies the row's rules_table files back from PRISTINE over ARM (recomputed from rules_table, never ROW_FILES, which may be stale when make_arm failed), confirms the whole tree then diffs empty against PRISTINE, rebuilds and retests the arm, checks the post-restore counts against N0/S0/K0, prints one RESTORE-FAIL line per failed step and exactly one ROW line at the end (a dash for a value not measured); returns EXIT_UNDETERMINED if any RESTORE-FAIL was printed, else EXIT_PASS.
restore() {
  local id=$1
  PHASE="restore $id"
  local tbl row file op k old new files_list f rc
  local diff_rc diff_state
  local build_status test_status fail_seen
  local build_rc_out executed_out failed_out skipped_out suites_out

  fail_seen=0
  tbl="$LOGS/$id.restore.rules.txt"
  rules_table > "$tbl"
  files_list=""
  : > "$LOGS/$id.restore.files.txt"
  while IFS='@' read -r row file op k old new; do
    case "$row" in
      ''|'#'*) continue ;;
    esac
    if [ "$row" != "$id" ]; then
      continue
    fi
    case " $files_list " in
      *" $file "*) : ;;
      *)
        files_list="${files_list:+$files_list }$file"
        echo "$file" >> "$LOGS/$id.restore.files.txt"
        ;;
    esac
  done < "$tbl"

  while IFS= read -r f; do
    cp -- "$PRISTINE/$f" "$ARM/$f"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      say "RESTORE-FAIL: $id cp $f rc=$rc"
      fail_seen=1
    fi
  done < "$LOGS/$id.restore.files.txt"

  diff -r -q "$PRISTINE" "$ARM" > "$LOGS/$id.restore.scope.txt"
  diff_rc=$?
  if [ "$diff_rc" -eq 0 ]; then
    diff_state="empty"
  else
    diff_state="nonempty"
    say "RESTORE-FAIL: $id diff nonempty"
    fail_seen=1
  fi

  build_rc_out="-"
  executed_out="-"
  failed_out="-"
  skipped_out="-"
  suites_out="-"

  forge_build "$id.restore"
  build_status=$?
  if [ "$build_status" -eq "$EXIT_UNDETERMINED" ]; then
    say "RESTORE-FAIL: $id forge_build"
    fail_seen=1
  else
    build_rc_out=$BUILD_RC
    if [ "$BUILD_RC" -ne 0 ]; then
      say "RESTORE-FAIL: $id build rc=$BUILD_RC"
      fail_seen=1
    else
      forge_test "$id.restore"
      test_status=$?
      if [ "$test_status" -eq "$EXIT_UNDETERMINED" ]; then
        say "RESTORE-FAIL: $id parse"
        fail_seen=1
      else
        executed_out=$((10#$TEST_P + 10#$TEST_F))
        failed_out=$TEST_F
        skipped_out=$TEST_S
        suites_out=$TEST_K
        if [ "$executed_out" -ne "$((10#$N0))" ] || [ "$((10#$TEST_F))" -ne 0 ] || [ "$((10#$TEST_S))" -ne "$((10#$S0))" ] || [ "$((10#$TEST_K))" -ne "$((10#$K0))" ]; then
          say "RESTORE-FAIL: $id counts executed=$executed_out failed=$failed_out skipped=$skipped_out suites=$suites_out want $N0/0/$S0/$K0"
          fail_seen=1
        fi
      fi
    fi
  fi

  say "ROW $id: restore diff=$diff_state build rc=$build_rc_out executed=$executed_out failed=$failed_out skipped=$skipped_out"

  if [ "$fail_seen" -eq 1 ]; then
    return "$EXIT_UNDETERMINED"
  fi
  return "$EXIT_PASS"
}

# run_baseline (no args; reads PRISTINE ARM LOGS OVERREACH_SENTINEL EXIT_UNDETERMINED; writes $LOGS/baseline.scope.txt directly, plus (through make_arm, forge_build baseline and forge_test baseline) $LOGS/baseline.build.log, $LOGS/baseline.test.log, $LOGS/baseline.summary.txt, $LOGS/baseline.suites.txt, $LOGS/baseline.red.raw and $LOGS/baseline.red.txt; assigns N0, S0 and K0 on success): runs make_arm, forge_build and forge_test in order, stopping at the first failed step, then on a successful test run checks failed=0, an empty red set, an empty PRISTINE/ARM diff and a sentinel-pass count of 1, printing one BASELINE-INVALID line per problem (all four checks always run); any BASELINE-INVALID prints BASELINE: red <n>: <names> and calls finish EXIT_UNDETERMINED, otherwise prints BASELINE: OK and returns EXIT_PASS.
run_baseline() {
  PHASE=baseline
  local invalid rc n names line c
  invalid=0

  make_arm
  rc=$?
  if [ "$rc" -ne 0 ]; then
    say "BASELINE-INVALID: make_arm"
    invalid=1
  fi

  if [ "$invalid" -eq 0 ]; then
    forge_build baseline
    rc=$?
    if [ "$rc" -eq "$EXIT_UNDETERMINED" ]; then
      say "BASELINE-INVALID: forge_build"
      invalid=1
    else
      say "BASELINE: build rc=$BUILD_RC"
      if [ "$BUILD_RC" -ne 0 ]; then
        say "BASELINE-INVALID: build rc=$BUILD_RC"
        invalid=1
      fi
    fi
  fi

  if [ "$invalid" -eq 0 ]; then
    forge_test baseline
    rc=$?
    if [ "$rc" -eq "$EXIT_UNDETERMINED" ]; then
      say "BASELINE-INVALID: parse"
      invalid=1
    else
      say "BASELINE: test rc=$TEST_RC executed=$((10#$TEST_P + 10#$TEST_F)) passed=$TEST_P failed=$TEST_F skipped=$TEST_S suites=$TEST_K"
      if [ "$((10#$TEST_F))" -ne 0 ]; then
        say "BASELINE-INVALID: failed=$TEST_F"
        invalid=1
      fi
      if [ "$((10#$TEST_RED_N))" -ne 0 ]; then
        say "BASELINE-INVALID: red set not empty"
        invalid=1
      fi
      diff -r -q "$PRISTINE" "$ARM" > "$LOGS/baseline.scope.txt"
      rc=$?
      if [ "$rc" -ne 0 ]; then
        say "BASELINE-INVALID: diff nonempty"
        invalid=1
      fi
      c=$(grep -c "^\[PASS\] $OVERREACH_SENTINEL(" "$LOGS/baseline.test.log")
      if [ "$((10#$c))" -ne 1 ]; then
        say "BASELINE-INVALID: sentinel pass count=$c want 1"
        invalid=1
      fi
    fi
  fi

  if [ "$invalid" -ne 0 ]; then
    n=0
    names=""
    if [ -f "$LOGS/baseline.red.txt" ]; then
      while IFS= read -r line; do
        n=$((n + 1))
        names="${names:+$names }$line"
      done < "$LOGS/baseline.red.txt"
    fi
    say "BASELINE: red $n: ${names:-(none)}"
    finish "$EXIT_UNDETERMINED"
  fi

  N0=$((10#$TEST_P + 10#$TEST_F))
  S0=$TEST_S
  K0=$TEST_K
  say "BASELINE: OK"
  return "$EXIT_PASS"
}

# run_row <id> (reads LOGS N0 S0 K0 EXIT_UNDETERMINED; writes, through apply_rules/check_diff/check_post/forge_build/forge_test/red_names/restore, $LOGS/<id>.rules.txt, $LOGS/<id>.rule<i>.count, $LOGS/<id>.diff.<n>.txt, $LOGS/<id>.scope.txt, $LOGS/<id>.post.txt, $LOGS/<id>.build.log, $LOGS/<id>.test.log, $LOGS/<id>.summary.txt, $LOGS/<id>.suites.txt, $LOGS/<id>.red.raw, $LOGS/<id>.red.txt, $LOGS/<id>.expected.txt, $LOGS/<id>.expected.names.txt, $LOGS/<id>.missing.txt, $LOGS/<id>.extra.txt, $LOGS/<id>.restore.files.txt and $LOGS/<id>.restore.scope.txt, and appends one line to $LOGS/results.log; escalates ROW_CLASS through record_class): runs make_arm, then always apply_rules/check_diff/check_post, then forge_build and forge_test (stopping early on a make_arm, criterion-2, build or test failure), then the (4a) count-collapse and setup-name-prefix checks, then always check_overreach/check_prefix/compare_sets/row_extra when nothing earlier stopped the row, then always restore <id> regardless of what came before, then prints and logs RESULT <id>: <class>, resets ROW_CLASS and returns EXIT_PASS.
run_row() {
  local id=$1
  local proceed rc st n names line
  PHASE="row $id"
  ROW_CLASS=""
  record_class "MATCH"
  proceed=1

  make_arm
  rc=$?
  case "$rc" in
    3) record_class "NO-BIT" ;;
    4) record_class "UNDETERMINED" ;;
  esac
  if [ "$rc" -ne 0 ]; then
    proceed=0
  fi

  if [ "$proceed" -eq 1 ]; then
    st=0

    apply_rules "$id"
    rc=$?
    case "$rc" in
      3) record_class "NO-BIT" ;;
      4) record_class "UNDETERMINED" ;;
    esac
    if [ "$rc" -ne 0 ]; then
      st=1
    fi

    check_diff "$id"
    rc=$?
    case "$rc" in
      3) record_class "NO-BIT" ;;
      4) record_class "UNDETERMINED" ;;
    esac
    if [ "$rc" -ne 0 ]; then
      st=1
    fi

    check_post "$id"
    rc=$?
    case "$rc" in
      3) record_class "NO-BIT" ;;
      4) record_class "UNDETERMINED" ;;
    esac
    if [ "$rc" -ne 0 ]; then
      st=1
    fi

    if [ "$st" -ne 0 ]; then
      proceed=0
    fi
  fi

  if [ "$proceed" -eq 1 ]; then
    forge_build "$id"
    rc=$?
    if [ "$rc" -eq "$EXIT_UNDETERMINED" ]; then
      record_class "UNDETERMINED"
      proceed=0
    else
      say "ROW $id: build rc=$BUILD_RC"
      if [ "$BUILD_RC" -ne 0 ]; then
        say "MUTATION-INVALID: $id 编译不过,本条承载 0 bit"
        record_class "NO-BIT"
        proceed=0
      fi
    fi
  fi

  if [ "$proceed" -eq 1 ]; then
    forge_test "$id"
    rc=$?
    if [ "$rc" -eq "$EXIT_UNDETERMINED" ]; then
      record_class "UNDETERMINED"
      proceed=0
    else
      say "ROW $id: test rc=$TEST_RC executed=$((10#$TEST_P + 10#$TEST_F)) skipped=$TEST_S suites=$TEST_K (baseline $N0/$S0/$K0)"
      n=0
      names=""
      if [ -f "$LOGS/$id.red.txt" ]; then
        while IFS= read -r line; do
          n=$((n + 1))
          names="${names:+$names }$line"
        done < "$LOGS/$id.red.txt"
      fi
      say "ROW $id: red $n: ${names:-(none)}"
    fi
  fi

  if [ "$proceed" -eq 1 ]; then
    if [ "$((10#$TEST_P + 10#$TEST_F))" -ne "$N0" ] || [ "$TEST_S" != "$S0" ] || [ "$TEST_K" != "$K0" ]; then
      say "COUNT-COLLAPSE: $id executed=$((10#$TEST_P + 10#$TEST_F)) want $N0 skipped=$TEST_S want $S0 suites=$TEST_K want $K0"
      record_class "NO-BIT"
    fi
    if [ -f "$LOGS/$id.red.txt" ]; then
      while IFS= read -r line; do
        case "$line" in
          test*) : ;;
          *)
            say "SETUP-FAIL: $id $line"
            record_class "NO-BIT"
            ;;
        esac
      done < "$LOGS/$id.red.txt"
    fi
  fi

  if [ "$proceed" -eq 1 ]; then
    check_overreach "$id" "$id"
    rc=$?
    case "$rc" in
      3) record_class "NO-BIT" ;;
      4) record_class "UNDETERMINED" ;;
    esac

    check_prefix "$id" "$id"
    rc=$?
    case "$rc" in
      3) record_class "NO-BIT" ;;
      4) record_class "UNDETERMINED" ;;
    esac

    compare_sets "$id" "$id"
    rc=$?
    case "$rc" in
      1) record_class "MISMATCH" ;;
      4) record_class "UNDETERMINED" ;;
    esac

    row_extra "$id" "$id"
    rc=$?
    case "$rc" in
      1) record_class "MISMATCH" ;;
    esac
  fi

  restore "$id"
  rc=$?
  if [ "$rc" -eq "$EXIT_UNDETERMINED" ]; then
    record_class "UNDETERMINED"
  fi

  say "RESULT $id: $ROW_CLASS"
  printf '%s\n' "RESULT $id: $ROW_CLASS" >> "$LOGS/results.log"
  ROW_CLASS=""
  return "$EXIT_PASS"
}

# main

# Step 0: parse arguments (ONLY is set here, or the script exits via usage
# or a USAGE line), check every required external tool is on PATH and that
# this is bash 3.2 or newer, then print the two header lines that need no
# scratch state and scrub the environment (which prints its own
# "BATTERY: env unset: ..." line); nothing has been created on disk yet at
# this point, so every failure here exits directly instead of calling
# finish.
#
# KG-U7B-5(a)(b). rm, mkdir, tail, cat and sh are called by this script and
# were all missing from the loop: cat builds the four tables (rules, post,
# expected, excluded) from heredocs, and sh runs ./forge.sh for every row's
# build and test. The list was checked against a sweep of every word in
# command position, minus this script's own functions and the shell
# builtins; xargs is the one entry left without a caller, and it stays
# because an extra name only makes the check stricter.
#
# The tool check now runs before the first header line on purpose: that
# line's digest comes from sha_file, which runs shasum, so printing it
# first would turn a missing shasum into a blank digest instead of the
# BATTERY-ERROR this check exists to raise. The order of the header lines
# themselves is unchanged.
parse_args "$@"

for tool in perl shasum cp diff cmp find xargs mktemp sort sed grep dirname rm mkdir tail cat sh; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    say "BATTERY-ERROR: required tool not on PATH: $tool"
    exit "$EXIT_UNDETERMINED"
  fi
done
unset tool

bash_version_num=$(( (${BASH_VERSINFO[0]} * 100) + ${BASH_VERSINFO[1]} ))
if [ "$bash_version_num" -lt 302 ]; then
  say "BATTERY-ERROR: bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]} is older than 3.2"
  exit "$EXIT_UNDETERMINED"
fi
unset bash_version_num

say "BATTERY: script sha256 $(sha_file "$0")"
say "BATTERY: bash $BASH_VERSION"

scrub_env

# Step 1: build the scratch run area -- guards, refusals, RUN/WORK/LOGS,
# FOUNDRY_OUT/FOUNDRY_CACHE_PATH exported before any forge.sh call, and the
# HUP/INT/TERM traps installed.
setup_run

say "BATTERY: run dir $RUN"
if [ -n "$ONLY" ]; then
  say "BATTERY: rows $ONLY"
else
  say "BATTERY: rows $ROWS"
fi

# Step 2: the "before" worktree manifest; finish's own after-run check
# (Step 7) compares against this same file.
manifest_before_line=$(manifest "$SRC" "$LOGS/manifest.before")
manifest_before_rc=$?
if [ "$manifest_before_rc" -ne 0 ]; then
  say "BATTERY-ERROR: manifest before failed"
  finish "$EXIT_UNDETERMINED"
fi
set -- $manifest_before_line
say "WORKTREE: before sha256 $1 files $2"
unset manifest_before_line manifest_before_rc

# Step 3: a pristine scratch copy of SRC with the excluded files removed
# (copy_pristine calls finish 4 itself on any COPY-FIDELITY or
# EXCLUSION-FAILED), then a report of that exclusion.
copy_pristine
print_exclusions

# Step 4: validate the four tables against ROWS, AS_TOKEN_RE and the
# function names that actually exist in the pristine tree (validate_tables
# calls finish 4 itself on any TABLE-INVALID or TABLE-NAME-UNKNOWN).
validate_tables

# Step 5 -- criterion 1: the baseline. run_baseline calls finish 4 itself
# on any BASELINE-INVALID; on return N0/S0/K0 are set and "BASELINE: OK"
# has already been printed.
run_baseline

# Step 6: run every selected row, in ROWS order. run_row never calls
# finish; a row-level MISMATCH, NO-BIT or UNDETERMINED (raised through
# record_class) never stops the rows still to come, so the loop always
# runs every row it selected.
if [ -n "$ONLY" ]; then
  run_row "$ONLY"
else
  for row_id in $ROWS; do
    run_row "$row_id"
  done
  unset row_id
fi

# Step 7: the single exit point. finish prints the row SUMMARY (from
# $LOGS/results.log), the after-run worktree check (raising 5 on any
# change), the work-tree cleanup (raising 6 on a nonzero rc), the
# kept-LOGS line and the final EXIT line, then exits with the
# precedence-resolved $FINAL.
finish
