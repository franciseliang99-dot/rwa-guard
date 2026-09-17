#!/usr/bin/env bash
# build_parity.sh -- build-layer criteria for this contract tree.
#
# The file name is legacy and does not describe what this script checks. It asserts that there
# is only one build configuration; it does not assert that two builds produce identical
# artifacts. That second claim was judged unsound and was removed.
#
# AS-33b proves there is no second build configuration. It does not prove there is no test-only
# branch in the sources. AS-33a attacks that from the other side, and neither of the two
# replaces the original claim on its own.
#
# SG7-3 is the pin for SG-7 (3). It fires only when this script is run, and SG-7 is not closed
# by it.
#
# Nothing in the tree turns red if this script is never run: no build step, no test step and no
# other script calls it (KG-U8-1).
#
# usage: bash build_parity.sh [--self-test | --help]
#        ./forge.sh parity [--self-test | --help]
# exit:  0 PASS, 1 RED, 2 USAGE, 3 UNDETERMINED, 4 WORKTREE-CHANGED, 128+n INTERRUPTED.
#        The last line printed is always PARITY-EXIT: <code> <NAME>.
# needs: bash 3.2+, perl with JSON::PP and Encode, shasum, cast, and forge through ./forge.sh.

set -u
set -o pipefail
export LC_ALL=C
unset CDPATH GREP_OPTIONS

EXIT_PASS=0
EXIT_RED=1
EXIT_USAGE=2
EXIT_UNDETERMINED=3
EXIT_WORKTREE_CHANGED=4
EXIT_INT_HUP=129
EXIT_INT_INT=130
EXIT_INT_TERM=143
FINAL=""
PHASE=start
MODE=full
SKIP_ALL=""
SKIP_BUILD=""
BUILD_RC=""
PV="FOUNDRY_""PROFILE"
PF="--pro""file"
J_VERDICT=""
J_MEASURED=""
ST_FAILED=0

say() {
  printf '%s\n' "$*"
}

refuse() {
  PARITY_REFUSED=1
  say "PARITY-ERROR: $1"
  say "PARITY-EXIT: 3 UNDETERMINED"
  exit 3
}

usage() {
  say "usage: bash build_parity.sh [--self-test | --help]"
  say "       ./forge.sh parity [--self-test | --help]"
  say "  (no argument)  run every check against this tree"
  say "  --self-test    run the synthetic arms only; no forge, no cast"
  say "  --help         print this text; no check runs"
  say "exit: 0 pass, 1 red, 2 usage, 3 undetermined, 4 work tree changed, 128+n interrupted"
}

parse_args() {
  if [ $# -eq 0 ]; then
    MODE=full
  elif [ $# -eq 1 ] && [ "$1" = "--self-test" ]; then
    MODE=self
  elif [ $# -eq 1 ] && [ "$1" = "--help" ]; then
    usage
    say "PARITY-EXIT: 0 PASS"
    exit 0
  else
    say "PARITY-USAGE: unrecognized arguments: $*"
    say "PARITY-EXIT: 2 USAGE"
    exit 2
  fi
}

setup_run() {
  local bv
  bv=$(( ${BASH_VERSINFO[0]} * 100 + ${BASH_VERSINFO[1]} ))
  if [ "$bv" -lt 302 ]; then
    say "PARITY-ERROR: bash 3.2 or newer is required"
    say "PARITY-EXIT: 3 UNDETERMINED"
    exit 3
  fi
  parse_args "$@"
  if [ -L "$0" ]; then refuse "this script is a symlink"; fi
  SRC=$(cd "$(dirname "$0")" && pwd -P) || refuse "cannot resolve the script directory"
  : "${SRC:?}"
  cd "$SRC" || refuse "cannot enter the source tree"
  if [ -n "$(find "$SRC" -type l 2>/dev/null)" ]; then refuse "a symlink exists under the source tree"; fi
  if [ "$MODE" = full ] && [ ! -f test/Opcodes.t.sol ]; then refuse "test/Opcodes.t.sol is absent: the OP deliverable must be installed before the build-layer checks run"; fi
  BASE_TMP=${TMPDIR:-/tmp}
  : "${BASE_TMP:?}"
  base_real=$(cd "$BASE_TMP" 2>/dev/null && pwd -P)
  case "$base_real" in
    "$SRC"|"$SRC"/*) refuse "the scratch base resolves under the source tree" ;;
    "") refuse "the scratch base does not exist" ;;
  esac
  D=$(mktemp -d "${BASE_TMP%/}/rwa-guard-parity.XXXXXX") || refuse "mktemp could not create the scratch directory"
  : "${D:?}"
  case "$D" in
    "$SRC"|"$SRC"/*) refuse "the scratch directory resolves under the source tree" ;;
  esac
  mkdir -p -- "$D/prog" "$D/json" "$D/ctl" "$D/st" "$D/out" "$D/cache" || refuse "cannot create the scratch subdirectories"
  FOUNDRY_OUT="$D/out"; FOUNDRY_CACHE_PATH="$D/cache"; export FOUNDRY_OUT FOUNDRY_CACHE_PATH
  if ! command -v forge >/dev/null 2>&1 || ! command -v cast >/dev/null 2>&1; then
    if [ -n "${HOME-}" ] && [ -x "$HOME/.foundry/bin/forge" ]; then
      PATH="$HOME/.foundry/bin:$PATH"; export PATH
    fi
  fi
  trap 'on_signal HUP' HUP
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  trap 'on_exit' EXIT
  emit_progs
}

exit_rank() {
  case "$1" in
    129|130|143) printf '%s\n' 5 ;;
    4) printf '%s\n' 4 ;;
    3) printf '%s\n' 3 ;;
    1) printf '%s\n' 2 ;;
    0) printf '%s\n' 0 ;;
    *) printf '%s\n' -1 ;;
  esac
}
raise() {
  local code=$1
  if [ -z "$FINAL" ] || [ "$(exit_rank "$code")" -gt "$(exit_rank "$FINAL")" ]; then
    FINAL=$code
  fi
}

finish() {
  if [ -n "${FINISH_DONE:-}" ]; then exit "${FINAL:-$EXIT_PASS}"; fi
  FINISH_DONE=1
  PHASE=finish
  if [ $# -ge 1 ] && [ -n "$1" ]; then raise "$1"; fi
  if [ -n "${D:-}" ] && [ -d "$D" ]; then
    rm -rf -- "${D:?}" || { say "PARITY-ERROR: the scratch directory could not be removed"; raise "$EXIT_UNDETERMINED"; }
  fi
  : "${FINAL:=$EXIT_PASS}"
  case "$FINAL" in
    0) say "PARITY-EXIT: 0 PASS" ;;
    1) say "PARITY-EXIT: 1 RED" ;;
    3) say "PARITY-EXIT: 3 UNDETERMINED" ;;
    4) say "PARITY-EXIT: 4 WORKTREE-CHANGED" ;;
    129) say "PARITY-EXIT: 129 INTERRUPTED" ;;
    130) say "PARITY-EXIT: 130 INTERRUPTED" ;;
    143) say "PARITY-EXIT: 143 INTERRUPTED" ;;
    *) say "PARITY-EXIT: 3 UNDETERMINED" ; FINAL=$EXIT_UNDETERMINED ;;
  esac
  exit "$FINAL"
}
on_signal() {
  local name=$1 code
  case "$name" in
    HUP) code=$EXIT_INT_HUP ;;
    INT) code=$EXIT_INT_INT ;;
    *)   code=$EXIT_INT_TERM ;;
  esac
  say "PARITY-INTERRUPTED: $name during ${PHASE:-unknown}"
  raise "$code"
  finish
}
on_exit() {
  if [ -n "${FINISH_DONE:-}" ] || [ -n "${PARITY_REFUSED:-}" ]; then return; fi
  say "PARITY-ERROR: unexpected exit during ${PHASE:-unknown}"
  if [ -n "${D:-}" ] && [ -d "$D" ]; then rm -rf -- "${D:?}"; fi
  say "PARITY-EXIT: 3 UNDETERMINED"
  exit 3
}

verdict() {
  local id=$1 v=$2 crit=$3 m=$4
  m=$(printf '%s' "$m" | tr ' \t\n\r' '____')
  if [ -z "$m" ]; then m=none; fi
  case "$v" in
    PASS) ;;
    FAIL) raise "$EXIT_RED" ;;
    UNDETERMINED) raise "$EXIT_UNDETERMINED" ;;
    *) v=UNDETERMINED; m="badverdict:$m"; raise "$EXIT_UNDETERMINED" ;;
  esac
  say "PARITY: $id $v $crit measured=$m"
}

st_arm() {
  local label=$1 want=$2; shift 2
  J_VERDICT=""; J_MEASURED=""
  "$@"
  if [ "$J_VERDICT" = "$want" ]; then
    say "PARITY: ST-$label PASS self-test arm expects $want measured=$J_VERDICT:${J_MEASURED:-none}"
  else
    ST_FAILED=1
    raise "$EXIT_UNDETERMINED"
    say "PARITY: ST-$label UNDETERMINED self-test arm expects $want measured=$J_VERDICT:${J_MEASURED:-none}"
  fi
}

skip_check() {
  verdict "$1" UNDETERMINED "$2" "skipped:$3"
}

run_prog() {   # <name> <perl flags...> -- <input args...> ; sets R_OUT and R_RC
  local name=$1; shift
  local flags="" saw=0
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then saw=1; shift; break; fi
    flags="$flags $1"; shift
  done
  if [ "$saw" -eq 0 ]; then R_OUT=""; R_RC=90; return 0; fi
  R_OUT=$(perl $flags "$D/prog/$name.pl" "$@" 2>"$D/prog/$name.err"); R_RC=$?
}

sha_file() { local line; line=$(shasum -a 256 -- "$1") || return 1; printf '%s\n' "${line%% *}"; }
manifest() {
  local dir=$1 listfile=$2 scratch f count=0 h
  scratch="$listfile.files"
  : > "$listfile" || return 1
  ( cd "$dir" && find . -type f -print ) | sort > "$scratch" || { rm -f -- "$scratch"; return 1; }
  while IFS= read -r f; do
    h=$(sha_file "$dir/$f") || { rm -f -- "$scratch"; return 1; }
    count=$((count + 1))
    printf '%s  %s\n' "$h" "$f" >> "$listfile"
  done < "$scratch"
  rm -f -- "$scratch"
  printf '%s %s\n' "$(sha_file "$listfile")" "$count"
}

manifest_diff() {   # prints one changed relative path per line
  [ -f "$1" ] && [ -f "$2" ] || return 1
  perl -e 'my %a; for my $i (0,1) { open(my $h, "<", $ARGV[$i]) or exit 3; while (my $l = <$h>) { chomp $l; my ($d, $p) = split(/  /, $l, 2); next unless defined $p; $a{$p}[$i] = $d } close($h) } for my $p (sort keys %a) { my $x = $a{$p}[0]; my $y = $a{$p}[1]; print "$p\n" if !defined($x) || !defined($y) || $x ne $y }' "$1" "$2"
}

# ==== end part head ====
# ==== part progs ====

emit_progs() {
  prog_toml > "$D/prog/toml.pl"
  prog_layout > "$D/prog/layout.pl"
  prog_abisurf > "$D/prog/abisurf.pl"
  prog_abictx > "$D/prog/abictx.pl"
  prog_e3view > "$D/prog/e3view.pl"
  prog_e3lib > "$D/prog/e3lib.pl"
  prog_e3lib_expect > "$D/prog/e3lib.expect"
  prog_e3h > "$D/prog/e3h.pl"
  prog_e1 > "$D/prog/e1.pl"
  prog_art > "$D/prog/art.pl"
  prog_cei > "$D/prog/cei.pl"
  prog_closure > "$D/prog/closure.pl"
  prog_etch > "$D/prog/etch.pl"
  prog_needle > "$D/prog/needle.pl"
}

prog_toml() {
  cat <<'PL'
$t++ if /^\s*\[profile\./;
$d++ if /^\s*\[profile\.default\]\s*(#.*)?$/;
END { printf "%d %d\n", $t + 0, $d + 0 }
PL
}

prog_layout() {
  cat <<'PL'
use strict; use warnings; use JSON::PP;
my $f = shift;
my $t = eval { open(my $h, "<", $f) or die "open\n"; local $/; my $s = <$h>; close($h); JSON::PP->new->decode($s) };
if (!defined $t || ref($t) ne "HASH" || ref($t->{storage}) ne "ARRAY") { print "error\n"; exit 3 }
my $ty = $t->{types};
my $k = !defined($ty) ? 0 : (ref($ty) eq "HASH" ? scalar(keys %$ty) : -1);
if ($k < 0) { print "error\n"; exit 3 }
printf "storage:%d,types:%d\n", scalar(@{ $t->{storage} }), $k;
PL
}

prog_abisurf() {
  cat <<'PL'
use strict; use warnings; use JSON::PP;
my $f = shift;
my $a = eval { open(my $h, "<", $f) or die "open\n"; local $/; my $s = <$h>; close($h); JSON::PP->new->decode($s) };
if (!defined $a || ref($a) ne "ARRAY") { print "error\n"; exit 3 }
my ($n, $safe, $special, $upg, $ctor) = (0, 0, 0, 0, 0);
for my $e (@$a) {
  if (ref($e) ne "HASH" || !defined $e->{type}) { print "error\n"; exit 3 }
  $n++;
  my $t = $e->{type};
  my $nm = defined $e->{name} ? $e->{name} : "";
  $ctor++ if $t eq "constructor";
  $special++ if $t eq "constructor" || $t eq "receive" || $t eq "fallback";
  $safe++ if $t eq "function" && $nm eq "isSafeToTrade";
  $upg++ if $nm =~ /^(?:initiali[sz]e|upgradeTo|upgradeToAndCall|_authorizeUpgrade|proxiableUUID)$/;
}
printf "entries:%d,isSafeToTrade:%d,special:%d,upgrade:%d,ctor:%d\n", $n, $safe, $special, $upg, $ctor;
PL
}

prog_abictx() {
  cat <<'PL'
use strict; use warnings; use JSON::PP;
my $f = shift;
my $a = eval { open(my $h, "<", $f) or die "open\n"; local $/; my $s = <$h>; close($h); JSON::PP->new->decode($s) };
if (!defined $a || ref($a) ne "ARRAY") { print "error\n"; exit 3 }
my @fn = grep { ref($_) eq "HASH" && defined $_->{type} && $_->{type} eq "function" && defined $_->{name} && $_->{name} eq "isSafeToTrade" } @$a;
if (scalar(@fn) != 1) { print "got:none\n"; exit 1 }
my $in = $fn[0]{inputs};
if (ref($in) ne "ARRAY" || scalar(@$in) < 2 || ref($in->[1]{components}) ne "ARRAY") { print "got:none\n"; exit 1 }
my @g = map { (defined $_->{name} ? $_->{name} : "") . ":" . (defined $_->{type} ? $_->{type} : "") } @{ $in->[1]{components} };
print "got:", join(",", @g), "\n";
exit(join(",", @g) eq "priceFeed:address,actor:address,counterparty:address,expectedImpl:address,maxFeedAge:uint64" ? 0 : 1);
PL
}

prog_e3view() {
  cat <<'PL'
s{/\*.*?\*/}{}gs; s{//[^\n]*}{}g; my %c; $c{forbidden}=()=/\b(?:if|else|for|while|do|break|continue|require|revert|assert|try|catch|assembly|unchecked|modifier|receive|fallback|constructor|immutable|constant|payable|event|emit|error|mapping|new|delete|msg|tx|block|this|selfdestruct|delegatecall|call|staticcall|library|interface|abstract|is|using|public|internal|private|override|virtual|struct|enum)\b|\?|&&|\|\||!|==|<|>/g; $c{function}=()=/\bfunction\b/g; $c{contract}=()=/\bcontract\b/g; $c{external}=()=/\bexternal\b/g; $c{return}=()=/\breturn\b/g; $c{forward}=()=/\breturn\s+GuardCore\.evaluate\(\s*token\s*,\s*ctx\s*\)\s*;/g; $c{semicolon}=()=/;/g; $c{lbrace}=()=/\{/g; $c{rbrace}=()=/\}/g; print join(" ", map {"$_=$c{$_}"} sort keys %c), "\n";
PL
}

prog_e3lib() {
  cat <<'PL'
my %c; my %u; $c{rawBlockComment}=()=m{/\*}g; s{//[^\n]*}{}g; s{"[^"\n]*"}{""}g;
$c{semicolon}=tr/;//; $c{lbrace}=tr/{//; $c{rbrace}=tr/}//; $c{lparen}=tr/(//; $c{rparen}=tr/)//;
$c{comma}=tr/,//; $c{dot}=tr/.//; $c{bang}=tr/!//; $c{eq}=tr/=//;
$c{ifNotOk}=()=/\bif\s*\(\s*!\s*ok\s*\)\s*\{/g;
$c{forward}=()=/GuardCore\.evaluate\(\s*token\s*,\s*ctx\s*\)/g;
$c{returnForward}=()=/\breturn\s+GuardCore\.evaluate\(\s*token\s*,\s*ctx\s*\)\s*;/g;
$c{destructure}=()=/\(\s*bool\s+ok\s*,\s*uint256\s+reasonBits\s*\)\s*=\s*GuardCore\.evaluate/g;
$c{fnEnforce}=()=/function\s+enforce\s*\(\s*address\s+token\s*,\s*Ctx\s+memory\s+ctx\s*\)\s*internal\s+view\s*\{/g;
$c{fnCheck}=()=/function\s+check\s*\(\s*address\s+token\s*,\s*Ctx\s+memory\s+ctx\s*\)\s*internal\s+view\s+returns\s*\(\s*bool\s+ok\s*,\s*uint256\s+reasonBits\s*\)\s*\{/g;
$c{errorDecl}=()=/\berror\s+GuardBlocked\s*\(\s*address\s+token\s*,\s*uint256\s+reasonBits\s*\)\s*;/g;
my %ok=map{$_=>1} qw(pragma solidity import GuardCore from Ctx library RWAGuard error GuardBlocked address token uint256 reasonBits function enforce memory ctx internal view bool ok evaluate if revert check returns return);
for my $w (/\b([A-Za-z_]\w*)\b/g){ $c{"w_$w"}++; $u{$w}++ unless $ok{$w} }
$c{unknownWords}=scalar keys %u; $c{unknownChars}=()=/[^A-Za-z0-9_\s;{}(),.=!"]/g;
print "$_=$c{$_}\n" for sort keys %c; print "unknown: @{[sort keys %u]}\n";
PL
}

prog_e3lib_expect() {
  cat <<'PL'
bang=1
comma=8
destructure=1
dot=4
eq=1
errorDecl=1
fnCheck=1
fnEnforce=1
forward=2
ifNotOk=1
lbrace=6
lparen=9
rawBlockComment=0
rbrace=6
returnForward=1
rparen=9
semicolon=7
unknownChars=0
unknownWords=0
w_GuardBlocked=2
w_error=1
w_evaluate=2
w_function=2
w_if=1
w_import=2
w_internal=2
w_library=1
w_return=1
w_returns=1
w_revert=1
w_view=2
PL
}

prog_e3h() {
  cat <<'PL'
s{//[^\n]*}{}g;
/contract\s+RWAGuardHost\s*\{(.*?)\n\}/s or do { print "nohost\n"; exit 3 };
$_ = $1;
my %c;
$c{lbrace} = tr/{//; $c{rbrace} = tr/}//; $c{semicolon} = tr/;//;
$c{callEnforce} = () = /RWAGuard\.enforce\(\s*token\s*,\s*ctx\s*\)\s*;/g;
$c{returnCheck} = () = /\breturn\s+RWAGuard\.check\(\s*token\s*,\s*ctx\s*\)\s*;/g;
my %ok = map { $_ => 1 } qw(function enforce check address token Ctx calldata ctx external view returns bool ok uint256 reasonBits return RWAGuard);
my %u; for my $w (/\b([A-Za-z_]\w*)\b/g) { $u{$w}++ unless $ok{$w} }
$c{unknownWords} = scalar keys %u;
print join(" ", map { "$_=$c{$_}" } sort keys %c), "\n";
PL
}

prog_e1() {
  cat <<'PL'
if (/^\s*(?:(note|warning|error|help)\[([\w-]+)\]|(Warning|Error|warning|error)(?:\s*\(\d+\))?):/) { $h = defined $1 ? "$1\[$2\]" : $3; $want = 0; next }
if (/(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*src\/RWAGuard\.sol:(\d+)/) { $loc = $1; $locs++; $want = 1; next }
if ($want && /^\s*\d+\s*(?:\xE2\x94\x82|\|)\s?(.*)$/) { my $src = $1; $want = 0; $cls++;
  if (($h // "") eq "note[internal-function-used-once]" && $src =~ /^\s*function (enforce|check)\(address token, Ctx memory ctx\) internal view\b/) { $allow{$1}++ }
  else { $block++; print "BLOCK ", ($h // "noheader"), " line=$loc src=$src\n" } next }
END { printf "allowed_enforce=%d allowed_check=%d blocking=%d locs=%d cls=%d\n", $allow{enforce}+0, $allow{check}+0, $block+0, $locs+0, $cls+0 }
PL
}

prog_art() {
  cat <<'PL'
use strict; use warnings; use JSON::PP;
my ($ln, $lg, $an, $ag) = @ARGV;
my %J;
my $okload = eval {
  for my $f ($ln, $lg, $an, $ag) {
    open(my $h, "<", $f) or die "open\n"; local $/; my $s = <$h>; close($h);
    $J{$f} = JSON::PP->new->decode($s);
  } 1;
};
if (!$okload) { print "error\n"; exit 3 }
my $enc = JSON::PP->new->canonical(1);
sub lay {
  my ($f) = @_; my $t = $J{$f};
  if (ref($t) ne "HASH" || ref($t->{storage}) ne "ARRAY") { print "error\n"; exit 3 }
  my @rows;
  for my $s (@{ $t->{storage} }) {
    if (ref($s) ne "HASH" || !exists $s->{label} || !exists $s->{slot} || !exists $s->{offset} || !exists $s->{type}) { print "error\n"; exit 3 }
    push @rows, [ $s->{label}, $s->{slot}, $s->{offset}, $s->{type} ];
  }
  return $enc->encode(\@rows);
}
sub entries {
  my ($f) = @_; my $a = $J{$f};
  if (ref($a) ne "ARRAY") { print "error\n"; exit 3 }
  for my $e (@$a) { if (ref($e) ne "HASH" || !exists $e->{type}) { print "error\n"; exit 3 } }
  return $a;
}
sub abin {
  my ($f, $t) = @_;
  my @n = sort map { exists $_->{name} ? $_->{name} : "" } grep { $_->{type} eq $t } @{ entries($f) };
  return join(",", @n);
}
my $LN = lay($ln); my $LG = lay($lg);
my %F;
$F{layout_eq} = ($LN eq $LG) ? 1 : 0;
$F{layout_exp} = ($LN eq '[["shares","0",0,"t_mapping(t_address,t_uint256)"],["totalShares","1",0,"t_uint256"],["_lock","2",0,"t_uint256"]]') ? 1 : 0;
$F{abi_fns} = (abin($an, "function") eq "deposit,redeem,shares,token,totalShares"
            && abin($ag, "function") eq "deposit,expectedImpl,maxFeedAge,priceFeed,redeem,shares,token,totalShares") ? 1 : 0;
$F{abi_events} = (abin($an, "event") eq "Deposited,Redeemed" && abin($ag, "event") eq "Deposited,Redeemed") ? 1 : 0;
my $ERR5 = "InsufficientShares,NotAContract,ReentrantCall,TransferFailed,ZeroAmount";
my %gerr = map { $_ => 1 } split(/,/, abin($ag, "error"), -1);
my %allowed = map { $_ => 1 } (split(/,/, $ERR5), "GuardBlocked");
my $sub = 1; for my $k (split(/,/, $ERR5)) { $sub = 0 unless $gerr{$k} }
my $sup = 1; for my $k (keys %gerr) { $sup = 0 unless $allowed{$k} }
$F{abi_errors} = (abin($an, "error") eq $ERR5 && $sub && $sup) ? 1 : 0;
$F{abi_mutating} = 1;
for my $f ($an, $ag) {
  my @m;
  for my $e (@{ entries($f) }) {
    next unless $e->{type} eq "function";
    if (!exists $e->{stateMutability}) { print "error\n"; exit 3 }
    next unless $e->{stateMutability} eq "nonpayable" || $e->{stateMutability} eq "payable";
    if (!exists $e->{name}) { print "error\n"; exit 3 }
    push @m, $e->{name};
  }
  $F{abi_mutating} = 0 unless join(",", sort @m) eq "deposit,redeem";
}
$F{abi_nopay} = 1;
for my $f ($an, $ag) {
  for my $e (@{ entries($f) }) {
    $F{abi_nopay} = 0 if (exists $e->{stateMutability} && $e->{stateMutability} eq "payable");
    $F{abi_nopay} = 0 if ($e->{type} eq "fallback" || $e->{type} eq "receive");
  }
}
my $PRIV = qr/^(?i:owner|admin|pause|unpause|upgrade|sweep|withdraw|emergency|rescue|grant|revoke|renounce|transferownership|set|initiali[sz]e|kill|destroy|migrate|mint|burn)/;
my $hits = 0;
for my $f ($an, $ag) { for my $x (split(/,/, abin($f, "function"), -1)) { $hits++ if $x =~ $PRIV } }
$F{shape_hits0} = ($hits == 0) ? 1 : 0;
my $ctl = 0;
for my $x (qw(owner admin pause unpause transferOwnership renounceOwnership upgradeTo upgradeToAndCall sweep withdraw)) { $ctl++ if $x =~ $PRIV }
$F{shape_ctl10} = ($ctl == 10) ? 1 : 0;
print join(" ", map { "$_=$F{$_}" } sort keys %F), "\n";
my $all = 1; for my $k (keys %F) { $all = 0 unless $F{$k} }
exit($all ? 0 : 1);
PL
}

prog_cei() {
  cat <<'PL'
use strict; use warnings; use Encode;
my ($pn, $pg) = @ARGV;
sub slurp {
  my ($p) = @_;
  open(my $h, "<:raw", $p) or do { print "error\n"; exit 3 };
  local $/; my $b = <$h>; close($h);
  my $t = eval { Encode::decode("UTF-8", $b, Encode::FB_CROAK) };
  if (!defined $t) { print "error\n"; exit 3 }
  $t =~ s/\r\n?/\n/g;
  return $t;
}
sub bodies {
  my ($p) = @_;
  my @L = split(/\n/, slurp($p), -1);
  my %out; my $i = 0;
  while ($i < scalar(@L)) {
    if ($L[$i] =~ /^    function (deposit|redeem)\(.*\{$/) {
      my $name = $1; my $j = $i + 1; my @b;
      while ($j < scalar(@L) && $L[$j] ne "    }") { push @b, $L[$j]; $j++ }
      $out{$name} = [ $L[$i], \@b ];
      $i = $j;
    }
    $i++;
  }
  return \%out;
}
sub L { my ($r) = @_; return scalar(@$r) . "\x00" . join("\n", @$r) }
my $N = bodies($pn); my $G = bodies($pg);
my $ok = 1;
$ok = 0 unless join(",", sort keys %$N) eq "deposit,redeem" && join(",", sort keys %$G) eq "deposit,redeem";
if (!$ok) { print "cei_ok=0\n"; exit 1 }
for my $d ($N, $G) {
  for my $k (keys %$d) {
    for my $s (@{ $d->{$k}[1] }) {
      $ok = 0 unless $s =~ /^        \S.*;$/ && index($s, "//") < 0;
    }
  }
}
$ok = 0 unless $N->{deposit}[0] eq $G->{deposit}[0] && L($N->{deposit}[1]) eq L($G->{deposit}[1]);
$ok = 0 unless $N->{redeem}[0] eq $G->{redeem}[0];
my @g = @{ $G->{redeem}[1] };
if (scalar(@g) == 0) { print "cei_ok=0\n"; exit 1 }
my @gtail = @g[1 .. $#g];
$ok = 0 unless L(\@gtail) eq L($N->{redeem}[1]);
$ok = 0 unless index($g[0], "        RWAGuard.enforce(token, Ctx({") == 0;
my @nd = @{ $N->{deposit}[1] };
if (scalar(@nd) == 0) { print "cei_ok=0\n"; exit 1 }
for my $pair ([ \@g, "        _safeTransfer(token, msg.sender, amountOut);" ], [ \@nd, "        _safeTransferFrom(token, msg.sender, address(this), amount);" ]) {
  my ($b, $last) = @$pair;
  $ok = 0 unless $b->[-1] eq $last;
  my $c = 0; for my $s (@$b) { $c++ if index($s, "_safeTransfer") >= 0 }
  $ok = 0 unless $c == 1;
  for my $k (0 .. $#$b) {
    next unless $b->[$k] =~ /^        (?:shares\[msg\.sender\] (?:\+)?=|totalShares [+-]=|emit )/;
    $ok = 0 unless $k < scalar(@$b) - 1;
  }
}
my @idx; for my $k (0 .. $#g) { push @idx, $k if $g[$k] =~ /^        (?:shares\[msg\.sender\] =|totalShares -=)/ }
$ok = 0 unless join(",", @idx) eq "5,6";
print "cei_ok=", ($ok ? 1 : 0), "\n";
exit($ok ? 0 : 1);
PL
}

prog_closure() {
  cat <<'PL'
my $opc = shift @ARGV;
open(my $h, "<", $opc) or do { print "error\n"; exit 3 };
my @L = <$h>; close($h);
my ($b, $e, $bi, $ei) = (0, 0, -1, -1);
for my $k (0 .. $#L) {
  if ($L[$k] =~ /^\s*\/\/ AS-33a population begin\s*$/) { $b++; $bi = $k }
  if ($L[$k] =~ /^\s*\/\/ AS-33a population end\s*$/)   { $e++; $ei = $k }
}
if ($b != 1 || $e != 1 || $bi > $ei) { print "markers:$b,$e\n"; exit 3 }
my %pop;
for my $k ($bi + 1 .. $ei - 1) { while ($L[$k] =~ /"[A-Za-z0-9_.\/-]*\.sol:([A-Za-z_][A-Za-z0-9_]*)"/g) { $pop{$1} = 1 } }
my %code;
for my $f (@ARGV) {
  open(my $g, "<", $f) or do { print "error\n"; exit 3 };
  while (my $l = <$g>) { $code{$1} = 1 if $l =~ /^contract\s+(\w+)/ }
  close($g);
}
my @missing = grep { !$pop{$_} } sort keys %code;
my @extra   = grep { !$code{$_} } sort keys %pop;
printf "missing:%s;extra:%s\n", (scalar(@missing) ? join(",", @missing) : "none"), (scalar(@extra) ? join(",", @extra) : "none");
exit((scalar(@missing) || scalar(@extra)) ? 1 : 0);
PL
}

prog_etch() {
  cat <<'PL'
my %allow = map { $_ => 1 } ("_loadProxyRuntime()", "_loadFixtureRuntime()", "runtime", "address(new MockEquityToken()).code", "address(new MockControlPlane()).code", "\"\"", "new bytes(0)");
while (/vm\.etch\(\s*(.*?)\s*,\s*(.*?)\);/gs) { $sites++; $unknown++ unless $allow{$2} }
END { printf "sites:%d,unknown:%d\n", $sites + 0, $unknown + 0 }
PL
}

prog_needle() {
  cat <<'PL'
my ($n, $f) = @ARGV; open(my $h, "<", $f) or exit 3; local $/; my $t = <$h>; my $c = () = $t =~ /\Q$n\E/g; print "$c\n";
PL
}
# ==== end part progs ====
# ==== part judges-a ====

run_build() {
  PHASE=build
  sh ./forge.sh build --force > "$D/build.log" 2>&1
  BUILD_RC=$?
  if [ "$BUILD_RC" -ne 0 ]; then
    say "PARITY-ERROR: the build failed rc=$BUILD_RC"
    SKIP_BUILD="build-rc:$BUILD_RC"
  fi
}

inspect_json() {   # <key> <path:Name> <field>
  sh ./forge.sh inspect "$2" "$3" --json > "$D/json/$1.json" 2> "$D/json/$1.err"
  printf '%s\n' "$?" > "$D/json/$1.rc"
}

# BP2.9: one inspect per storageLayout key and per abi key, run once each.
collect_json() {
  inspect_json lay_view src/RWAGuardView.sol:RWAGuardView storageLayout
  inspect_json lay_core src/GuardCore.sol:GuardCore storageLayout
  inspect_json lay_lib src/RWAGuard.sol:RWAGuard storageLayout
  inspect_json lay_bits src/GuardBits.sol:GuardBits storageLayout
  inspect_json lay_vb src/demo/VaultBase.sol:VaultBase storageLayout
  inspect_json lay_nv src/demo/NaiveVault.sol:NaiveVault storageLayout
  inspect_json lay_gv src/demo/GuardedVault.sol:GuardedVault storageLayout
  inspect_json abi_view src/RWAGuardView.sol:RWAGuardView abi
  inspect_json abi_feed test/mocks/MockPriceFeed.sol:MockPriceFeed abi
  inspect_json abi_nv src/demo/NaiveVault.sol:NaiveVault abi
  inspect_json abi_gv src/demo/GuardedVault.sol:GuardedVault abi
}

# ---- 1. TOOLS ----

judge_tools_list() {   # <comma-joined missing names, or empty>
  local missing=$1
  if [ -z "$missing" ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=UNDETERMINED
  fi
  J_MEASURED="missing:${missing:-none}"
}

check_tools() {
  local crit="every required tool resolves and perl loads JSON::PP and Encode"
  local missing="" t
  for t in perl shasum find sort mktemp cmp wc tr rm mkdir dirname cat sh; do
    command -v "$t" >/dev/null 2>&1 || missing="${missing:+$missing,}$t"
  done
  [ -x /usr/bin/grep ] || missing="${missing:+$missing,}grep"
  perl -MJSON::PP -e 1 >/dev/null 2>&1 || missing="${missing:+$missing,}JSON::PP"
  perl -MEncode -e 1 >/dev/null 2>&1 || missing="${missing:+$missing,}Encode"
  if [ "$MODE" = full ]; then
    command -v forge >/dev/null 2>&1 || missing="${missing:+$missing,}forge"
    command -v cast >/dev/null 2>&1 || missing="${missing:+$missing,}cast"
  fi
  if perl -MNoSuchModule::Absent -e 1 >/dev/null 2>&1; then
    SKIP_ALL=tools
    verdict "TOOLS" UNDETERMINED "$crit" "control:module-probe"
    return
  fi
  judge_tools_list "$missing"
  if [ "$J_VERDICT" != PASS ]; then SKIP_ALL=tools; fi
  verdict "TOOLS" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 2. AS33b-1 ----

judge_as33b1() {   # <t> <d>
  local t=$1 d=$2
  if [ "$t" -eq 1 ] && [ "$d" -eq 1 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED=$((t - d))
}

check_as33b1() {
  local crit="profile sections other than profile.default in foundry.toml"
  if [ -n "$SKIP_ALL" ]; then skip_check "AS33b-1" "$crit" "$SKIP_ALL"; return; fi
  if [ ! -f foundry.toml ]; then
    verdict "AS33b-1" UNDETERMINED "$crit" "missing:foundry.toml"
    return
  fi
  run_prog toml -n -- foundry.toml
  local t d
  set -- $R_OUT
  t=${1:-}
  d=${2:-}
  if [ "$R_RC" -ne 0 ] || [ -z "$t" ] || [ -z "$d" ]; then
    verdict "AS33b-1" UNDETERMINED "$crit" "missing:foundry.toml"
    return
  fi
  case "$t" in ''|*[!0-9]*) verdict "AS33b-1" UNDETERMINED "$crit" "missing:foundry.toml"; return ;; esac
  case "$d" in ''|*[!0-9]*) verdict "AS33b-1" UNDETERMINED "$crit" "missing:foundry.toml"; return ;; esac
  judge_as33b1 "$t" "$d"
  verdict "AS33b-1" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 3. AS33b-2 ----

judge_as33b2() {   # <needle count in one file>
  local n=$1
  if [ "$n" -eq 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="count:$n"
}

check_as33b2() {
  local crit="occurrences of the profile variable and the long profile flag in forge.sh and build_parity.sh"
  if [ -n "$SKIP_ALL" ]; then skip_check "AS33b-2" "$crit" "$SKIP_ALL"; return; fi
  local envset=0
  if perl -e 'exit((exists $ENV{$ARGV[0]}) ? 0 : 1)' "$PV"; then envset=1; fi
  local names n unset_list=""
  names=$(perl -e 'print join(" ", sort grep { /^(?:FOUNDRY|DAPP)_/ } keys %ENV), "\n"')
  for n in $names; do
    case "$n" in
      FOUNDRY_OUT|FOUNDRY_CACHE_PATH) ;;
      *) unset_list="${unset_list:+$unset_list }$n"; unset "$n" ;;
    esac
  done
  if [ -n "$unset_list" ]; then
    say "PARITY-ENV: unset $unset_list"
  else
    say "PARITY-ENV: unset (none)"
  fi
  if [ "$envset" -eq 1 ]; then
    verdict "AS33b-2" UNDETERMINED "$crit" "env:set"
    return
  fi
  if [ ! -f forge.sh ] || [ ! -f build_parity.sh ]; then
    verdict "AS33b-2" UNDETERMINED "$crit" "read:error"
    return
  fi
  run_prog needle -- "$PV" forge.sh
  local a1=$R_OUT a1rc=$R_RC
  run_prog needle -- "$PF" forge.sh
  local a2=$R_OUT a2rc=$R_RC
  run_prog needle -- "$PV" build_parity.sh
  local b1=$R_OUT b1rc=$R_RC
  run_prog needle -- "$PF" build_parity.sh
  local b2=$R_OUT b2rc=$R_RC
  case "$a1$a2$b1$b2" in *[!0-9]*|'') verdict "AS33b-2" UNDETERMINED "$crit" "read:error"; return ;; esac
  if [ "$a1rc" -ne 0 ] || [ "$a2rc" -ne 0 ] || [ "$b1rc" -ne 0 ] || [ "$b2rc" -ne 0 ]; then
    verdict "AS33b-2" UNDETERMINED "$crit" "read:error"
    return
  fi
  local a=$((a1 + a2)) b=$((b1 + b2))
  judge_as33b2 "$a"; local va=$J_VERDICT
  judge_as33b2 "$b"; local vb=$J_VERDICT
  local v=PASS
  if [ "$va" != PASS ] || [ "$vb" != PASS ]; then v=FAIL; fi
  verdict "AS33b-2" "$v" "$crit" "forge.sh:$a,build_parity.sh:$b"
}

# ---- 4. AS33b-3 ----

judge_as33b3() {   # <n>
  local n=$1
  if [ "$n" -eq 1 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="$n"
}

check_as33b3() {
  local crit="foundry.toml files under the source tree"
  if [ -n "$SKIP_ALL" ]; then skip_check "AS33b-3" "$crit" "$SKIP_ALL"; return; fi
  local n rc
  n=$( ( cd "$SRC" && find . -name foundry.toml -type f -print ) | perl -ne '$n++; END { print $n + 0, "\n" }' )
  rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ] || [ -z "$n" ]; then
    verdict "AS33b-3" UNDETERMINED "$crit" "find:error"
    return
  fi
  judge_as33b3 "$n"
  verdict "AS33b-3" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 5. SG7-3 (A4) ----

judge_sg73() {   # <version-line-count> <version> <base7>
  local vcount=$1 v=$2 b=$3
  if [ "$vcount" -ne 1 ]; then
    J_VERDICT=UNDETERMINED
    J_MEASURED="forge:unparsed"
    return
  fi
  if [ -z "$b" ]; then
    J_VERDICT=UNDETERMINED
    J_MEASURED="base7:none"
    return
  fi
  if [ "$v" = "1.8.1" ] && [ "$b" = "1" ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="forge:$v,base7:$b"
}

check_sg73() {
  local crit="forge version equals the pinned 1.8.1 and test/Base.sol line 7 names 1.8.1"
  if [ -n "$SKIP_ALL" ]; then skip_check "SG7-3" "$crit" "$SKIP_ALL"; return; fi
  sh ./forge.sh --version > "$D/version.txt" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    verdict "SG7-3" UNDETERMINED "$crit" "forge-rc:$rc"
    return
  fi
  local vout vcount v
  vout=$(perl -ne 'print "$1\n" if /^forge\b.*?(\d+\.\d+\.\d+)/' "$D/version.txt")
  vcount=0
  v=""
  if [ -n "$vout" ]; then
    while IFS= read -r _line; do
      vcount=$((vcount + 1))
      v=$_line
    done < <(printf '%s\n' "$vout")
  fi
  local b7=""
  if [ -f test/Base.sol ]; then
    b7=$(perl -ne 'if ($. == 7) { print((/(?<!\d)1\.8\.1(?!\d)/) ? "1\n" : "0\n"); exit } END { }' test/Base.sol)
  fi
  judge_sg73 "$vcount" "$v" "$b7"
  verdict "SG7-3" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 6. AS32a ----

judge_as32a() {   # <storage> <types>
  local s=$1 t=$2
  case "$s" in ''|*[!0-9]*)
    J_VERDICT=UNDETERMINED
    J_MEASURED="storage:$s,types:$t"
    return
    ;;
  esac
  case "$t" in ''|*[!0-9]*)
    J_VERDICT=UNDETERMINED
    J_MEASURED="storage:$s,types:$t"
    return
    ;;
  esac
  if [ "$s" -eq 0 ] && [ "$t" -eq 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="storage:$s,types:$t"
}

as32a_run() {   # <jsonkey> ; sets AS32A_STORAGE AS32A_TYPES AS32A_STATE
  local key=$1 rc
  AS32A_STATE=""
  if [ ! -f "$D/json/$key.rc" ] || [ ! -f "$D/json/$key.json" ]; then AS32A_STATE="inspect-rc:unknown"; return; fi
  rc=$(cat "$D/json/$key.rc")
  if [ "$rc" -ne 0 ]; then AS32A_STATE="inspect-rc:$rc"; return; fi
  run_prog layout -- "$D/json/$key.json"
  if [ "$R_RC" -ne 0 ] || [ -z "$R_OUT" ]; then AS32A_STATE="decode:error"; return; fi
  case "$R_OUT" in storage:*,types:*) ;; *) AS32A_STATE="decode:error"; return ;; esac
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  AS32A_STORAGE=$1
  AS32A_TYPES=$2
  AS32A_STATE=ok
}

check_as32a() {
  local crit1="storage layout of src/RWAGuardView.sol:RWAGuardView is empty"
  local crit2="storage layout of src/GuardCore.sol:GuardCore is empty"
  local crit3="storage layout of src/RWAGuard.sol:RWAGuard is empty"
  local crit4="storage layout of src/GuardBits.sol:GuardBits is empty"
  if [ -n "$SKIP_ALL" ]; then
    skip_check "AS32a" "$crit1" "$SKIP_ALL"
    skip_check "AS32a" "$crit2" "$SKIP_ALL"
    skip_check "AS32a" "$crit3" "$SKIP_ALL"
    skip_check "AS32a" "$crit4" "$SKIP_ALL"
    return
  fi
  if [ -n "$SKIP_BUILD" ]; then
    skip_check "AS32a" "$crit1" "$SKIP_BUILD"
    skip_check "AS32a" "$crit2" "$SKIP_BUILD"
    skip_check "AS32a" "$crit3" "$SKIP_BUILD"
    skip_check "AS32a" "$crit4" "$SKIP_BUILD"
    return
  fi
  as32a_run lay_vb
  if [ "$AS32A_STATE" != ok ] || [ "$AS32A_STORAGE" -lt 1 ]; then
    local n=${AS32A_STORAGE:-0}
    verdict "AS32a" UNDETERMINED "$crit1" "control:vaultbase-storage:$n"
    verdict "AS32a" UNDETERMINED "$crit2" "control:vaultbase-storage:$n"
    verdict "AS32a" UNDETERMINED "$crit3" "control:vaultbase-storage:$n"
    verdict "AS32a" UNDETERMINED "$crit4" "control:vaultbase-storage:$n"
    return
  fi
  as32a_run lay_view
  if [ "$AS32A_STATE" = ok ]; then judge_as32a "$AS32A_STORAGE" "$AS32A_TYPES"; verdict "AS32a" "$J_VERDICT" "$crit1" "$J_MEASURED"
  else verdict "AS32a" UNDETERMINED "$crit1" "$AS32A_STATE"; fi
  as32a_run lay_core
  if [ "$AS32A_STATE" = ok ]; then judge_as32a "$AS32A_STORAGE" "$AS32A_TYPES"; verdict "AS32a" "$J_VERDICT" "$crit2" "$J_MEASURED"
  else verdict "AS32a" UNDETERMINED "$crit2" "$AS32A_STATE"; fi
  as32a_run lay_lib
  if [ "$AS32A_STATE" = ok ]; then judge_as32a "$AS32A_STORAGE" "$AS32A_TYPES"; verdict "AS32a" "$J_VERDICT" "$crit3" "$J_MEASURED"
  else verdict "AS32a" UNDETERMINED "$crit3" "$AS32A_STATE"; fi
  as32a_run lay_bits
  if [ "$AS32A_STATE" = ok ]; then judge_as32a "$AS32A_STORAGE" "$AS32A_TYPES"; verdict "AS32a" "$J_VERDICT" "$crit4" "$J_MEASURED"
  else verdict "AS32a" UNDETERMINED "$crit4" "$AS32A_STATE"; fi
}

# ---- 7. ABI-SURFACE ----

judge_abisurf() {   # <entries> <isSafeToTrade> <special> <upgrade>
  local e=$1 s=$2 sp=$3 u=$4
  if [ "$e" -eq 1 ] && [ "$s" -eq 1 ] && [ "$sp" -eq 0 ] && [ "$u" -eq 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="entries:$e,isSafeToTrade:$s,special:$sp,upgrade:$u"
}

abisurf_run() {   # <jsonkey> ; sets AB_ENTRIES AB_SAFE AB_SPECIAL AB_UPGRADE AB_CTOR AB_STATE
  local key=$1 rc
  AB_STATE=""
  if [ ! -f "$D/json/$key.rc" ] || [ ! -f "$D/json/$key.json" ]; then AB_STATE="inspect-rc:unknown"; return; fi
  rc=$(cat "$D/json/$key.rc")
  if [ "$rc" -ne 0 ]; then AB_STATE="inspect-rc:$rc"; return; fi
  run_prog abisurf -- "$D/json/$key.json"
  if [ "$R_RC" -ne 0 ] || [ -z "$R_OUT" ]; then AB_STATE="decode:error"; return; fi
  case "$R_OUT" in entries:*,isSafeToTrade:*,special:*,upgrade:*,ctor:*) ;; *) AB_STATE="decode:error"; return ;; esac
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  AB_ENTRIES=$1
  AB_SAFE=$2
  AB_SPECIAL=$3
  AB_UPGRADE=$4
  AB_CTOR=$5
  AB_STATE=ok
}

check_abisurf() {
  local crit="abi of src/RWAGuardView.sol:RWAGuardView is exactly isSafeToTrade with no constructor, receive, fallback or upgrade entry"
  if [ -n "$SKIP_ALL" ]; then skip_check "ABI-SURFACE" "$crit" "$SKIP_ALL"; return; fi
  if [ -n "$SKIP_BUILD" ]; then skip_check "ABI-SURFACE" "$crit" "$SKIP_BUILD"; return; fi
  abisurf_run abi_view
  if [ "$AB_STATE" != ok ]; then verdict "ABI-SURFACE" UNDETERMINED "$crit" "$AB_STATE"; return; fi
  local ve=$AB_ENTRIES vs=$AB_SAFE vsp=$AB_SPECIAL vu=$AB_UPGRADE
  abisurf_run abi_feed
  if [ "$AB_STATE" != ok ] || [ "$AB_ENTRIES" -le 1 ]; then
    verdict "ABI-SURFACE" UNDETERMINED "$crit" "control:feed:${AB_ENTRIES:-0},gvctor:0"
    return
  fi
  local feedn=$AB_ENTRIES
  abisurf_run abi_gv
  if [ "$AB_STATE" != ok ] || [ "$AB_CTOR" -lt 1 ]; then
    verdict "ABI-SURFACE" UNDETERMINED "$crit" "control:feed:$feedn,gvctor:${AB_CTOR:-0}"
    return
  fi
  judge_abisurf "$ve" "$vs" "$vsp" "$vu"
  verdict "ABI-SURFACE" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 8. ABI-CTX ----

judge_abictx() {   # <rc> <payload>
  local rc=$1 payload=$2
  if [ "$rc" -eq 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="$payload"
}

check_abictx() {
  local crit="the Ctx components of isSafeToTrade are priceFeed, actor, counterparty and expectedImpl as address then maxFeedAge as uint64"
  if [ -n "$SKIP_ALL" ]; then skip_check "ABI-CTX" "$crit" "$SKIP_ALL"; return; fi
  if [ -n "$SKIP_BUILD" ]; then skip_check "ABI-CTX" "$crit" "$SKIP_BUILD"; return; fi
  if [ ! -f "$D/json/abi_view.rc" ] || [ ! -f "$D/json/abi_view.json" ]; then
    verdict "ABI-CTX" UNDETERMINED "$crit" "inspect-rc:unknown"
    return
  fi
  local irc
  irc=$(cat "$D/json/abi_view.rc")
  if [ "$irc" -ne 0 ]; then verdict "ABI-CTX" UNDETERMINED "$crit" "inspect-rc:$irc"; return; fi
  run_prog abictx -- "$D/json/abi_view.json"
  local mainrc=$R_RC mainout=$R_OUT
  case "$mainrc" in 0|1) ;; *) verdict "ABI-CTX" UNDETERMINED "$crit" "decode:error"; return ;; esac
  case "$mainout" in got:*) ;; *) verdict "ABI-CTX" UNDETERMINED "$crit" "decode:error"; return ;; esac
  local payload=${mainout#got:}
  perl -pe 's/"priceFeed"/"TMPX"/g; s/"expectedImpl"/"priceFeed"/g; s/"TMPX"/"expectedImpl"/g' "$D/json/abi_view.json" > "$D/ctl/abi_ctx_swapped.json"
  if cmp -s "$D/json/abi_view.json" "$D/ctl/abi_ctx_swapped.json"; then
    verdict "ABI-CTX" UNDETERMINED "$crit" "control:swap"
    return
  fi
  run_prog abictx -- "$D/ctl/abi_ctx_swapped.json"
  if [ "$R_RC" -eq 0 ]; then
    verdict "ABI-CTX" UNDETERMINED "$crit" "control:swap"
    return
  fi
  judge_abictx "$mainrc" "$payload"
  verdict "ABI-CTX" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 9. E3-VIEW ----

judge_e3view() {   # <space-joined counters> <blockopen>
  local j=$1 bo=$2 m
  if [ "$j" = "contract=1 external=1 forbidden=0 forward=1 function=1 lbrace=4 rbrace=4 return=1 semicolon=4" ] && [ "$bo" -eq 0 ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=FAIL
  fi
  m=$(printf '%s' "$j" | tr ' ' ',')
  J_MEASURED="${m},blockopen:${bo}"
}

check_e3view() {
  local crit="src/RWAGuardView.sol is the thin shell"
  if [ -n "$SKIP_ALL" ]; then skip_check "E3-VIEW" "$crit" "$SKIP_ALL"; return; fi
  if [ ! -f src/RWAGuardView.sol ]; then verdict "E3-VIEW" UNDETERMINED "$crit" "output:short"; return; fi
  run_prog e3view -0777 -n -- src/RWAGuardView.sol
  local viewout=$R_OUT viewrc=$R_RC
  if [ "$viewrc" -ne 0 ] || [ -z "$viewout" ]; then verdict "E3-VIEW" UNDETERMINED "$crit" "output:short"; return; fi
  local blockopen
  blockopen=$(perl -0777 -ne '$n = () = /\/\*/g; print "$n\n"' src/RWAGuardView.sol)
  case "$blockopen" in ''|*[!0-9]*) verdict "E3-VIEW" UNDETERMINED "$crit" "output:short"; return ;; esac
  if [ ! -f src/GuardCore.sol ]; then verdict "E3-VIEW" UNDETERMINED "$crit" "control:guardcore"; return; fi
  run_prog e3view -0777 -n -- src/GuardCore.sol
  local ctlout=$R_OUT ctlrc=$R_RC
  if [ "$ctlrc" -ne 0 ] || [ -z "$ctlout" ]; then verdict "E3-VIEW" UNDETERMINED "$crit" "control:guardcore"; return; fi
  local ctl_forbidden ctl_function
  ctl_forbidden=$(printf '%s\n' "$ctlout" | perl -ne 'print $1 if /forbidden=(\d+)/')
  ctl_function=$(printf '%s\n' "$ctlout" | perl -ne 'print $1 if /function=(\d+)/')
  case "$ctl_forbidden" in ''|*[!0-9]*) verdict "E3-VIEW" UNDETERMINED "$crit" "control:guardcore"; return ;; esac
  if [ "$ctl_forbidden" -lt 1 ] || [ "$ctl_function" = "1" ]; then
    verdict "E3-VIEW" UNDETERMINED "$crit" "control:guardcore"
    return
  fi
  judge_e3view "$viewout" "$blockopen"
  verdict "E3-VIEW" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 10. E3-LIB ----

judge_e3lib() {   # <program output, possibly multi-line>
  local out=$1 result rc
  result=$(printf '%s\n' "$out" | perl -e '
    my ($expectf) = @ARGV;
    open(my $eh, "<", $expectf) or exit 3;
    my %exp;
    while (my $l = <$eh>) { chomp $l; my ($k, $v) = split(/=/, $l, 2); next unless defined $v; $exp{$k} = $v }
    close($eh);
    my %got;
    while (my $l = <STDIN>) { chomp $l; next if $l =~ /^unknown:/; my ($k, $v) = split(/=/, $l, 2); next unless defined $v; $got{$k} = $v }
    my @mismatch;
    for my $k (sort keys %exp) { push @mismatch, $k if (!exists $got{$k} || $got{$k} ne $exp{$k}) }
    if (@mismatch) {
      my $n = @mismatch > 5 ? 5 : scalar(@mismatch);
      my @first = @mismatch[0 .. $n - 1];
      print "mismatch:" . join(",", @first) . (@mismatch > 5 ? ",..." : "") . "\n";
      exit 1;
    }
    print "pinned:" . scalar(keys %exp) . "\n";
    exit 0;
  ' "$D/prog/e3lib.expect")
  rc=$?
  case "$rc" in
    0) J_VERDICT=PASS; J_MEASURED="$result" ;;
    1) J_VERDICT=FAIL; J_MEASURED="$result" ;;
    *) J_VERDICT=UNDETERMINED; J_MEASURED="output:short" ;;
  esac
}

check_e3lib() {
  local crit="src/RWAGuard.sol matches the pinned thin-library counts"
  if [ -n "$SKIP_ALL" ]; then skip_check "E3-LIB" "$crit" "$SKIP_ALL"; return; fi
  if [ ! -f src/RWAGuard.sol ] || [ ! -f "$D/prog/e3lib.expect" ]; then
    verdict "E3-LIB" UNDETERMINED "$crit" "output:short"
    return
  fi
  run_prog e3lib -0777 -n -- src/RWAGuard.sol
  if [ "$R_RC" -ne 0 ] || [ -z "$R_OUT" ]; then verdict "E3-LIB" UNDETERMINED "$crit" "output:short"; return; fi
  local mainout=$R_OUT
  perl -0777 -pe 's/GuardCore\.evaluate\(token/GuardCorX.evaluate(token/g' src/RWAGuard.sol > "$D/ctl/e3lib_a.sol"
  if cmp -s src/RWAGuard.sol "$D/ctl/e3lib_a.sol"; then verdict "E3-LIB" UNDETERMINED "$crit" "control:a"; return; fi
  run_prog e3lib -0777 -n -- "$D/ctl/e3lib_a.sol"
  local aok=1
  if [ "$R_RC" -ne 0 ]; then aok=0; fi
  if ! printf '%s\n' "$R_OUT" | /usr/bin/grep -q 'unknownWords=1'; then aok=0; fi
  judge_e3lib "$R_OUT"
  if [ "$J_VERDICT" != FAIL ]; then aok=0; fi
  if [ "$aok" -ne 1 ]; then verdict "E3-LIB" UNDETERMINED "$crit" "control:a"; return; fi
  perl -0777 -pe 's/\A/\/\/ if (x) { }\n/' src/RWAGuard.sol > "$D/ctl/e3lib_b.sol"
  if cmp -s src/RWAGuard.sol "$D/ctl/e3lib_b.sol"; then verdict "E3-LIB" UNDETERMINED "$crit" "control:b"; return; fi
  run_prog e3lib -0777 -n -- "$D/ctl/e3lib_b.sol"
  local bok=1
  if [ "$R_RC" -ne 0 ]; then bok=0; fi
  judge_e3lib "$R_OUT"
  if [ "$J_VERDICT" != PASS ]; then bok=0; fi
  if [ "$bok" -ne 1 ]; then verdict "E3-LIB" UNDETERMINED "$crit" "control:b"; return; fi
  perl -0777 -pe 's/(\n\s*)return GuardCore/$1if (!ok) { }$1return GuardCore/' src/RWAGuard.sol > "$D/ctl/e3lib_c.sol"
  if cmp -s src/RWAGuard.sol "$D/ctl/e3lib_c.sol"; then verdict "E3-LIB" UNDETERMINED "$crit" "control:c"; return; fi
  run_prog e3lib -0777 -n -- "$D/ctl/e3lib_c.sol"
  local cok=1
  if [ "$R_RC" -ne 0 ]; then cok=0; fi
  if ! printf '%s\n' "$R_OUT" | /usr/bin/grep -q 'w_if=2'; then cok=0; fi
  judge_e3lib "$R_OUT"
  if [ "$J_VERDICT" != FAIL ]; then cok=0; fi
  if [ "$cok" -ne 1 ]; then verdict "E3-LIB" UNDETERMINED "$crit" "control:c"; return; fi
  judge_e3lib "$mainout"
  verdict "E3-LIB" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 11. E3H ----

judge_e3h() {   # <output>
  local o=$1
  if [ "$o" = "callEnforce=1 lbrace=2 rbrace=2 returnCheck=1 semicolon=2 unknownWords=0" ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=FAIL
  fi
  J_MEASURED=$(printf '%s' "$o" | tr ' ' ',')
}

check_e3h() {
  local crit="the host in test/RWAGuard.t.sol forwards to the library and nothing else"
  if [ -n "$SKIP_ALL" ]; then skip_check "E3H" "$crit" "$SKIP_ALL"; return; fi
  if [ ! -f test/RWAGuard.t.sol ]; then verdict "E3H" UNDETERMINED "$crit" "host:missing"; return; fi
  run_prog e3h -0777 -n -- test/RWAGuard.t.sol
  if [ "$R_RC" -eq 3 ] || [ "$R_OUT" = "nohost" ] || [ -z "$R_OUT" ]; then
    verdict "E3H" UNDETERMINED "$crit" "host:missing"
    return
  fi
  local mainout=$R_OUT
  perl -0777 -pe 's/(contract\s+RWAGuardHost\s*\{\n)/$1    function who() external view returns (address) { return msg.sender; }\n/' test/RWAGuard.t.sol > "$D/ctl/e3h_who.sol"
  if cmp -s test/RWAGuard.t.sol "$D/ctl/e3h_who.sol"; then
    verdict "E3H" UNDETERMINED "$crit" "control:who"
    return
  fi
  run_prog e3h -0777 -n -- "$D/ctl/e3h_who.sol"
  local wok=1
  if [ "$R_RC" -eq 3 ] || [ "$R_OUT" = "nohost" ]; then wok=0; fi
  if [ "$wok" -eq 1 ]; then
    judge_e3h "$R_OUT"
    if [ "$J_VERDICT" != FAIL ]; then wok=0; fi
    if ! printf '%s' "$R_OUT" | /usr/bin/grep -q 'unknownWords=3'; then wok=0; fi
  fi
  if [ "$wok" -ne 1 ]; then verdict "E3H" UNDETERMINED "$crit" "control:who"; return; fi
  judge_e3h "$mainout"
  verdict "E3H" "$J_VERDICT" "$crit" "$J_MEASURED"
}

# ---- 12. E1-LINT ----
# Ruling R-BP-1: the listing regex is narrowed to src/RWAGuard.sol only (not test/*),
# matching e1.pl's own population; the recorded HEAD measured and B10's expected
# measured are the ruled values, not the design's original ones.

judge_e1lint() {   # <allowed_enforce> <allowed_check> <blocking> <locs> <cls> <listing>
  local ae=$1 ac=$2 blocking=$3 locs=$4 cls=$5 listing=$6
  if [ "$blocking" -eq 0 ] && [ "$locs" -eq "$cls" ] && [ "$ae" -le 1 ] && [ "$ac" -le 1 ] && [ "$locs" -eq "$listing" ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=FAIL
  fi
  J_MEASURED="ae:$ae,ac:$ac,blocking:$blocking,locs:$locs,cls:$cls,listing:$listing"
}

check_e1lint() {
  local crit="the build log carries no lint finding on src/RWAGuard.sol other than the allowed internal-function note"
  if [ -n "$SKIP_ALL" ]; then skip_check "E1-LINT" "$crit" "$SKIP_ALL"; return; fi
  if [ -n "$SKIP_BUILD" ]; then skip_check "E1-LINT" "$crit" "$SKIP_BUILD"; return; fi
  if [ ! -f "$D/build.log" ]; then verdict "E1-LINT" UNDETERMINED "$crit" "missing:build.log"; return; fi
  local headers
  headers=$(/usr/bin/grep -cE '^[[:space:]]*(note|warning|error|help)\[[A-Za-z0-9_-]+\]' "$D/build.log")
  case "$headers" in ''|*[!0-9]*) headers=0 ;; esac
  if [ "$headers" -lt 1 ]; then
    verdict "E1-LINT" UNDETERMINED "$crit" "lint-headers:0"
    return
  fi
  run_prog e1 -n -- "$D/build.log"
  if [ "$R_RC" -ne 0 ] || [ -z "$R_OUT" ]; then
    verdict "E1-LINT" UNDETERMINED "$crit" "output:short"
    return
  fi
  local summary=""
  while IFS= read -r _line; do
    case "$_line" in
      BLOCK\ *) say "PARITY-NOTE: E1-LINT $_line" ;;
      allowed_enforce=*) summary=$_line ;;
    esac
  done <<__LINES__
$R_OUT
__LINES__
  if [ -z "$summary" ]; then
    verdict "E1-LINT" UNDETERMINED "$crit" "output:short"
    return
  fi
  local ae ac blocking locs cls
  set -- $(printf '%s' "$summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  ae=$1
  ac=$2
  blocking=$3
  locs=$4
  cls=$5
  case "$ae$ac$blocking$locs$cls" in *[!0-9]*|'') verdict "E1-LINT" UNDETERMINED "$crit" "output:short"; return ;; esac
  local listing
  listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/build.log")
  case "$listing" in ''|*[!0-9]*) verdict "E1-LINT" UNDETERMINED "$crit" "output:short"; return ;; esac
  judge_e1lint "$ae" "$ac" "$blocking" "$locs" "$cls" "$listing"
  verdict "E1-LINT" "$J_VERDICT" "$crit" "$J_MEASURED"
}
# ==== end part judges-a ====
# ==== part judges-b ====
# Checks 14-20 (VAULT-ART, CEI, CEI-VB, CITE-V5, EIP55, 19a CLOSURE-SET, 19b ETCH-SHAPES,
# MANIFEST). Every judge_* below sets J_VERDICT and J_MEASURED and prints nothing except
# where noted; every check_* runs its in-run controls, then the judge, then exactly one
# verdict line.

jb_ceivb_pin() {   # <label> <want> <line> <file> ; appends <label> to the caller's mism on mismatch
  local label=$1 want=$2 line=$3 file=$4 got
  got=$(/usr/bin/grep -Fxc -- "$line" "$file")
  [ "$got" = "$want" ] || mism="${mism:+$mism,}$label"
}

judge_vaultart() {   # <lay_nv.json> <lay_gv.json> <abi_nv.json> <abi_gv.json>
  local ln=$1 lg=$2 an=$3 ag=$4 out
  local want='abi_errors=1 abi_events=1 abi_fns=1 abi_mutating=1 abi_nopay=1 layout_eq=1 layout_exp=1 shape_ctl10=1 shape_hits0=1'
  run_prog art -- "$ln" "$lg" "$an" "$ag"
  out=$R_OUT
  case "$out" in
    *shape_ctl10=0*) J_VERDICT=UNDETERMINED; J_MEASURED=control:shape_ctl10; return ;;
  esac
  if [ "$R_RC" = 0 ] && [ "$out" = "$want" ]; then
    J_VERDICT=PASS; J_MEASURED=flags:9; return
  fi
  if [ "$R_RC" = 1 ]; then
    J_VERDICT=FAIL
    J_MEASURED=$(printf '%s\n' "$out" | perl -ne 'my @f; for (split) { my ($k,$v) = split /=/, $_, 2; push @f, $k if defined($v) && $v eq "0" } print "false:", join(",", @f)')
    return
  fi
  J_VERDICT=UNDETERMINED
  J_MEASURED=${out:-rc:$R_RC}
}

check_vaultart() {
  local crit="the two demo vaults agree on storage layout and abi surface"
  if [ -n "$SKIP_ALL" ]; then skip_check VAULT-ART "$crit" "$SKIP_ALL"; return; fi
  if [ -n "$SKIP_BUILD" ]; then skip_check VAULT-ART "$crit" "build-rc:$BUILD_RC"; return; fi
  judge_vaultart "$D/json/lay_nv.json" "$D/json/lay_gv.json" "$D/json/abi_nv.json" "$D/json/abi_gv.json"
  verdict VAULT-ART "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_cei() {   # <naive-file> <guarded-file>
  run_prog cei -- "$1" "$2"
  case "$R_RC" in
    0) J_VERDICT=PASS; J_MEASURED=cei_ok:1 ;;
    1) J_VERDICT=FAIL; J_MEASURED=cei_ok:0 ;;
    *) J_VERDICT=UNDETERMINED; J_MEASURED=port:error ;;
  esac
}

check_cei() {
  local crit="the guarded vault differs from the naive vault only by a first enforce line, and both keep effects before interactions"
  if [ -n "$SKIP_ALL" ]; then skip_check CEI "$crit" "$SKIP_ALL"; return; fi
  local pn="src/demo/NaiveVault.sol" pg="src/demo/GuardedVault.sol" ctl="$D/ctl/cei_c8a.sol"
  if [ ! -f "$pg" ]; then verdict CEI UNDETERMINED "$crit" "missing:$pg"; return; fi
  perl -0777 -pe 's/^(        RWAGuard\.enforce\(token, Ctx\(\{[^\n]*\n)((?:[^\n]*\n)*?        totalShares -= shares_;\n)/$2$1/m' "$pg" > "$ctl" 2>/dev/null
  if [ ! -s "$ctl" ] || cmp -s "$pg" "$ctl"; then
    verdict CEI UNDETERMINED "$crit" "control:c8a"
    return
  fi
  judge_cei "$pn" "$ctl"
  if [ "$J_VERDICT" != FAIL ]; then
    verdict CEI UNDETERMINED "$crit" "control:c8a"
    return
  fi
  judge_cei "$pn" "$pg"
  verdict CEI "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_ceivb() {   # <root>
  local root=$1 vb nv gv
  vb="$root/src/demo/VaultBase.sol" nv="$root/src/demo/NaiveVault.sol" gv="$root/src/demo/GuardedVault.sol"
  local f mism="" got
  for f in "$vb" "$nv" "$gv"; do
    if [ ! -f "$f" ]; then J_VERDICT=UNDETERMINED; J_MEASURED="missing:$f"; return; fi
  done
  got=$(perl -0777 -ne 'print scalar(() = /\n    modifier nonReentrant\(\) \{\n        if \(_lock != 1\) revert ReentrantCall\(\);\n        _lock = 2;\n        _;\n        _lock = 1;\n    \}\n/g), "\n"' "$vb")
  [ "$got" = 1 ] || mism="${mism:+$mism,}vb.mod"
  got=$(perl -0777 -ne 'print scalar(() = /\n    constructor\(address token_\) \{\n        token = token_;\n        _lock = 1;\n    \}\n/g), "\n"' "$vb")
  [ "$got" = 1 ] || mism="${mism:+$mism,}vb.ctor"
  jb_ceivb_pin vb.l01 1 '    bytes4 private constant _SEL_TRANSFER = bytes4(keccak256(bytes("transfer(address,uint256)")));' "$vb"
  jb_ceivb_pin vb.l02 1 '    bytes4 private constant _SEL_TRANSFER_FROM = bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));' "$vb"
  jb_ceivb_pin vb.l03 1 '    uint256 private constant _RETURNDATA_COPY_BOUND = 256;' "$vb"
  jb_ceivb_pin vb.l04 1 '    uint256 private _lock;' "$vb"
  jb_ceivb_pin vb.l05 1 '        if (token_.code.length == 0) revert NotAContract(token_);' "$vb"
  jb_ceivb_pin vb.l06 1 '        if (success && (size == 0 || (size == 32 && word == 1))) return;' "$vb"
  jb_ceivb_pin vb.l07 1 '        uint256 n = size > _RETURNDATA_COPY_BOUND ? _RETURNDATA_COPY_BOUND : size;' "$vb"
  jb_ceivb_pin vb.l08 1 '        bytes memory ret = new bytes(n);' "$vb"
  jb_ceivb_pin vb.l09 1 '        revert TransferFailed(token_, ret);' "$vb"
  jb_ceivb_pin vb.l10 1 '            returndatacopy(add(ret, 0x20), 0, n)' "$vb"
  jb_ceivb_pin vb.l11 1 '            success := call(gas(), token_, 0, add(data, 0x20), mload(data), 0, 0)' "$vb"
  jb_ceivb_pin asm.vb 2 '        assembly ("memory-safe") {' "$vb"
  jb_ceivb_pin asm.nv 0 '        assembly ("memory-safe") {' "$nv"
  jb_ceivb_pin asm.gv 0 '        assembly ("memory-safe") {' "$gv"
  got=$(/usr/bin/grep -o 'returndatacopy(' "$vb" | wc -l | tr -d ' ')
  [ "$got" = 2 ] || mism="${mism:+$mism,}rdc.vb"
  got=$(/usr/bin/grep -v '^[[:space:]]*//' "$vb" | /usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient')
  [ "$got" = 0 ] || mism="${mism:+$mism,}flt.vb"
  got=$(/usr/bin/grep -v '^[[:space:]]*//' "$nv" | /usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient')
  [ "$got" = 0 ] || mism="${mism:+$mism,}flt.nv"
  got=$(/usr/bin/grep -v '^[[:space:]]*//' "$gv" | /usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient')
  [ "$got" = 0 ] || mism="${mism:+$mism,}flt.gv"
  got=$(/usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient' "$vb")
  [ "$got" = 1 ] || mism="${mism:+$mism,}raw.vb"
  got=$(/usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient' "$nv")
  [ "$got" = 0 ] || mism="${mism:+$mism,}raw.nv"
  got=$(/usr/bin/grep -ciE 'staticcall|delegatecall|tstore|tload|transient' "$gv")
  [ "$got" = 0 ] || mism="${mism:+$mism,}raw.gv"
  jb_ceivb_pin anchor.vb 1 '/// @dev The lock stays in plain storage by design, never a transient slot.' "$vb"
  if [ -z "$mism" ]; then
    J_VERDICT=PASS; J_MEASURED=pins:24
  else
    mism=$(printf '%s' "$mism" | perl -ne 'my @f = split /,/, $_; print join(",", sort @f)')
    J_VERDICT=FAIL; J_MEASURED="mismatch:$mism"
  fi
}

jb_ceivb_control() {   # <name> <perl-pe-expr> <expect-mismatch> <vb> <nv> <gv>
  local name=$1 expr=$2 expect=$3 vb=$4 nv=$5 gv=$6 root
  root="$D/ctl/$name"
  mkdir -p -- "$root/src/demo" || return 1
  perl -pe "$expr" "$vb" > "$root/src/demo/VaultBase.sol" 2>/dev/null
  cmp -s "$vb" "$root/src/demo/VaultBase.sol" && return 1
  cat -- "$nv" > "$root/src/demo/NaiveVault.sol" || return 1
  cat -- "$gv" > "$root/src/demo/GuardedVault.sol" || return 1
  judge_ceivb "$root"
  [ "$J_VERDICT" = FAIL ] && [ "$J_MEASURED" = "mismatch:$expect" ]
}

check_ceivb() {
  local crit="the VaultBase transfer and lock lines are the pinned ones"
  if [ -n "$SKIP_ALL" ]; then skip_check CEI-VB "$crit" "$SKIP_ALL"; return; fi
  local vb="src/demo/VaultBase.sol" nv="src/demo/NaiveVault.sol" gv="src/demo/GuardedVault.sol"
  if [ ! -f "$vb" ] || [ ! -f "$nv" ] || [ ! -f "$gv" ]; then
    verdict CEI-VB UNDETERMINED "$crit" "missing:src/demo"
    return
  fi
  if ! jb_ceivb_control vb1 's/, 0, n\)$/, 0, size)/' vb.l10 "$vb" "$nv" "$gv"; then
    verdict CEI-VB UNDETERMINED "$crit" "control:vb1"; return
  fi
  if ! jb_ceivb_control vb2 's/word == 1/word != 0/' vb.l06 "$vb" "$nv" "$gv"; then
    verdict CEI-VB UNDETERMINED "$crit" "control:vb2"; return
  fi
  if ! jb_ceivb_control vb3 's/size := returndatasize\(\)$/size := tload(0)/' flt.vb,raw.vb "$vb" "$nv" "$gv"; then
    verdict CEI-VB UNDETERMINED "$crit" "control:vb3"; return
  fi
  judge_ceivb "$SRC"
  verdict CEI-VB "$J_VERDICT" "$crit" "$J_MEASURED"
}

jb_citev5_count() {   # <file>
  perl -ne '$a++ if /^\s*function test_U3_9_storageSlotsStayZero\(\)/; $b++ if /^\s*function test_U3_10_forcedEthDoesNotChangeVerdict\(\)/; END { printf "a:%d,b:%d\n", $a + 0, $b + 0 }' "$1" 2>/dev/null
}

judge_citev5() {   # <file>
  local f=$1 out
  if [ ! -f "$f" ]; then J_VERDICT=UNDETERMINED; J_MEASURED="missing:$f"; return; fi
  out=$(jb_citev5_count "$f")
  case "$out" in
    a:*,b:*)
      J_MEASURED=$out
      if [ "$out" = "a:1,b:1" ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
      ;;
    *) J_VERDICT=UNDETERMINED; J_MEASURED=parse:error ;;
  esac
}

check_citev5() {
  local crit="the two cited view tests are defined exactly once"
  if [ -n "$SKIP_ALL" ]; then skip_check CITE-V5 "$crit" "$SKIP_ALL"; return; fi
  local ctlfile="test/Gates.t.sol" ctlout
  if [ ! -f "$ctlfile" ]; then verdict CITE-V5 UNDETERMINED "$crit" "control:gates"; return; fi
  ctlout=$(jb_citev5_count "$ctlfile")
  if [ "$ctlout" != "a:0,b:0" ]; then verdict CITE-V5 UNDETERMINED "$crit" "control:gates"; return; fi
  judge_citev5 "test/RWAGuardView.t.sol"
  verdict CITE-V5 "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_eip55() {   # <written> <rt> <ctlin> <ctl> ; ctlin is carried for symmetry with the extraction, not used below
  local written=$1 rt=$2 ctl=$4 roundtrip=0 diff lcctl
  [ "$rt" = "$written" ] && roundtrip=1
  lcctl=$(printf '%s' "$ctl" | perl -ne 'chomp; print lc($_)')
  if [ "$lcctl" = "$ctl" ]; then
    J_VERDICT=UNDETERMINED; J_MEASURED=control:cast-flat; return
  fi
  diff=$(perl -e 'my ($a, $b) = @ARGV; my $len = length($a) < length($b) ? length($a) : length($b); my $n = 0; for my $k (0 .. $len - 2) { $n++ if substr($a, $k, 1) ne substr($b, $k, 1) } print $n' "$ctl" "$written")
  if [ "$roundtrip" = 1 ] && [ "$diff" -ge 2 ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=FAIL
  fi
  J_MEASURED="roundtrip:$roundtrip,ctl_diff:${diff:-0}"
}

check_eip55() {
  local crit="the control plane address in src/GuardCore.sol round-trips through the checksum"
  if [ -n "$SKIP_ALL" ]; then skip_check EIP55 "$crit" "$SKIP_ALL"; return; fi
  local src="src/GuardCore.sol"
  if [ ! -f "$src" ]; then verdict EIP55 UNDETERMINED "$crit" "missing:$src"; return; fi
  local lits litfile="$D/ctl/eip55_lits" n=0 l written lower rt ctlin ctl
  lits=$(perl -0777 -ne 'while (/CONTROL_PLANE\s*=\s*(0x[0-9a-fA-F]{40})/g) { print "$1\n" }' "$src")
  printf '%s\n' "$lits" > "$litfile"
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    n=$((n + 1))
    written=$l
  done < "$litfile"
  if [ "$n" != 1 ]; then verdict EIP55 UNDETERMINED "$crit" "literal:$n"; return; fi
  lower=$(printf '%s' "$written" | perl -ne 'chomp; print lc($_), "\n"')
  rt=$(cast to-check-sum-address "$lower" 2>/dev/null | perl -ne 'chomp; print "$_\n"')
  if [ -z "$rt" ]; then verdict EIP55 UNDETERMINED "$crit" "cast:error"; return; fi
  ctlin=$(perl -e 'my $s = shift; my $c = substr($s, -1); substr($s, -1) = sprintf("%x", hex($c) ^ 1); print "$s\n"' "$lower")
  ctl=$(cast to-check-sum-address "$ctlin")
  judge_eip55 "$written" "$rt" "$ctlin" "$ctl"
  verdict EIP55 "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_closureset() {   # <opc-file> <code-file...>
  local opc=$1; shift
  run_prog closure -- "$opc" "$@"
  case "$R_RC" in
    0) J_VERDICT=PASS ;;
    1) J_VERDICT=FAIL ;;
    *) J_VERDICT=UNDETERMINED ;;
  esac
  J_MEASURED=$R_OUT
}

check_closureset() {
  # Value rows without a colon -- including the three state constants the population
  # carries (empty-etch-state, empty-code-hash, never-deployed-hash) -- never match the
  # population pattern and are ignored by construction; nothing here special-cases them.
  # This check can only ever be PASS once the companion opcodes test file is present in
  # the tree; absent that file the program cannot open its first argument and the check
  # is UNDETERMINED with "error", never PASS on its own.
  local crit="every contract in src, test and test/mocks is a population row and every row exists"
  if [ -n "$SKIP_ALL" ]; then skip_check CLOSURE-SET "$crit" "$SKIP_ALL"; return; fi
  local opc="test/Opcodes.t.sol" list="$D/ctl/closure.files" f
  : > "$list" 2>/dev/null || { verdict CLOSURE-SET UNDETERMINED "$crit" "scratch:error"; return; }
  find src -name '*.sol' -type f 2>/dev/null >> "$list"
  for f in test/*.sol; do [ -f "$f" ] && printf '%s\n' "$f" >> "$list"; done
  for f in test/mocks/*.sol; do [ -f "$f" ] && printf '%s\n' "$f" >> "$list"; done
  set --
  while IFS= read -r f; do set -- "$@" "$f"; done < "$list"
  local ectl="$D/ctl/closure_empty.sol"
  { printf '%s\n' "// AS-33a population begin"; printf '%s\n' "// AS-33a population end"; } > "$ectl" 2>/dev/null
  if [ ! -f "$ectl" ]; then verdict CLOSURE-SET UNDETERMINED "$crit" "scratch:error"; return; fi
  judge_closureset "$ectl" "$@"
  case "$J_MEASURED" in
    missing:none\;extra:none)
      verdict CLOSURE-SET UNDETERMINED "$crit" "control:empty-scan"
      return
      ;;
  esac
  judge_closureset "$opc" "$@"
  verdict CLOSURE-SET "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_etchshapes() {   # <file...>
  run_prog etch -0777 -n -- "$@"
  local out=$R_OUT
  case "$out" in
    sites:*,unknown:*)
      J_MEASURED=$out
      if [ "${out##*unknown:}" = 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
      ;;
    *) J_VERDICT=UNDETERMINED; J_MEASURED=${out:-rc:$R_RC} ;;
  esac
}

check_etchshapes() {
  local crit="every vm.etch second argument is one of the frozen shapes"
  if [ -n "$SKIP_ALL" ]; then skip_check ETCH-SHAPES "$crit" "$SKIP_ALL"; return; fi
  local list="$D/ctl/etch.files" f n=0 sitesnum
  : > "$list" 2>/dev/null || { verdict ETCH-SHAPES UNDETERMINED "$crit" "scratch:error"; return; }
  for f in test/*.t.sol; do
    [ -f "$f" ] || continue
    case "$f" in
      test/Opcodes.t.sol) continue ;;
    esac
    printf '%s\n' "$f" >> "$list"
  done
  set --
  while IFS= read -r f; do set -- "$@" "$f"; done < "$list"
  if [ $# -eq 0 ]; then
    verdict ETCH-SHAPES UNDETERMINED "$crit" "control:sites:0,grep:0"
    return
  fi
  judge_etchshapes "$@"
  if [ "$J_VERDICT" = UNDETERMINED ]; then
    verdict ETCH-SHAPES UNDETERMINED "$crit" "$J_MEASURED"
    return
  fi
  while IFS= read -r f; do
    n=$((n + $(/usr/bin/grep -o 'vm\.etch(' -- "$f" 2>/dev/null | wc -l | tr -d ' ')))
  done < "$list"
  sitesnum=${J_MEASURED#sites:}
  sitesnum=${sitesnum%%,*}
  if [ "$n" != "$sitesnum" ]; then
    verdict ETCH-SHAPES UNDETERMINED "$crit" "control:sites:$sitesnum,grep:$n"
    return
  fi
  verdict ETCH-SHAPES "$J_VERDICT" "$crit" "$J_MEASURED"
}

judge_manifest() {   # <before-listfile> <after-listfile> ; also prints the PARITY-CHANGED lines
  local before=$1 after=$2 diffile="$D/ctl/manifest_diff.out" n=0 d
  manifest_diff "$before" "$after" > "$diffile" 2>/dev/null
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    n=$((n + 1))
    say "PARITY-CHANGED: $d"
  done < "$diffile"
  if [ "$n" -eq 0 ]; then J_VERDICT=PASS; else J_VERDICT=FAIL; fi
  J_MEASURED="changed:$n"
}

check_manifest() {
  local crit="the source tree is byte-identical before and after the run"
  if [ -n "$SKIP_ALL" ]; then skip_check MANIFEST "$crit" "$SKIP_ALL"; return; fi
  local before="$D/manifest.before" after="$D/manifest.after" res count
  if [ ! -f "$before" ]; then verdict MANIFEST UNDETERMINED "$crit" "manifest:error"; return; fi
  res=$(manifest "$SRC" "$after")
  if [ -z "$res" ]; then verdict MANIFEST UNDETERMINED "$crit" "manifest:error"; return; fi
  count=${res##* }
  judge_manifest "$before" "$after"
  verdict MANIFEST "$J_VERDICT" "$crit" "$J_MEASURED,files:$count"
  if [ "$J_VERDICT" = FAIL ]; then raise "$EXIT_WORKTREE_CHANGED"; fi
}

judge_natspec() {
  local bits_file="$1"
  local dev_file="$2"
  local view_file="$3"
  local lib_file="$4"

  local bits_out="" dev_out="" view_out="" lib_out=""
  local bits_rc=1 dev_rc=1 view_rc=1 lib_rc=1

  if [ -r "$bits_file" ]; then
    bits_out=$(perl -n -e '$c{$1}++ if /^\/\/\/ ([1-7])\. /; END { my $t = 0; $t += $c{$_} for keys %c; my $d = 0; for my $k (1..7) { $d++ if ($c{$k} || 0) == 1 } print "$t/$d\n" }' -- "$bits_file" 2>/dev/null)
    bits_rc=$?
  fi

  if [ -r "$dev_file" ]; then
    dev_out=$(perl -n -e '$c{$1}++ if /^\/\/\/ \@dev D([1-7])\. /; END { my $t = 0; $t += $c{$_} for keys %c; my $d = 0; for my $k (1..7) { $d++ if ($c{$k} || 0) == 1 } print "$t/$d\n" }' -- "$dev_file" 2>/dev/null)
    dev_rc=$?
  fi

  if [ -r "$view_file" ]; then
    view_out=$(perl -0777 -ne '$n = () = /defined only in GuardBits\.sol/g; print "$n\n"' -- "$view_file" 2>/dev/null)
    view_rc=$?
  fi

  if [ -r "$lib_file" ]; then
    lib_out=$(perl -0777 -ne '$n = () = /defined only in GuardBits\.sol/g; print "$n\n"' -- "$lib_file" 2>/dev/null)
    lib_rc=$?
  fi

  local bits_field="?"
  local dev_field="?"
  local view_field="?"
  local lib_field="?"
  local all_ok=1

  if [ "$bits_rc" -eq 0 ] && printf '%s' "$bits_out" | /usr/bin/grep -Eq '^[0-9]+/[0-9]+$'; then
    bits_field="$bits_out"
  else
    all_ok=0
  fi

  if [ "$dev_rc" -eq 0 ] && printf '%s' "$dev_out" | /usr/bin/grep -Eq '^[0-9]+/[0-9]+$'; then
    dev_field="$dev_out"
  else
    all_ok=0
  fi

  if [ "$view_rc" -eq 0 ] && printf '%s' "$view_out" | /usr/bin/grep -Eq '^[0-9]+$'; then
    view_field="$view_out"
  else
    all_ok=0
  fi

  if [ "$lib_rc" -eq 0 ] && printf '%s' "$lib_out" | /usr/bin/grep -Eq '^[0-9]+$'; then
    lib_field="$lib_out"
  else
    all_ok=0
  fi

  J_MEASURED="bits:${bits_field},dev:${dev_field},view:${view_field},lib:${lib_field}"

  if [ "$all_ok" -ne 1 ]; then
    J_VERDICT=UNDETERMINED
    return
  fi

  if [ "$bits_out" = "7/7" ] && [ "$dev_out" = "7/7" ] && [ "$view_out" -ge 1 ] && [ "$lib_out" -ge 1 ]; then
    J_VERDICT=PASS
  else
    J_VERDICT=FAIL
  fi
}

check_natspec() {
  local crit="the seven-clause NatSpec anchors and the GuardBits sentence are present"
  if [ -n "$SKIP_ALL" ]; then
    skip_check "NATSPEC" "$crit" "$SKIP_ALL"
    return
  fi
  if [ ! -r src/RWAGuard.sol ] || [ ! -r src/RWAGuardView.sol ]; then
    verdict "NATSPEC" UNDETERMINED "$crit" "bits:?,dev:?,view:?,lib:?"
    return
  fi
  judge_natspec src/GuardBits.sol src/RWAGuard.sol src/RWAGuardView.sol src/RWAGuard.sol
  verdict "NATSPEC" "$J_VERDICT" "$crit" "$J_MEASURED"
}
# ==== end part judges-b ====
# ==== part drive ====
st_put() {
  local dest=$1
  mkdir -p -- "$(dirname -- "$dest")" || return 1
  cat > "$dest"
}

st_write_as33b1() {
  st_put "$D/st/as33b1_pass.toml" <<'EOF'
[profile.default]
src = "src"
EOF
  st_put "$D/st/as33b1_fail.toml" <<'EOF'
[profile.default]
[profile.ci]
EOF
}

st_write_as33b2() {
  printf 'exec forge "$@"\n' > "$D/st/as33b2_pass.txt"
  printf 'export %s=ci\n' "$PV" > "$D/st/as33b2_fail.txt"
}

st_write_as33b3() {
  mkdir -p -- "$D/st/t1" "$D/st/t2/x"
  st_put "$D/st/t1/foundry.toml" <<'EOF'
[profile.default]
EOF
  st_put "$D/st/t2/foundry.toml" <<'EOF'
[profile.default]
EOF
  st_put "$D/st/t2/x/foundry.toml" <<'EOF'
[profile.default]
EOF
}

st_write_sg73() {
  printf 'forge Version: 1.8.1\n' > "$D/st/sg73_v_pass.txt"
  printf 'forge Version: 1.9.0-stable\n' > "$D/st/sg73_v_fail.txt"
  printf 'no version here\n' > "$D/st/sg73_v_bad.txt"
  st_put "$D/st/sg73_base.sol" <<'EOF'
// line 1
// line 2
// line 3
// line 4
// line 5
// line 6
// pinned forge 1.8.1
EOF
}

st_write_as32a() {
  printf '%s\n' '{"storage":[],"types":null}' > "$D/st/as32a_1.json"
  printf '%s\n' '{"storage":[],"types":{}}' > "$D/st/as32a_2.json"
  printf '%s\n' '{"storage":[{"label":"x","slot":"0","offset":0,"type":"t_uint256"}],"types":{"t_uint256":{}}}' > "$D/st/as32a_3.json"
  printf '%s\n' 'not json' > "$D/st/as32a_4.json"
}

st_write_abisurface() {
  printf '%s\n' '[{"type":"function","name":"isSafeToTrade","stateMutability":"view"}]' > "$D/st/abisurf_1.json"
  printf '%s\n' '[{"type":"function","name":"isSafeToTrade","stateMutability":"view"},{"type":"function","name":"initialize","stateMutability":"nonpayable"}]' > "$D/st/abisurf_2.json"
}

st_write_abictx() {
  printf '%s\n' '[{"type":"function","name":"isSafeToTrade","inputs":[{"name":"token","type":"address"},{"name":"ctx","type":"tuple","components":[{"name":"priceFeed","type":"address"},{"name":"actor","type":"address"},{"name":"counterparty","type":"address"},{"name":"expectedImpl","type":"address"},{"name":"maxFeedAge","type":"uint64"}]}]}]' > "$D/st/abictx_1.json"
  printf '%s\n' '[{"type":"function","name":"isSafeToTrade","inputs":[{"name":"token","type":"address"},{"name":"ctx","type":"tuple","components":[{"name":"expectedImpl","type":"address"},{"name":"actor","type":"address"},{"name":"counterparty","type":"address"},{"name":"priceFeed","type":"address"},{"name":"maxFeedAge","type":"uint64"}]}]}]' > "$D/st/abictx_2.json"
}

st_write_e3view() {
  st_put "$D/st/e3view_1.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

contract RWAGuardView {
    function isSafeToTrade(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return GuardCore.evaluate(token, ctx);
    }
}
EOF
  st_put "$D/st/e3view_2.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

contract RWAGuardView {
    /// if (x) {}
    function isSafeToTrade(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return GuardCore.evaluate(token, ctx);
    }
}
EOF
  st_put "$D/st/e3view_3.sol" <<'EOF'
contract C { function f() external view { if (x) {} } }
EOF
}

st_write_e3lib() {
  st_put "$D/st/e3lib_1.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

library RWAGuard {
    error GuardBlocked(address token, uint256 reasonBits);

    function enforce(address token, Ctx memory ctx) internal view {
        (bool ok, uint256 reasonBits) = GuardCore.evaluate(token, ctx);
        if (!ok) {
            revert GuardBlocked(token, reasonBits);
        }
    }

    function check(address token, Ctx memory ctx) internal view returns (bool ok, uint256 reasonBits) {
        return GuardCore.evaluate(token, ctx);
    }
}
EOF
  st_put "$D/st/e3lib_2.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GuardCore} from "./GuardCore.sol";
import {Ctx} from "./GuardBits.sol";

library RWAGuard {
    error GuardBlocked(address token, uint256 reasonBits);

    function enforce(address token, Ctx memory ctx) internal view {
        (bool ok, uint256 reasonBits) = GuardCorX.evaluate(token, ctx);
        if (!ok) {
            revert GuardBlocked(token, reasonBits);
        }
    }

    function check(address token, Ctx memory ctx) internal view returns (bool ok, uint256 reasonBits) {
        return GuardCorX.evaluate(token, ctx);
    }
}
EOF
}

st_write_e3h() {
  st_put "$D/st/e3h_1.sol" <<'EOF'
contract RWAGuardHost {
    function enforce(address token, Ctx calldata ctx) external view { RWAGuard.enforce(token, ctx); }
    function check(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return RWAGuard.check(token, ctx);
    }
}
EOF
  st_put "$D/st/e3h_2.sol" <<'EOF'
contract RWAGuardHost {
    function who() external view returns (address) { return msg.sender; }
    function enforce(address token, Ctx calldata ctx) external view { RWAGuard.enforce(token, ctx); }
    function check(address token, Ctx calldata ctx) external view returns (bool ok, uint256 reasonBits) {
        return RWAGuard.check(token, ctx);
    }
}
EOF
}

st_write_e1lint() {
  printf 'note[internal-function-used-once]: x\n   \342\225\255\342\226\270 src/RWAGuard.sol:43:5\n   \342\224\202\n43 \342\224\202     function enforce(address token, Ctx memory ctx) internal view {\n' > "$D/st/e1lint_1.log"
  printf 'warning[unsafe-typecast]: x\n   \342\225\255\342\226\270 src/RWAGuard.sol:43:5\n   \342\224\202\n43 \342\224\202     function enforce(address token, Ctx memory ctx) internal view {\n' > "$D/st/e1lint_2.log"
  printf 'note[internal-function-used-once]: x\n   \342\225\255\342\226\270 src/RWAGuard.sol:44:9\n   \342\224\202\n44 \342\224\202         (bool ok, uint256 reasonBits) = GuardCore.evaluate(token, ctx);\n' > "$D/st/e1lint_3.log"
  printf 'note[internal-function-used-once]: x\n   \342\225\255\342\226\270 src/RWAGuard.sol:43:5\n   \342\224\202\n' > "$D/st/e1lint_4.log"
  printf 'Warning (2519): x\n  --> src/RWAGuard.sol:9:5\n   |\n9  |     foo\n' > "$D/st/e1lint_5.log"
}

st_write_natspec() {
  printf '/// %s. x\n' 1 2 3 4 5 6 7 > "$D/st/natspec_bits_pass.txt"
  printf '/// %s. x\n' 1 2 3 4 5 6 6 > "$D/st/natspec_bits_fail.txt"
  printf '/// @dev D%s. x\n' 1 2 3 4 5 6 7 > "$D/st/natspec_dev.txt"
  printf 'types are defined only in GuardBits.sol\n' > "$D/st/natspec_view.txt"
  printf 'types are defined only in GuardBits.sol\n' > "$D/st/natspec_lib.txt"
}

st_write_vaultart() {
  mkdir -p -- "$D/st/vaultart"
  printf '%s\n' '{"storage":[{"label":"shares","slot":"0","offset":0,"type":"t_mapping(t_address,t_uint256)"},{"label":"totalShares","slot":"1","offset":0,"type":"t_uint256"},{"label":"_lock","slot":"2","offset":0,"type":"t_uint256"}],"types":null}' > "$D/st/vaultart/lay_nv.json"
  cp -- "$D/st/vaultart/lay_nv.json" "$D/st/vaultart/lay_gv.json"
  printf '%s\n' '{"storage":[{"label":"shares","slot":"0","offset":0,"type":"t_mapping(t_address,t_uint256)"},{"label":"totalShares","slot":"1","offset":0,"type":"t_uint256"},{"label":"_lock","slot":"2","offset":0,"type":"t_uint256"},{"label":"_u6Probe","slot":"3","offset":0,"type":"t_uint256"}],"types":null}' > "$D/st/vaultart/lay_gv_c6.json"
  printf '%s\n' '{"storage":[{"label":"shares","slot":0,"offset":0,"type":"t_mapping(t_address,t_uint256)"},{"label":"totalShares","slot":"1","offset":0,"type":"t_uint256"},{"label":"_lock","slot":"2","offset":0,"type":"t_uint256"}],"types":null}' > "$D/st/vaultart/lay_gv_slot0.json"
  printf '%s\n' '[{"type":"constructor","stateMutability":"nonpayable"},{"type":"function","name":"deposit","stateMutability":"nonpayable"},{"type":"function","name":"redeem","stateMutability":"nonpayable"},{"type":"function","name":"shares","stateMutability":"view"},{"type":"function","name":"token","stateMutability":"view"},{"type":"function","name":"totalShares","stateMutability":"view"},{"type":"event","name":"Deposited"},{"type":"event","name":"Redeemed"},{"type":"error","name":"InsufficientShares"},{"type":"error","name":"NotAContract"},{"type":"error","name":"ReentrantCall"},{"type":"error","name":"TransferFailed"},{"type":"error","name":"ZeroAmount"}]' > "$D/st/vaultart/abi_nv.json"
  printf '%s\n' 'not json' > "$D/st/vaultart/abi_nv_bad.json"
  printf '%s\n' '[{"type":"constructor","stateMutability":"nonpayable"},{"type":"function","name":"deposit","stateMutability":"nonpayable"},{"type":"function","name":"redeem","stateMutability":"nonpayable"},{"type":"function","name":"shares","stateMutability":"view"},{"type":"function","name":"token","stateMutability":"view"},{"type":"function","name":"totalShares","stateMutability":"view"},{"type":"function","name":"expectedImpl","stateMutability":"view"},{"type":"function","name":"maxFeedAge","stateMutability":"view"},{"type":"function","name":"priceFeed","stateMutability":"view"},{"type":"event","name":"Deposited"},{"type":"event","name":"Redeemed"},{"type":"error","name":"InsufficientShares"},{"type":"error","name":"NotAContract"},{"type":"error","name":"ReentrantCall"},{"type":"error","name":"TransferFailed"},{"type":"error","name":"ZeroAmount"},{"type":"error","name":"GuardBlocked"}]' > "$D/st/vaultart/abi_gv.json"
}

st_write_cei() {
  mkdir -p -- "$D/st/cei"
  st_put "$D/st/cei/NaiveVault.sol" <<'EOF'
contract NaiveVault is VaultBase {
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
EOF
  st_put "$D/st/cei/GuardedVault.sol" <<'EOF'
contract NaiveVault is VaultBase {
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
EOF
  st_put "$D/st/cei/NaiveVault_probe.sol" <<'EOF'
contract NaiveVault is VaultBase {
    function deposit(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        shares[msg.sender] += amount;
        totalShares += amount;
        // probe
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
EOF
}

st_write_ceivb() {
  mkdir -p -- "$D/st/vb/src/demo" "$D/st/vb2/src/demo"
  st_put "$D/st/vb/src/demo/VaultBase.sol" <<'EOF'
/// @dev The lock stays in plain storage by design, never a transient slot.
abstract contract VaultBase {
    constructor(address token_) {
        token = token_;
        _lock = 1;
    }
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
    function _callToken(address token_, bytes memory data) private {
        if (token_.code.length == 0) revert NotAContract(token_);
        assembly ("memory-safe") {
            success := call(gas(), token_, 0, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, 32)
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
EOF
  printf 'contract NaiveVault {}\n' > "$D/st/vb/src/demo/NaiveVault.sol"
  printf 'contract GuardedVault {}\n' > "$D/st/vb/src/demo/GuardedVault.sol"
  st_put "$D/st/vb2/src/demo/VaultBase.sol" <<'EOF'
/// @dev The lock stays in plain storage by design, never a transient slot.
abstract contract VaultBase {
    constructor(address token_) {
        token = token_;
        _lock = 1;
    }
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
    function _callToken(address token_, bytes memory data) private {
        if (token_.code.length == 0) revert NotAContract(token_);
        assembly ("memory-safe") {
            success := call(gas(), token_, 0, add(data, 0x20), mload(data), 0, 0)
            returndatacopy(0, 0, 32)
        }
        if (success && (size == 0 || (size == 32 && word == 1))) return;
        uint256 n = size > _RETURNDATA_COPY_BOUND ? _RETURNDATA_COPY_BOUND : size;
        bytes memory ret = new bytes(n);
        assembly ("memory-safe") {
            returndatacopy(add(ret, 0x20), 0, size)
        }
        revert TransferFailed(token_, ret);
    }
}
EOF
  printf 'contract NaiveVault {}\n' > "$D/st/vb2/src/demo/NaiveVault.sol"
  printf 'contract GuardedVault {}\n' > "$D/st/vb2/src/demo/GuardedVault.sol"
}

st_write_citev5() {
  st_put "$D/st/citev5_1.sol" <<'EOF'
    function test_U3_9_storageSlotsStayZero() public {
    function test_U3_10_forcedEthDoesNotChangeVerdict() public {
EOF
  st_put "$D/st/citev5_2.sol" <<'EOF'
    function test_U3_9_storageSlotsStayZero() public {
EOF
}

st_write_closureset() {
  st_put "$D/st/closure_pop.txt" <<'EOF'
// AS-33a population begin
    "a.sol:Alpha",
    "a.sol:Beta",
    "empty-code-state",
// AS-33a population end
EOF
  st_put "$D/st/closure_pop_noend.txt" <<'EOF'
// AS-33a population begin
    "a.sol:Alpha",
    "a.sol:Beta",
    "empty-code-state",
EOF
  st_put "$D/st/closure_code.sol" <<'EOF'
contract Alpha {}
contract Beta {}
EOF
  st_put "$D/st/closure_code_extra.sol" <<'EOF'
contract Alpha {}
contract Beta {}
contract ZZProbe {}
EOF
}

st_write_etchshapes() {
  st_put "$D/st/etch_1.sol" <<'EOF'
vm.etch(a, "");
vm.etch(b, new bytes(0));
EOF
  st_put "$D/st/etch_2.sol" <<'EOF'
vm.etch(a, hex"00");
EOF
}

st_write_manifest() {
  printf '%s  %s\n' HASH1 a.txt > "$D/st/manifest_before_1.txt"
  printf '%s  %s\n' HASH1 a.txt > "$D/st/manifest_after_1.txt"
  printf '%s  %s\n' HASH1 a.txt > "$D/st/manifest_before_2.txt"
  printf '%s  %s\n' HASH2 a.txt > "$D/st/manifest_after_2.txt"
}

run_self_test() {
  PHASE=self-test
  st_write_as33b1
  st_write_as33b2
  st_write_as33b3
  st_write_sg73
  st_write_as32a
  st_write_abisurface
  st_write_abictx
  st_write_e3view
  st_write_e3lib
  st_write_e3h
  st_write_e1lint
  st_write_natspec
  st_write_vaultart
  st_write_cei
  st_write_ceivb
  st_write_citev5
  st_write_closureset
  st_write_etchshapes
  st_write_manifest

  st_arm TOOLS-1 PASS judge_tools_list ""
  st_arm TOOLS-2 UNDETERMINED judge_tools_list "forge"

  run_prog toml -n -- "$D/st/as33b1_pass.toml"
  st_arm AS33b-1-1 PASS judge_as33b1 "${R_OUT%% *}" "${R_OUT##* }"
  run_prog toml -n -- "$D/st/as33b1_fail.toml"
  st_arm AS33b-1-2 FAIL judge_as33b1 "${R_OUT%% *}" "${R_OUT##* }"

  run_prog needle -- "$PV" "$D/st/as33b2_pass.txt"
  local as33b2_n=$R_OUT
  run_prog needle -- "$PF" "$D/st/as33b2_pass.txt"
  st_arm AS33b-2-1 PASS judge_as33b2 "$((as33b2_n + R_OUT))"
  run_prog needle -- "$PV" "$D/st/as33b2_fail.txt"
  local as33b2_n=$R_OUT
  run_prog needle -- "$PF" "$D/st/as33b2_fail.txt"
  st_arm AS33b-2-2 FAIL judge_as33b2 "$((as33b2_n + R_OUT))"

  local as33b3_n
  as33b3_n=$( ( cd "$D/st/t1" && find . -name foundry.toml -type f -print ) | perl -ne '$n++; END { print $n + 0, "\n" }' )
  st_arm AS33b-3-1 PASS judge_as33b3 "$as33b3_n"
  local as33b3_n
  as33b3_n=$( ( cd "$D/st/t2" && find . -name foundry.toml -type f -print ) | perl -ne '$n++; END { print $n + 0, "\n" }' )
  st_arm AS33b-3-2 FAIL judge_as33b3 "$as33b3_n"

  local sg73_vout sg73_vcount sg73_v sg73_b7 sg73_line
  sg73_vout=$(perl -ne 'print "$1\n" if /^forge\b.*?(\d+\.\d+\.\d+)/' "$D/st/sg73_v_pass.txt")
  sg73_vcount=0; sg73_v=""
  if [ -n "$sg73_vout" ]; then
    while IFS= read -r sg73_line; do sg73_vcount=$((sg73_vcount + 1)); sg73_v=$sg73_line; done < <(printf '%s\n' "$sg73_vout")
  fi
  sg73_b7=$(perl -ne 'if ($. == 7) { print((/(?<!\d)1\.8\.1(?!\d)/) ? "1\n" : "0\n"); exit }' "$D/st/sg73_base.sol")
  st_arm SG7-3-1 PASS judge_sg73 "$sg73_vcount" "$sg73_v" "$sg73_b7"
  local sg73_vout sg73_vcount sg73_v sg73_b7 sg73_line
  sg73_vout=$(perl -ne 'print "$1\n" if /^forge\b.*?(\d+\.\d+\.\d+)/' "$D/st/sg73_v_fail.txt")
  sg73_vcount=0; sg73_v=""
  if [ -n "$sg73_vout" ]; then
    while IFS= read -r sg73_line; do sg73_vcount=$((sg73_vcount + 1)); sg73_v=$sg73_line; done < <(printf '%s\n' "$sg73_vout")
  fi
  sg73_b7=$(perl -ne 'if ($. == 7) { print((/(?<!\d)1\.8\.1(?!\d)/) ? "1\n" : "0\n"); exit }' "$D/st/sg73_base.sol")
  st_arm SG7-3-2 FAIL judge_sg73 "$sg73_vcount" "$sg73_v" "$sg73_b7"
  local sg73_vout sg73_vcount sg73_v sg73_b7 sg73_line
  sg73_vout=$(perl -ne 'print "$1\n" if /^forge\b.*?(\d+\.\d+\.\d+)/' "$D/st/sg73_v_bad.txt")
  sg73_vcount=0; sg73_v=""
  if [ -n "$sg73_vout" ]; then
    while IFS= read -r sg73_line; do sg73_vcount=$((sg73_vcount + 1)); sg73_v=$sg73_line; done < <(printf '%s\n' "$sg73_vout")
  fi
  sg73_b7=$(perl -ne 'if ($. == 7) { print((/(?<!\d)1\.8\.1(?!\d)/) ? "1\n" : "0\n"); exit }' "$D/st/sg73_base.sol")
  st_arm SG7-3-3 UNDETERMINED judge_sg73 "$sg73_vcount" "$sg73_v" "$sg73_b7"

  run_prog layout -- "$D/st/as32a_1.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm AS32a-1 PASS judge_as32a "${1:-}" "${2:-}"
  run_prog layout -- "$D/st/as32a_2.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm AS32a-2 PASS judge_as32a "${1:-}" "${2:-}"
  run_prog layout -- "$D/st/as32a_3.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm AS32a-3 FAIL judge_as32a "${1:-}" "${2:-}"
  run_prog layout -- "$D/st/as32a_4.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm AS32a-4 UNDETERMINED judge_as32a "${1:-}" "${2:-}"

  run_prog abisurf -- "$D/st/abisurf_1.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm ABI-SURFACE-1 PASS judge_abisurf "${1:-}" "${2:-}" "${3:-}" "${4:-}"
  run_prog abisurf -- "$D/st/abisurf_2.json"
  set -- $(printf '%s' "$R_OUT" | perl -pe 's/[a-zA-Z]+:/ /g; s/,/ /g')
  st_arm ABI-SURFACE-2 FAIL judge_abisurf "${1:-}" "${2:-}" "${3:-}" "${4:-}"

  run_prog abictx -- "$D/st/abictx_1.json"
  st_arm ABI-CTX-1 PASS judge_abictx "$R_RC" "${R_OUT#got:}"
  run_prog abictx -- "$D/st/abictx_2.json"
  st_arm ABI-CTX-2 FAIL judge_abictx "$R_RC" "${R_OUT#got:}"

  run_prog e3view -0777 -n -- "$D/st/e3view_1.sol"
  st_arm E3-VIEW-1 PASS judge_e3view "$R_OUT" "$(perl -0777 -ne '$n = () = /\/\*/g; print "$n\n"' "$D/st/e3view_1.sol")"
  run_prog e3view -0777 -n -- "$D/st/e3view_2.sol"
  st_arm E3-VIEW-2 PASS judge_e3view "$R_OUT" "$(perl -0777 -ne '$n = () = /\/\*/g; print "$n\n"' "$D/st/e3view_2.sol")"
  run_prog e3view -0777 -n -- "$D/st/e3view_3.sol"
  st_arm E3-VIEW-3 FAIL judge_e3view "$R_OUT" "$(perl -0777 -ne '$n = () = /\/\*/g; print "$n\n"' "$D/st/e3view_3.sol")"

  run_prog e3lib -0777 -n -- "$D/st/e3lib_1.sol"
  st_arm E3-LIB-1 PASS judge_e3lib "$R_OUT"
  run_prog e3lib -0777 -n -- "$D/st/e3lib_2.sol"
  st_arm E3-LIB-2 FAIL judge_e3lib "$R_OUT"

  run_prog e3h -0777 -n -- "$D/st/e3h_1.sol"
  st_arm E3H-1 PASS judge_e3h "$R_OUT"
  run_prog e3h -0777 -n -- "$D/st/e3h_2.sol"
  st_arm E3H-2 FAIL judge_e3h "$R_OUT"

  run_prog e1 -n -- "$D/st/e1lint_1.log"
  local e1_summary e1_listing
  e1_summary=$(printf '%s\n' "$R_OUT" | /usr/bin/grep '^allowed_enforce=')
  set -- $(printf '%s' "$e1_summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  e1_listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/st/e1lint_1.log")
  st_arm E1-LINT-1 PASS judge_e1lint "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$e1_listing"
  run_prog e1 -n -- "$D/st/e1lint_2.log"
  local e1_summary e1_listing
  e1_summary=$(printf '%s\n' "$R_OUT" | /usr/bin/grep '^allowed_enforce=')
  set -- $(printf '%s' "$e1_summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  e1_listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/st/e1lint_2.log")
  st_arm E1-LINT-2 FAIL judge_e1lint "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$e1_listing"
  run_prog e1 -n -- "$D/st/e1lint_3.log"
  local e1_summary e1_listing
  e1_summary=$(printf '%s\n' "$R_OUT" | /usr/bin/grep '^allowed_enforce=')
  set -- $(printf '%s' "$e1_summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  e1_listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/st/e1lint_3.log")
  st_arm E1-LINT-3 FAIL judge_e1lint "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$e1_listing"
  run_prog e1 -n -- "$D/st/e1lint_4.log"
  local e1_summary e1_listing
  e1_summary=$(printf '%s\n' "$R_OUT" | /usr/bin/grep '^allowed_enforce=')
  set -- $(printf '%s' "$e1_summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  e1_listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/st/e1lint_4.log")
  st_arm E1-LINT-4 FAIL judge_e1lint "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$e1_listing"
  run_prog e1 -n -- "$D/st/e1lint_5.log"
  local e1_summary e1_listing
  e1_summary=$(printf '%s\n' "$R_OUT" | /usr/bin/grep '^allowed_enforce=')
  set -- $(printf '%s' "$e1_summary" | perl -pe 's/[a-zA-Z_]+=/ /g')
  e1_listing=$(perl -ne '$n++ if /(?:-->|\xE2\x95\xAD\xE2\x96\xB8)\s*(src\/RWAGuard\.sol:\d+)/; END { print $n + 0, "\n" }' "$D/st/e1lint_5.log")
  st_arm E1-LINT-5 FAIL judge_e1lint "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$e1_listing"

  st_arm NATSPEC-1 PASS judge_natspec "$D/st/natspec_bits_pass.txt" "$D/st/natspec_dev.txt" "$D/st/natspec_view.txt" "$D/st/natspec_lib.txt"
  st_arm NATSPEC-2 FAIL judge_natspec "$D/st/natspec_bits_fail.txt" "$D/st/natspec_dev.txt" "$D/st/natspec_view.txt" "$D/st/natspec_lib.txt"

  st_arm VAULT-ART-1 PASS judge_vaultart "$D/st/vaultart/lay_nv.json" "$D/st/vaultart/lay_gv.json" "$D/st/vaultart/abi_nv.json" "$D/st/vaultart/abi_gv.json"
  st_arm VAULT-ART-2 FAIL judge_vaultart "$D/st/vaultart/lay_nv.json" "$D/st/vaultart/lay_gv_c6.json" "$D/st/vaultart/abi_nv.json" "$D/st/vaultart/abi_gv.json"
  st_arm VAULT-ART-3 FAIL judge_vaultart "$D/st/vaultart/lay_nv.json" "$D/st/vaultart/lay_gv_slot0.json" "$D/st/vaultart/abi_nv.json" "$D/st/vaultart/abi_gv.json"
  st_arm VAULT-ART-4 UNDETERMINED judge_vaultart "$D/st/vaultart/lay_nv.json" "$D/st/vaultart/lay_gv.json" "$D/st/vaultart/abi_nv_bad.json" "$D/st/vaultart/abi_gv.json"

  st_arm CEI-1 PASS judge_cei "$D/st/cei/NaiveVault.sol" "$D/st/cei/GuardedVault.sol"
  st_arm CEI-2 FAIL judge_cei "$D/st/cei/NaiveVault_probe.sol" "$D/st/cei/GuardedVault.sol"

  st_arm CEI-VB-1 PASS judge_ceivb "$D/st/vb"
  st_arm CEI-VB-2 FAIL judge_ceivb "$D/st/vb2"

  st_arm CITE-V5-1 PASS judge_citev5 "$D/st/citev5_1.sol"
  st_arm CITE-V5-2 FAIL judge_citev5 "$D/st/citev5_2.sol"

  st_arm EIP55-1 PASS judge_eip55 0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5 0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5 0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca4 0x1Df3ca0Fd30Ed5Eeb09eB01938f4E9c5196E6Ca4
  st_arm EIP55-2 FAIL judge_eip55 0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca5 0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5 0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca4 0x1Df3ca0Fd30Ed5Eeb09eB01938f4E9c5196E6Ca4
  st_arm EIP55-3 UNDETERMINED judge_eip55 0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5 0x1dF3cA0fD30ED5eeb09eB01938f4E9c5196E6Ca5 0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca4 0x1df3ca0fd30ed5eeb09eb01938f4e9c5196e6ca4

  st_arm CLOSURE-1 PASS judge_closureset "$D/st/closure_pop.txt" "$D/st/closure_code.sol"
  st_arm CLOSURE-2 FAIL judge_closureset "$D/st/closure_pop.txt" "$D/st/closure_code_extra.sol"
  st_arm CLOSURE-3 UNDETERMINED judge_closureset "$D/st/closure_pop_noend.txt" "$D/st/closure_code.sol"

  st_arm ETCH-1 PASS judge_etchshapes "$D/st/etch_1.sol"
  st_arm ETCH-2 FAIL judge_etchshapes "$D/st/etch_2.sol"

  st_arm MANIFEST-1 PASS judge_manifest "$D/st/manifest_before_1.txt" "$D/st/manifest_after_1.txt"
  st_arm MANIFEST-2 FAIL judge_manifest "$D/st/manifest_before_2.txt" "$D/st/manifest_after_2.txt"
}

run_full() {
  PHASE=check
  check_tools
  if ! mb_out=$(manifest "$SRC" "$D/manifest.before"); then
    say "PARITY-ERROR: cannot take a manifest of the source tree before the run"
    raise "$EXIT_UNDETERMINED"
  fi
  if [ -z "$SKIP_ALL" ]; then
    run_build
    collect_json
  fi
  check_as33b1
  check_as33b2
  check_as33b3
  check_sg73
  check_as32a
  check_abisurf
  check_abictx
  check_e3view
  check_e3lib
  check_e3h
  check_e1lint
  check_natspec
  check_vaultart
  check_cei
  check_ceivb
  check_citev5
  check_eip55
  check_closureset
  check_etchshapes
  check_manifest
}

main() {
  setup_run "$@"
  if [ "$MODE" = self ]; then
    run_self_test
  else
    run_full
  fi
  finish
}

main "$@"
