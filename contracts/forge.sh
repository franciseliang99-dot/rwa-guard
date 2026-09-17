#!/bin/sh
# 把 forge 的构建产物导到仓外再跑。
#
# 为什么需要它:提交前的检查扫的是整棵工作树、不读 .gitignore,
# 而 forge 的 out/ 里内嵌机器绝对路径。仅靠 .gitignore 只挡得住 git,挡不住那道检查。
#
# 用法:  ./forge.sh test -vv        ./forge.sh build        ./forge.sh fmt
# 覆盖:  FOUNDRY_OUT=… FOUNDRY_CACHE_PATH=… ./forge.sh test
# 电池:  ./forge.sh battery [--only <id>]   转给同目录的 mutation_battery.sh,不走下面的 forge 路径
# 判据:  ./forge.sh parity [--self-test]  转给同目录的 build_parity.sh(AS-33b 等构建层判据),不走下面的 forge 路径
# 覆盖率:./forge.sh coverage --report lcov   没给 --report-file 时,报告落 $TMPDIR 而不是仓内
#
# 刻意不写任何绝对路径:落点取自 $TMPDIR,所以这个文件可以原样进参赛提交物。
set -eu

if [ "${1-}" = "battery" ]; then
    shift
    exec bash "$(dirname "$0")/mutation_battery.sh" "$@"
fi

if [ "${1-}" = "parity" ]; then
    shift
    exec bash "$(dirname "$0")/build_parity.sh" "$@"
fi

# forge coverage 的 --report-file 默认落在 cwd = 仓内,而上面那条同样适用:
# 检查扫的是整棵工作树、不读 .gitignore。用户没显式给落点时补一个 $TMPDIR 下的默认值;
# 显式给了就原样放行(两种写法都认:--report-file <路径> 与 --report-file=<路径>)。
if [ "${1-}" = "coverage" ]; then
    _rf=0
    for _a in "$@"; do
        case "$_a" in
            --report-file|--report-file=*) _rf=1 ;;
        esac
    done
    if [ "$_rf" -eq 0 ]; then
        mkdir -p "${TMPDIR:-/tmp}/rwa-guard-forge"
        set -- "$@" --report-file "${TMPDIR:-/tmp}/rwa-guard-forge/lcov.info"
    fi
    unset _a _rf
fi

: "${FOUNDRY_OUT:=${TMPDIR:-/tmp}/rwa-guard-forge/out}"
: "${FOUNDRY_CACHE_PATH:=${TMPDIR:-/tmp}/rwa-guard-forge/cache}"
export FOUNDRY_OUT FOUNDRY_CACHE_PATH

if ! command -v forge >/dev/null 2>&1; then
    # foundry 的默认安装位置不在非登录 shell 的 PATH 上
    if [ -x "$HOME/.foundry/bin/forge" ]; then
        PATH="$PATH:$HOME/.foundry/bin"
        export PATH
    else
        echo "forge 不在 PATH 上,且 ~/.foundry/bin/forge 不存在" >&2
        exit 127
    fi
fi

exec forge "$@"
